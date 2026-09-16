#!/usr/bin/env python3
"""Warm a reviewed pull request's wheelhouse while running only main's code.

The dangerous shape this replaces is a credentialed job that CHECKS OUT a
contributor's branch. Anything in that tree — a build backend, a `setup.py`, a
post-install hook, a Poetry plugin — then runs on a runner holding a registry
credential, and the review that approved the diff never covered the code that
executed.

So nothing here is ever checked out or executed. Exactly two files are read, as
BOUNDED DATA, over the API, at one exact commit: `pyproject.toml` and
`poetry.lock`. They are parsed, never evaluated. Wheels are downloaded and
hash-checked against the lock, and nothing in them is built or imported. The
result is bytes in a directory and a cache key derived from those bytes.

The snapshot binding is the property worth stating, and it is carried by the
FIXED ref: both files are read at one exact SHA passed as `?ref=`, so nothing
landing on the branch mid-run can change what either read returns, and each
file's bytes are proven to hash to the git blob id the API named for it at that
SHA. The head is separately confirmed to be the pull request's head before the
reads and again after them — a different claim, freshness of the reviewed head,
so the warm is not produced for a commit the pull request has moved past.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

API = "https://api.github.com"
MAIN_REF = "refs/heads/main"

# A private name may only come from a host on this list, and the credential is
# only ever handed to a host on this list. A lock entry naming any other host is
# refused outright rather than resolved from somewhere unexpected.
PRIVATE_HOSTS = frozenset({"registry.dotmac.io"})
PUBLIC_INDEX = "https://pypi.org/simple"
PUBLIC_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org"})

# The dependency-confusion control: only these names may resolve privately.
PRIVATE_SCOPE = re.compile(r"dotmac-[a-z0-9]+(?:-[a-z0-9]+)*\Z")

# A lock is contributor-supplied, and its names and versions end up in pip's
# argv as "<name>==<version>". A name beginning with "-" would be parsed as an
# OPTION rather than a requirement, so the shapes are pinned rather than
# assumed: both must start with an alphanumeric, and neither may contain a
# space, a slash or a leading dash.
NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.!+_-]*\Z")

# Input bounds. Both files are small by nature; a large one means the reference
# is not what this workflow was built to read, so it is refused, not truncated.
MAX_MANIFEST_BYTES = 256 * 1024
MAX_LOCK_BYTES = 8 * 1024 * 1024

# Runtime bound, per acquisition, independent of the job-level timeout.
ACQUIRE_TIMEOUT_SECONDS = 300

# The downloader's environment is CONSTRUCTED from this list, not filtered from
# the job's. An allowlist, because the job step that runs `acquire` also holds
# the registry credential as a plain variable (`FORGEJO_BUNDLE_READ_TOKEN`) and
# the downloader has no use for it — the credential it needs is already inside
# `PIP_INDEX_URL`. A denylist would have to anticipate every name worth
# withholding; this only has to name what pip legitimately needs, and anything
# added to the step's environment later does not reach the child by default.
CHILD_ENV_KEYS = (
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    # Not cargo: `actions/setup-python` builds its toolcache interpreters
    # `--enable-shared` and exports `LD_LIBRARY_PATH=<toolcache>/lib` on Linux.
    # Whether `sys.executable -m pip` starts without it depends on that build's
    # rpath, and if it does not the child dies before pip runs — surfacing only
    # as the fixed `acquisition failed for <name>` message, which is fixed
    # precisely so it cannot relay the cause. It carries no secret.
    "LD_LIBRARY_PATH",
)

SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
HASH_RE = re.compile(r"sha256:([0-9a-f]{64})\Z")
WHEEL_RE = re.compile(r"([A-Za-z0-9_.]+)-([^-]+)-(?:[^-]+-)?[^-]+-[^-]+-[^-]+\.whl\Z")


class WarmRefused(Exception):
    """A precondition of the warm does not hold. Nothing is cached."""


class Fetch(Protocol):
    def __call__(self, path: str, *, raw: bool = False) -> Any: ...


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _host(url: str) -> str:
    """The host an index URL actually resolves to, per the standard parser.

    Hand-splitting on "/" and "@" gets this wrong, and wrong here means handing
    the registry credential to somebody else's host: in
    `https://registry.dotmac.io@evil.example/simple` the trusted-looking name is
    USERINFO and the host is `evil.example`. `urlsplit().hostname` is the
    authority on that, and it also lowercases, strips any port and rejects a
    malformed bracketed netloc — which is raised here as a refusal rather than
    escaping as a ValueError.
    """
    if not url.startswith("https://"):
        raise WarmRefused("index url is not https")
    try:
        host = urlsplit(url).hostname
    except ValueError:
        raise WarmRefused("index url is unparseable") from None
    if not host:
        raise WarmRefused("index url names no host")
    return host.lower()


def _refuse_a_decorated_index(url: str) -> None:
    """A private index URL is a bare https origin and path — nothing else.

    `acquire` injects the credential by REBUILDING the URL from the hostname it
    validated, so a decorated netloc cannot survive that step structurally. This
    refusal is the other half, and it is about the lock rather than the splice:
    a private source URL carrying userinfo is not a shape this workflow has any
    reason to accept, and `https://someone@registry.dotmac.io/simple` passes the
    host allowlist because the trusted name IS the hostname. A port is refused
    for the same reason — the allowlist admits a HOST, and that host on another
    port is a different endpoint than the one that was admitted. Refused here,
    where the plan is built from lock data, so it is a data-shape refusal and
    not a surprise in the one step that holds the credential.
    """
    parsed = urlsplit(url)
    if parsed.username:
        raise WarmRefused("private index url carries a username")
    if parsed.password:
        raise WarmRefused("private index url carries a password")
    try:
        port = parsed.port
    except ValueError:
        # A non-numeric port; `hostname` does not validate it, so `_host` let
        # it through. Still a port component, still refused.
        raise WarmRefused("private index url carries an unreadable port") from None
    if port is not None:
        raise WarmRefused("private index url carries a port")


def git_blob_id(payload: bytes) -> str:
    """The git object id of these bytes, so the API's `sha` can be checked."""
    return hashlib.sha1(  # noqa: S324 -- git's object id is defined as SHA-1.
        b"blob " + str(len(payload)).encode() + b"\0" + payload
    ).hexdigest()


# --------------------------------------------------------------------------
# 1. Dispatch admission
# --------------------------------------------------------------------------


def admit_dispatch(ref: str, pr_number: str, head_sha: str) -> tuple[int, str]:
    """Refuse a dispatch that is not main's code, or whose inputs are not exact.

    The environment's branch policy is the OTHER half of this. It is not enough
    alone: `workflow_dispatch` accepts a `ref`, so a dispatcher can ask for this
    workflow's file as it exists on some other branch. This check is what makes
    the job refuse to be that.
    """
    if ref != MAIN_REF:
        raise WarmRefused("refusing to warm from a ref that is not protected main")
    if not re.fullmatch(r"[1-9][0-9]{0,6}", pr_number or ""):
        raise WarmRefused("pull request number is not a plain positive integer")
    if not SHA_RE.fullmatch(head_sha or ""):
        raise WarmRefused("head sha is not an exact 40-character commit id")
    return int(pr_number), head_sha


# --------------------------------------------------------------------------
# 2. The one-snapshot read
# --------------------------------------------------------------------------


def _pull_head(fetch: Fetch, repo: str, pr_number: int) -> str:
    pull = fetch(f"/repos/{repo}/pulls/{pr_number}")
    head = (pull or {}).get("head", {}).get("sha")
    if not isinstance(head, str) or not SHA_RE.fullmatch(head):
        raise WarmRefused("pull request head sha is unreadable")
    return head


def _read_blob(fetch: Fetch, repo: str, path: str, sha: str, limit: int) -> bytes:
    """Read one path at one commit as data: metadata, bound, then exact bytes."""
    entry = fetch(f"/repos/{repo}/contents/{path}?ref={sha}")
    if not isinstance(entry, dict) or entry.get("type") != "file":
        raise WarmRefused(f"{path} is not a regular file at the named commit")
    size, blob_id = entry.get("size"), entry.get("sha")
    if not isinstance(size, int) or not isinstance(blob_id, str):
        raise WarmRefused(f"{path} metadata is unreadable")
    if size > limit:
        raise WarmRefused(f"{path} exceeds the {limit}-byte input bound")
    payload = fetch(f"/repos/{repo}/git/blobs/{blob_id}", raw=True)
    if not isinstance(payload, bytes) or len(payload) != size:
        raise WarmRefused(f"{path} bytes do not match the declared size")
    if git_blob_id(payload) != blob_id:
        raise WarmRefused(f"{path} bytes do not hash to the blob the commit names")
    return payload


def bind_snapshot(
    fetch: Fetch, repo: str, pr_number: int, head_sha: str
) -> tuple[bytes, bytes]:
    """Read both files at ONE commit, then confirm that commit is still the head.

    Two distinct claims, and conflating them loses the load-bearing one. The
    SNAPSHOT claim rests entirely on the FIXED ref: both `_read_blob` calls pass
    the same validated 40-character `head_sha` as `?ref=`, so a push landing
    between the two reads cannot change what either read returns and the
    manifest and the lock cannot come from different trees. No timing check
    would recover that property if the fixed ref were replaced by a moving one,
    because each read would individually be 'current'.

    The re-confirmation after the reads is a separate FRESHNESS claim: that the
    commit the administrator named is still the pull request's head when the
    snapshot finishes. It does not make the two reads one snapshot — the fixed
    ref already did — it stops a warm being produced for a head the pull request
    has already moved past.
    """
    if _pull_head(fetch, repo, pr_number) != head_sha:
        raise WarmRefused("named sha is not the pull request's head")
    manifest = _read_blob(fetch, repo, "pyproject.toml", head_sha, MAX_MANIFEST_BYTES)
    lock = _read_blob(fetch, repo, "poetry.lock", head_sha, MAX_LOCK_BYTES)
    if _pull_head(fetch, repo, pr_number) != head_sha:
        raise WarmRefused("pull request head moved while the snapshot was read")
    return manifest, lock


# --------------------------------------------------------------------------
# 3. The plan: hosts, scope, and the hashes every wheel must match
# --------------------------------------------------------------------------


def build_plan(manifest: bytes, lock: bytes) -> dict[str, dict[str, Any]]:
    """Parse — never evaluate — the snapshot into per-package acquisition rules."""
    try:
        manifest_doc = tomllib.loads(manifest.decode("utf-8"))
        lock_doc = tomllib.loads(lock.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise WarmRefused("manifest or lock is not readable TOML") from exc

    declared = manifest_doc.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if not isinstance(declared, dict):
        raise WarmRefused("manifest declares no readable dependency table")
    private: set[str] = set()
    for raw_name, declaration in declared.items():
        if isinstance(declaration, dict) and declaration.get("source"):
            name = _normalise(raw_name)
            if not PRIVATE_SCOPE.fullmatch(name):
                # `!r` because `name` has not passed `NAME_RE` yet: it is raw
                # manifest text, and raw text in a message the job prints can
                # forge a workflow command in the log.
                raise WarmRefused(f"{name!r} is outside the private package scope")
            private.add(name)

    packages = lock_doc.get("package")
    if not isinstance(packages, list) or not packages:
        raise WarmRefused("lock contains no packages")

    plan: dict[str, dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise WarmRefused("lock package is unreadable")
        raw_name, version, files = (
            package.get(key) for key in ("name", "version", "files")
        )
        if not (
            isinstance(raw_name, str)
            and isinstance(version, str)
            and isinstance(files, list)
        ):
            raise WarmRefused("lock package is unreadable")
        name = _normalise(raw_name)
        if not NAME_RE.fullmatch(name):
            raise WarmRefused(f"{raw_name!r} is not a usable package name")
        if not VERSION_RE.fullmatch(version):
            raise WarmRefused(f"{name} has a version that is not a plain version")
        if name in plan:
            raise WarmRefused(f"{name} is locked twice")

        source = package.get("source")
        if source is None:
            index = PUBLIC_INDEX
            if name in private:
                raise WarmRefused(f"{name} is declared private but locked publicly")
        else:
            if not isinstance(source, dict):
                raise WarmRefused(f"{name} has an unreadable lock source")
            host = _host(str(source.get("url", "")))
            if host in PRIVATE_HOSTS:
                if name not in private:
                    raise WarmRefused(
                        f"{name} resolves privately but is not declared private"
                    )
                index = str(source["url"])
                _refuse_a_decorated_index(index)
            elif host in PUBLIC_HOSTS:
                index = PUBLIC_INDEX
            else:
                raise WarmRefused(f"{name} resolves from unallowed host {host!r}")

        wheels: dict[str, str] = {}
        for item in files:
            if not isinstance(item, dict):
                raise WarmRefused(f"{name} has an unreadable file record")
            filename, recorded = item.get("file"), item.get("hash")
            if not isinstance(filename, str) or not isinstance(recorded, str):
                raise WarmRefused(f"{name} has an unreadable file record")
            if not filename.endswith(".whl"):
                continue
            digest = HASH_RE.fullmatch(recorded)
            if digest is None or Path(filename).name != filename:
                raise WarmRefused(f"{name} has an unusable wheel hash or name")
            match = WHEEL_RE.fullmatch(filename)
            if match is None or _normalise(match.group(1)) != name:
                # `!r` because `filename` is lock text this job prints: a name
                # holding `::` or a newline would otherwise forge a workflow
                # command in the log.
                raise WarmRefused(f"{filename!r} does not belong to {name}")
            wheels[filename] = digest.group(1)
        if not wheels:
            raise WarmRefused(f"{name} locks no wheel")
        plan[name] = {"version": version, "index": index, "wheels": wheels}

    missing = private - set(plan)
    if missing:
        raise WarmRefused(
            f"declared private package absent from lock: {sorted(missing)}"
        )
    return plan


# --------------------------------------------------------------------------
# 4. The cache key
# --------------------------------------------------------------------------


def cache_key(
    manifest: bytes, lock: bytes, os_name: str, arch: str, python: str
) -> str:
    """Key the cache on the dependency BYTES, the platform, and the interpreter.

    Deliberately not a branch name, a pull request number or any moving ref: two
    dispatches that read identical dependency bytes onto the same platform must
    land on the same entry, and any change to either file must land elsewhere.
    The digest follows `hashFiles`' shape — SHA-256 per file, in argument order,
    then SHA-256 over the concatenated raw digests — so a consumer restoring
    with `hashFiles('pyproject.toml', 'poetry.lock')` computes this same value.
    """
    if not re.fullmatch(r"3\.[0-9]{1,2}", python):
        raise WarmRefused("python version is not a bare minor version")
    combined = hashlib.sha256()
    for payload in (manifest, lock):
        combined.update(hashlib.sha256(payload).digest())
    short = python.replace(".", "")
    return f"workspace-wheelhouse-{os_name}-{arch}-py{short}-{combined.hexdigest()}"


# --------------------------------------------------------------------------
# 5. Acquisition: download, never execute
# --------------------------------------------------------------------------


def _digest_file(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def acquire(
    plan: dict[str, dict[str, Any]],
    destination: Path,
    credential: str,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> None:
    """Download each locked wheel and verify it, with nothing built or run.

    `--only-binary=:all:` and `--no-deps` together mean no sdist is selected and
    no build backend is invoked, so no code from any dependency executes here.
    The credential travels in the environment, never in argv, and no output from
    the downloader is ever relayed — its error text can contain the index URL.
    That environment is CONSTRUCTED from `CHILD_ENV_KEYS` rather than inherited,
    so the step's own copy of the registry token is not handed to pip a second
    time as a plain variable it has no use for.

    The surplus sweep runs after the whole loop, so a refusal partway through
    leaves verified wheels at the destination. That is only harmless because the
    workflow's cache-save step carries no `if:` and no `continue-on-error`: a
    non-zero exit means nothing is saved, so a partially populated destination
    is never observable. `tests/test_wheelhouse_warm_workflow.py` pins that
    premise, because it lives in a file this module cannot see.
    """
    if not credential:
        raise WarmRefused("registry credential unavailable")

    # The host screen runs over the WHOLE plan before any effect — before the
    # destination is created and before the first download. Screening inside the
    # download loop would already have made a directory, and would already have
    # contacted the hosts of every entry that happened to sort earlier, by the
    # time it reached the entry that was not allowed.
    for entry in plan.values():
        screened = _host(str(entry["index"]))
        if screened not in PRIVATE_HOSTS | PUBLIC_HOSTS:
            raise WarmRefused(f"refusing to contact unallowed host {screened!r}")

    if destination.exists():
        raise WarmRefused("wheelhouse destination must not already exist")
    destination.mkdir(parents=True)

    for name, item in sorted(plan.items()):
        index = item["index"]
        host = _host(index)
        # Re-checked per entry: the screen above is what makes the refusal
        # effect-free, this is what makes the credential's own line of code
        # readable as safe on its own.
        if host not in PRIVATE_HOSTS | PUBLIC_HOSTS:
            raise WarmRefused(f"refusing to contact unallowed host {host!r}")
        if host in PRIVATE_HOSTS:
            # Rebuilt, not spliced. String-slicing after `https://` carries the
            # lock's own netloc through verbatim, so a URL that arrived with
            # userinfo would become `https://ci-reader:TOKEN@someone@host/...`
            # — two `@`, and which one the request honours is the parser's
            # opinion. The netloc here is composed from `host`, which is
            # `_host`'s validated, lowercased hostname and nothing else, so any
            # username, password or port in the source URL is dropped by
            # construction rather than by a check that could be skipped.
            # `urlunsplit` passes the netloc through unaltered, so the
            # credential's bytes are exactly what was handed in.
            parsed = urlsplit(index)
            index = urlunsplit(
                (
                    "https",
                    f"ci-reader:{credential}@{host}",
                    parsed.path,
                    parsed.query,
                    parsed.fragment,
                )
            )
        with tempfile.TemporaryDirectory() as staging:
            env = {key: os.environ[key] for key in CHILD_ENV_KEYS if key in os.environ}
            env["PIP_INDEX_URL"] = index
            env["PIP_CONFIG_FILE"] = os.devnull
            env["PIP_NO_INPUT"] = "1"
            try:
                # No shell. The one snapshot-derived argument is the
                # requirement, whose name and version `build_plan` has
                # already constrained so neither can read as a pip option.
                runner(
                    [
                        sys.executable,
                        "-m",
                        "pip",
                        "download",
                        "--disable-pip-version-check",
                        "--no-cache-dir",
                        "--no-deps",
                        "--only-binary=:all:",
                        "--dest",
                        staging,
                        f"{name}=={item['version']}",
                    ],
                    env=env,
                    capture_output=True,
                    check=True,
                    timeout=ACQUIRE_TIMEOUT_SECONDS,
                )
            except (OSError, subprocess.SubprocessError):
                # The index URL carries the credential. Relaying `exc` or the
                # captured streams would print it; the message is fixed instead.
                raise WarmRefused(f"acquisition failed for {name}") from None

            got = list(Path(staging).iterdir())
            if len(got) != 1 or got[0].name not in item["wheels"]:
                raise WarmRefused(f"acquired a wheel {name} does not lock")
            if _digest_file(got[0]) != item["wheels"][got[0].name]:
                raise WarmRefused(f"wheel hash disagrees with the lock for {name}")
            shutil.copy2(got[0], destination / got[0].name)

    surplus = [
        entry.name
        for entry in destination.iterdir()
        if entry.is_symlink() or not entry.is_file() or entry.suffix != ".whl"
    ]
    if surplus:
        raise WarmRefused(f"wheelhouse holds a non-wheel entry: {sorted(surplus)}")


# --------------------------------------------------------------------------
# Wiring
# --------------------------------------------------------------------------


def _live_fetch(token: str) -> Fetch:
    def fetch(path: str, *, raw: bool = False) -> Any:
        url = f"{API}{path}"
        if not url.startswith(f"{API}/"):
            raise WarmRefused("refusing a request outside the API host")
        request = urllib.request.Request(  # noqa: S310 -- literal https base.
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.raw"
                if raw
                else "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                body = response.read()
        except (urllib.error.URLError, OSError):
            raise WarmRefused(f"could not read {path.split('?')[0]}") from None
        return body if raw else json.loads(body)

    return fetch


def _emit(name: str, value: str) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as stream:
            stream.write(f"{name}={value}\n")


def main(argv: list[str] | None = None) -> int:
    """Two operations, so the registry credential's window is as small as it can be.

    `bind` reads the snapshot; only the API token is in scope for it. `acquire`
    downloads wheels; only the registry credential is in scope for it. Neither
    step ever has both, and no step has either while any pull request content
    could be executed — because no step ever executes pull request content.
    """
    parser = argparse.ArgumentParser(description="Warm a reviewed PR's wheelhouse.")
    parser.add_argument("operation", choices=("bind", "acquire"))
    parser.add_argument("--pr-number")
    parser.add_argument("--head-sha")
    parser.add_argument("--repository")
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--python-version")
    args = parser.parse_args(argv)

    try:
        if args.operation == "bind":
            pr_number, head_sha = admit_dispatch(
                os.environ.get("GITHUB_REF", ""), args.pr_number, args.head_sha
            )
            api_token = os.environ.get("GITHUB_TOKEN", "")
            if not api_token:
                raise WarmRefused("api token unavailable")
            manifest, lock = bind_snapshot(
                _live_fetch(api_token), args.repository, pr_number, head_sha
            )
            # Parse before anything is downloaded, so a lock naming an
            # unallowed host or an out-of-scope private name refuses while the
            # registry credential is still nowhere in this job.
            build_plan(manifest, lock)
            key = cache_key(
                manifest,
                lock,
                os.environ.get("RUNNER_OS", ""),
                os.environ.get("RUNNER_ARCH", ""),
                args.python_version or "",
            )
            args.snapshot.mkdir(parents=True, exist_ok=True)
            (args.snapshot / "pyproject.toml").write_bytes(manifest)
            (args.snapshot / "poetry.lock").write_bytes(lock)
            _emit("cache-key", key)
            print(f"bound {head_sha} for pull request {pr_number}")
        else:
            manifest = (args.snapshot / "pyproject.toml").read_bytes()
            lock = (args.snapshot / "poetry.lock").read_bytes()
            plan = build_plan(manifest, lock)
            acquire(
                plan,
                args.directory,
                os.environ.get("FORGEJO_BUNDLE_READ_TOKEN", ""),
            )
            print(f"acquired {len(plan)} locked wheels")
    except WarmRefused as exc:
        # `exc` is always one of this module's own fixed messages. No captured
        # downloader output and no index URL can reach this line.
        print(f"wheelhouse warm refused: {exc}", file=sys.stderr)
        return 2
    except OSError:
        print("wheelhouse warm refused: snapshot unavailable", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
