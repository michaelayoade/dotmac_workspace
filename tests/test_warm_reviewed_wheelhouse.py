"""The warmer refuses by its own mechanism, and refuses only what it should.

Every test below except the last asserts a REFUSAL, which is why the last one
exists: a warmer that refused every dispatch would satisfy all of them and warm
nothing. `test_a_reviewed_dispatch_produces_the_intended_cache_key` is the
accept direction, and it pins the exact key rather than merely observing that
something was returned.

Each test names the change to `scripts/warm_reviewed_wheelhouse.py` that would
make it pass wrongly — its designed break condition — because a guard whose
failure mode nobody has stated is a guard nobody has checked.
"""

from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/wheelhouse-warm.yml"

_spec = importlib.util.spec_from_file_location(
    "warm_reviewed_wheelhouse", ROOT / "scripts/warm_reviewed_wheelhouse.py"
)
assert _spec and _spec.loader
warm = importlib.util.module_from_spec(_spec)
sys.modules["warm_reviewed_wheelhouse"] = warm
_spec.loader.exec_module(warm)

HEAD = "a" * 40
OTHER = "b" * 40
REPO = "michaelayoade/dotmac_workspace"
KERNEL_WHEEL = "dotmac_kernel-0.1.0a97-py3-none-any.whl"
PYTEST_WHEEL = "pytest-8.3.3-py3-none-any.whl"
PRIVATE_URL = "https://registry.dotmac.io/api/packages/dotmac/pypi/simple"

MANIFEST = b"""
[tool.poetry.dependencies]
python = ">=3.12,<3.14"
dotmac-kernel = { version = "0.1.0a97", source = "forgejo" }
pytest = "^8.3"
"""


def _lock(private_url: str = PRIVATE_URL) -> bytes:
    kernel_hash = hashlib.sha256(b"kernel-wheel").hexdigest()
    pytest_hash = hashlib.sha256(b"pytest-wheel").hexdigest()
    return f"""
[[package]]
name = "dotmac-kernel"
version = "0.1.0a97"
files = [{{file = "{KERNEL_WHEEL}", hash = "sha256:{kernel_hash}"}}]

[package.source]
type = "legacy"
url = "{private_url}"
reference = "forgejo"

[[package]]
name = "pytest"
version = "8.3.3"
files = [{{file = "{PYTEST_WHEEL}", hash = "sha256:{pytest_hash}"}}]
""".encode()


class FakeForge:
    """A forge that answers the four reads `bind_snapshot` makes, and records them."""

    def __init__(self, heads: list[str], blobs: dict[str, bytes] | None = None) -> None:
        self.heads = list(heads)
        self.blobs = blobs or {"pyproject.toml": MANIFEST, "poetry.lock": _lock()}
        self.requests: list[str] = []
        self._by_id = {
            warm.git_blob_id(payload): payload for payload in self.blobs.values()
        }

    def __call__(self, path: str, *, raw: bool = False) -> Any:
        self.requests.append(path)
        if "/pulls/" in path:
            return {"head": {"sha": self.heads.pop(0) if self.heads else OTHER}}
        if "/contents/" in path:
            name = path.split("/contents/")[1].split("?")[0]
            payload = self.blobs[name]
            return {
                "type": "file",
                "size": len(payload),
                "sha": warm.git_blob_id(payload),
            }
        if "/git/blobs/" in path:
            return self._by_id[path.rsplit("/", 1)[1]]
        raise AssertionError(path)


# ---------------------------------------------------------------------------
# 1. A dispatch that is not main's code
# ---------------------------------------------------------------------------


def test_a_dispatch_from_a_ref_other_than_main_refuses() -> None:
    """BREAK CONDITION: delete the `ref != MAIN_REF` branch in `admit_dispatch`.

    The job would then rely entirely on the `dependency-bundle` environment's
    branch policy — a setting in the forge's UI, outside this repository, which
    a `workflow_dispatch` naming another ref is precisely the request to test.
    """
    with pytest.raises(warm.WarmRefused, match="protected main"):
        warm.admit_dispatch("refs/heads/attacker", "41", HEAD)
    with pytest.raises(warm.WarmRefused, match="protected main"):
        warm.admit_dispatch("refs/pull/41/merge", "41", HEAD)

    # Near miss: main itself, and a well-formed pair, must still be admitted —
    # otherwise the check above passes because nothing is ever admitted.
    assert warm.admit_dispatch("refs/heads/main", "41", HEAD) == (41, HEAD)


def test_an_inexact_pr_number_or_head_sha_refuses() -> None:
    """BREAK CONDITION: loosen either regex in `admit_dispatch` to `.+`.

    A short SHA is ambiguous and an abbreviation can be made to collide; a
    non-numeric PR input is a path-injection surface on the API URL.
    """
    for bad_sha in ("a" * 39, "a" * 41, "A" * 40, "z" * 40, "HEAD", ""):
        with pytest.raises(warm.WarmRefused, match="exact 40-character"):
            warm.admit_dispatch("refs/heads/main", "41", bad_sha)
    for bad_pr in ("0", "-1", "41/../99", "", "abc"):
        with pytest.raises(warm.WarmRefused, match="positive integer"):
            warm.admit_dispatch("refs/heads/main", bad_pr, HEAD)


# ---------------------------------------------------------------------------
# 2. A head SHA that is not the named pull request's head
# ---------------------------------------------------------------------------


def test_a_head_sha_that_is_not_the_pull_requests_head_refuses() -> None:
    """BREAK CONDITION: drop the pre-read `_pull_head(...) != head_sha` check.

    Without it a dispatcher could name ANY commit in the repository — including
    one on a branch nobody reviewed, or an old commit of the PR whose lock has
    since been corrected — and have its dependencies warmed under a key that a
    later CI run would restore.
    """
    forge = FakeForge(heads=[OTHER])
    with pytest.raises(warm.WarmRefused, match="not the pull request's head"):
        warm.bind_snapshot(forge, REPO, 41, HEAD)

    # It refused BEFORE reading anything: no content or blob request was made.
    assert all("/pulls/" in request for request in forge.requests)


# ---------------------------------------------------------------------------
# 3. Manifest and lock from different commits
# ---------------------------------------------------------------------------


def test_a_head_that_moves_while_the_snapshot_is_read_refuses() -> None:
    """BREAK CONDITION: delete the post-read `_pull_head` re-confirmation.

    This is the only check that catches a push landing BETWEEN the two file
    reads. Without it the manifest could come from one tree and the lock from
    the next, and the resulting cache would describe a commit that never
    existed — the exact state a lock file exists to make impossible.
    """
    forge = FakeForge(heads=[HEAD, OTHER])
    with pytest.raises(warm.WarmRefused, match="head moved"):
        warm.bind_snapshot(forge, REPO, 41, HEAD)


def test_both_files_are_read_at_one_and_the_same_commit() -> None:
    """BREAK CONDITION: pass a re-resolved head to the second `_read_blob` call.

    The refusal above catches a head that moves; this catches the other way in
    — reading each file at a separately resolved ref, which no timing check
    would notice because both reads would individually be 'current'.
    """
    forge = FakeForge(heads=[HEAD, HEAD])
    warm.bind_snapshot(forge, REPO, 41, HEAD)
    refs = [
        request.split("?ref=")[1]
        for request in forge.requests
        if "/contents/" in request
    ]
    assert refs == [HEAD, HEAD], refs
    assert sorted(
        request.split("/contents/")[1].split("?")[0]
        for request in forge.requests
        if "/contents/" in request
    ) == ["poetry.lock", "pyproject.toml"]


def test_bytes_that_do_not_hash_to_the_blob_the_commit_names_refuse() -> None:
    """BREAK CONDITION: remove the `git_blob_id(payload) != blob_id` comparison.

    This is what makes the read a SNAPSHOT rather than a fetch: it ties the
    bytes actually received to the object id the commit's tree names, so a
    substituted body is caught even when the metadata request looked correct.
    """
    forge = FakeForge(heads=[HEAD, HEAD])
    forge._by_id[warm.git_blob_id(MANIFEST)] = MANIFEST + b"\n# tampered\n"
    with pytest.raises(warm.WarmRefused, match="do not hash to the blob"):
        warm.bind_snapshot(forge, REPO, 41, HEAD)


# ---------------------------------------------------------------------------
# 4. Input size
# ---------------------------------------------------------------------------


def test_an_oversized_input_refuses_before_its_bytes_are_requested() -> None:
    """BREAK CONDITION: remove the `size > limit` check in `_read_blob`.

    The bound is on the METADATA, so an oversized file is refused without ever
    being transferred; a bound applied after the read would still have pulled
    the bytes onto the runner.
    """
    forge = FakeForge(heads=[HEAD, HEAD])
    huge = b"x" * (warm.MAX_MANIFEST_BYTES + 1)
    forge.blobs["pyproject.toml"] = huge
    forge._by_id[warm.git_blob_id(huge)] = huge
    with pytest.raises(warm.WarmRefused, match="input bound"):
        warm.bind_snapshot(forge, REPO, 41, HEAD)
    assert not any("/git/blobs/" in request for request in forge.requests)


# ---------------------------------------------------------------------------
# 5. Registry host and package scope
# ---------------------------------------------------------------------------


def test_a_registry_host_outside_the_allowlist_refuses() -> None:
    """BREAK CONDITION: accept any `source.url` instead of testing its host.

    A lock is contributor-supplied data. Without the allowlist, a pull request
    could point a private-source package at a host it controls and this job
    would present the registry credential to it.
    """
    # Built by concatenation: the middle case is the one that matters and a
    # literal would read as an address rather than as a URL with USERINFO.
    userinfo = "https://registry.dotmac.io" + "@" + "evil.example/simple"
    for hostile in (
        "https://evil.example/simple",
        "https://registry.dotmac.io.evil.example/simple",
        userinfo,
        "https://registry.dotmac.io" + "@" + "evil.example:443/simple",
        "http://registry.dotmac.io/simple",
    ):
        with pytest.raises(warm.WarmRefused):
            warm.build_plan(MANIFEST, _lock(hostile))

    # Near miss: the real host, with the real path, is accepted. Without this
    # the test above would pass if `build_plan` rejected every lock.
    plan = warm.build_plan(MANIFEST, _lock())
    assert plan["dotmac-kernel"]["index"] == PRIVATE_URL
    assert plan["pytest"]["index"] == warm.PUBLIC_INDEX


def test_a_private_source_on_an_out_of_scope_name_refuses() -> None:
    """BREAK CONDITION: drop the `PRIVATE_SCOPE` test in `build_plan`.

    Dependency confusion in the other direction: a manifest that claims a
    common public name resolves from the private index makes this job fetch
    `requests` or `urllib3` from somewhere it must never fetch them.
    """
    manifest = MANIFEST.replace(
        b'pytest = "^8.3"', b'pytest = { version = "8.3.3", source = "forgejo" }'
    )
    with pytest.raises(warm.WarmRefused, match="outside the private package scope"):
        warm.build_plan(manifest, _lock())


def test_a_lock_name_that_would_read_as_a_pip_option_refuses() -> None:
    """BREAK CONDITION: drop `NAME_RE`/`VERSION_RE` from `build_plan`.

    The lock is contributor-supplied and its names reach pip's argv as
    `<name>==<version>`. A name beginning with a dash is parsed by pip as an
    OPTION, not a requirement — `--index-url`, `-r`, `--target` are all
    reachable that way — so the shape is constrained before the value is ever
    placed in an argument vector. `shell=False` does not help here: the
    injection is into pip's own option parser, not into a shell.
    """
    for hostile_name in ("--index-url", "-r/etc/passwd", "../evil", "a b"):
        lock = _lock().replace(b'name = "pytest"', f'name = "{hostile_name}"'.encode())
        with pytest.raises(warm.WarmRefused):
            warm.build_plan(MANIFEST, lock)
    for hostile_version in ("--target=/tmp", "8.3.3 --upgrade", "-8"):
        lock = _lock().replace(
            b'version = "8.3.3"', f'version = "{hostile_version}"'.encode()
        )
        with pytest.raises(warm.WarmRefused):
            warm.build_plan(MANIFEST, lock)

    # Near miss: a real name and a real pre-release version are accepted.
    plan = warm.build_plan(MANIFEST, _lock())
    assert plan["dotmac-kernel"]["version"] == "0.1.0a97"


def test_acquisition_refuses_to_contact_a_host_outside_the_allowlist() -> None:
    """BREAK CONDITION: remove the second host check at the top of `acquire`.

    `build_plan` screens the lock, but `acquire` is the step that actually holds
    the credential, so it re-checks rather than trusting a plan handed to it.
    """
    plan = {
        "dotmac-kernel": {
            "version": "1",
            "index": "https://evil.example/s",
            "wheels": {},
        }
    }
    with pytest.raises(warm.WarmRefused, match="unallowed host"):
        warm.acquire(plan, Path("/nonexistent/wheelhouse"), "token")


# ---------------------------------------------------------------------------
# 6. A wheel whose hash disagrees with the lock
# ---------------------------------------------------------------------------


def _runner(contents: dict[str, bytes]):
    def run(argv, **kwargs):
        dest = Path(argv[argv.index("--dest") + 1])
        name = argv[-1].split("==")[0]
        for filename, payload in contents.items():
            if filename.startswith(name.replace("-", "_")) or filename.startswith(name):
                (dest / filename).write_bytes(payload)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    return run


def test_a_wheel_whose_hash_disagrees_with_the_lock_refuses(tmp_path: Path) -> None:
    """BREAK CONDITION: delete the `_digest_file(...) != wheels[name]` comparison.

    The lock is the only authority on what bytes are acceptable. Without this
    the job would cache whatever the index served — which is the whole attack
    a compromised or substituted registry represents.
    """
    plan = warm.build_plan(MANIFEST, _lock())
    runner = _runner(
        {KERNEL_WHEEL: b"not-the-kernel-wheel", PYTEST_WHEEL: b"pytest-wheel"}
    )
    with pytest.raises(warm.WarmRefused, match="hash disagrees with the lock"):
        warm.acquire(plan, tmp_path / "wheelhouse", "token", runner=runner)


def test_a_wheel_the_lock_does_not_name_refuses(tmp_path: Path) -> None:
    """BREAK CONDITION: drop the `got[0].name not in item['wheels']` test.

    A hash check alone would not catch an index that serves a DIFFERENT but
    internally consistent artifact, so the filename must be one the lock names.
    """
    plan = warm.build_plan(MANIFEST, _lock())
    runner = _runner({"dotmac_kernel-9.9.9-py3-none-any.whl": b"kernel-wheel"})
    with pytest.raises(warm.WarmRefused, match="does not lock"):
        warm.acquire(plan, tmp_path / "wheelhouse", "token", runner=runner)


def test_acquisition_never_builds_or_executes_a_dependency(tmp_path: Path) -> None:
    """BREAK CONDITION: remove `--only-binary=:all:` or add `--no-deps`' opposite.

    `--only-binary=:all:` is what guarantees no sdist is selected, and therefore
    that no build backend, `setup.py` or PEP 517 hook from a contributor's
    dependency graph runs on a runner holding the registry credential.
    """
    seen: list[list[str]] = []
    inner = _runner({KERNEL_WHEEL: b"kernel-wheel", PYTEST_WHEEL: b"pytest-wheel"})

    def run(argv, **kwargs):
        seen.append(list(argv))
        return inner(argv, **kwargs)

    plan = warm.build_plan(MANIFEST, _lock())
    warm.acquire(plan, tmp_path / "wheelhouse", "token", runner=run)
    assert seen and all("--only-binary=:all:" in argv for argv in seen)
    assert all("--no-deps" in argv for argv in seen)
    assert all("--no-cache-dir" in argv for argv in seen)
    assert all("install" not in argv for argv in seen)


# ---------------------------------------------------------------------------
# 7. An absent credential, and credential-bearing output
# ---------------------------------------------------------------------------


def test_an_absent_registry_credential_refuses(tmp_path: Path) -> None:
    """BREAK CONDITION: remove the `if not credential` guard in `acquire`.

    An empty environment-scoped secret would otherwise produce an anonymous
    index URL, and the job would either fail obscurely deep in pip or — worse —
    succeed against a public name that shadows a private one. The workflow's
    own `[ -z ... ]` check is the other half; neither is allowed to be the only
    one, since the script is also runnable outside the workflow.
    """
    plan = warm.build_plan(MANIFEST, _lock())
    with pytest.raises(warm.WarmRefused, match="credential unavailable"):
        warm.acquire(plan, tmp_path / "wheelhouse", "", runner=_runner({}))


def test_a_failed_acquisition_relays_no_downloader_output(tmp_path: Path) -> None:
    """BREAK CONDITION: interpolate `exc`, `exc.stderr` or the index URL into the
    raised message, or re-raise with `from exc`.

    The index URL contains the credential, and pip prints the index URL on
    failure. Chaining the original exception would put that text in the
    traceback the runner logs even though the message itself is clean.
    """
    secret = "s3cr3t-registry-token"
    plan = warm.build_plan(MANIFEST, _lock())

    def run(argv, **kwargs):
        raise subprocess.CalledProcessError(
            1, argv, output=b"", stderr=f"could not reach {secret}".encode()
        )

    with pytest.raises(warm.WarmRefused) as raised:
        warm.acquire(plan, tmp_path / "wheelhouse", secret, runner=run)
    assert secret not in str(raised.value)
    assert raised.value.__cause__ is None
    assert secret not in repr(raised.value.__context__ or "")


def test_the_credential_never_appears_in_the_downloader_argv(tmp_path: Path) -> None:
    """BREAK CONDITION: pass `--index-url <url-with-credential>` in argv.

    Process arguments are readable by any other process on the runner and are
    echoed by pip's own diagnostics; the environment is the narrower channel.
    """
    secret = "s3cr3t-registry-token"
    seen: list[list[str]] = []
    envs: list[dict[str, str]] = []
    inner = _runner({KERNEL_WHEEL: b"kernel-wheel", PYTEST_WHEEL: b"pytest-wheel"})

    def run(argv, **kwargs):
        seen.append(list(argv))
        envs.append(dict(kwargs["env"]))
        return inner(argv, **kwargs)

    plan = warm.build_plan(MANIFEST, _lock())
    warm.acquire(plan, tmp_path / "wheelhouse", secret, runner=run)
    assert not any(secret in part for argv in seen for part in argv)
    # And the credential reached only the private index, never the public one.
    private = [env for env in envs if secret in env["PIP_INDEX_URL"]]
    public = [env for env in envs if env["PIP_INDEX_URL"] == warm.PUBLIC_INDEX]
    assert len(private) == 1 and len(public) == 1


# ---------------------------------------------------------------------------
# 8. The accept direction — MANDATORY
# ---------------------------------------------------------------------------


def test_a_reviewed_dispatch_produces_the_intended_cache_key() -> None:
    """The control for every refusal above: a warmer that refused everything
    would pass all of them and warm nothing.

    BREAK CONDITION: key on a branch name, a PR number, `github.sha` or any
    moving ref. The expected value is recomputed here from the bytes rather
    than by calling `cache_key`, so a change to the composition fails rather
    than agreeing with itself.
    """
    forge = FakeForge(heads=[HEAD, HEAD])
    manifest, lock = warm.bind_snapshot(forge, REPO, 41, HEAD)
    assert (manifest, lock) == (MANIFEST, _lock())

    digest = hashlib.sha256()
    digest.update(hashlib.sha256(MANIFEST).digest())
    digest.update(hashlib.sha256(_lock()).digest())
    expected = f"workspace-wheelhouse-Linux-X64-py312-{digest.hexdigest()}"

    assert warm.cache_key(manifest, lock, "Linux", "X64", "3.12") == expected

    # Identical bytes on a different platform or interpreter key elsewhere.
    assert warm.cache_key(manifest, lock, "Linux", "ARM64", "3.12") != expected
    assert warm.cache_key(manifest, lock, "macOS", "X64", "3.12") != expected
    assert warm.cache_key(manifest, lock, "Linux", "X64", "3.13") != expected

    # A one-byte change to either file keys elsewhere. This is the property the
    # whole snapshot binding exists to deliver.
    assert warm.cache_key(manifest + b"\n", lock, "Linux", "X64", "3.12") != expected
    assert warm.cache_key(manifest, lock + b"\n", "Linux", "X64", "3.12") != expected

    # And no moving ref is in it.
    for moving in (HEAD, "main", "41", "refs/heads/main"):
        assert moving not in expected


def test_a_reviewed_dispatch_acquires_exactly_the_locked_wheels(tmp_path: Path) -> None:
    """The accept direction for acquisition: the happy path must actually pass.

    BREAK CONDITION: any refusal added above that is too broad — this is what
    fails if, say, the host allowlist or the scope check rejects the real lock.
    """
    plan = warm.build_plan(MANIFEST, _lock())
    runner = _runner({KERNEL_WHEEL: b"kernel-wheel", PYTEST_WHEEL: b"pytest-wheel"})
    destination = tmp_path / "wheelhouse"
    warm.acquire(plan, destination, "token", runner=runner)
    assert sorted(p.name for p in destination.iterdir()) == sorted(
        [KERNEL_WHEEL, PYTEST_WHEEL]
    )
