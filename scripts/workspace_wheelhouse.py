#!/usr/bin/env python3
"""Warm, verify, and install the exact locked Workspace wheelhouse.

The cache transports bytes; the checked-in Poetry lock supplies their hashes.
No value from a restored cache is trusted before verification.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

PRIVATE_INDEX = "https://registry.dotmac.io/api/packages/dotmac/pypi/simple"
PUBLIC_INDEX = "https://pypi.org/simple"
HASH = re.compile(r"sha256:([0-9a-f]{64})\Z")
WHEEL = re.compile(r"([A-Za-z0-9_.]+)-([^-]+)-(?:[^-]+-)?[^-]+-[^-]+-[^-]+\.whl\Z")
CHILD_ENV_KEYS = (
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "LD_LIBRARY_PATH",
)


class WheelhouseError(ValueError):
    """The lock, wheelhouse, or acquisition does not satisfy the contract."""


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def _private_names(manifest: dict[str, Any]) -> dict[str, str]:
    dependencies = manifest.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if not isinstance(dependencies, dict):
        raise WheelhouseError("invalid manifest dependencies")
    result: dict[str, str] = {}
    for name, declaration in dependencies.items():
        if not isinstance(declaration, dict) or declaration.get("source") != "forgejo":
            continue
        version = declaration.get("version")
        if not isinstance(version, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9.!+_-]*", version
        ):
            raise WheelhouseError("private dependency is not exactly pinned")
        result[_normalise(name)] = version
    if not result:
        raise WheelhouseError("no private dependencies declared")
    return result


def load_plan(manifest_path: Path, lock_path: Path) -> dict[str, dict[str, Any]]:
    """Map each locked package to its version, source, and allowed wheel hashes."""
    try:
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise WheelhouseError("invalid manifest or lock") from exc
    private = _private_names(manifest)
    packages = lock.get("package")
    if not isinstance(packages, list) or not packages:
        raise WheelhouseError("empty or invalid lock")
    plan: dict[str, dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise WheelhouseError("invalid lock package")
        raw_name, version, files = (
            package.get(key) for key in ("name", "version", "files")
        )
        if (
            not isinstance(raw_name, str)
            or not isinstance(version, str)
            or not isinstance(files, list)
        ):
            raise WheelhouseError("invalid lock package")
        name = _normalise(raw_name)
        if name in plan or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
            raise WheelhouseError("duplicate or invalid lock package")
        source = package.get("source")
        if name in private:
            if version != private[name] or source != {
                "type": "legacy",
                "url": PRIVATE_INDEX,
                "reference": "forgejo",
            }:
                raise WheelhouseError("private package source or version drift")
            registry = "private"
        elif source is None:
            registry = "public"
        else:
            raise WheelhouseError("undeclared non-public lock package")
        allowed: dict[str, str] = {}
        for item in files:
            if not isinstance(item, dict):
                raise WheelhouseError("invalid lock file record")
            filename, recorded_hash = item.get("file"), item.get("hash")
            if not isinstance(filename, str) or not isinstance(recorded_hash, str):
                raise WheelhouseError("invalid lock file record")
            digest = HASH.fullmatch(recorded_hash)
            if digest is None or Path(filename).name != filename:
                raise WheelhouseError("invalid lock file hash or name")
            if not filename.endswith(".whl"):
                continue
            match = WHEEL.fullmatch(filename)
            if (
                match is None
                or _normalise(match.group(1)) != name
                or match.group(2) != version
            ):
                raise WheelhouseError("wheel name or version differs from lock package")
            if filename in allowed:
                raise WheelhouseError("duplicate wheel filename in lock")
            allowed[filename] = digest.group(1)
        if not allowed:
            raise WheelhouseError("locked package has no wheel")
        plan[name] = {"version": version, "registry": registry, "wheels": allowed}
    if set(private) - set(plan):
        raise WheelhouseError("declared private package absent from lock")
    return plan


def verify(plan: dict[str, dict[str, Any]], directory: Path) -> dict[str, Path]:
    """Reject missing, extra, linked, or hash-mismatched cached wheels."""
    if not directory.is_dir() or directory.is_symlink():
        raise WheelhouseError("wheelhouse directory unavailable")
    selected: dict[str, Path] = {}
    entries = list(directory.iterdir())
    for path in entries:
        if path.is_symlink() or not path.is_file() or path.suffix != ".whl":
            raise WheelhouseError("wheelhouse contains a link or unexpected entry")
        owners = [name for name, item in plan.items() if path.name in item["wheels"]]
        if len(owners) != 1 or owners[0] in selected:
            raise WheelhouseError("wheelhouse contains an extra or duplicate wheel")
        name = owners[0]
        if _digest(path) != plan[name]["wheels"][path.name]:
            raise WheelhouseError("wheel hash differs from lock")
        selected[name] = path
    if set(selected) != set(plan):
        raise WheelhouseError("wheelhouse is missing a locked wheel")
    return selected


def warm(plan: dict[str, dict[str, Any]], directory: Path) -> None:
    """Acquire one wheel per package on protected main, with no secret output."""
    if directory.exists():
        raise WheelhouseError("wheelhouse destination must not already exist")
    directory.mkdir(parents=True)
    credential = os.environ.get("FORGEJO_BUNDLE_READ_TOKEN", "")
    if not credential:
        raise WheelhouseError("private registry credential unavailable")
    private_url = (
        "https://ci-reader:"
        + quote(credential, safe="")
        + "@registry.dotmac.io/api/packages/dotmac/pypi/simple"
    )
    try:
        hostname = urlsplit(private_url).hostname
    except ValueError:
        hostname = None
    if hostname != "registry.dotmac.io":
        raise WheelhouseError("private registry credential unavailable")
    for name, item in sorted(plan.items()):
        with tempfile.TemporaryDirectory() as temporary:
            env = {key: os.environ[key] for key in CHILD_ENV_KEYS if key in os.environ}
            env["PIP_INDEX_URL"] = (
                private_url if item["registry"] == "private" else PUBLIC_INDEX
            )
            env.pop("PIP_EXTRA_INDEX_URL", None)
            env["PIP_CONFIG_FILE"] = os.devnull
            command = [
                sys.executable,
                "-m",
                "pip",
                "download",
                "--disable-pip-version-check",
                "--no-cache-dir",
                "--no-deps",
                "--only-binary=:all:",
                "--dest",
                temporary,
                f"{name}=={item['version']}",
            ]
            try:
                subprocess.run(  # noqa: S603 -- fixed pip argv; no shell
                    command, env=env, capture_output=True, check=True
                )
            except (OSError, subprocess.CalledProcessError) as exc:
                # pip output can contain a URL with credentials. Never relay it.
                raise WheelhouseError(f"wheel acquisition failed for {name}") from exc
            candidates = list(Path(temporary).iterdir())
            if len(candidates) != 1 or candidates[0].name not in item["wheels"]:
                raise WheelhouseError(f"unlocked wheel acquired for {name}")
            if _digest(candidates[0]) != item["wheels"][candidates[0].name]:
                raise WheelhouseError(f"wheel hash mismatch for {name}")
            shutil.copy2(candidates[0], directory / candidates[0].name)
    verify(plan, directory)


def install(plan: dict[str, dict[str, Any]], directory: Path, python: Path) -> None:
    verify(plan, directory)
    packages = [f"{name}=={item['version']}" for name, item in sorted(plan.items())]
    try:
        subprocess.run(  # noqa: S603 -- fixed pip argv; no shell
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-index",
                "--find-links",
                str(directory),
                "--no-deps",
                *packages,
            ],
            check=True,
        )
        subprocess.run(  # noqa: S603 -- fixed pip argv; no shell
            [str(python), "-m", "pip", "check"], check=True
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise WheelhouseError("offline wheelhouse installation failed") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("warm", "verify", "install"))
    parser.add_argument("--manifest", type=Path, default=Path("pyproject.toml"))
    parser.add_argument("--lock", type=Path, default=Path("poetry.lock"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    args = parser.parse_args(argv)
    try:
        plan = load_plan(args.manifest, args.lock)
        if args.operation == "warm":
            warm(plan, args.directory)
        elif args.operation == "verify":
            verify(plan, args.directory)
        else:
            install(plan, args.directory, args.python)
    except WheelhouseError as exc:
        print(f"workspace wheelhouse refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
