#!/usr/bin/env python3
"""Build the offline, verified wheel plan for the Workspace assembly.

This intentionally reads only the checked-in Poetry manifest and lock file.  It
does not resolve dependencies or contact an index: the lock file is the
authority for the exact private artifacts that a later producer may fetch.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
PRIVATE_SOURCE = "forgejo"
PRIVATE_INDEX = "https://registry.dotmac.io/api/packages/dotmac/pypi/simple"
_NAME_RE = re.compile(r"[-_.]+")
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_WHEEL_RE = re.compile(
    r"^(?P<distribution>[A-Za-z0-9_.-]+)-(?P<version>[^-]+)-"
    r"(?P<python>[^-]+)-(?P<abi>[^-]+)-(?P<platform>[^.]+(?:\.[^.]+)*)\.whl$"
)


class PlanError(ValueError):
    """A checked-in dependency record cannot produce a safe plan."""


def _canonical_name(name: str) -> str:
    return _NAME_RE.sub("-", name).lower()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _wheel_candidate(filename: str, package: str, version: str) -> bool:
    match = _WHEEL_RE.fullmatch(filename)
    if match is None:
        raise PlanError(f"unsupported or malformed wheel filename: {filename}")
    expected_distribution = _canonical_name(package).replace("-", "_")
    if match.group("distribution") != expected_distribution:
        raise PlanError(f"noncanonical wheel distribution: {filename}")
    if match.group("version") != version:
        raise PlanError(f"wheel version drift for {package}: {filename}")
    python_tag = match.group("python")
    abi_tag = match.group("abi")
    platform_tag = match.group("platform")
    return (python_tag, abi_tag, platform_tag) in {
        ("py3", "none", "any"),
        ("py312", "none", "any"),
        ("cp312", "abi3", "manylinux_2_17_x86_64"),
        ("cp312", "cp312", "manylinux_2_17_x86_64"),
        ("cp312", "abi3", "manylinux2014_x86_64"),
        ("cp312", "cp312", "manylinux2014_x86_64"),
    }


def _private_dependencies(manifest: dict[str, Any]) -> dict[str, str]:
    deps = manifest.get("tool", {}).get("poetry", {}).get("dependencies", {})
    result: dict[str, str] = {}
    for name, declaration in deps.items():
        if name == "python" or not isinstance(declaration, dict):
            continue
        if declaration.get("source") == PRIVATE_SOURCE:
            version = declaration.get("version")
            if not isinstance(version, str) or not version:
                raise PlanError(f"private dependency has no exact version: {name}")
            if version.startswith(("^", "~", ">", "<", "=")) or "," in version:
                raise PlanError(f"private dependency is not exactly pinned: {name}")
            result[_canonical_name(name)] = version
    if not result:
        raise PlanError("manifest declares no private Forgejo dependencies")
    return result


def build_plan(manifest_path: Path, lock_path: Path) -> dict[str, Any]:
    """Return the deterministic expected-file plan or raise :class:`PlanError`."""
    manifest_bytes = manifest_path.read_bytes()
    lock_bytes = lock_path.read_bytes()
    try:
        manifest = tomllib.loads(manifest_bytes.decode("utf-8"))
        lock = tomllib.loads(lock_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PlanError(f"invalid authoritative input: {exc}") from exc

    required = _private_dependencies(manifest)
    locked: dict[str, dict[str, Any]] = {}
    undeclared_private: set[str] = set()
    for package in lock.get("package", []):
        name = package.get("name")
        if not isinstance(name, str):
            continue
        key = _canonical_name(name)
        package_source = package.get("source")
        if (
            isinstance(package_source, dict)
            and package_source.get("reference") == PRIVATE_SOURCE
            and key not in required
        ):
            undeclared_private.add(key)
        if key in required:
            if key in locked:
                raise PlanError(f"duplicate lock package: {name}")
            locked[key] = package
    if undeclared_private or set(locked) != set(required):
        missing = sorted(set(required) - set(locked))
        extra = sorted(undeclared_private | (set(locked) - set(required)))
        raise PlanError(
            f"private lock package mismatch (missing={missing}, extra={extra})"
        )

    artifacts: list[dict[str, str]] = []
    for key in sorted(required):
        expected_version = required[key]
        package = locked[key]
        name = package.get("name")
        if package.get("version") != expected_version:
            raise PlanError(f"lock version drift for {name}")
        source = package.get("source")
        if not isinstance(source, dict) or source.get("type") != "legacy":
            raise PlanError(f"missing Forgejo source for {name}")
        if (
            source.get("reference") != PRIVATE_SOURCE
            or source.get("url") != PRIVATE_INDEX
        ):
            raise PlanError(f"lock source drift for {name}")
        files = package.get("files")
        if not isinstance(files, list):
            raise PlanError(f"missing lock files for {name}")
        candidates: list[dict[str, str]] = []
        for record in files:
            filename = record.get("file") if isinstance(record, dict) else None
            digest = record.get("hash") if isinstance(record, dict) else None
            if not isinstance(filename, str) or not isinstance(digest, str):
                raise PlanError(f"malformed lock file record for {name}")
            if not _HASH_RE.fullmatch(digest):
                raise PlanError(f"unsupported hash for {name}: {filename}")
            if filename.endswith(".whl"):
                if _wheel_candidate(filename, name, expected_version):
                    candidates.append(
                        {
                            "filename": filename,
                            "sha256": digest.removeprefix("sha256:"),
                        }
                    )
            elif not (filename.endswith(".tar.gz") or filename.endswith(".zip")):
                raise PlanError(
                    f"unsupported lock artifact format for {name}: {filename}"
                )
        if len(candidates) != 1:
            raise PlanError(
                f"expected one compatible wheel for {name}, found {len(candidates)}"
            )
        artifact = candidates[0]
        artifacts.append(
            {
                "package_normalised_name": _canonical_name(name),
                **artifact,
            }
        )

    binding = {
        "schema_version": SCHEMA_VERSION,
        "manifest_sha256": _sha256(manifest_path),
        "lock_sha256": _sha256(lock_path),
        "artifacts": artifacts,
    }
    plan_digest = hashlib.sha256(
        json.dumps(binding, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": SCHEMA_VERSION,
        "plan_digest": plan_digest,
        "artifacts": [
            {
                "package_normalised_name": artifact["package_normalised_name"],
                "filename": artifact["filename"],
                "sha256": artifact["sha256"],
            }
            for artifact in artifacts
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("pyproject.toml"))
    parser.add_argument("--lock", type=Path, default=Path("poetry.lock"))
    args = parser.parse_args(argv)
    try:
        plan = build_plan(args.manifest, args.lock)
    except (OSError, PlanError) as exc:
        print(f"workspace dependency plan refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(plan, sort_keys=True, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
