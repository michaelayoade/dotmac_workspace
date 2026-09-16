#!/usr/bin/env python3
"""Install a Starter-verified dependency bundle without contacting an index."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


class BundleError(ValueError):
    """The expected file or copied wheel set is not trusted."""


_FILENAME = re.compile(r"^[A-Za-z0-9_.-]+\.whl$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PEP503 = re.compile(r"[-_.]+")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _normalise(name: str) -> str:
    return _PEP503.sub("-", name).lower()


def _read_expected(path: Path) -> list[dict[str, str]]:
    try:
        document: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BundleError("invalid expected dependency file") from exc
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "plan_digest",
        "artifacts",
    }:
        raise BundleError("invalid expected dependency file schema")
    if document["schema_version"] != 1 or not isinstance(document["plan_digest"], str):
        raise BundleError("invalid expected dependency file schema")
    if not _DIGEST.fullmatch(document["plan_digest"]):
        raise BundleError("invalid expected dependency file schema")
    artifacts = document["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise BundleError("expected dependency file contains no wheels")

    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {
            "package_normalised_name",
            "filename",
            "sha256",
        }:
            raise BundleError("invalid expected dependency artifact")
        package = artifact["package_normalised_name"]
        filename = artifact["filename"]
        digest = artifact["sha256"]
        if (
            not isinstance(package, str)
            or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", package)
            or not isinstance(filename, str)
            or _FILENAME.fullmatch(filename) is None
            or not isinstance(digest, str)
            or _DIGEST.fullmatch(digest) is None
            or filename in seen
        ):
            raise BundleError("invalid expected dependency artifact")
        parts = filename[:-4].split("-")
        if len(parts) < 5 or _normalise(parts[0]) != package:
            raise BundleError("wheel package does not match expected artifact")
        seen.add(filename)
        result.append(
            {
                "package_normalised_name": package,
                "filename": filename,
                "sha256": digest,
            }
        )
    return result


def _wheel_path(index_root: Path, package: str, filename: str) -> Path:
    if not index_root.is_dir() or index_root.is_symlink():
        raise BundleError("invalid bundle index root")
    current = index_root
    for component in ("simple", package, filename):
        current = current / component
        try:
            if current.is_symlink():
                raise BundleError("bundle contains a symlink")
        except OSError as exc:
            raise BundleError("bundle path cannot be inspected") from exc
    resolved_root = index_root.resolve()
    resolved = current.resolve()
    if resolved_root not in resolved.parents:
        raise BundleError("bundle path escapes index root")
    if not current.is_file():
        raise BundleError("expected wheel is missing")
    return current


def _bundle_wheels(index_root: Path) -> set[Path]:
    simple = index_root / "simple"
    if simple.is_symlink() or not simple.is_dir():
        raise BundleError("invalid bundle simple index")
    wheels: set[Path] = set()
    for path in simple.rglob("*.whl"):
        if path.is_symlink() or not path.is_file():
            raise BundleError("bundle contains a symlink")
        wheels.add(path)
    return wheels


def install(expected_file: Path, index_root: Path, python: Path) -> None:
    artifacts = _read_expected(expected_file)
    wheels: list[Path] = []
    for artifact in artifacts:
        wheel = _wheel_path(
            index_root, artifact["package_normalised_name"], artifact["filename"]
        )
        if _sha256(wheel) != artifact["sha256"]:
            raise BundleError("wheel hash does not match expected file")
        wheels.append(wheel)
    if _bundle_wheels(index_root) != set(wheels):
        raise BundleError("bundle contains unexpected wheels")
    try:
        # The caller-selected interpreter runs fixed pip flags on verified,
        # local wheel paths; no index or shell is involved.
        subprocess.run(  # noqa: S603
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                *(str(path) for path in wheels),
            ],
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise BundleError("bundle installation failed") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-file", type=Path, required=True)
    parser.add_argument("--index-root", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    args = parser.parse_args(argv)
    try:
        install(args.expected_file, args.index_root, args.python)
    except BundleError:
        print("workspace dependency bundle installation failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
