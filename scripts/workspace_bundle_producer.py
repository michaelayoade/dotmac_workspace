#!/usr/bin/env python3
"""Fetch and assemble the exact wheel set described by a workspace plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

_WHEEL_NAME = re.compile(
    r"^(?P<name>[A-Za-z0-9_.-]+)-(?P<version>[^-]+)-[^-]+-[^-]+-[^.]+(?:\.[^.]+)*\.whl$"
)


class BundleError(ValueError):
    """The plan or fetched files cannot produce a verified bundle."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_plan(path: Path) -> list[dict[str, str]]:
    try:
        plan: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleError("invalid dependency plan") from exc
    if not isinstance(plan, dict) or plan.get("schema_version") != 1:
        raise BundleError("unsupported dependency plan")
    artifacts = plan.get("artifacts")
    if not isinstance(artifacts, list):
        raise BundleError("unsupported dependency plan")
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise BundleError("malformed dependency plan")
        filename = artifact.get("filename")
        digest = artifact.get("sha256")
        if (
            not isinstance(filename, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]+\.whl", filename)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or filename in seen
        ):
            raise BundleError("malformed dependency plan")
        seen.add(filename)
        result.append({"filename": filename, "sha256": digest})
    if not result:
        raise BundleError("dependency plan contains no wheels")
    return result


def _download(plan: list[dict[str, str]], destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    requirements: list[str] = []
    for artifact in plan:
        match = _WHEEL_NAME.fullmatch(artifact["filename"])
        if match is None:
            raise BundleError("malformed wheel filename")
        package = match.group("name").replace("_", "-")
        requirements.append(f"{package}=={match.group('version')}")
    try:
        # Fixed interpreter/module/flags; requirements come from the validated
        # checked-in plan. pip output is captured because it can include a URL.
        subprocess.run(  # noqa: S603
            [
                sys.executable,
                "-m",
                "pip",
                "download",
                "--disable-pip-version-check",
                "--no-deps",
                "--only-binary=:all:",
                "--dest",
                str(destination),
                *requirements,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        # Never relay pip's captured output: it may contain an authenticated URL.
        raise BundleError("dependency download failed") from exc


def build_bundle(plan_path: Path, wheel_dir: Path, output_path: Path) -> None:
    plan = _read_plan(plan_path)
    expected = {artifact["filename"]: artifact["sha256"] for artifact in plan}
    try:
        entries = list(wheel_dir.iterdir())
    except OSError as exc:
        raise BundleError("download directory is unavailable") from exc
    if any(not stat.S_ISREG(entry.lstat().st_mode) for entry in entries):
        raise BundleError("download directory contains a non-regular file")
    actual = {path.name for path in entries}
    if actual != set(expected):
        raise BundleError("downloaded files do not match dependency plan")
    for filename, digest in expected.items():
        path = wheel_dir / filename
        if _sha256(path) != digest:
            raise BundleError("downloaded file hash does not match dependency plan")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(
            output_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as bundle:
            for filename in sorted(expected):
                info = zipfile.ZipInfo(filename, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                bundle.writestr(info, (wheel_dir / filename).read_bytes())
    except OSError as exc:
        raise BundleError("bundle creation failed") from exc


def produce(plan_path: Path, wheel_dir: Path, output_path: Path) -> None:
    plan = _read_plan(plan_path)
    _download(plan, wheel_dir)
    build_bundle(plan_path, wheel_dir, output_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--download-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        produce(args.plan, args.download_dir, args.output)
    except BundleError:
        print("workspace dependency bundle production failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
