#!/usr/bin/env python3
"""Read reviewed coordinates for one immutable Workspace dependency bundle.

The bundle verifier independently observes the GitHub run, workflow, and
artifacts. This file only chooses which immutable run and artifacts to ask it
to verify; a missing coordinate file fails CI closed during the bootstrap.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


class CoordinateError(ValueError):
    """The checked-in locator is absent or not an exact v1 coordinate."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CoordinateError("duplicate coordinate key")
        result[key] = value
    return result


def load_coordinates(path: Path) -> dict[str, int]:
    try:
        data = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CoordinateError("bundle coordinates are unavailable or invalid") from exc
    keys = {"schema_version", "run_id", "archive_artifact_id", "sidecar_artifact_id"}
    if not isinstance(data, dict) or set(data) != keys or data["schema_version"] != 1:
        raise CoordinateError("bundle coordinates have an unsupported shape")
    values = {key: data[key] for key in keys - {"schema_version"}}
    if any(type(value) is not int or value <= 0 for value in values.values()):
        raise CoordinateError("bundle coordinates must be positive integers")
    return values


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coordinates", type=Path, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        values = load_coordinates(args.coordinates)
        with args.github_output.open("a", encoding="utf-8") as output:
            for key in ("run_id", "archive_artifact_id", "sidecar_artifact_id"):
                output.write(f"{key}={values[key]}\n")
    except (CoordinateError, OSError) as exc:
        print(f"Workspace bundle locator refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
