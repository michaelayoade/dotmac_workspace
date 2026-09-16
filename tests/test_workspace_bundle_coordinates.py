from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.workspace_bundle_coordinates import CoordinateError, load_coordinates


def test_exact_positive_coordinates_are_accepted(tmp_path: Path) -> None:
    path = tmp_path / "coordinates.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": 101,
                "archive_artifact_id": 201,
                "sidecar_artifact_id": 202,
            }
        )
    )
    assert load_coordinates(path) == {
        "run_id": 101,
        "archive_artifact_id": 201,
        "sidecar_artifact_id": 202,
    }


@pytest.mark.parametrize(
    "content",
    [
        "{}",
        '{"schema_version":1,"run_id":1,"archive_artifact_id":2}',
        '{"schema_version":1,"run_id":true,"archive_artifact_id":2,"sidecar_artifact_id":3}',
        '{"schema_version":1,"run_id":0,"archive_artifact_id":2,"sidecar_artifact_id":3}',
        '{"schema_version":1,"run_id":1,"run_id":2,"archive_artifact_id":3,"sidecar_artifact_id":4}',
        '{"schema_version":1,"run_id":1,"archive_artifact_id":2,"sidecar_artifact_id":3,"unreviewed":1}',
    ],
)
def test_refuses_non_exact_locator(tmp_path: Path, content: str) -> None:
    path = tmp_path / "coordinates.json"
    path.write_text(content)
    with pytest.raises(CoordinateError):
        load_coordinates(path)


def test_missing_locator_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(CoordinateError):
        load_coordinates(tmp_path / "not-issued.json")
