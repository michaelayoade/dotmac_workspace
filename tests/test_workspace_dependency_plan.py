from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.workspace_dependency_plan import PlanError, build_plan

MANIFEST = """
[tool.poetry.dependencies]
python = ">=3.12,<3.14"
dotmac-kernel = {version = "0.1.0a97", source = "forgejo"}
dotmac-ui = {version = "0.1.0a7", source = "forgejo"}
"""


def lock(
    wheel: str = "dotmac_kernel-0.1.0a97-py3-none-any.whl",
    digest: str = "a" * 64,
) -> str:
    return f"""
[[package]]
name = "dotmac-kernel"
version = "0.1.0a97"
files = [
  {{file = "{wheel}", hash = "sha256:{digest}"}},
  {{file = "dotmac_kernel-0.1.0a97.tar.gz", hash = "sha256:{"b" * 64}"}},
]
[package.source]
type = "legacy"
url = "https://registry.dotmac.io/api/packages/dotmac/pypi/simple"
reference = "forgejo"

[[package]]
name = "dotmac-ui"
version = "0.1.0a7"
files = [
  {{file = "dotmac_ui-0.1.0a7-py3-none-any.whl", hash = "sha256:{"c" * 64}"}},
]
[package.source]
type = "legacy"
url = "https://registry.dotmac.io/api/packages/dotmac/pypi/simple"
reference = "forgejo"
"""


def inputs(tmp_path: Path, lock_text: str | None = None) -> tuple[Path, Path]:
    manifest = tmp_path / "pyproject.toml"
    lockfile = tmp_path / "poetry.lock"
    manifest.write_text(MANIFEST)
    lockfile.write_text(lock_text or lock())
    return manifest, lockfile


def test_plan_is_deterministic_and_contains_exact_private_wheels(
    tmp_path: Path,
) -> None:
    manifest, lockfile = inputs(tmp_path)
    first = build_plan(manifest, lockfile)
    second = build_plan(manifest, lockfile)
    assert first == second
    assert first["schema_version"] == 1
    assert len(first["plan_digest"]) == 64
    assert set(first) == {"schema_version", "plan_digest", "artifacts"}
    assert all(
        set(artifact) == {"package_normalised_name", "filename", "sha256"}
        for artifact in first["artifacts"]
    )
    assert [a["filename"] for a in first["artifacts"]] == [
        "dotmac_kernel-0.1.0a97-py3-none-any.whl",
        "dotmac_ui-0.1.0a7-py3-none-any.whl",
    ]


@pytest.mark.parametrize(
    "mutator",
    [
        lambda text: text.replace("0.1.0a97", "0.1.0a96"),
        lambda text: text.replace('reference = "forgejo"', 'reference = "pypi"', 1),
        lambda text: text.replace(
            "dotmac_kernel-0.1.0a97-py3-none-any.whl", "dotmac-kernel.whl"
        ),
        lambda text: text.replace("sha256:" + "a" * 64, "sha256:bad"),
        lambda text: text.replace("sha256:" + "a" * 64, "a" * 64),
    ],
)
def test_tampering_or_drift_is_refused(tmp_path: Path, mutator) -> None:
    manifest, lockfile = inputs(tmp_path, mutator(lock()))
    with pytest.raises(PlanError):
        build_plan(manifest, lockfile)


def test_ambiguous_compatible_wheels_are_refused(tmp_path: Path) -> None:
    extra = (
        '  {file = "dotmac_kernel-0.1.0a97-py312-none-any.whl", '
        'hash = "sha256:' + "d" * 64 + '"},\n'
    )
    manifest, lockfile = inputs(
        tmp_path, lock().replace("files = [\n", "files = [\n" + extra, 1)
    )
    with pytest.raises(PlanError):
        build_plan(manifest, lockfile)


def test_valid_lock_evidence_changes_plan_digest(tmp_path: Path) -> None:
    manifest, lockfile = inputs(tmp_path)
    original = build_plan(manifest, lockfile)
    changed_lock = lockfile.read_text().replace(
        "sha256:" + "a" * 64, "sha256:" + "d" * 64
    )
    lockfile.write_text(changed_lock)
    changed = build_plan(manifest, lockfile)
    assert changed["plan_digest"] != original["plan_digest"]
    assert changed["artifacts"][0]["sha256"] == "d" * 64


def test_undeclared_private_lock_package_is_refused(tmp_path: Path) -> None:
    extra = (
        '[[package]]\nname = "dotmac-secret"\nversion = "1.0"\n'
        'files = [{file = "dotmac_secret-1.0-py3-none-any.whl", hash = "sha256:'
        + "e"
        * 64
        + '"}]\n[package.source]\ntype = "legacy"\n'
        'url = "https://registry.dotmac.io/api/packages/dotmac/pypi/simple"\n'
        'reference = "forgejo"\n\n'
    )
    manifest, lockfile = inputs(
        tmp_path, extra + lock().replace("[[package]]\n", "[[package]]\n", 1)
    )
    with pytest.raises(PlanError):
        build_plan(manifest, lockfile)


def test_output_is_json_serialisable(tmp_path: Path) -> None:
    manifest, lockfile = inputs(tmp_path)
    json.dumps(build_plan(manifest, lockfile), sort_keys=True)
