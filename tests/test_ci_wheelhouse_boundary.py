"""The credentialed warmer and candidate jobs have distinct cache authority."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github/workflows/ci.yml"
WARM = ROOT / ".github/workflows/dependency-bundle-producer.yml"
CACHE_SHA = "caa296126883cff596d87d8935842f9db880ef25"
KEY = (
    "workspace-wheelhouse-${{ runner.os }}-${{ runner.arch }}-py312-"
    "${{ hashFiles('pyproject.toml', 'poetry.lock') }}"
)


def test_reviewed_warmer_and_candidate_use_the_same_dependency_key() -> None:
    module_path = ROOT / "scripts/warm_reviewed_wheelhouse.py"
    spec = importlib.util.spec_from_file_location(
        "warm_reviewed_wheelhouse", module_path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    manifest = (ROOT / "pyproject.toml").read_bytes()
    lock = (ROOT / "poetry.lock").read_bytes()
    combined = hashlib.sha256()
    for payload in (manifest, lock):
        combined.update(hashlib.sha256(payload).digest())
    assert module.cache_key(manifest, lock, "Linux", "X64", "3.12") == (
        f"workspace-wheelhouse-Linux-X64-py312-{combined.hexdigest()}"
    )
    assert KEY == (
        "workspace-wheelhouse-${{ runner.os }}-${{ runner.arch }}-py312-"
        "${{ hashFiles('pyproject.toml', 'poetry.lock') }}"
    )

    ci = yaml.safe_load(CI.read_text())
    expected_names = {
        "quality": "Static checks and DB-free tests",
        "postgres": "Composed migrations and tenant isolation",
        "from-wheel": "Boot from a built wheel",
    }
    for job_name, expected_name in expected_names.items():
        assert ci["jobs"][job_name]["name"] == expected_name
        restore = next(
            step
            for step in ci["jobs"][job_name]["steps"]
            if step.get("id") == "wheelhouse-cache"
        )
        assert restore["with"]["key"] == KEY
    producer = yaml.safe_load(WARM.read_text())
    assert producer[True]["push"]["branches"] == ["main"]
    assert producer["jobs"]["warm"]["runs-on"] == "ubuntu-latest"
    save = next(
        step
        for step in producer["jobs"]["warm"]["steps"]
        if str(step.get("uses", "")).startswith("actions/cache/save@")
    )
    assert save["with"]["key"] == KEY


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [part for item in value for part in _strings(item)]
    if isinstance(value, dict):
        return [part for item in value.values() for part in _strings(item)]
    return []


def test_merge_dependency_drift_refuses_before_cache_restore(tmp_path: Path) -> None:
    """Removing either comparison makes the mismatched merge case pass."""
    jobs = yaml.safe_load(CI.read_text())["jobs"]
    step = next(
        item
        for item in jobs["quality"]["steps"]
        if item.get("name") == "Require reviewed PR dependency snapshot"
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    assert repo.is_relative_to(tmp_path)
    git_bin = shutil.which("git")
    bash_bin = shutil.which("bash")
    assert git_bin is not None and bash_bin is not None

    def git(*args: str) -> subprocess.CompletedProcess[str]:
        # Fixed test arguments in a disposable repository; no shell or secrets.
        return subprocess.run(  # noqa: S603
            [git_bin, *args], cwd=repo, check=True, text=True, capture_output=True
        )

    git("init", "-q")
    (repo / "pyproject.toml").write_text("reviewed manifest\n")
    (repo / "poetry.lock").write_text("reviewed lock\n")
    git("add", "pyproject.toml", "poetry.lock")
    git(
        "-c",
        "user.name=CI Test",
        "-c",
        "user.email=ci@example.invalid",
        "commit",
        "-qm",
        "reviewed head",
    )
    head = git("rev-parse", "HEAD").stdout.strip()

    def check() -> subprocess.CompletedProcess[str]:
        # Execute only this checked-in step against the disposable repository.
        return subprocess.run(  # noqa: S603
            [bash_bin, "-e", "-o", "pipefail", "-c", step["run"]],
            cwd=repo,
            env={**os.environ, "PR_HEAD_SHA": head},
            text=True,
            capture_output=True,
            check=False,
        )

    assert check().returncode == 0
    (repo / "pyproject.toml").write_text("merge manifest differs\n")
    mismatch = check()
    assert mismatch.returncode == 2
    assert "update the branch and rewarm" in mismatch.stderr
    (repo / "pyproject.toml").write_text("reviewed manifest\n")
    (repo / "poetry.lock").write_text("merge lock differs\n")
    assert check().returncode == 2


def test_candidate_ci_is_secret_free_read_only_and_offline() -> None:
    workflow = yaml.safe_load(CI.read_text())
    assert set(workflow) == {"name", True, "permissions", "env", "jobs"}
    assert workflow["permissions"] == {"contents": "read"}
    assert set(workflow["jobs"]) == {"quality", "postgres", "from-wheel"}
    assert not any(
        "secrets." in value or "FORGEJO_" in value for value in _strings(workflow)
    )
    for name, job in workflow["jobs"].items():
        assert "environment" not in job, name
        steps = job["steps"]
        checkout = [
            step
            for step in steps
            if str(step.get("uses", "")).startswith("actions/checkout@")
        ]
        assert len(checkout) == 1
        assert checkout[0]["with"] == {
            "persist-credentials": False,
            "fetch-depth": 0,
        }
        snapshot = [
            step
            for step in steps
            if step.get("name") == "Require reviewed PR dependency snapshot"
        ]
        assert len(snapshot) == 1
        assert snapshot[0]["if"] == "github.event_name == 'pull_request'"
        assert snapshot[0]["env"] == {
            "PR_HEAD_SHA": "${{ github.event.pull_request.head.sha }}"
        }
        assert "git cat-file -e" in snapshot[0]["run"]
        assert "cmp -s pyproject.toml" in snapshot[0]["run"]
        assert "cmp -s poetry.lock" in snapshot[0]["run"]
        assert "update the branch and rewarm" in snapshot[0]["run"]
        restore = [
            step
            for step in steps
            if step.get("uses") == f"actions/cache/restore@{CACHE_SHA}"
        ]
        assert len(restore) == 1
        assert steps.index(snapshot[0]) < steps.index(restore[0])
        assert restore[0]["id"] == "wheelhouse-cache"
        assert restore[0]["with"]["key"] == KEY
        assert restore[0]["with"]["fail-on-cache-miss"] is True
        assert "restore-keys" not in restore[0]["with"]
        assert any(
            step.get("env", {}).get("CACHE_HIT")
            == "${{ steps.wheelhouse-cache.outputs.cache-hit }}"
            and step.get("run") == 'test "$CACHE_HIT" = true'
            for step in steps
        )
        if name == "from-wheel":
            assert any("make from-wheel-boot" in value for value in _strings(steps))
            assert (
                "workspace_wheelhouse.py install"
                in (ROOT / "scripts/from_wheel_boot.sh").read_text()
            )
        else:
            assert any(
                "workspace_wheelhouse.py install" in value for value in _strings(steps)
            )
            build = next(
                step
                for step in steps
                if step.get("name") == "Build and install Workspace wheel offline"
            )
            assert ".ci-venv/bin/python -m pip install" in build["run"]
            assert ".ci-venv/bin/python -m pip check" in build["run"]
        assert not any("poetry install" in value for value in _strings(steps))
        assert not any("actions/cache/save@" in value for value in _strings(steps))
        assert not any("./.github/actions/" in value for value in _strings(steps))


def test_only_protected_main_can_warm_and_save_cache() -> None:
    workflow = yaml.safe_load(WARM.read_text())
    assert set(workflow) == {"name", True, "permissions", "jobs"}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["warm"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    assert job["environment"] == "dependency-bundle"
    steps = job["steps"]
    checkout = next(
        step
        for step in steps
        if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert checkout["with"] == {
        "ref": "${{ github.sha }}",
        "persist-credentials": False,
    }
    assert any(
        'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' in value
        for value in _strings(steps)
    )
    assert sum("secrets." in value for value in _strings(steps)) == 1
    assert any("workspace_wheelhouse.py warm" in value for value in _strings(steps))
    save = [
        step for step in steps if step.get("uses") == f"actions/cache/save@{CACHE_SHA}"
    ]
    assert len(save) == 1 and save[0]["with"]["key"] == KEY
