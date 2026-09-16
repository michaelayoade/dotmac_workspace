"""Keep candidate CI secret-free and tied to the protected bundle verifier."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github/workflows/ci.yml"
ACTION = ROOT / ".github/actions/verified-workspace-dependencies/action.yml"
STARTER_ACTION = (
    "michaelayoade/dotmac_starter_mt/.github/actions/verified-dependency-bundle@"
    "7ec614c7b8051e7d399d80381ffdb6344d50dbc6"
)


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [text for item in value for text in _strings(item)]
    if isinstance(value, dict):
        return [text for item in value.values() for text in _strings(item)]
    return []


def _problems(ci: dict[str, Any], action: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    if ci.get("permissions") != {"contents": "read", "actions": "read"}:
        problems.append("candidate CI permissions are not read-only")
    if any(
        "secrets." in text.lower() or "pip_extra_index_url" in text.lower()
        for text in _strings(ci)
    ):
        problems.append("candidate CI references a secret or private-index credential")
    if set(ci.get("jobs", {})) != {"quality", "postgres", "from-wheel"}:
        problems.append("candidate CI job set changed")
    for name, job in ci.get("jobs", {}).items():
        steps = job.get("steps", [])
        checkout = [
            step
            for step in steps
            if str(step.get("uses", "")).startswith("actions/checkout@")
        ]
        if (
            len(checkout) != 1
            or checkout[0].get("with", {}).get("persist-credentials") is not False
        ):
            problems.append(f"{name} checkout persists a GitHub credential")
        verifiers = [
            i
            for i, step in enumerate(steps)
            if step.get("uses") == "./.github/actions/verified-workspace-dependencies"
        ]
        install = [
            i
            for i, step in enumerate(steps)
            if "Install" in str(step.get("name", ""))
            or "Build, install" in str(step.get("name", ""))
        ]
        if len(verifiers) != 1 or not install or verifiers[0] >= min(install):
            problems.append(f"{name} does not verify before installation")
        if "environment" in job:
            problems.append(f"{name} incorrectly binds a credentialed environment")
    action_steps = action.get("runs", {}).get("steps", [])
    verifier = [
        step
        for step in action_steps
        if "verified-dependency-bundle" in str(step.get("uses", ""))
    ]
    if len(verifier) != 1 or verifier[0].get("uses") != STARTER_ACTION:
        problems.append("Starter verifier is not pinned exactly")
    else:
        supplied = verifier[0].get("with", {})
        expected = {
            "operation": "verify-and-index",
            "expected-file": "${{ steps.expected.outputs.path }}",
            "producer-repository": "${{ github.repository }}",
            "producer-repository-id": "${{ github.repository_id }}",
            "producer-workflow-path": (
                ".github/workflows/dependency-bundle-producer.yml"
            ),
            "archive-artifact-name": "workspace-dependency-bundle",
            "sidecar-artifact-name": "workspace-dependency-bundle-manifest",
            "archive-artifact-id": (
                "${{ steps.coordinates.outputs.archive_artifact_id }}"
            ),
            "run-id": "${{ steps.coordinates.outputs.run_id }}",
            "sidecar-artifact-id": (
                "${{ steps.coordinates.outputs.sidecar_artifact_id }}"
            ),
            "github-token": "${{ github.token }}",
        }
        if supplied != expected:
            problems.append("verifier inputs do not preserve trusted provenance")
    if any("secrets." in text.lower() for text in _strings(action)):
        problems.append("local verifier action references a secret")
    if not any(
        "workspace_dependency_plan.py" in str(step.get("run", ""))
        for step in action_steps
    ):
        problems.append("dependency plan is not derived from checked-in policy")
    if not any(
        "workspace_bundle_coordinates.py" in str(step.get("run", ""))
        for step in action_steps
    ):
        problems.append("immutable artifact coordinates are not read")
    return problems


def _load() -> tuple[dict[str, Any], dict[str, Any]]:
    return yaml.safe_load(CI.read_text()), yaml.safe_load(ACTION.read_text())


def test_current_candidate_ci_is_secret_free_and_source_bound() -> None:
    assert _problems(*_load()) == []


def test_guard_detects_secret_and_verifier_regressions() -> None:
    ci, action = _load()
    leaked = copy.deepcopy(ci)
    leaked["jobs"]["quality"]["steps"].append(
        {"env": {"TOKEN": "${{ secrets.FORGEJO_READ_TOKEN }}"}}
    )
    assert "candidate CI references a secret or private-index credential" in _problems(
        leaked, action
    )

    unverified = copy.deepcopy(ci)
    unverified["jobs"]["postgres"]["steps"] = [
        step
        for step in unverified["jobs"]["postgres"]["steps"]
        if step.get("uses") != "./.github/actions/verified-workspace-dependencies"
    ]
    assert "postgres does not verify before installation" in _problems(
        unverified, action
    )

    mutable = copy.deepcopy(action)
    next(
        step
        for step in mutable["runs"]["steps"]
        if "verified-dependency-bundle" in str(step.get("uses", ""))
    )["uses"] = (
        "michaelayoade/dotmac_starter_mt/"
        ".github/actions/verified-dependency-bundle@main"
    )
    assert "Starter verifier is not pinned exactly" in _problems(ci, mutable)
