"""The warmer's trigger, environment, refusal and pinning structure hold.

These are checks on the workflow FILE, because the properties they cover are
properties of the file and not of any Python this repository can run: a job that
reintroduced a `pull_request_target` trigger, dropped the environment binding or
floated an action pin to a tag would be a serious regression that no unit test
of `scripts/warm_reviewed_wheelhouse.py` could observe.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/wheelhouse-warm.yml"
CACHE_SAVE = "actions/cache/save@caa296126883cff596d87d8935842f9db880ef25"
PIN = re.compile(r"[^@\s]+@([0-9a-f]{40})(?:\s+#.*)?\Z")


def _workflow() -> dict[str, Any]:
    # PyYAML resolves the bare key `on` to the boolean True (YAML 1.1).
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    document["on"] = document.pop(True, document.get("on"))
    return document


def _job() -> dict[str, Any]:
    return _workflow()["jobs"]["warm"]


def test_the_warmer_is_dispatch_only_and_takes_an_exact_reviewed_commit() -> None:
    """BREAK CONDITION: add `pull_request_target`, `pull_request` or `push`.

    `pull_request_target` in particular is the classic shape of this
    vulnerability: it runs with repository secrets available on a trigger that
    any outside contributor can fire.
    """
    triggers = _workflow()["on"]
    assert set(triggers) == {"workflow_dispatch"}, triggers
    inputs = triggers["workflow_dispatch"]["inputs"]
    assert set(inputs) == {"pr-number", "head-sha"}
    assert all(field["required"] is True for field in inputs.values())


def test_the_job_is_bound_to_the_environment_and_also_refuses_a_non_main_ref() -> None:
    """BREAK CONDITION: delete either the `environment:` key, the job `if:`, or
    the first step.

    The brief's requirement is BOTH, and the reason is that they fail
    differently: the environment is a forge-side policy this file cannot see or
    assert, and a `workflow_dispatch` can name a ref other than the one the
    policy was written about.
    """
    job = _job()
    assert job["environment"] == "dependency-bundle"
    assert job["if"] == "github.ref == 'refs/heads/main'"

    first = job["steps"][0]
    assert "uses" not in first, "the ref refusal must run before any action"
    assert "env" not in job, "no credential may be in scope for the whole job"
    assert "refs/heads/main" in first["run"] and "exit 2" in first["run"]
    # It precedes every step that could hold or spend a credential.
    assert all("secrets." not in str(first.get(key, "")) for key in first)


def test_no_step_checks_out_or_runs_pull_request_code() -> None:
    """BREAK CONDITION: set the checkout `ref:` to the dispatched head SHA.

    That single change is the whole vulnerability this workflow is built to
    avoid — it would put a contributor's tree on a runner holding a registry
    credential.
    """
    job = _job()
    checkouts = [
        step
        for step in job["steps"]
        if str(step.get("uses", "")).startswith("actions/checkout@")
    ]
    assert len(checkouts) == 1
    with_ = checkouts[0]["with"]
    assert with_["ref"] == "${{ github.sha }}"
    assert with_["persist-credentials"] is False
    assert "inputs.head-sha" not in str(with_)
    assert "repository" not in with_, "no foreign repository may be checked out"


def test_the_registry_credential_is_scoped_to_the_acquisition_step_alone() -> None:
    """BREAK CONDITION: move `FORGEJO_BUNDLE_READ_TOKEN` to the job's `env:`,
    or name the broad repository secret.

    Reading the snapshot and spending the credential are separate privileges,
    and the step that reads contributor-supplied data must not hold the one it
    does not need.
    """
    steps = _job()["steps"]
    holding = [
        step
        for step in steps
        if "FORGEJO_BUNDLE_READ_TOKEN" in str(step.get("env", {}))
    ]
    assert len(holding) == 1
    step = holding[0]
    assert step["name"] == "Acquire the locked wheels"
    assert (
        step["env"]["FORGEJO_BUNDLE_READ_TOKEN"]
        == "${{ secrets.FORGEJO_BUNDLE_READ_TOKEN }}"
    )
    # Main's fail-closed empty check survives the cutover.
    assert '[ -z "$FORGEJO_BUNDLE_READ_TOKEN" ]' in step["run"]
    assert "exit 2" in step["run"]
    # And the runner masks the value, so an accidental echo is redacted.
    assert "::add-mask::$FORGEJO_BUNDLE_READ_TOKEN" in step["run"]
    # The snapshot read holds the API token and the two inputs, and no secret.
    bind = next(s for s in steps if s.get("id") == "bind")
    assert set(bind["env"]) == {"GITHUB_TOKEN", "PR_NUMBER", "HEAD_SHA"}
    assert "secrets." not in str(bind["env"])


def test_no_dispatch_input_is_interpolated_into_a_shell_line() -> None:
    """BREAK CONDITION: write `--pr-number '${{ inputs.pr-number }}'` in `run:`.

    `${{ }}` is substituted into the script text BEFORE bash parses it, so an
    input carrying a quote executes as a command — and it executes before
    `admit_dispatch` has any opportunity to reject it. Validation downstream of
    a shell interpolation is not validation. Passing through `env:` makes the
    value data that bash never reparses.
    """
    for step in _job()["steps"]:
        run = step.get("run", "")
        assert "${{ inputs." not in run, step.get("name")
        assert "${{ github.event" not in run, step.get("name")
    # And both inputs are reached only as shell variables.
    bind = next(s for s in _job()["steps"] if s.get("id") == "bind")
    assert '"$PR_NUMBER"' in bind["run"] and '"$HEAD_SHA"' in bind["run"]


def test_the_job_is_least_privileged_and_time_bounded() -> None:
    """BREAK CONDITION: widen `permissions:` or drop `timeout-minutes`."""
    workflow, job = _workflow(), _job()
    assert workflow["permissions"] == {"contents": "read"}
    assert "permissions" not in job or job["permissions"] == {"contents": "read"}
    assert isinstance(job["timeout-minutes"], int) and job["timeout-minutes"] <= 30


def test_the_cache_is_saved_under_the_bound_key_and_only_the_wheelhouse() -> None:
    """BREAK CONDITION: key the save on `hashFiles` of the CHECKED-OUT tree.

    That is main's lock, not the reviewed pull request's — the cache would be
    saved under a key describing bytes the job never acquired.
    """
    saves = [
        step for step in _job()["steps"] if str(step.get("uses", "")) == CACHE_SAVE
    ]
    assert len(saves) == 1
    with_ = saves[0]["with"]
    assert with_["key"] == "${{ steps.bind.outputs.cache-key }}"
    assert with_["path"] == "${{ runner.temp }}/workspace-wheelhouse"
    assert "restore-keys" not in with_, "a prefix restore would defeat the exact key"


def test_a_refused_acquisition_cannot_leave_a_partial_wheelhouse_in_the_cache() -> None:
    """BREAK CONDITION: add `if: always()` (or `if: success() || failure()`, or
    `continue-on-error: true`) to the cache-save step, or to the acquire step.

    `acquire` copies each verified wheel to the destination as it goes and only
    sweeps for surplus entries AFTER the whole loop, so a refusal partway
    through — a hash that disagrees with the lock, a wheel the lock does not
    name — leaves a DIRECTORY holding some of the wheels and not others. Nothing
    in the script removes it, and nothing needs to, because this step is the
    only thing that would make it observable: a non-zero exit from acquire ends
    the job and an unconditional step does not run, so the partial directory is
    discarded with the runner.

    That is a premise about a file the script cannot see, which is why it is
    asserted here. Adding `if: always()` would save a cache entry under the
    exact dependency key describing a wheelhouse that is missing wheels — and a
    later CI run restoring that key would get a silent partial hit, not a miss.
    Whoever adds it should be told what it breaks.
    """
    steps = _job()["steps"]
    save = next(step for step in steps if str(step.get("uses", "")) == CACHE_SAVE)
    assert "if" not in save, "an unconditional save is what makes a refusal discard"
    assert "continue-on-error" not in save

    acquire = next(s for s in steps if s["name"] == "Acquire the locked wheels")
    assert "continue-on-error" not in acquire, "a refusal must fail the job"
    # Sensitivity. A check over a clean tree proves nothing about itself, so
    # plant the defect and show the predicate names it, and plant a near miss
    # and show it does not. `_conditional` is the exact predicate applied above.

    def _conditional(step: dict[str, Any]) -> bool:
        return "if" in step or "continue-on-error" in step

    planted = dict(save)
    planted["if"] = "always()"
    assert _conditional(planted)
    planted = dict(save)
    planted["continue-on-error"] = True
    assert _conditional(planted)
    # Near miss: a step gaining an unrelated key, or shell text containing the
    # word "if", is not the defect and must not be named as one.
    planted = dict(save)
    planted["timeout-minutes"] = 5
    assert not _conditional(planted)
    assert not _conditional({"run": "if [ -z \"$X\" ]; then exit 2; fi"})
    # And the key name really is readable as written: PyYAML does not fold `if`
    # the way it folds the bare `on` key this module has to work around.
    assert "if" in _job(), "the job's own `if:` is how that is established"


def test_every_action_is_pinned_to_a_full_forty_character_commit() -> None:
    """BREAK CONDITION: pin to a tag, a branch, or an abbreviated SHA.

    Main's producer carries a 39-character `actions/upload-artifact` pin, which
    is not a commit id at all; the sensitivity proof below is that this same
    predicate names it.
    """
    uses = [step["uses"] for step in _job()["steps"] if "uses" in step]
    assert uses, "the guard must have something to check"
    for reference in uses:
        assert PIN.fullmatch(reference), reference

    # Sensitivity: the predicate rejects the defect it exists for, including
    # main's real invalid pin, and accepts a genuine one. A check that passed
    # over every input would prove nothing about itself.
    assert not PIN.fullmatch(
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0"
    )
    assert not PIN.fullmatch("actions/checkout@v7.0.1")
    assert not PIN.fullmatch("actions/checkout@main")
    assert not PIN.fullmatch("actions/checkout@" + "3d3c42e5"[:8])
    assert PIN.fullmatch("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1")


def test_the_cache_action_is_the_node_24_capable_release() -> None:
    """BREAK CONDITION: pin `actions/cache` to a v4 commit.

    v4 runs on Node 20, which GitHub is removing; the job would stop running
    rather than fail visibly, and the cache would silently go cold.
    """
    assert CACHE_SAVE in WORKFLOW.read_text(encoding="utf-8")


def test_the_warmer_does_not_touch_candidate_ci() -> None:
    """BREAK CONDITION: this workflow gaining a `workflow_call` or writing an
    artifact that candidate CI consumes.

    PR A establishes the producer half only; the consumer half is a separate
    change, and the two must not be coupled through anything but the cache key.
    """
    document = _workflow()
    assert "workflow_call" not in document["on"]
    assert not any(
        "upload-artifact" in str(step.get("uses", "")) for step in _job()["steps"]
    )
