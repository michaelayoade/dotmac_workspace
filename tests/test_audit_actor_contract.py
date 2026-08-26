"""Workspace audit writes name the canonical actor pair without a fallback."""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

SERVICE = Path("src/dotmac_workspace/identity/service.py")
PYPROJECT = Path("pyproject.toml")


def _actor_problem(call: ast.Call) -> str | None:
    keywords = {keyword.arg: keyword.value for keyword in call.keywords}
    actor_type = keywords.get("actor_type")
    actor_id = keywords.get("actor_id")
    party_id = keywords.get("actor_party_id")
    if actor_type is None or actor_id is None or party_id is None:
        return "actor_party_id, actor_type and actor_id must all be explicit"
    if not isinstance(actor_type, ast.Constant) or actor_type.value != "user":
        return "Workspace's authenticated Party actor must be a user"
    if ast.unparse(actor_id) != f"str({ast.unparse(party_id)})":
        return "actor_id must identify the same principal as actor_party_id"
    return None


def test_every_workspace_audit_writer_names_the_actor_pair() -> None:
    tree = ast.parse(SERVICE.read_text(), filename=str(SERVICE))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "write_audit_event"
    ]

    assert len(calls) == 2, "the ratchet must change when the caller set changes"
    problems = [
        f"{SERVICE}:{call.lineno}: {problem}"
        for call in calls
        if (problem := _actor_problem(call))
    ]
    assert not problems, f"non-canonical audit actor callers: {problems}"


#: The kernel release that began REFUSING to derive an audit actor, making the
#: explicit `actor_type`/`actor_id` call sites above load-bearing rather than
#: decorative.
STRICT_ACTOR_KERNEL_SERIAL = 70


def test_workspace_pins_the_kernel_that_refuses_actor_derivation() -> None:
    """The explicit callers and the strict callee never come apart.

    A FLOOR, not a snapshot. This was an equality assertion against `0.1.0a70`
    and it failed the first kernel bump — reporting that the pin had moved,
    which says nothing about actor derivation and is not what this guard is
    for. What must never happen is the pin dropping BELOW the release that
    made the callee strict, which would leave the explicit callers guarding
    a kernel that still derives actors silently.
    """
    dependencies = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["tool"][
        "poetry"
    ]["dependencies"]
    pinned = dependencies["dotmac-kernel"]["version"]
    prefix, _, serial = pinned.partition("a")
    assert prefix == "0.1.0", f"unexpected kernel version shape: {pinned!r}"
    assert int(serial) >= STRICT_ACTOR_KERNEL_SERIAL, (
        f"kernel pinned at {pinned!r}, below 0.1.0a{STRICT_ACTOR_KERNEL_SERIAL} "
        "which is where the kernel stopped deriving audit actors"
    )


def test_actor_guard_ignores_prose_that_only_names_the_writer() -> None:
    """A comment describing the rule is not an audit write."""
    tree = ast.parse("# write_audit_event must name the actor pair\nvalue = 1\n")
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "write_audit_event"
        for node in ast.walk(tree)
    )


def test_actor_guard_rejects_the_retired_party_only_shape() -> None:
    """Sensitivity: removing the pair produces the exact compatibility shape."""
    tree = ast.parse("write_audit_event(db, actor_party_id=party.id)")
    call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))
    assert _actor_problem(call) == (
        "actor_party_id, actor_type and actor_id must all be explicit"
    )
