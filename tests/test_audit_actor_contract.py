"""Workspace audit writes name the canonical actor pair without a fallback."""

from __future__ import annotations

import ast
from pathlib import Path

SERVICE = Path("src/dotmac_workspace/identity/service.py")


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
