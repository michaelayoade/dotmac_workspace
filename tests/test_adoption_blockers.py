"""The adoption blockers stay visible, and stay unclosed the wrong way.

ADR-0018: an exemption must state an enforceable premise, or the region is
unmonitored rather than exempt. These tests keep the repository's adoption
statements aligned with the production state and the module dossier.

The important one is `test_the_guard_does_not_hand_roll_a_role_check`, and it
outlives the blocker it was written for. B1 has since been closed the RIGHT way
— kernel 0.1.0a62's `permission_guard` — but the wrong way is still available to
anyone editing this file, and closing it locally by querying roles here would
look like progress while making this plane one that falls behind kernel security
fixes. The guard stays.

B2 is closed and the 2026-08-16 production pilot made this repository the first
consumer of `dotmac-application-directory`. That adoption must be stated without
turning directory visibility into authorization or a shared target-app session.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from dotmac_workspace import web_auth
from dotmac_workspace.launcher import guard

BLOCKERS = Path(__file__).resolve().parents[1] / "docs" / "ADOPTION-BLOCKERS.md"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
GUARD_SOURCE = Path(inspect.getfile(guard)).read_text(encoding="utf-8")
AUTH_SOURCE = Path(inspect.getfile(web_auth)).read_text(encoding="utf-8")
#: Both halves of the Workspace's guard: "may you?" (the launcher's, which
#: declares the permission) and "who are you?" (the assembly's, which reads the
#: cookie). The forbidden query is forbidden in BOTH — the wrong fix is
#: available in whichever file somebody opens next, so the guard follows the
#: property rather than one path it used to live at.
GUARDED_SOURCES = {"launcher/guard.py": GUARD_SOURCE, "web_auth.py": AUTH_SOURCE}


def test_the_repository_records_production_adoption_without_moving_authority() -> None:
    """Every adoption statement agrees on the earned state and its boundary."""
    assert BLOCKERS.is_file()
    adoption_sources = {
        "README.md": PROJECT_ROOT / "README.md",
        "docs/ADOPTION-BLOCKERS.md": BLOCKERS,
        "docs/PILOT-RUNBOOK.md": PROJECT_ROOT / "docs" / "PILOT-RUNBOOK.md",
        "pyproject.toml": PROJECT_ROOT / "pyproject.toml",
    }
    assert set(adoption_sources) == {
        "README.md",
        "docs/ADOPTION-BLOCKERS.md",
        "docs/PILOT-RUNBOOK.md",
        "pyproject.toml",
    }, "the adoption-claim inventory changed without updating this ratchet"

    for label, path in adoption_sources.items():
        text = path.read_text(encoding="utf-8")
        assert "audit-complete" not in text, f"{label} still denies adoption"
        assert (
            "zero production consumers" not in text.lower()
        ), f"{label} still denies the production consumer"

    blockers = BLOCKERS.read_text(encoding="utf-8")
    assert "workspace.applications.read" in blockers
    assert "adopted" in blockers
    assert "workspace.dotmac.io" in blockers
    assert "dotmac-application-directory 0.1.0a3" in blockers
    assert "directory visibility is not authorization" in blockers.lower()


def test_the_blockers_file_records_b2_against_a_surface_that_now_exists() -> None:
    """B2 was "nothing issues `dmws_session`, and there is no `/login`".

    This assertion has been INVERTED, deliberately, and the inversion is the
    interesting part. It used to require the file to keep saying the surface
    was unreachable; keeping that after the surface existed would have forced
    the documentation to claim a gap the code no longer has — the same drift,
    pointing the other way (ADR-0018's two-directional ratchet).

    So it now requires the file to keep naming B2 AND the cookie, and it
    requires the CODE to actually mint that cookie: a blockers file that
    declared B2 closed while nothing set `dmws_session` would be the lie in the
    other direction.
    """
    text = BLOCKERS.read_text(encoding="utf-8")
    assert "B2" in text
    assert "dmws_session" in text

    from dotmac_workspace.identity import session
    from dotmac_workspace.session_contract import SESSION_COOKIE

    source = Path(inspect.getfile(session)).read_text(encoding="utf-8")
    assert SESSION_COOKIE == "dmws_session"
    assert "set_cookie" in source, (
        "B2 is only closed while something in this repository actually sets "
        "the Workspace session cookie"
    )


def test_the_role_check_guard_does_not_fire_on_prose_describing_it() -> None:
    """The guard above matches AST nodes, never words in a file.

    Three guards in this programme have flagged the comment explaining the very
    invariant they enforced, and the cheapest way to satisfy such a guard is to
    delete the explanation. Both guarded modules DO name `PartyRoleGrant`,
    `Role`, `select` and `execute` in their docstrings — that is how a reader
    learns what is forbidden — and the guard must be indifferent to it.
    """
    prose = (
        '"""This module must never query PartyRoleGrant or Role, and never '
        'call select, execute, scalars or query."""\n'
        "VALUE = 1\n"
    )
    names: set[str] = set()
    for node in ast.walk(ast.parse(prose)):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
    forbidden = {"PartyRoleGrant", "Role", "select", "execute", "scalars", "query"}
    assert not (forbidden & names), (
        "the detector matched prose. A guard that cannot tell an explanation "
        "from a call site is a guard whose cheapest fix is deleting the "
        "explanation."
    )

    # And the sensitivity half: it DOES fire on a real call site. A detector
    # that never fires passes every review for the wrong reason.
    real = "from x import Role\nrows = db.query(Role).all()\n"
    caught: set[str] = set()
    for node in ast.walk(ast.parse(real)):
        if isinstance(node, ast.Name):
            caught.add(node.id)
        elif isinstance(node, ast.Attribute):
            caught.add(node.attr)
    assert forbidden & caught


def test_the_guard_still_names_the_decision_it_enforces() -> None:
    """A reader of the guard must be able to see WHICH decision it makes.

    This replaces the older `test_the_guard_points_at_the_blocker`, which
    asserted the guard advertised B1. Keeping that assertion after B1 closed
    would have forced the code to keep claiming a gap it no longer has — the
    exact drift these tests exist to catch, pointing the other way.
    """
    assert guard.APPLICATIONS_READ == "workspace.applications.read"
    assert "permission_guard" in GUARD_SOURCE, (
        "the guard must authorize through the kernel's authentication-neutral "
        "seam, which is the whole reason B1 could be closed here at all"
    )


def test_the_guard_does_not_hand_roll_a_role_check() -> None:
    """The fix for B1 is a kernel seam, not a local query.

    Duplicating kernel authorization logic in an assembly is how a plane falls
    behind a kernel security fix — the failure ADR-0015 recorded against
    academy, where a control was configured, asserted in config validation, and
    never armed. If this test fails because someone added a role lookup here,
    the fix is to remove it and press for the seam.
    """
    forbidden = {"PartyRoleGrant", "Role", "select", "execute", "scalars", "query"}
    for label, source in GUARDED_SOURCES.items():
        names: set[str] = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
        offenders = forbidden & names
        assert not offenders, (
            f"{label} is querying authorization state itself "
            f"({sorted(offenders)}). B1 is closed by a kernel permission seam "
            "that works for cookie-authenticated callers, never by duplicating "
            "the kernel's role logic here."
        )


def test_the_kernel_dependency_declares_no_unused_extra() -> None:
    """B5, kept closed. An unused extra is surface a deployment carries and
    nobody checks."""
    pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    for line in pyproject.splitlines():
        if line.startswith("dotmac-kernel ="):
            assert "extras" not in line, (
                "the kernel test kit was declared and never used; add it back "
                "only alongside a test that consumes it"
            )
            break
    else:  # pragma: no cover - the dependency cannot vanish
        raise AssertionError("dotmac-kernel dependency not found")
