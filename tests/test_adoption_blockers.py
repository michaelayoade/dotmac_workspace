"""The adoption blockers stay visible, and stay unclosed the wrong way.

ADR-0018: an exemption must state an enforceable premise, or the region is
unmonitored rather than exempt. `docs/ADOPTION-BLOCKERS.md` is this repository's
statement that it is a scaffold rather than a consumer, and these tests are what
stop that statement drifting away from the code.

The important one is `test_the_guard_does_not_hand_roll_a_role_check`, and it
outlives the blocker it was written for. B1 has since been closed the RIGHT way
— kernel 0.1.0a62's `permission_guard` — but the wrong way is still available to
anyone editing this file, and closing it locally by querying roles here would
look like progress while making this plane one that falls behind kernel security
fixes. The guard stays.

B2 is open, so this repository is still a scaffold and
`dotmac-application-directory` still has zero production consumers. The file
these tests read must keep saying so until that is untrue.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from dotmac_workspace.launcher import guard

BLOCKERS = Path(__file__).resolve().parents[1] / "docs" / "ADOPTION-BLOCKERS.md"
GUARD_SOURCE = Path(inspect.getfile(guard)).read_text(encoding="utf-8")


def test_the_blockers_file_exists_and_names_the_permission_code() -> None:
    """The permission code is the load-bearing name in that file. It named the
    decision B1 could not enforce; it now names the decision the launcher DOES
    enforce, and the file has to keep tracking which."""
    assert BLOCKERS.is_file()
    text = BLOCKERS.read_text(encoding="utf-8")
    assert "workspace.applications.read" in text
    assert "audit-complete" in text, (
        "the blockers file must keep stating that the directory has zero "
        "production consumers — that is what the dossier claims"
    )


def test_the_blockers_file_still_records_an_unreachable_surface() -> None:
    """B2 is workstream 4's, and it is what keeps this repository a scaffold.

    A blockers file that quietly stopped naming B2 while nothing minted
    `dmws_session` would be this repository claiming to be deployable when
    `/applications` still redirects to a route that does not exist.
    """
    text = BLOCKERS.read_text(encoding="utf-8")
    assert "B2" in text
    assert "dmws_session" in text


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
    names: set[str] = set()
    for node in ast.walk(ast.parse(GUARD_SOURCE)):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
    offenders = forbidden & names
    assert not offenders, (
        f"the Workspace guard is querying authorization state itself "
        f"({sorted(offenders)}). B1 is closed by a kernel permission seam that "
        "works for cookie-authenticated callers, never by duplicating the "
        "kernel's role logic here."
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
