"""No isolation assertion in this repository may read a direct-grant listing.

Governance **ADR 0022 § 3 property 9** makes the METHOD part of the property,
and its drift section names this exact shape as detectable from repository
content: *an isolation assertion reading `information_schema.table_privileges`
or another DIRECT-grant listing where property 9 requires effective-privilege
semantics.* This repository is where that defect was found, so it is the
repository that should be unable to grow it back.

`information_schema.table_privileges` and its siblings enumerate grants made
DIRECTLY to the named grantee. A role reaching a table through a membership,
through `PUBLIC`, or through a column grant appears in them as holding nothing,
so the assertion goes green over the leak. The corrected form —
`has_table_privilege` / `has_any_column_privilege` across all seven table
privileges — lives in `tests/db/effective_privileges.py`.

**The guard matches string LITERALS in the AST, never source text**, and it
skips docstrings. Three guards in this programme have flagged the comment
explaining the very invariant they enforce, and the cheapest way to satisfy such
a guard is to delete the explanation — so prose about the discredited view is
deliberately outside its reach, and the two sensitivity tests below pin that
behaviour in both directions.

One site is allowlisted: the negative control in `effective_privileges.py`,
whose only caller is the planted-reach proof that observes the listing MISSING a
membership-only reach. That allowlist is a two-directional ratchet — a test
below fails if the allowlisted site stops containing a listing, because an
allowlist outliving its reason is how the next one gets granted.
"""

from __future__ import annotations

import ast
from pathlib import Path

TESTS_ROOT = Path(__file__).resolve().parent

#: The `information_schema` views that answer with DIRECT grants only. Each one
#: reports "nothing" for a role that reaches the object through a membership.
DIRECT_GRANT_LISTINGS: tuple[str, ...] = (
    "information_schema.table_privileges",
    "information_schema.column_privileges",
    "information_schema.role_table_grants",
    "information_schema.role_column_grants",
)

#: The ONE place a direct-grant listing may be written: the negative control
#: that the sensitivity proof watches fail.
NEGATIVE_CONTROL = TESTS_ROOT / "db" / "effective_privileges.py"

#: This file names the views in order to detect them.
_GUARD_ITSELF = Path(__file__).resolve()


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """Identity of every node that is a docstring, so prose is out of reach."""
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(
            node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef
        ):
            continue
        body = getattr(node, "body", [])
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            docstrings.add(id(body[0].value))
    return docstrings


def direct_grant_listings_in(source: str) -> list[str]:
    """Every non-docstring string literal in `source` naming a listing view."""
    tree = ast.parse(source)
    skip = _docstring_nodes(tree)
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if id(node) in skip:
            continue
        lowered = node.value.lower()
        found.extend(view for view in DIRECT_GRANT_LISTINGS if view in lowered)
    return found


def _scanned_files() -> list[Path]:
    return sorted(
        path
        for path in TESTS_ROOT.rglob("*.py")
        if path.resolve() not in {_GUARD_ITSELF, NEGATIVE_CONTROL.resolve()}
    )


def test_no_isolation_assertion_reads_a_direct_grant_listing() -> None:
    offenders = {
        str(path.relative_to(TESTS_ROOT)): sorted(set(found))
        for path in _scanned_files()
        if (found := direct_grant_listings_in(path.read_text(encoding="utf-8")))
    }
    assert not offenders, (
        f"a direct-grant listing is back: {offenders}. It answers 'no privilege "
        "found' for a role that reaches the object through a membership, so it "
        "passes exactly when the boundary is broken (ADR 0022 § 3 property 9). "
        "Ask the effective question — tests/db/effective_privileges.py."
    )


def test_the_scan_actually_covers_the_isolation_canary() -> None:
    """A guard over an empty set passes for the wrong reason."""
    scanned = {path.resolve() for path in _scanned_files()}
    canary = (TESTS_ROOT / "db" / "test_login_state_isolation.py").resolve()
    assert canary in scanned, "the file this defect was found in is not scanned"
    assert len(scanned) > 10, f"the scan found only {len(scanned)} files"


def test_the_allowlisted_negative_control_still_contains_one() -> None:
    """The ratchet's other direction.

    The allowlist exists because the sensitivity proof needs a working example
    of the discredited method to watch fail. If that example is gone, the
    exemption has outlived its premise and must be removed rather than left
    standing as a hole somebody later widens.
    """
    found = direct_grant_listings_in(NEGATIVE_CONTROL.read_text(encoding="utf-8"))
    assert found, (
        f"{NEGATIVE_CONTROL.name} no longer contains a direct-grant listing, so "
        "its allowlist entry has no premise left. Delete the entry."
    )


def test_the_guard_does_not_fire_on_prose_describing_the_defect() -> None:
    """The failure mode this repository has hit three times.

    A module explaining why the listing is wrong must not be punished for
    saying the words — the cheapest way to satisfy such a guard is to delete
    the explanation.
    """
    prose = (
        '"""Never read information_schema.table_privileges for isolation.\n\n'
        "It lists DIRECT grants only, so information_schema.role_table_grants\n"
        'and its relatives miss a membership."""\n'
        "\n"
        "# information_schema.table_privileges is wrong here, in a comment too.\n"
        "def check():\n"
        '    """Uses information_schema.column_privileges? No — never."""\n'
        "    return None\n"
    )
    assert direct_grant_listings_in(prose) == []


def test_the_guard_fires_on_a_real_direct_grant_assertion() -> None:
    """And on the real thing, in the shape this repository actually shipped."""
    real = (
        '"""A module whose docstring says nothing incriminating."""\n'
        "\n"
        "QUERY = (\n"
        '    "SELECT privilege_type FROM information_schema.table_privileges "\n'
        "    \"WHERE table_name = 'workspace_login_states' \"\n"
        "    \"AND grantee = 'platform_api'\"\n"
        ")\n"
    )
    assert direct_grant_listings_in(real) == ["information_schema.table_privileges"]
