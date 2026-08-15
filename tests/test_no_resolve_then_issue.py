"""There is no resolve-then-issue path in this repository, anywhere.

## The defect this forbids

    resolved = resolve_external_identity(...)  # binding active, party a person
    ── an administrator disables the binding, and commits ──
    db.add(AuthSession(...))                   # a live session, revoked identity

Both halves report success. The disable really did deactivate the row and every
later resolution really does refuse; the login really did authenticate somebody
the binding named. What makes them incompatible is an ORDERING neither one
records, so nothing in either audit trail contradicts the other.

`dotmac-kernel 0.1.0a64` exists because of this. `finalize_external_login`
takes the binding under `SELECT … FOR UPDATE`, re-checks `is_active` under that
lock, stamps `last_authenticated_at`, and hands back the party so the caller
mints its session in the SAME transaction with the row still held. The disable
path's `UPDATE` needs the same lock, so the two serialize and there is no
interleaving that mints a session from a binding that was already inactive.

Carrying `binding_id` across the gap does NOT close it: the window is between a
read and the write that depends on it, and a value read before the window is
still a value read before the window. That is why this guard forbids the READ
on the login path rather than requiring the id to be passed along.

## Why these guards match syntax

Every check here matches an AST node — a `Name`, an `Attribute`, an import
alias. None greps for a word. This file's own prose names
`resolve_external_identity` a dozen times, `service.py`'s docstring shows the
racy pair as an example, and both must stay: a guard whose cheapest fix is
deleting the explanation of the rule it enforces is worse than no guard. Each
guard is paired below with a test that it does not fire on prose, and one that
it does fire on a real call.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from dotmac_workspace.identity import service, state_store

SRC = Path(inspect.getfile(state_store)).resolve().parents[2]
SOURCES = sorted(SRC.rglob("*.py"))

#: The kernel READ. Legitimate for an admin screen or a support lookup, and
#: never on a path that ends in a session. This assembly has no such screen, so
#: the name must not appear as code anywhere in it.
FORBIDDEN = frozenset({"resolve_external_identity", "record_external_authentication"})

#: The one entry point a caller may end a session on.
REQUIRED = "finalize_external_login"


def _code_identifiers(source: str) -> set[str]:
    """Identifiers that are CODE. `ast.Constant` — docstrings and string
    literals — is deliberately excluded, and that exclusion is the guard's
    specificity."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.alias):
            # BOTH halves. `import x as y` carries the original in `name` and
            # the local binding in `asname`; recording only one of them makes
            # renaming-on-import the way around this guard.
            names.add(node.name.rsplit(".", 1)[-1])
            if node.asname:
                names.add(node.asname)
    return names


def test_the_sweep_actually_sees_the_package() -> None:
    assert SRC.name == "src"
    assert len(SOURCES) >= 10, f"only {len(SOURCES)} modules found under {SRC}"


def test_the_racy_resolver_is_not_called_anywhere_in_the_package() -> None:
    offenders: dict[str, set[str]] = {}
    for path in SOURCES:
        found = FORBIDDEN & _code_identifiers(path.read_text(encoding="utf-8"))
        if found:
            offenders[str(path.relative_to(SRC))] = found
    assert not offenders, (
        f"a resolve-then-issue path has appeared: {offenders}. The login path "
        "must go through `finalize_external_login`, which holds the binding's "
        "row lock across the decision and the session. See this module's "
        "docstring for the interleaving that is otherwise available."
    )


def test_the_callback_uses_the_locking_finalizer() -> None:
    """The positive half. "No racy resolver" would also pass in a repository
    that had no login at all."""
    source = Path(inspect.getfile(service)).read_text(encoding="utf-8")
    assert REQUIRED in _code_identifiers(source), (
        "the login service must CALL finalize_external_login — the guard above "
        "only proves what it does not do"
    )


def test_the_session_is_minted_in_the_finalizers_transaction() -> None:
    """The lock only helps if the session is added before the commit.

    `complete_login` takes the request's `Session` and passes THE SAME one to
    `finalize_external_login` and to `session.issue`. A second session, a
    nested commit, or a `db.commit()` between them would release the row lock
    before the session existed and reopen the whole window.
    """
    source = Path(inspect.getfile(service)).read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "complete_login"
    )
    calls = {
        node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name | ast.Attribute)
    }
    assert REQUIRED in calls
    assert "issue" in calls, "the session must be minted inside this function"
    assert "commit" not in calls, (
        "complete_login commits: the commit is what releases the binding's row "
        "lock, and it belongs to `dotmac_kernel.db` at the end of the request "
        "(hard rule 8). Committing here would put the session outside the lock."
    )


def test_the_guard_does_not_fire_on_prose_naming_the_forbidden_call() -> None:
    """This very file, and `service.py`, must be able to EXPLAIN the defect.

    A guard that flags the explanation is a guard whose cheapest fix is
    deleting it.
    """
    prose = (
        '"""Never call resolve_external_identity on a path that ends in a\n'
        'session; use finalize_external_login instead."""\n'
        "# resolve_external_identity is a READ and takes no lock.\n"
        'DOCS = "resolve_external_identity then issue is the racy pair"\n'
    )
    assert not (FORBIDDEN & _code_identifiers(prose))

    # The real one: `service.py`'s docstring shows the racy pair verbatim, and
    # the sweep above passed over that file. Both facts together are the proof.
    service_doc = ast.get_docstring(
        ast.parse(Path(inspect.getfile(service)).read_text(encoding="utf-8"))
    )
    assert service_doc is not None
    assert "resolve_external_identity" in service_doc, (
        "the login service must keep showing the racy pair it refuses. If this "
        "is what failed, somebody deleted the explanation to satisfy a guard — "
        "which is the failure this pairing exists to catch."
    )


def test_the_guard_does_fire_on_a_real_call_or_import() -> None:
    """Sensitivity. A detector that never fires proves nothing."""
    imported = "from dotmac_kernel.external_identity import resolve_external_identity\n"
    called = "x = resolve_external_identity(db, tenant=t, issuer=i, subject=s)\n"
    attribute = "x = external_identity.resolve_external_identity(db)\n"
    aliased = (
        "from dotmac_kernel.external_identity import "
        "resolve_external_identity as look_up\n"
    )
    # An alias is the obvious way around a name-based guard, so it is in the
    # list: `ast.alias` carries the ORIGINAL name alongside the local binding,
    # and both are collected, so renaming on import does not launder it.
    for source in (imported, called, attribute, aliased):
        assert FORBIDDEN & _code_identifiers(source), source
