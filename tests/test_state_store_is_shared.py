"""The production state store is the shared one, and there is no other in `src/`.

A login started on one worker must complete on another. That is not a nice
property — it is the difference between a Workspace that works behind a load
balancer and one whose logins succeed about half the time, with a failure that
reproduces on nobody's laptop.

So this module holds two guards and their sensitivity proofs:

1. no per-process store is DEFINED or REFERENCED anywhere under `src/`, and
2. the only store the composed flow uses is `PostgresStateStore`, whose consume
   path is a single `DELETE … RETURNING`.

Both match SYNTAX — a `ClassDef` name, a `Name`, an `Attribute`, an import
alias — never words in a file. `state_store.py`'s docstring has a whole section
headed `InMemoryStateStore` explaining why there isn't one, and a guard that
flagged it would be satisfied most cheaply by deleting the explanation. Each
guard below is therefore paired with a test that it does not fire on prose AND
one that it does fire on the real thing.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from dotmac_workspace.identity import service, state_store

SRC = Path(inspect.getfile(state_store)).resolve().parents[2]
SOURCES = sorted(SRC.rglob("*.py"))

#: The shapes a per-process store would take. Matched as identifiers, never as
#: text: the point is a definition or a reference, not a mention.
FORBIDDEN_STORE_NAMES = frozenset({"InMemoryStateStore", "MemoryStateStore"})


def _identifiers(source: str) -> set[str]:
    """Every identifier that is CODE: definitions, references, imports.

    Deliberately excludes `ast.Constant`, which is where docstrings, comments
    (via the tokenizer, absent here) and string literals live. That exclusion
    IS the guard's specificity, and the test below proves it.
    """
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ClassDef | ast.FunctionDef):
            names.add(node.name)
        elif isinstance(node, ast.Name):
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


def test_src_is_a_real_tree() -> None:
    """The sweep below is worthless if it walked an empty directory."""
    assert SRC.name == "src", SRC
    assert len(SOURCES) >= 10, f"only {len(SOURCES)} modules found under {SRC}"


def test_no_per_process_state_store_exists_in_the_shipped_package() -> None:
    """Nothing under `src/` defines or names one — so nothing can select one."""
    offenders: dict[str, set[str]] = {}
    for path in SOURCES:
        found = FORBIDDEN_STORE_NAMES & _identifiers(path.read_text(encoding="utf-8"))
        if found:
            offenders[str(path.relative_to(SRC))] = found
    assert not offenders, (
        f"a per-process state store appears in the shipped package: {offenders}. "
        "A login started on one worker must complete on another; a test double "
        "belongs in tests/support/, outside the wheel, where no configuration "
        "can reach it."
    )


def test_the_store_guard_does_not_fire_on_prose_describing_its_absence() -> None:
    """`state_store.py` explains at length that there is no in-memory store.

    A guard that flagged that explanation would be satisfied most cheaply by
    deleting it, which is how a codebase loses the reason a rule exists.
    """
    prose = (
        '"""There is deliberately no InMemoryStateStore in this package."""\n'
        "# An InMemoryStateStore would complete a login only on the worker\n"
        "# that started it.\n"
        'NOTE = "InMemoryStateStore lives in tests/support/"\n'
    )
    assert not (FORBIDDEN_STORE_NAMES & _identifiers(prose))

    # And the real docstring, which is the case that actually matters.
    real_docstring = ast.get_docstring(
        ast.parse(Path(inspect.getfile(state_store)).read_text(encoding="utf-8"))
    )
    assert real_docstring is not None
    assert "InMemoryStateStore" in real_docstring, (
        "the module must keep explaining why there is no in-memory store — if "
        "this assertion is what fails, the explanation was deleted, and that "
        "is the failure mode this pairing exists to make visible"
    )


def test_the_store_guard_does_fire_on_a_real_definition_or_reference() -> None:
    """Sensitivity. A detector that never fires passes for the wrong reason."""
    defined = "class InMemoryStateStore:\n    pass\n"
    imported = "from tests.support import InMemoryStateStore\n"
    used = "store = InMemoryStateStore()\n"
    for source in (defined, imported, used):
        assert FORBIDDEN_STORE_NAMES & _identifiers(source), source


def test_the_composed_flow_uses_the_postgres_store() -> None:
    """Not merely "no in-memory store" — the shared one, positively asserted.

    The negative guard alone would pass in a repository that had deleted the
    store entirely.
    """
    assert isinstance(service._STORE, state_store.PostgresStateStore)


def test_consuming_a_ceremony_is_one_statement() -> None:
    """The single-use guarantee is the statement, not the code around it.

    A `SELECT` followed by a `DELETE` lets two callbacks both see the row and
    both proceed with the same verifier. This asserts the shape that makes that
    impossible: one `DELETE … RETURNING`, and no `SELECT` anywhere in the
    module.
    """
    sql = state_store._CONSUME_SQL.upper()
    assert sql.startswith("DELETE FROM")
    assert "RETURNING" in sql
    assert "SELECT" not in sql, (
        "the consume path grew a SELECT — single-use is a property of ONE "
        "statement, and a read before the delete gives it away"
    )
    assert "EXPIRES_AT > NOW()" in sql, (
        "expiry must be enforced IN the consuming statement, so an expired "
        "ceremony is refused whether or not anything has swept it"
    )
