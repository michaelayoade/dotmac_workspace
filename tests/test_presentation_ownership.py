"""One Workspace shell, plus styled kernel-owned error pages.

CE-001 existed because the document was spelled once in Python and once in
Jinja. The repair is not another agreement check: Python no longer owns a
document, every route renders the facet template through the kernel, and the
assembly's one stylesheet declaration reaches the kernel's own error layout.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from dotmac_kernel import create_app
from dotmac_kernel.errors import render_error
from fastapi import Request

from dotmac_workspace import page
from dotmac_workspace.assembly import build_spec

SRC = Path(page.__file__).resolve().parent
TEMPLATES = SRC / "templates"


def _request(path: str = "/missing") -> Request:
    app = create_app(build_spec())
    return Request(
        {
            "type": "http",
            "app": app,
            "method": "GET",
            "path": path,
            "raw_path": path.encode(),
            "root_path": "",
            "scheme": "https",
            "query_string": b"",
            "headers": [(b"accept", b"text/html")],
            "client": ("testclient", 50000),
            "server": ("testserver", 443),
        }
    )


def _python_document_literals(source: str) -> list[str]:
    """Executable string literals that try to own an HTML document."""
    tree = ast.parse(source)
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "<!doctype html" in node.value.lower()
    ]


def _stylesheet_positions(rendered: str, expected: tuple[str, ...]) -> list[int]:
    hrefs = re.findall(r'<link rel="stylesheet" href="([^"]+)">', rendered)
    return [hrefs.index(href) for href in expected]


def test_the_facet_names_the_only_document_shell() -> None:
    spec = build_spec()
    facets = {facet.code: facet for facet in spec.web_facets}
    shell = TEMPLATES / page.SHELL_TEMPLATE

    document_templates = [
        path
        for path in TEMPLATES.rglob("*.html")
        if "<!doctype html" in path.read_text(encoding="utf-8").lower()
    ]
    assert document_templates == [shell]
    assert facets["staff_admin"].shell.qualified_name == page.SHELL_TEMPLATE


def test_python_does_not_spell_a_second_document_shell() -> None:
    offenders = {
        str(path.relative_to(SRC)): _python_document_literals(
            path.read_text(encoding="utf-8")
        )
        for path in SRC.rglob("*.py")
        if _python_document_literals(path.read_text(encoding="utf-8"))
    }
    assert not offenders, f"Python document shells reintroduced: {sorted(offenders)}"


def test_the_python_shell_guard_would_notice_one() -> None:
    probe = 'SHELL = "<!doctype html><html><body>x</body></html>"'
    assert _python_document_literals(probe)


def test_kernel_error_pages_receive_the_workspace_cascade() -> None:
    """The acceptance criterion for setting `ProductAssemblySpec.stylesheets`.

    Status is preserved and both product sheets appear in declared order. If
    the assembly slot is cleared, this fails against the kernel's real error
    renderer instead of merely comparing two configuration values.
    """
    response = render_error(
        _request(),
        404,
        {"code": "not_found", "message": "Missing", "request_id": "req-1"},
    )
    rendered = bytes(response.body).decode()

    assert response.status_code == 404
    positions = _stylesheet_positions(rendered, page.stylesheets())
    assert positions == sorted(positions)


def test_the_error_stylesheet_assertion_is_not_vacuous() -> None:
    damaged = '<link rel="stylesheet" href="/one.css">'
    with pytest.raises(ValueError):
        _stylesheet_positions(damaged, ("/one.css", "/missing.css"))
