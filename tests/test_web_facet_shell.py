"""The facet's shell template and `page.render_page` compose the SAME document.

Kernel 0.1.0a97 makes a browser facet declare its shell as a real template. This
assembly already had a shell — `dotmac_workspace.page.render_page`, an f-string —
and adopting a97 did not rewrite three web modules to render through the
kernel's `render()`, which needs a `Request` that none of `_refusal`,
`launcher.web._page` or `operator.web._shell` currently takes.

So there are two spellings of one document, which is exactly the hazard
`page.py`'s own docstring names: "What it must NOT be is two hand-written
shells, because the thing they carry is not decoration." The thing they carry is
the CSRF header bridge — `static/js/csrf.js` copies the `csrf_token` cookie onto
the `X-CSRF-Token` header `CSRFMiddleware` validates — and a shell that lost it
would render mutating controls that silently 403.

This file is what makes the duplication safe rather than merely cheap: both
spellings are rendered with the same inputs and required to agree. Edit one
without the other and the build fails here, which is the only reason deferring
the rewrite is defensible.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from dotmac_workspace import page
from dotmac_workspace.assembly import build_spec

TEMPLATE_DIR = Path(page.__file__).resolve().parent / "templates"

#: The exact document the shell must carry, whichever spelling produced it.
#: Named here so a page that lost one is a named failure rather than a diff.
LOAD_BEARING = (
    "/static/js/csrf.js",
    "/static/js/htmx.min.js",
)


def _render_template(*, title: str, body: str) -> str:
    """The template, rendered on its own loader.

    Deliberately NOT through `dotmac_kernel.templating.templates.env`: that
    environment's loader is composed inside `create_app`, from
    `ProductAssemblySpec.assembly_template_dir`, and this suite builds no app.
    Reading the directory the spec actually declares keeps the two in step —
    `test_the_spec_declares_the_directory_this_guard_reads` below is what stops
    this helper drifting into checking a file the assembly does not ship.
    """
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
        undefined=StrictUndefined,
    )
    return env.get_template(page.SHELL_TEMPLATE).render(
        title=title, body=body, stylesheets=page.stylesheets()
    )


def _tags(document: str) -> list[str]:
    """The document's tags and text, with inter-tag whitespace removed.

    The comparison is deliberately whitespace-insensitive BETWEEN tags and
    nowhere else. A Jinja file that composed the same document on one
    unreadable line would be worse than the f-string it mirrors, and the
    newlines it does carry are not part of what either spelling promises. Every
    attribute, every URL and every element still has to match exactly.
    """
    collapsed = re.sub(r">\s+<", "><", document.strip())
    return re.findall(r"<[^>]+>|[^<>]+", collapsed)


def test_the_spec_declares_the_directory_this_guard_reads() -> None:
    """A guard reading a file the wheel does not ship proves nothing."""
    assert build_spec().assembly_template_dir == TEMPLATE_DIR
    assert (TEMPLATE_DIR / page.SHELL_TEMPLATE).is_file()


def test_the_facet_names_the_shell_this_guard_compares() -> None:
    """The facet, `page.py` and this file must all mean the same template."""
    facets = {facet.code: facet for facet in build_spec().web_facets}
    assert facets["staff_admin"].shell.qualified_name == page.SHELL_TEMPLATE


@pytest.mark.parametrize(
    ("title", "body"),
    [
        ("Sign in", "<h1>Sign in</h1>"),
        ("Applications", '<ul class="dmws-tiles"></ul>'),
        ("Members", '<div id="operator-screen"></div>'),
    ],
)
def test_both_spellings_compose_the_same_document(title: str, body: str) -> None:
    assert _tags(_render_template(title=title, body=body)) == _tags(
        page.render_page(title=title, body=body)
    )


@pytest.mark.parametrize("asset", LOAD_BEARING)
def test_both_spellings_carry_the_csrf_bridge(asset: str) -> None:
    """The positive half.

    Without it, two shells that had BOTH lost the bridge would agree with each
    other perfectly and pass the comparison above — a guard satisfied by the
    failure it exists to prevent.
    """
    rendered = _render_template(title="t", body="<p>b</p>")
    assert asset in rendered
    assert asset in page.render_page(title="t", body="<p>b</p>")


def test_both_spellings_link_the_same_stylesheet_cascade() -> None:
    """One source, read twice: `page.stylesheets()`.

    Order is asserted, not just membership. `workspace.css` is written entirely
    in terms of `var(--dmui-*)`, so a cascade that loaded it before the design
    system's would resolve every rule in it to nothing — a page that renders,
    unstyled, with no error anywhere.
    """
    cascade = list(page.stylesheets())
    assert cascade[0].startswith("/static/dotmac-ui/")
    assert cascade[1] == page.WORKSPACE_CSS

    # The assembly deliberately does NOT re-declare the cascade. Setting
    # `ProductAssemblySpec.stylesheets` would give it a second source and would
    # also style the kernel's branded error pages — a real repair, unrelated to
    # the facet adoption, owed its own change. The shell template reads a
    # caller-supplied `stylesheets` and only falls back to `surface.stylesheets`,
    # so an empty slot changes nothing a member sees. Asserting emptiness pins
    # that decision rather than leaving it to be re-litigated by accident.
    assert tuple(build_spec().stylesheets) == ()

    for document in (
        _render_template(title="t", body="<p>b</p>"),
        page.render_page(title="t", body="<p>b</p>"),
    ):
        found = re.findall(r'<link rel="stylesheet" href="([^"]+)">', document)
        assert found == cascade


def test_the_comparison_would_notice_a_divergence() -> None:
    """Sensitivity proof (AGENTS.md § "Writing an architecture guard").

    Both spellings agree today, which is exactly the condition under which a
    broken comparison looks healthy. Feed it a document with one script tag
    removed and require that it is seen.
    """
    intact = page.render_page(title="t", body="<p>b</p>")
    damaged = intact.replace('<script src="/static/js/csrf.js" defer></script>', "")
    assert _tags(intact) != _tags(damaged), (
        "the comparison cannot see a missing script tag, so it could not have "
        "seen the CSRF bridge disappear from one of the two shells"
    )


def test_the_comparison_ignores_only_whitespace_between_tags() -> None:
    """The other half of the sensitivity proof.

    `_tags` normalises inter-tag whitespace so the template may be readable. It
    must not normalise anything else — a comparison that also ignored attribute
    differences would let the two shells load different assets.
    """
    a = '<a href="/one">x</a>'
    b = '<a href="/two">x</a>'
    assert _tags(a) != _tags(b)
    assert _tags("<p>\n  <span>x</span>\n</p>") == _tags("<p><span>x</span></p>")
