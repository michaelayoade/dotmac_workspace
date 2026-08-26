"""This plane consumes `dotmac-ui`, and does so through its published surface.

Before this, every screen shipped unstyled markup and the assembly composed no
design system at all. Fixing that is easy; keeping it fixed is what these
guards are for, because both failure modes are silent:

* A raw colour or hand-picked spacing creeps into `workspace.css`. Nothing
  breaks, and the page stops matching the fleet the next time a token is
  retuned — with no failure anywhere to say so.
* A `.dmui-*` class is invented. It renders unstyled today (nothing defines it)
  and collides the day `dotmac-ui` publishes a component by that name.

Hard rules 16 and 17, checked here rather than assumed.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import dotmac_ui

from dotmac_workspace import page
from dotmac_workspace.assembly import build_spec

CSS = Path(page.__file__).resolve().parent / "static" / "css" / "workspace.css"


def _declarations(text: str) -> list[str]:
    """Every `property: value` pair, comments stripped.

    Comments are removed first because this file's comments legitimately
    DISCUSS hex colours and the reasons not to use them, and a scan that read
    them would flag the explanation — making the cheapest way to pass the guard
    "delete the reasoning".
    """
    without_comments = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return [
        m.group(2).strip()
        for m in re.finditer(r"([\w-]+)\s*:\s*([^;{}]+);", without_comments)
    ]


def _dmui_names_actually_shipped() -> set[str]:
    """Every `dmui-*` name this assembly really emits or styles.

    Structure, not text. The first version of this guard grepped both file
    types and failed on its OWN prose: `workspace.css`'s header comment
    explains that inventing a `.dmui-table` would be claiming a name the design
    system owns, and a text scan read that explanation as a usage. The cheapest
    way to satisfy such a guard is to delete the reasoning, which is precisely
    the wrong repair — so the detector parses instead.

    * Python: the AST's string constants, with docstrings excluded. Comments
      are not in the AST at all, so they cannot be misread.
    * CSS: comments stripped, then class selectors only. Token references are
      `--dmui-*` and are excluded by requiring a `.` before the name.
    * Jinja: comments stripped, then whatever remains. Templates joined this
      scope when kernel 0.1.0a97 made the facet declare a shell — before that
      this assembly shipped no HTML files at all. Extending the scope in the
      same change that adds the surface is the point: a governance scope that
      is not widened alongside the product silently stops covering it.
    """
    src = Path(page.__file__).resolve().parent
    found: set[str] = set()

    for path in src.rglob("*.py"):
        tree = ast.parse(path.read_text())
        docstrings = {
            ast.get_docstring(node, clean=False)
            for node in ast.walk(tree)
            if isinstance(
                node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef
            )
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value in docstrings:
                    continue
                found |= set(re.findall(r"\bdmui-[a-z0-9_-]+", node.value))

    css = re.sub(r"/\*.*?\*/", "", CSS.read_text(), flags=re.S)
    found |= {name.lstrip(".") for name in re.findall(r"\.dmui-[a-z0-9_-]+", css)}

    for path in src.rglob("*.html"):
        found |= set(re.findall(r"\bdmui-[a-z0-9_-]+", _template_markup(path)))
    return found


def _template_markup(path: Path) -> str:
    """A template with its Jinja and HTML comments removed.

    Same discipline as the CSS and Python branches: the shell's comment block
    explains at length that `.dmui-*` belongs to `dotmac-ui` and that this
    assembly's own markup uses `.dmws-*`, and a scan that read the explanation
    would make deleting it the cheapest way to pass.
    """
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
    return re.sub(r"<!--.*?-->", "", text, flags=re.S)


def test_the_workspace_stylesheet_exists_and_is_served() -> None:
    assert CSS.is_file(), f"{CSS} is missing"
    assert build_spec().assembly_static_dir == CSS.parent.parent, (
        "the assembly does not mount its own static directory, so the "
        "stylesheet the shell links would 404"
    )


def test_the_design_system_is_composed() -> None:
    """The package's compiled assets are layered into the static mount."""
    assert dotmac_ui.static_dir() in tuple(build_spec().packaged_static_dirs)


def test_every_page_links_the_design_system_stylesheet() -> None:
    html = page.render_page(title="t", body="<p>b</p>")
    assert dotmac_ui.stylesheet_url() in html, (
        "the shell does not link dotmac-ui's stylesheet, so no token resolves "
        "and every rule in workspace.css falls back to nothing"
    )


def test_no_raw_colour_survives_in_the_workspace_stylesheet() -> None:
    """Colour comes from tokens, never from a literal.

    A hex value here is a second design system: it looks right on the day it is
    written and silently stops matching the fleet afterwards.
    """
    offenders = [
        value
        for value in _declarations(CSS.read_text())
        if re.search(r"#[0-9a-fA-F]{3,8}\b", value)
        or re.search(r"\b(rgb|rgba|hsl|hsla|oklch)\s*\(", value)
    ]
    assert not offenders, f"raw colour values in workspace.css: {offenders}"


def test_the_raw_colour_guard_would_notice_one() -> None:
    """Sensitivity proof. A check that never fires proves nothing — and this
    one runs against a file that currently has no offender, which is exactly
    the condition under which a broken detector looks healthy."""
    seen = [
        v
        for v in _declarations(".x { color: #ff0000; }")
        if re.search(r"#[0-9a-fA-F]{3,8}\b", v)
    ]
    assert seen, "the detector cannot see a hex colour even when one is present"


def test_no_undeclared_dmui_class_is_used_anywhere() -> None:
    """`.dmui-*` is the design system's namespace (hard rule 16).

    Only classes `dotmac-ui` actually publishes may appear. Everything this
    assembly styles itself lives under `.dmws-*`.
    """
    published = {cls for component in dotmac_ui.COMPONENTS for cls in component.classes}
    invented = _dmui_names_actually_shipped() - published
    assert not invented, (
        f"undeclared .dmui-* names used: {sorted(invented)}. That namespace "
        "belongs to dotmac-ui; use .dmws-* for this assembly's own markup."
    )


def test_the_empty_state_uses_the_published_component_classes() -> None:
    """The one component `dotmac-ui` declares is reused rather than reinvented."""
    from dotmac_workspace.operator import web

    rendered = web._empty_state(title="none", message="nothing here")
    assert "dmui-empty-state" in rendered
    emitted = set(re.findall(r"\bdmui-[a-z0-9_-]+", rendered))
    assert emitted <= dotmac_ui.EMPTY_STATE.classes


def test_the_namespace_guard_still_bites() -> None:
    """Sensitivity proof, and this one has already earned its keep.

    The guard's first version fired on a comment rather than on shipped markup.
    Now that it parses, the risk inverts: an AST walk that quietly matched
    nothing would pass forever. So feed it an invented class in a real string
    constant and require that it is seen — and confirm that the same name in a
    docstring and in a CSS comment is NOT, which is the discrimination the
    whole rewrite exists to make.
    """
    module = ast.parse('X = "<table class=\\"dmui-invented\\">"')
    shipped: set[str] = set()
    docstrings = {ast.get_docstring(module, clean=False)}
    for node in ast.walk(module):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value in docstrings:
                continue
            shipped |= set(re.findall(r"\bdmui-[a-z0-9_-]+", node.value))
    assert "dmui-invented" in shipped, "the detector cannot see a shipped class"

    prose = ast.parse('"""Never invent a dmui-invented class."""')
    prose_docstrings = {ast.get_docstring(prose, clean=False)}
    prose_found: set[str] = set()
    for node in ast.walk(prose):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value in prose_docstrings:
                continue
            prose_found |= set(re.findall(r"\bdmui-[a-z0-9_-]+", node.value))
    assert not prose_found, "the detector still reads its own documentation"

    css = re.sub(r"/\*.*?\*/", "", "/* never write .dmui-invented */", flags=re.S)
    assert not re.findall(
        r"\.dmui-[a-z0-9_-]+", css
    ), "the detector still reads CSS comments"


def test_the_template_branch_reads_markup_and_not_its_own_explanation() -> None:
    """The Jinja branch's sensitivity proof, both directions.

    The shell is the only template this assembly ships and it uses no `.dmui-*`
    class at all — which is exactly the condition under which a branch that
    matched nothing would pass forever. So prove it sees a real one, and prove
    it does not see the same name inside the comment that forbids it.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        shipped = Path(directory) / "shipped.html"
        shipped.write_text('<div class="dmui-invented">x</div>', encoding="utf-8")
        assert "dmui-invented" in _template_markup(
            shipped
        ), "the detector cannot see a class in shipped markup"

        prose = Path(directory) / "prose.html"
        prose.write_text(
            "{#- never invent a dmui-invented class -#}\n"
            "<!-- nor a dmui-invented one here -->\n<p>x</p>",
            encoding="utf-8",
        )
        assert "dmui-invented" not in _template_markup(prose), (
            "the detector still reads the comment explaining the invariant, so "
            "the cheapest way to satisfy it is to delete the explanation"
        )
