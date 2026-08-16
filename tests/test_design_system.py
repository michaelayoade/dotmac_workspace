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

    used: set[str] = set()
    src = Path(page.__file__).resolve().parent
    for path in [*src.rglob("*.py"), CSS]:
        used |= set(re.findall(r"\bdmui-[a-z0-9_-]+", path.read_text()))

    # Token references are `--dmui-*` and are matched by the pattern above once
    # the leading dashes are consumed; they are not classes.
    tokens = {
        name.lstrip("-")
        for path in [CSS]
        for name in re.findall(r"--dmui-[a-z0-9-]+", path.read_text())
    }
    invented = used - published - tokens
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
