"""The Workspace's HTML shell — one `<head>`, so the CSRF bridge is never absent.

Small on purpose. This assembly has two screens; a template engine, a layout
hierarchy and a component library would all be scaffolding around eleven lines
of markup. What it must NOT be is two hand-written shells, because the thing
they carry is not decoration.

## What the shell actually carries

`static/js/csrf.js` (the kernel's) copies the `csrf_token` COOKIE onto the
`X-CSRF-Token` HEADER for every htmx request. `dotmac_kernel.middleware.csrf`
validates one against the other — double submit — which is why the cookie is
deliberately not `HttpOnly`.

A plain `<form method="post">` has no hook for attaching a custom header, so
**every mutating control in this assembly uses `hx-post`**, never a bare
`method="post"`. A page that forgot these two script tags would render a logout
button that silently 403s; a page that used a bare form would do the same. One
shell means neither can happen on one screen and not the other.

Everything is served from `/static`, which `create_app` mounts from the
kernel's packaged assets. Nothing is inline, nothing is remote: the kernel's
default Content-Security-Policy is `script-src 'self'`, and an inline handler
here would be a policy exception argued for by a button.

## The second spelling, and why it is not a second shell

Kernel 0.1.0a97 requires a declared web facet to name its shell as a real
TEMPLATE, resolved at boot. `templates/layouts/workspace.html` is that template,
and it composes the same document this function does.

That is the duplication the paragraph above forbids, so it is not left on trust:
`tests/test_web_facet_shell.py` renders both with the same inputs and requires
them to agree, link for link and script for script. The stylesheet cascade is
not duplicated at all — `stylesheets()` below is the one source. This function
reads it, and the template is HANDED it: `ProductAssemblySpec.stylesheets` is
deliberately left empty (see `assembly.py`), so the template's fallback to
`surface.stylesheets` is a path nothing currently takes.

The honest alternative was to delete this function and route every page through
`dotmac_kernel.templating.render()`. It was not taken here because `render()`
needs a `Request` that `_refusal`, `launcher.web._page` and `operator.web._shell`
do not currently take — a three-module surface rewrite riding along on a
dependency bump. The guard makes deferring it safe rather than merely cheap.
"""

from __future__ import annotations

import html
from typing import Final

import dotmac_ui

#: Kernel-packaged, served from the `/static` mount `create_app` installs.
_HTMX: Final[str] = "/static/js/htmx.min.js"
_CSRF_BRIDGE: Final[str] = "/static/js/csrf.js"

#: This assembly's own small stylesheet, served from the same mount via
#: `ProductAssemblySpec.assembly_static_dir`. It defines the `.dmws-*` classes
#: this plane's markup uses and defines them ENTIRELY in terms of
#: `var(--dmui-*)` tokens — see `static/css/workspace.css`. Two rules make that
#: distinction load-bearing rather than stylistic:
#:
#: * `.dmui-*` is a RESERVED namespace. Only components `dotmac-ui` actually
#:   declares may ship under it (today: `empty-state`), so inventing
#:   `.dmui-table` here would be claiming a name the design system owns.
#: * A raw colour here would be a second, private design system that silently
#:   stops matching the fleet the first time a token is retuned.
#:
#: PUBLIC (it lost its underscore when kernel 0.1.0a97 arrived) because the
#: facet's shell template renders the same two links and must read them from
#: here rather than spell them again. The kernel CAN feed a shell from
#: `ProductAssemblySpec.stylesheets`, but this assembly leaves that slot empty
#: on purpose, so `stylesheets()` below stays the single source of "the cascade
#: this plane serves" — see `assembly.py` and
#: `templates/layouts/workspace.html`.
WORKSPACE_CSS: Final[str] = "/static/css/workspace.css"


#: The cascade every Workspace page loads, in order. `dotmac-ui`'s compiled
#: stylesheet FIRST, because `workspace.css` is written entirely in terms of the
#: `--dmui-*` tokens it defines and resolves to nothing without it.
#:
#: Not a constant, because `dotmac_ui.stylesheet_url()` carries a content digest
#: that changes with the installed package version — computing it once at import
#: would pin a checkout's asset URL into anything that imported this module
#: early.
def stylesheets() -> tuple[str, ...]:
    """The `<link>` cascade, for `page.py` and the assembly spec alike."""
    return (dotmac_ui.stylesheet_url(), WORKSPACE_CSS)


def render_page(*, title: str, body: str) -> str:
    """One page. `title` is escaped; `body` is markup the caller assembled.

    `body` is NOT escaped — it is composed markup, and every value interpolated
    into it is escaped at the point it is interpolated (see `launcher.web._tile`
    and this module's callers). That split is the usual one, and it is worth
    naming: the shell escapes what it is given as TEXT and trusts what it is
    given as MARKUP, so a caller that forgets to escape a value has made the
    mistake in a place a reader is looking for it.
    """
    links = "".join(f'<link rel="stylesheet" href="{href}">' for href in stylesheets())
    return (
        "<!doctype html>"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)} — DotMac Workspace</title>"
        f"{links}"
        f'<script src="{_HTMX}" defer></script>'
        f'<script src="{_CSRF_BRIDGE}" defer></script>'
        "</head>"
        f'<body class="dmws-body"><main class="dmws-main">{body}</main></body></html>'
    )


#: The facet shell that must stay equivalent to `render_page`. Named here, next
#: to the function it mirrors, so `assembly.py`'s `TemplateRef` and the guard in
#: `tests/test_web_facet_shell.py` cannot name different files.
SHELL_TEMPLATE: Final[str] = "layouts/workspace.html"

__all__ = ["SHELL_TEMPLATE", "WORKSPACE_CSS", "render_page", "stylesheets"]
