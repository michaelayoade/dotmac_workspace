"""Workspace presentation composition: one template and one stylesheet cascade.

`templates/layouts/workspace.html` is the only document shell. Every browser
adapter reaches it through `dotmac_kernel.templating.render`; this module owns
only the template reference and the ordered stylesheet declaration the assembly
projects into the kernel.

The shell carries the kernel's CSRF header bridge. A plain
`<form method="post">` has no hook for its header, so every mutating control
uses `hx-post`. Keeping the document in one Jinja template means the bridge
cannot disappear from one screen while surviving on another.
"""

from __future__ import annotations

from typing import Final

import dotmac_ui

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
#: Public because the assembly projects it into `ProductAssemblySpec.stylesheets`.
#: The kernel then supplies the ordered cascade to both this facet shell and its
#: own branded error templates. The URL is written once here, never in Jinja.
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
    """The ordered cascade the assembly supplies to every HTML surface."""
    return (dotmac_ui.stylesheet_url(), WORKSPACE_CSS)


#: The one document shell, named beside its cascade so the assembly and routes
#: cannot select different presentation contracts.
SHELL_TEMPLATE: Final[str] = "layouts/workspace.html"

__all__ = ["SHELL_TEMPLATE", "WORKSPACE_CSS", "stylesheets"]
