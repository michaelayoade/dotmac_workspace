"""ASGI entrypoint — the Workspace is `create_app(build_spec())`.

`uvicorn dotmac_workspace.main:app`. All composition lives in
`assembly.build_spec()`; this module is the thinnest possible adapter, exactly
as the kernel intends and as ADR-0015 requires.
"""

from __future__ import annotations

from dotmac_kernel import create_app

from dotmac_workspace.assembly import build_spec

app = create_app(build_spec())

__all__ = ["app"]
