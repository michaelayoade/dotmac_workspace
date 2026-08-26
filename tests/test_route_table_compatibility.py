"""The constructed route table did not move when the kernel did.

Adopting kernel `0.1.0a97` changed how routes are MOUNTED — a declared facet,
a compatibility adapter, and route names that are now facet-qualified. An
unchanged source diff does not prove URLs survived that: the decorators declare
paths, but the kernel composes them, and the composition is exactly what
changed. Only the table the application actually constructs can settle it.

These pins were captured from a running app on kernel `0.1.0a70` — the last
version before the adoption — and every one of them still holds on `0.1.0a97`.

Route NAMES are deliberately NOT pinned. a97 qualifies them
(`login_page` became `web:staff_admin:identity:legacy:login_page`), which is
correct and expected. It is safe here only because nothing in this repository
resolves a route by name: there is no `url_for`, no `url_path_for`, and every
link is a hardcoded path constant. `test_no_route_is_resolved_by_name` keeps
that true, because the day it stops being true these renames become breaking.
"""

from __future__ import annotations

from pathlib import Path

from dotmac_workspace.main import app

SRC = Path(__file__).resolve().parents[1] / "src"

# (method, path) as constructed on kernel 0.1.0a70, before the facet adoption.
PRE_ADOPTION_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("-", "/static"),
        ("GET", "/applications"),
        ("GET", "/docs"),
        ("GET", "/docs/oauth2-redirect"),
        ("GET", "/health"),
        ("GET", "/login"),
        ("GET", "/login/callback"),
        ("GET", "/openapi.json"),
        ("GET", "/operator/identity"),
        ("GET", "/operator/members"),
        ("GET", "/platform"),
        ("GET", "/platform/entitlements"),
        ("GET", "/platform/entitlements/{tenant_id}"),
        ("GET", "/platform/flags"),
        ("GET", "/platform/login"),
        ("GET", "/redoc"),
        ("POST", "/login"),
        ("POST", "/logout"),
        ("POST", "/operator/identity/bind"),
        ("POST", "/operator/identity/{binding_id}/disable"),
        ("POST", "/operator/members"),
        ("POST", "/operator/members/{party_id}/revoke"),
        ("POST", "/platform/auth/login"),
        ("POST", "/platform/auth/logout"),
        ("POST", "/platform/entitlements/{tenant_id}/{code}"),
        ("POST", "/platform/flags/{code}"),
        ("POST", "/platform/login"),
        ("POST", "/platform/logout"),
    }
)


def _constructed_routes() -> set[tuple[str, str]]:
    """Every mounted (method, path), including lazily-included routers.

    FastAPI 0.140 stores an included router lazily and exposes its flattened,
    prefix-aware routes through `effective_route_contexts`. Walking `app.routes`
    alone sees only the kernel's own handful and silently misses every feature
    route — which would make this whole file pass over almost nothing.
    """

    def expand(routes):
        for route in routes:
            contexts = getattr(route, "effective_route_contexts", None)
            if callable(contexts):
                yield from expand(contexts())
            else:
                yield route

    found: set[tuple[str, str]] = set()
    for route in expand(app.routes):
        path = getattr(route, "path", None)
        if path is None:
            continue
        for method in getattr(route, "methods", None) or {"-"}:
            if method in {"HEAD", "OPTIONS"}:
                continue
            found.add((method, path))
    return found


def test_the_scan_is_not_vacuous() -> None:
    """The sensitivity proof for everything below.

    If the lazy-router expansion above ever stops working, `_constructed_routes`
    returns the kernel's six system routes and the compatibility assertion
    passes over a set that contains no product route at all.
    """
    constructed = _constructed_routes()
    assert len(constructed) >= 20, (
        "route scan found only "
        f"{len(constructed)} routes — the lazy-router expansion has broken and "
        "the compatibility check below is passing over nothing"
    )


def test_no_pre_adoption_url_moved() -> None:
    missing = PRE_ADOPTION_ROUTES - _constructed_routes()
    assert not missing, (
        "the kernel adoption moved or removed URLs that existed on a70: "
        + ", ".join(f"{m} {p}" for m, p in sorted(missing))
    )


def test_no_route_is_resolved_by_name() -> None:
    """Route names are facet-qualified now, so resolving by name is breaking."""
    offenders = [
        str(path.relative_to(SRC))
        for path in SRC.rglob("*.py")
        for text in [path.read_text(encoding="utf-8")]
        if "url_for(" in text or "url_path_for(" in text
    ]
    assert not offenders, (
        "these resolve routes by name, which a97's facet-qualified names break: "
        + ", ".join(offenders)
    )
