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


#: Every suffix this plane can serve a route name from. `.py` was the whole
#: story until a97, because the assembly rendered no templates at all — adopting
#: the facet introduced an HTML surface, and Jinja's `url_for` resolves route
#: names exactly as Starlette's does. A guard that scanned only Python would
#: have gone on passing while the one new file type it needed to cover appeared
#: underneath it.
NAME_RESOLVING_SUFFIXES = ("*.py", "*.html", "*.jinja", "*.jinja2", "*.j2")

#: The spellings that turn a route NAME into a URL, in Python and in Jinja.
NAME_RESOLVERS = ("url_for(", "url_path_for(")


def _name_resolving_files() -> list[str]:
    return sorted(
        str(path.relative_to(SRC))
        for suffix in NAME_RESOLVING_SUFFIXES
        for path in SRC.rglob(suffix)
        for text in [path.read_text(encoding="utf-8")]
        if any(resolver in text for resolver in NAME_RESOLVERS)
    )


def test_the_name_resolution_scan_covers_the_html_surface() -> None:
    """Sensitivity proof: the scan must actually reach templates.

    `test_no_route_is_resolved_by_name` asserts an EMPTY result, so it passes
    just as happily when it scans nothing. This pins that the HTML surface the
    facet introduced is inside its reach, and that a `url_for` written there
    would be seen.
    """
    templates = list(SRC.rglob("*.html"))
    assert templates, (
        "no .html found under src/ — the facet shell should be here, and the "
        "name-resolution scan below is no longer covering an HTML surface"
    )
    probe = templates[0].read_text(encoding="utf-8") + '\n{{ url_for("x") }}\n'
    assert any(
        resolver in probe for resolver in NAME_RESOLVERS
    ), "the scan would not notice a url_for in a template"


def test_no_route_is_resolved_by_name() -> None:
    """Route names are facet-qualified now, so resolving by name is breaking.

    a97 renamed 20 of this plane's 28 routes (`login_page` became
    `web:staff_admin:identity:legacy:login_page`). That was safe ONLY because
    nothing here turns a name into a URL. This is the guard that keeps it safe.
    """
    offenders = _name_resolving_files()
    assert not offenders, (
        "these resolve routes by name, which a97's facet-qualified names break: "
        + ", ".join(offenders)
    )
