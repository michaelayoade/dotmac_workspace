"""The Workspace's front door: `/login`, its callback, and `/logout`.

A thin adapter (AGENTS.md §5). It validates, delegates to `service.py`, and
turns what comes back into a response. No query, no protocol, no decision.

## Four routes, and why each has the method it has

| route | method | why |
|---|---|---|
| `/login` | GET | renders a page; changes nothing |
| `/login` | POST | STARTS a ceremony — a state row is written |
| `/login/callback` | GET | the provider redirects a browser here |
| `/logout` | POST | ENDS a session |

Starting a login is a POST because it writes, and because a GET that begins an
authentication ceremony is login CSRF: a third-party page could trigger it with
an `<img src=…>` and silently sign a victim in as somebody else. It is issued
with `hx-post`, so the kernel's `static/js/csrf.js` attaches the `X-CSRF-Token`
header that `CSRFMiddleware` validates against the `csrf_token` cookie. A bare
`<form method="post">` has no hook for that header and would simply 403 — which
is why no page in this assembly contains one.

Logout is a POST for the same reason and one sharper: a CSRF-exempt safe method
that a third-party page can trigger by loading an image is a forced logout, and
a `<a href="/logout">` is exactly that. There is no "logout is special"
exemption here.

## The callback is a GET, and that is not an exception being carved

The authorization-code flow ends in a browser redirect, so the method is not
this assembly's to choose. What protects it is not the CSRF header bridge —
which no cross-site redirect could carry — but a PAIR of values that must
match:

* the `state` query parameter the provider echoed back, and
* the `dmws_login_state` cookie this server set when the ceremony started.

The state alone is not enough, and an earlier version of this module argued
that it was. It is a 256-bit random this server generated, it resolves to a row
only a browser that STARTED a ceremony could have, and consuming it is a single
`DELETE … RETURNING`, so it works exactly once on whichever worker the load
balancer picks. All true — and all beside the point. Those properties establish
that A ceremony exists; they say nothing about WHICH browser is standing in
front of the callback. An attacker who authenticates honestly as themselves
holds a valid `code` and a valid `state`, and forwarding that URL to a victim
would sign the victim in as the attacker. PKCE cannot see this either: the
verifier never left this server, so the exchange succeeds.

The cookie is the half an attacker cannot supply, because they cannot write a
host-only cookie onto somebody else's browser. `service.complete_login`
requires both and compares them with `secrets.compare_digest`; the comparison
happens BEFORE the state is consumed, so a forged callback cannot burn a
ceremony belonging to someone else. See `session.py` for the cookie's
attributes, `state_store.py` for the row, and `tests/test_login_csrf.py` for
the attack driven end to end.

## Every refusal looks the same

`LoginRefused` has no reason field, and this module renders one page for all of
them. Distinguishing "no such subject" from "disabled binding" from "bad nonce"
would hand whoever can drive a login an oracle for which subjects exist. The
detail is in the server log, where an operator can act on it — including the
subject an unbound identity presented, which is the value they need in order to
create the binding.
"""

from __future__ import annotations

import html
import logging
from urllib.parse import quote

from dotmac_kernel.deps import get_db, require_tenant
from dotmac_kernel.models import Party, Tenant
from dotmac_kernel.templating import render
from dotmac_kernel.web_deps import is_secure_request, safe_next_url
from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from dotmac_workspace.identity import service
from dotmac_workspace.identity.config import (
    ProviderNotConfiguredError,
    provider_or_none,
)
from dotmac_workspace.identity.session import (
    attach_cookie,
    attach_state_cookie,
    clear_cookie,
    clear_state_cookie,
)
from dotmac_workspace.page import SHELL_TEMPLATE
from dotmac_workspace.session_contract import (
    CALLBACK_PATH,
    DEFAULT_LANDING_PATH,
    LOGIN_PATH,
    LOGIN_STATE_COOKIE,
    LOGOUT_PATH,
    SESSION_COOKIE,
)
from dotmac_workspace.web_auth import require_workspace_auth

logger = logging.getLogger(__name__)

router = APIRouter()

#: Set by htmx on every request it issues. Its presence is how one route serves
#: both a scripted browser (which needs `HX-Redirect` to leave the origin) and a
#: plain client (which follows an ordinary 303).
HTMX_HEADER = "hx-request"

#: A cross-origin redirect cannot be followed by an XHR, so htmx is told to
#: navigate instead. Without this the browser would attempt the identity
#: provider's authorization endpoint as a background fetch and be refused by
#: CORS — a login that fails with a console error and no visible cause.
HTMX_REDIRECT_HEADER = "HX-Redirect"


def _refusal(request: Request, message: str, *, status_code: int) -> HTMLResponse:
    """One refusal shape. Says what the visitor can DO, never what went wrong."""
    return render(
        request,
        SHELL_TEMPLATE,
        {
            "title": "Sign in",
            "body": (
                "<h1>Sign in</h1>"
                f"<p>{html.escape(message)}</p>"
                f'<p><a href="{LOGIN_PATH}">Try again</a></p>'
            ),
        },
        status_code=status_code,
    )


@router.get(LOGIN_PATH, response_class=HTMLResponse)
def login_page(
    request: Request,
    tenant: Tenant = Depends(require_tenant),
    next_path: str = Query(default="", alias="next"),
) -> Response:
    """The front door.

    Deliberately says nothing about the tenant, the provider, or whether any
    account exists. It offers one control, and that control is a POST.

    `?next=` is reduced to a same-origin absolute path here, by the kernel's
    `safe_next_url`, and then stored SERVER-SIDE with the ceremony. It never
    travels to the provider and never comes back in a parameter, so there is no
    value in the round trip an attacker could rewrite into an open redirect.
    """
    if provider_or_none() is None:
        # Not a 500: the deployment is coherent, it simply has no federated
        # login configured. `config.configuration_errors()` is what makes that
        # fatal in production; here it is an honest 503.
        return _refusal(
            request,
            "Federated sign-in is not configured for this workspace. "
            "Contact your administrator.",
            status_code=503,
        )
    landing = safe_next_url(next_path, default=DEFAULT_LANDING_PATH)
    # Percent-encoded into the POST's own query string, then HTML-escaped for
    # the attribute. Two encodings because there are two contexts, and skipping
    # either is how a path with a quote or an ampersand in it stops being one
    # value. `hx-vals` would need a third (JSON inside an attribute) and buys
    # nothing here.
    target = html.escape(f"{LOGIN_PATH}?next={quote(landing, safe='/')}", quote=True)
    return render(
        request,
        SHELL_TEMPLATE,
        {
            "title": "Sign in",
            "body": (
                "<h1>Sign in</h1>"
                "<p>Sign in to your workspace with your organisation's "
                "identity provider.</p>"
                f'<button type="button" hx-post="{target}" '
                'hx-swap="none">Continue</button>'
            ),
        },
    )


@router.post(LOGIN_PATH)
def begin_login(
    request: Request,
    tenant: Tenant = Depends(require_tenant),
    next_path: str = Query(default="", alias="next"),
    db: Session = Depends(get_db),
) -> Response:
    """Start a ceremony and send the browser to the provider.

    A POST under the CSRF header bridge — see the module docstring for why
    starting a login is a mutation and why a GET here would be login CSRF.
    """
    try:
        started = service.begin_login(
            db,
            tenant=tenant,
            return_path=safe_next_url(next_path, default=DEFAULT_LANDING_PATH),
        )
    except ProviderNotConfiguredError:
        return _refusal(
            request,
            "Federated sign-in is not configured for this workspace.",
            status_code=503,
        )
    except service.LoginRefused:
        return _refusal(request, "Sign-in could not be started.", status_code=502)

    if request.headers.get(HTMX_HEADER):
        response: Response = Response(
            status_code=200, headers={HTMX_REDIRECT_HEADER: started.url}
        )
    else:
        response = RedirectResponse(started.url, status_code=303)
    # Both shapes carry the cookie: the htmx one is still a real response the
    # browser processes before navigating, and a login started through htmx
    # that skipped this would arrive at the callback with no cookie and be
    # refused — a working attack defence that breaks the ordinary path is not
    # a defence anyone keeps.
    attach_state_cookie(
        response,
        state=started.state,
        expires_at=started.expires_at,
        secure=is_secure_request(request),
    )
    return response


@router.get(CALLBACK_PATH)
def callback(
    request: Request,
    tenant: Tenant = Depends(require_tenant),
    code: str = Query(default=""),
    state: str = Query(default=""),
    error: str = Query(default=""),
    db: Session = Depends(get_db),
) -> Response:
    """Finish the ceremony, or refuse.

    The `state` query parameter and the `dmws_login_state` cookie are both
    passed to the service, which requires them to match — see the module
    docstring for why either one alone is not a defence. This adapter reads the
    cookie and makes no decision about it.

    Whatever happens, the state cookie is cleared: the ceremony has been
    answered, and a value left behind can only ever produce a later refusal.

    On success the response carries two things and they belong together: the
    `dmws_session` cookie, and a redirect to where the member was going. The
    session row behind that cookie was added inside THIS request's transaction,
    while `finalize_external_login` still held the binding's row lock — so a
    concurrent disable could not have landed between the decision and the
    session. `dotmac_kernel.db` commits at the end of the request, and that
    commit is what releases the lock.
    """
    secure = is_secure_request(request)

    def _done(response: Response) -> Response:
        """Every exit from this route goes through here. A `return` that
        skipped it would leave the ceremony cookie in the browser."""
        clear_state_cookie(response, secure=secure)
        return response

    if error:
        # The provider declined. Logged with its own code; shown as the same
        # refusal as everything else.
        logger.warning(
            "Workspace login refused by the provider for tenant %s: %s",
            tenant.id,
            error,
        )
        return _done(_refusal(request, "Sign-in was not completed.", status_code=403))
    if not code or not state:
        return _done(_refusal(request, "Sign-in was not completed.", status_code=400))

    try:
        completed = service.complete_login(
            db,
            tenant=tenant,
            state=state,
            stored_state=request.cookies.get(LOGIN_STATE_COOKIE),
            code=code,
            request_id=getattr(request.state, "request_id", None),
        )
    except ProviderNotConfiguredError:
        return _done(
            _refusal(
                request,
                "Federated sign-in is not configured for this workspace.",
                status_code=503,
            )
        )
    except service.LoginRefused:
        return _done(_refusal(request, "Sign-in was not completed.", status_code=403))

    response = RedirectResponse(completed.return_path, status_code=303)
    attach_cookie(
        response,
        token=completed.token,
        expires_at=completed.expires_at,
        secure=secure,
    )
    return _done(response)


@router.post(LOGOUT_PATH)
def logout(
    request: Request,
    tenant: Tenant = Depends(require_tenant),
    member: Party = Depends(require_workspace_auth),
    db: Session = Depends(get_db),
) -> Response:
    """End this session. POST, CSRF-bridged, and idempotent.

    The cookie is cleared with the SAME attributes it was set with — a
    `delete_cookie` whose path or flags differ leaves the original in place,
    and the symptom is a logout that reports success while the browser keeps
    sending the session.
    """
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        service.end_session(
            db,
            tenant=tenant,
            party=member,
            token=token,
            request_id=getattr(request.state, "request_id", None),
        )

    secure = is_secure_request(request)
    if request.headers.get(HTMX_HEADER):
        response: Response = Response(
            status_code=200, headers={HTMX_REDIRECT_HEADER: LOGIN_PATH}
        )
    else:
        response = RedirectResponse(LOGIN_PATH, status_code=303)
    clear_cookie(response, secure=secure)
    return response


__all__ = ["router"]
