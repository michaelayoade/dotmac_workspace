"""The Workspace's OWN session vocabulary — cookie name and front-door paths.

ADR-0021 §1 requires the Workspace to share **no database, session, cookie or
guard** with any application. That invariant is carried by exactly one string,
`SESSION_COOKIE`, and a string that lives in two files is a string that will
eventually exist in two spellings.

So it lives here, once, at the ASSEMBLY level rather than inside either feature
that needs it. Two features do:

- `launcher.guard` READS the cookie (`require_workspace_auth`), and
- `identity` WRITES it (the callback) and CLEARS it (logout).

Neither imports the other — this module is shared assembly vocabulary, the same
shape as a constants module in any product, and deliberately not a feature. It
imports nothing, holds no state, and makes no decision; it names things.

## Why `dmws_session` and never `access_token`

`access_token` is what every product data plane's portal reads. On separate
hosts a browser scopes those separately, so today they cannot collide — but
"cannot collide because of how we happen to deploy it" is a deployment
coincidence, not the invariant ADR-0021 states. A Workspace and a target
application served under one parent domain, with a `Domain=`-scoped cookie,
would share a session name and the containment property would evaporate without
a single line of code changing.

Which is also why the cookie this assembly sets carries **no `Domain`
attribute** — see `identity.session`. A host-only cookie cannot be widened by a
later deployment decision.
"""

from __future__ import annotations

from typing import Final

#: The Workspace's session cookie. Deliberately NOT `access_token`.
SESSION_COOKIE: Final[str] = "dmws_session"

#: Binds a login ceremony to the BROWSER that started it. Set when `/login` is
#: POSTed, required to match the callback's `state` query parameter, cleared on
#: every callback outcome. Without it the `state` parameter proves only that a
#: ceremony exists — not that this browser began it — and a callback URL
#: forwarded to a victim signs them in as the attacker. See
#: `identity.service.complete_login` and `tests/test_login_csrf.py`.
LOGIN_STATE_COOKIE: Final[str] = "dmws_login_state"

#: Where an unauthenticated visitor is sent, and where the ceremony begins.
LOGIN_PATH: Final[str] = "/login"

#: The provider's redirect target. A GET, because the authorization-code flow
#: is a browser redirect — see `identity.web` for why that is not a violation
#: of "a GET never mutates session state" and what protects it instead.
CALLBACK_PATH: Final[str] = "/login/callback"

#: Ending a session is a POST under the CSRF header bridge, never a link.
LOGOUT_PATH: Final[str] = "/logout"

#: Where a completed login lands when the ceremony recorded no return path.
DEFAULT_LANDING_PATH: Final[str] = "/applications"

__all__ = [
    "CALLBACK_PATH",
    "DEFAULT_LANDING_PATH",
    "LOGIN_PATH",
    "LOGIN_STATE_COOKIE",
    "LOGOUT_PATH",
    "SESSION_COOKIE",
]
