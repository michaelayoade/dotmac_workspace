"""The callback must bind the ceremony to the BROWSER, not only to the server.

This is a regression test for a login-CSRF hole found in review, and the attack
is worth stating plainly because the fix looks like a formality otherwise:

1. the attacker starts a login in their own browser and authenticates honestly
   at the identity provider, as themselves;
2. the provider redirects them to `/login/callback?code=…&state=…`;
3. instead of following it, the attacker sends that URL to a victim;
4. the victim's browser opens it. Workspace consumes the state, completes the
   exchange, and issues `dmws_session` — **for the attacker's identity, on the
   victim's browser**.

The victim is now silently signed in as the attacker. Everything they do lands
in the attacker's account, and anything they type is the attacker's to read
later. No credential was phished and nothing looks broken.

**PKCE does not prevent this.** The verifier never left the server, so the
server is perfectly happy to complete the exchange — it is the same server that
started the ceremony. PKCE stops an interceptor of the CODE; it says nothing
about *which browser* is standing in front of the callback.

The `state` parameter alone does not prevent it either, and that was the
reasoning error: a state that resolves to a stored ceremony proves the ceremony
EXISTS, not that this browser started it. Only a value the attacker cannot set
on the victim's browser can prove that — hence a host-only cookie, compared
against the query parameter.

`dotmac-auth-oidc` reaches the same conclusion: its `complete_login` requires
both `state_parameter` and `stored_state` and compares them with
`secrets.compare_digest`. This module is the Workspace-side proof of the same
property, and it must keep passing after the local client is retired in favour
of that package — at which point it becomes the test that the SWAP preserved
the defence rather than inherited it.

No database and no network, matching `test_login_flow.py`: the `store` fixture
is the in-memory ceremony store from `conftest.py`, and the provider exchange
is substituted, because what is under test is which pair this assembly accepts.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from dotmac_workspace.identity import oidc, service
from dotmac_workspace.identity.config import ProviderConfig

CONFIG = ProviderConfig(
    issuer="https://idp.example.net",
    client_id="dotmac-workspace",
    redirect_url="https://ws.example.net/login/callback",
    provider_binding="primary",
    scopes="openid",
    discovery_url="https://idp.example.net/.well-known/openid-configuration",
    http_timeout_seconds=10.0,
    metadata_ttl_seconds=900,
    ceremony_ttl_seconds=600,
    clock_skew_seconds=60,
)

METADATA = oidc.ProviderMetadata(
    issuer=CONFIG.issuer,
    authorization_endpoint="https://idp.example.net/authorize",
    token_endpoint="https://idp.example.net/token",
    jwks_uri="https://idp.example.net/jwks",
)


def _tenant() -> Any:
    return SimpleNamespace(id=uuid4())


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Discovery and the token exchange are network calls.

    The exchange is stubbed to SUCCEED — deliberately. A stub that failed would
    let a refusal mean "the provider said no", and the tests below would pass
    against a Workspace that had no cookie check at all.
    """
    monkeypatch.setattr(oidc, "metadata", lambda config: METADATA)
    monkeypatch.setattr(
        oidc,
        "complete_ceremony",
        lambda *a, **k: oidc.VerifiedSubject(issuer=CONFIG.issuer, subject="sub-1"),
    )


def test_a_callback_whose_state_does_not_match_the_cookie_is_refused(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The attack, driven end to end at the service seam.

    The attacker's ceremony is real and their query state is valid — that is
    what makes this dangerous. The only thing that differs is the cookie, which
    the attacker cannot write onto the victim's browser.

    `finalize_external_login` is made to SUCCEED, so that if the pair were not
    checked this test would observe a session being minted rather than an
    incidental failure further down.
    """
    tenant = _tenant()
    monkeypatch.setattr(
        service,
        "finalize_external_login",
        lambda *a, **k: pytest.fail(
            "the kernel was asked to finalize a login whose callback state did "
            "not match the browser's cookie — this is the CSRF hole"
        ),
    )

    attacker = service.begin_login(
        object(), tenant=tenant, return_path="/applications", store=store, config=CONFIG
    )
    victim = service.begin_login(
        object(), tenant=tenant, return_path="/applications", store=store, config=CONFIG
    )
    assert attacker.state != victim.state

    with pytest.raises(service.LoginRefused):
        service.complete_login(
            object(),
            tenant=tenant,
            state=attacker.state,
            stored_state=victim.state,
            code="an-authorization-code",
            store=store,
            config=CONFIG,
        )


def test_a_callback_with_no_cookie_state_is_refused(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The victim who never started a login has no cookie at all.

    That is the ORDINARY shape of the attack — the forged URL arrives cold, and
    an absent cookie must be a refusal rather than a comparison that is skipped
    because there is nothing to compare against.
    """
    tenant = _tenant()
    monkeypatch.setattr(
        service, "finalize_external_login", lambda *a, **k: pytest.fail("finalized")
    )
    started = service.begin_login(
        object(), tenant=tenant, return_path="/applications", store=store, config=CONFIG
    )

    for absent in (None, ""):
        with pytest.raises(service.LoginRefused):
            service.complete_login(
                object(),
                tenant=tenant,
                state=started.state,
                stored_state=absent,
                code="an-authorization-code",
                store=store,
                config=CONFIG,
            )


def test_a_mismatched_callback_does_not_burn_the_ceremony(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ordering, asserted rather than left to reading order.

    The pair is compared BEFORE the state is consumed. If it were the other way
    round, anyone holding a member's state — or simply spraying the callback —
    could destroy that member's ceremony and make their sign-in fail. Refusing
    an attacker must not cost the legitimate member their login.

    The ceremony belongs to whoever STARTED it; a third party may not end it.
    It expires on its own schedule, which `test_login_flow.py` covers.
    """
    tenant = _tenant()
    monkeypatch.setattr(
        service, "finalize_external_login", lambda *a, **k: pytest.fail("finalized")
    )
    victim = service.begin_login(
        object(), tenant=tenant, return_path="/applications", store=store, config=CONFIG
    )
    before = len(store)

    with pytest.raises(service.LoginRefused):
        service.complete_login(
            object(),
            tenant=tenant,
            state=victim.state,
            stored_state="a-cookie-from-somewhere-else",
            code="an-authorization-code",
            store=store,
            config=CONFIG,
        )

    assert len(store) == before, (
        "the mismatched callback consumed the ceremony — a stranger can now "
        "deny a member their login by replaying the state with a wrong cookie"
    )
    assert (
        store.take(victim.state) is not None
    ), "the victim's own ceremony must still be there to complete"


def test_the_matching_pair_still_completes(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The negative control.

    Without it, a `complete_login` that refused EVERYTHING would satisfy every
    test above for entirely the wrong reason.
    """
    tenant = _tenant()
    party = SimpleNamespace(id=uuid4())
    monkeypatch.setattr(
        service,
        "finalize_external_login",
        lambda *a, **k: SimpleNamespace(party=party, binding_id=uuid4()),
    )
    monkeypatch.setattr(
        service.session,
        "issue",
        lambda *a, **k: (
            SimpleNamespace(id=uuid4(), expires_at=datetime.now(UTC)),
            "a-session-token",
        ),
    )
    # There is no database here, and minting is not what this test is about.
    monkeypatch.setattr(service, "write_audit_event", lambda *a, **k: None)

    started = service.begin_login(
        object(), tenant=tenant, return_path="/applications", store=store, config=CONFIG
    )
    completed = service.complete_login(
        object(),
        tenant=tenant,
        state=started.state,
        stored_state=started.state,
        code="an-authorization-code",
        store=store,
        config=CONFIG,
    )

    assert completed.token == "a-session-token"
    assert completed.return_path == "/applications"


def test_the_comparison_is_constant_time() -> None:
    """`==` on a secret leaks its prefix through timing.

    The state is a 256-bit random and the attacker cannot observe the
    comparison remotely with any precision, so this is defence in depth rather
    than a live hole. It is asserted because the correct call is one word and
    the incorrect one is invisible in review.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(service.complete_login))
    calls = [
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    assert "compare_digest" in calls, (
        "complete_login no longer compares the state pair with "
        "secrets.compare_digest"
    )
