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
`secrets.compare_digest`. As of the 0.1.0a1 pin, that package is what ENFORCES
the property here — this assembly forwards the pair rather than checking it,
because one implementation of a security decision is the entire reason the
package exists.

Which makes this module more valuable after the swap, not less. It was written
against the local implementation and it still passes against the published
wheel, unchanged in what it asserts: that is the evidence the swap PRESERVED
the defence rather than assuming it. A delegation nobody tests end to end is a
delegation to nowhere.

No database and no live network: the ceremony store is the in-memory double and
the provider is `FakeIdentityProvider`, which serves discovery and a key set and
mints REAL signed ID tokens. The package's own verification runs — nothing in
the security path is stubbed.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from dotmac_auth_oidc import OIDCClient

from dotmac_workspace.identity import relying_party, service
from dotmac_workspace.identity.state_store import state_hash


def _tenant() -> Any:
    return SimpleNamespace(id=uuid4())


@pytest.fixture(autouse=True)
def _real_client(monkeypatch: pytest.MonkeyPatch, rp_client: Any) -> None:
    """The service uses a REAL `OIDCClient` from the published wheel.

    Patched at the module boundary rather than inside the package: what the
    service asks for is "the client for this config", and substituting the
    network under a genuine client keeps every protocol decision in the hands
    of the code under test.

    The provider is stubbed to SUCCEED. A provider that failed would let a
    refusal below mean "the exchange went wrong", and every test here would
    pass against a Workspace with no cookie check at all.
    """
    monkeypatch.setattr(relying_party, "client", lambda config: rp_client)


def test_a_callback_whose_state_does_not_match_the_cookie_is_refused(
    store: Any, monkeypatch: pytest.MonkeyPatch, provider_config: Any
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
        object(),
        tenant=tenant,
        return_path="/applications",
        store=store,
        config=provider_config,
    )
    victim = service.begin_login(
        object(),
        tenant=tenant,
        return_path="/applications",
        store=store,
        config=provider_config,
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
            config=provider_config,
        )


def test_a_callback_with_no_cookie_state_is_refused(
    store: Any, monkeypatch: pytest.MonkeyPatch, provider_config: Any
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
        object(),
        tenant=tenant,
        return_path="/applications",
        store=store,
        config=provider_config,
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
                config=provider_config,
            )


def test_a_mismatched_callback_does_not_burn_the_ceremony(
    store: Any, monkeypatch: pytest.MonkeyPatch, provider_config: Any
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
        object(),
        tenant=tenant,
        return_path="/applications",
        store=store,
        config=provider_config,
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
            config=provider_config,
        )

    assert len(store) == before, (
        "the mismatched callback consumed the ceremony — a stranger can now "
        "deny a member their login by replaying the state with a wrong cookie"
    )
    assert (
        store.take(victim.state) is not None
    ), "the victim's own ceremony must still be there to complete"


def test_the_matching_pair_still_completes(
    store: Any, monkeypatch: pytest.MonkeyPatch, idp: Any, provider_config: Any
) -> None:
    """The negative control, and the pilot's end-to-end evidence.

    Without it, a `complete_login` that refused EVERYTHING would satisfy every
    test above for entirely the wrong reason.

    It is also the one test in this repository that runs the whole published
    protocol: a real ceremony, a real PKCE challenge, a real signed ID token,
    the wheel's own signature verification, nonce check and claim validation —
    then this assembly's finalize-and-mint. Only the socket is fake.
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
        object(),
        tenant=tenant,
        return_path="/applications",
        store=store,
        config=provider_config,
    )
    # What a real provider learns from the authorization request. Read back out
    # of the store rather than passed around, so the ceremony the package wrote
    # is the one the token is minted against — a nonce invented here would be
    # rejected, correctly, and the test would be proving the wrong thing.
    idp.nonce = store._rows[state_hash(started.state)][0].nonce

    completed = service.complete_login(
        object(),
        tenant=tenant,
        state=started.state,
        stored_state=started.state,
        code="an-authorization-code",
        store=store,
        config=provider_config,
    )

    assert completed.token == "a-session-token"
    assert completed.return_path == "/applications"


#: A module whose only mention of the call is a docstring. Exactly the shape
#: that broke the substring version of the guard below.
DOCSTRING_MENTIONING_THE_CALL = (
    '"""Compared with secrets.compare_digest by the package."""\n' "x = 1\n"
)


def _calls_named(tree: ast.AST, name: str) -> list[int]:
    """Lines calling `name`, as SYNTAX. Docstrings and comments are invisible to
    an AST, which is the entire reason this is not a substring search."""
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id == name)
            or (isinstance(node.func, ast.Attribute) and node.func.attr == name)
        )
    ]


def _forwards_keyword(tree: ast.AST, name: str) -> bool:
    """True if some call passes `name=<expression mentioning name>`.

    The value need not be the bare parameter: this assembly forwards
    `stored_state=stored_state or ""`, normalising an absent cookie to the empty
    string the package already refuses. Requiring an exact `Name` node rejected
    that and would have pushed the code to be shaped by its guard.

    What it still catches is the failure that matters — a keyword bound to
    something ELSE, which is how the cookie half stops arriving while the call
    still looks right.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg != name:
                continue
            mentioned = {
                sub.id for sub in ast.walk(kw.value) if isinstance(sub, ast.Name)
            }
            if name in mentioned:
                return True
    return False


def test_the_delegation_checks_match_syntax_not_prose() -> None:
    """Sensitivity AND specificity, because this exact mistake has now been made
    three times in this programme.

    A substring search for the name of the function being delegated to fails on
    the DOCSTRING of the very function it is checking — which is what happened
    here, and the only way to satisfy it would have been to delete the
    explanation. The fleet rule is settled: an executable invariant matches call
    sites, never concepts.
    """
    real = ast.parse("import secrets\nsecrets.compare_digest(a, b)\n")
    bare = ast.parse("from secrets import compare_digest\ncompare_digest(a, b)\n")
    prose = ast.parse(DOCSTRING_MENTIONING_THE_CALL)
    assert _calls_named(real, "compare_digest")
    assert _calls_named(bare, "compare_digest")
    assert not _calls_named(prose, "compare_digest"), (
        "the guard fires on prose again — that is the failure mode, not a "
        "stricter check"
    )

    forwards = ast.parse("f(stored_state=stored_state)\n")
    normalised = ast.parse('f(stored_state=stored_state or "")\n')
    renamed = ast.parse("f(stored_state=something_else)\n")
    assert _forwards_keyword(forwards, "stored_state")
    assert _forwards_keyword(normalised, "stored_state"), (
        "the real call normalises an absent cookie to the empty string the "
        "package refuses; a guard that rejected that would shape the code"
    )
    assert not _forwards_keyword(renamed, "stored_state"), (
        "a keyword bound to a DIFFERENT value must not count as forwarding — "
        "that is how the cookie half would silently stop arriving"
    )


def test_this_assembly_does_not_check_the_pair_itself() -> None:
    """The delegation, asserted — because a SECOND check would be the defect.

    This test used to require `compare_digest` in `service.complete_login`. It
    now requires its ABSENCE, and the inversion is the point of the swap: two
    implementations of one security decision is how they drift, and the one
    that drifts is the one nobody is reading.

    What replaces it is not trust. The behavioural tests above run the real
    package and observe the refusal, and the signature check below fails the
    build if the pair ever stops being forwarded — a service that quietly
    dropped `stored_state` would otherwise still type-check.
    """
    tree = ast.parse(textwrap.dedent(inspect.getsource(service.complete_login)))
    assert not _calls_named(tree, "compare_digest"), (
        "the assembly compares the state pair itself. That decision belongs to "
        "dotmac_auth_oidc; a local copy is a second implementation to keep in "
        "step, and security decisions do not survive being kept in step."
    )
    assert _forwards_keyword(tree, "stored_state"), (
        "the cookie half is no longer forwarded to the package — the pair "
        "check cannot fire on a value it never receives"
    )

    required = inspect.signature(OIDCClient.complete_login).parameters
    assert "stored_state" in required, (
        "the pinned dotmac-auth-oidc no longer takes stored_state; the pair "
        "check this assembly depends on has moved or gone"
    )
    assert required["stored_state"].default is inspect.Parameter.empty, (
        "stored_state gained a default in the pinned package — an omitted "
        "cookie would stop being a refusal and start being a skipped check"
    )
