"""What THIS assembly decides about a login, now that the protocol is a package.

Rewritten when `dotmac-auth-oidc 0.1.0a1` was pinned and `identity/oidc.py` was
deleted. The deletions are the interesting part.

## What left this file, and why keeping it would have been worse

The old version asserted that the S256 challenge was the SHA-256 of the stored
verifier, that the algorithm allow-list held no symmetric entry, and that the
required-claim set covered issuer, audience and lifetime. Those are all true and
all still tested — in `dotmac-auth-oidc`'s own suite, against a real key pair,
which is where a protocol property belongs.

Re-asserting them here would be a second opinion about someone else's contract:
it passes for exactly as long as the two happen to agree, and the day the
package tightens something, the assembly's copy is what has to be edited — by
somebody who did not make the decision. A consumer's tests should say what the
CONSUMER does.

What stays is exactly that: which failures this assembly turns into
`LoginRefused`, what it refuses to provision, and what it never lets a caller
distinguish. Plus a live end-to-end proof in `test_login_csrf.py`, because a
consumer suite that stubbed the package everywhere would prove the pin resolves
and nothing more.

## No database and no live network

The ceremony store is the in-memory double; the provider is
`FakeIdentityProvider`, which serves real discovery and mints real signed
tokens, so the wheel's own verification runs. The kernel's
`finalize_external_login` is substituted, because what is under test is which
answer this assembly turns a `None` into — not the kernel's row lock, which the
kernel tests against a real database where it means something.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import pytest
from dotmac_auth_oidc import IDTokenError, LoginState, StateUnavailableError
from tests.conftest import CONFIG

from dotmac_workspace.identity import relying_party, service
from dotmac_workspace.identity.state_store import state_hash


def _tenant() -> Any:
    return SimpleNamespace(id=uuid4())


@pytest.fixture(autouse=True)
def _real_client(monkeypatch: pytest.MonkeyPatch, rp_client: Any) -> None:
    """A REAL `OIDCClient` from the published wheel, on a fake network.

    Substituted at the module boundary — what the service asks for is "the
    client for this config" — so every protocol decision stays with the code
    under test rather than being patched out of it.
    """
    monkeypatch.setattr(relying_party, "client", lambda config: rp_client)


def _start(store: Any, tenant: Any, *, return_path: str = "/applications") -> Any:
    return service.begin_login(
        object(), tenant=tenant, return_path=return_path, store=store, config=CONFIG
    )


def _ceremony(store: Any, state: str) -> LoginState:
    """The stored ceremony, WITHOUT consuming it — `take` here would make the
    call under test fail for the wrong reason."""
    return store._rows[state_hash(state)][0]


def _finish(store: Any, tenant: Any, *, state: str, code: str = "c") -> Any:
    """A callback whose cookie matches its query parameter. The MISMATCH is
    `test_login_csrf.py`'s subject, not this file's."""
    return service.complete_login(
        object(),
        tenant=tenant,
        state=state,
        stored_state=state,
        code=code,
        store=store,
        config=CONFIG,
    )


# ── What starting a login puts on the wire, and what it does not ────────────
#
# Not a re-test of the package's PKCE: these assert what this assembly hands to
# a browser and what it holds back, which is its own decision to get wrong.


def test_the_verifier_and_the_return_path_never_leave_the_server(
    store: Any,
) -> None:
    """The load-bearing property of an opaque state.

    Everything the callback needs stays in the store; the browser carries a
    lookup key. A return path that travelled would be a value an attacker could
    rewrite into an open redirect, and a verifier that travelled would not be a
    verifier at all.
    """
    started = _start(store, _tenant())
    ceremony = _ceremony(store, started.state)

    assert ceremony.code_verifier not in started.url
    assert ceremony.nonce in started.url, "the nonce is a request parameter by design"
    assert "applications" not in urlparse(started.url).query
    assert ceremony.return_to == "/applications"


def test_the_state_is_stored_hashed_never_in_the_clear(store: Any) -> None:
    """A dump, a replica or a logged query plan must not yield a usable state.

    This is the ASSEMBLY's decision rather than the package's:
    `LoginState.state_id` is the clear value, and hashing it on the way into the
    table is something `PostgresStateStore` chooses. The in-memory double copies
    that choice so the property is visible here too.
    """
    started = _start(store, _tenant())
    assert state_hash(started.state) in store._rows
    assert started.state not in store._rows


def test_two_logins_never_share_a_state(store: Any) -> None:
    states = {_start(store, _tenant()).state for _ in range(50)}
    assert len(states) == 50


def test_the_landing_path_is_carried_through_the_ceremony(store: Any) -> None:
    """`return_to` round-trips through the package and comes back on the
    verified subject, so this assembly never has to trust a query parameter for
    where to send somebody after they sign in."""
    started = _start(store, _tenant(), return_path="/applications/erp")
    assert _ceremony(store, started.state).return_to == "/applications/erp"


# ── What the callback refuses ───────────────────────────────────────────────


def test_an_unknown_state_is_refused_without_contacting_the_provider(
    store: Any, idp: Any
) -> None:
    """Claim first. A replayed or forged callback costs a round trip to the
    identity provider if the ordering is the other way round, which turns the
    login endpoint into a lever on the provider."""
    before = idp.discovery_fetches
    with pytest.raises(service.LoginRefused):
        _finish(store, _tenant(), state="never-issued")
    assert idp.discovery_fetches == before


def test_a_state_works_exactly_once(
    store: Any, monkeypatch: pytest.MonkeyPatch, idp: Any
) -> None:
    """The second presentation is refused, and refused the same way as a forged
    one — a caller must not be able to tell "already used" from "never
    existed"."""
    tenant = _tenant()
    started = _start(store, tenant)
    idp.nonce = _ceremony(store, started.state).nonce
    monkeypatch.setattr(service, "finalize_external_login", lambda *a, **k: None)

    with pytest.raises(service.LoginRefused):
        _finish(store, tenant, state=started.state)
    # The ceremony is gone even though the login FAILED downstream: claiming is
    # what makes a state single-use, and a state returned to the pool on failure
    # would be a state an attacker can retry.
    assert len(store) == 0
    with pytest.raises(service.LoginRefused):
        _finish(store, tenant, state=started.state)


def test_an_expired_ceremony_is_refused(store: Any) -> None:
    """Expired in the STORE, which is where this assembly enforces it. The
    package re-checks its own TTL against `issued_at` as belt and braces, and
    the two are deliberately independent: a store with coarse expiry must not
    be able to extend a login's life."""
    tenant = _tenant()
    started = _start(store, tenant)
    ceremony, _ = store._rows[state_hash(started.state)]
    store._rows[state_hash(started.state)] = (
        ceremony,
        datetime.now(UTC) - timedelta(seconds=1),
    )

    with pytest.raises(service.LoginRefused):
        _finish(store, tenant, state=started.state)


def test_tenant_scoping_is_not_asserted_here() -> None:
    """Deliberately empty, and recorded so the omission is a decision.

    This file used to assert that one tenant could not consume another's
    ceremony, against the in-memory double. That proved only the double's own
    key tuple. The store is constructed per request holding its tenant, so
    scoping is a SQL predicate and an RLS policy — neither of which a dictionary
    can stand in for.

    The real property is proven against a migrated PostgreSQL with RLS FORCEd,
    in `tests/db/test_login_state_isolation.py`. Moving an assertion to where it
    can be true is not losing coverage; keeping it here would have been keeping
    the appearance of it.
    """


def test_an_unbound_subject_is_refused_and_nothing_is_provisioned(
    store: Any, monkeypatch: pytest.MonkeyPatch, idp: Any
) -> None:
    """No JIT provisioning and no email linking.

    `finalize_external_login` returning `None` is the whole answer: this
    assembly turns it into a refusal and never into a party, a credential, or a
    fallback lookup on an email claim.

    The subject is genuinely VERIFIED first — a real signed token from the
    provider double — so this is the "we do not know this person" path rather
    than the "that token was bad" path. The two must stay distinguishable in the
    log even though they are identical to the caller.
    """
    tenant = _tenant()
    idp.subject = "never-bound"
    started = _start(store, tenant)
    idp.nonce = _ceremony(store, started.state).nonce

    asked: list[str] = []

    def _unbound(*args: object, **kwargs: object) -> None:
        asked.append(str(kwargs.get("subject")))
        return None

    monkeypatch.setattr(service, "finalize_external_login", _unbound)
    monkeypatch.setattr(
        service.session,
        "issue",
        lambda *a, **k: pytest.fail("a session was minted for an unbound subject"),
    )

    with pytest.raises(service.LoginRefused):
        _finish(store, tenant, state=started.state)
    assert asked == ["never-bound"], (
        "the kernel was not asked about the subject the provider actually " "verified"
    )


def test_a_provider_failure_is_the_same_refusal_as_an_unbound_subject(
    store: Any, idp: Any
) -> None:
    """One exception type, no reason field.

    A caller able to distinguish "bad nonce" from "no such subject" is an oracle
    for whoever can drive a login. Here the ID token is genuinely invalid — the
    provider mints it against a DIFFERENT ceremony's nonce — so the package
    raises `NonceMismatchError`, and what reaches the caller is the same
    `LoginRefused` an unbound subject gets.
    """
    tenant = _tenant()
    started = _start(store, tenant)
    idp.nonce = "a-nonce-from-some-other-ceremony"

    with pytest.raises(service.LoginRefused):
        _finish(store, tenant, state=started.state)


def test_every_package_refusal_arrives_as_the_same_local_refusal(
    store: Any, idp: Any
) -> None:
    """The mapping is TOTAL, and that is the property worth pinning.

    `OIDCError` has a taxonomy whose subclass names are stable reason codes.
    This assembly catches the BASE class deliberately: a package release adding
    a new subclass must not start leaking through as a 500 whose traceback names
    an HTTP client. Two structurally different failures are driven here so the
    funnel is shown to be a funnel rather than one special case.
    """
    tenant = _tenant()

    # 1. no ceremony at all — the package raises StateUnavailableError.
    with pytest.raises(service.LoginRefused):
        _finish(store, tenant, state="never-issued")

    # 2. a live ceremony whose token carries no usable `sub` — IDTokenError.
    started = _start(store, tenant)
    idp.nonce = _ceremony(store, started.state).nonce
    idp.claim_overrides = {"sub": ""}
    with pytest.raises(service.LoginRefused):
        _finish(store, tenant, state=started.state)

    # Both are `OIDCError`s, which is WHY catching the base class is total
    # rather than lucky. If either stops being one, the funnel above has a hole.
    assert issubclass(StateUnavailableError, service.OIDCError)
    assert issubclass(IDTokenError, service.OIDCError)


def test_the_refusal_type_carries_no_reason_a_caller_could_branch_on() -> None:
    assert not [
        name for name in vars(service.LoginRefused) if not name.startswith("__")
    ], (
        "LoginRefused grew an attribute. Every refusal must be the same "
        "refusal — see the module docstring on subject-enumeration oracles."
    )
