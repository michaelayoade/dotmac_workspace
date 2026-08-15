"""The ceremony: opaque, single-use, PKCE-bound, and refusing an unbound subject.

No database and no network. What is under test is the FLOW this assembly owns —
what it stores, what it sends, what it refuses — not PostgreSQL's `DELETE …
RETURNING` (proven in `tests/db/test_state_store_atomicity.py`) and not PyJWT's
signature verification (proven by PyJWT).

The kernel's `finalize_external_login` is substituted, because what is under
test is which answer this assembly turns a `None` into, not the kernel's row
lock — which the kernel tests, against a real database, where it means
something.
"""

from __future__ import annotations

import base64
import hashlib
import time
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import pytest

from dotmac_workspace.identity import oidc, service
from dotmac_workspace.identity.config import ProviderConfig
from dotmac_workspace.identity.state_store import LoginState, state_hash

# The `store` parameter throughout is the `store` FIXTURE from
# `tests/conftest.py` — an in-memory `StateStore` that is deliberately not an
# importable module anywhere, so the wrong store is not one import away from
# production code. It is annotated `Any` because naming its type would mean
# importing it, which is the thing being avoided.

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
def _no_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Discovery is a network call; it is not what these tests are about."""
    monkeypatch.setattr(oidc, "metadata", lambda config: METADATA)


# ── What starting a login puts on the wire, and what it does not ────────────


def test_the_authorization_request_carries_state_nonce_and_an_s256_challenge(
    store: Any,
) -> None:
    tenant = _tenant()
    url = service.begin_login(
        object(), tenant=tenant, return_path="/applications", store=store, config=CONFIG
    ).url
    query = parse_qs(urlparse(url).query)

    assert query["response_type"] == ["code"]
    assert query["client_id"] == [CONFIG.client_id]
    assert query["redirect_uri"] == [CONFIG.redirect_url]
    assert query["code_challenge_method"] == ["S256"], (
        "`plain` makes the challenge equal to the verifier, so anyone who can "
        "read the authorization request can complete the exchange — the entire "
        "attack PKCE exists to stop"
    )
    assert query["state"] and query["nonce"] and query["code_challenge"]


def test_the_verifier_and_the_return_path_never_leave_the_server(
    store: Any,
) -> None:
    """The load-bearing property of an opaque state.

    Everything the callback needs stays in the store; the browser carries a
    lookup key. A return path that travelled would be a value an attacker could
    rewrite into an open redirect, and a verifier that travelled would not be a
    verifier at all.
    """
    tenant = _tenant()
    url = service.begin_login(
        object(),
        tenant=tenant,
        return_path="/applications",
        store=store,
        config=CONFIG,
    ).url
    state = parse_qs(urlparse(url).query)["state"][0]
    ceremony = store.take(state)
    assert ceremony is not None

    assert ceremony.code_verifier not in url
    assert ceremony.nonce in url, "the nonce is a request parameter by design"
    assert "applications" not in urlparse(url).query
    assert ceremony.return_to == "/applications"


def test_the_challenge_is_the_sha256_of_the_stored_verifier(
    store: Any,
) -> None:
    tenant = _tenant()
    url = service.begin_login(
        object(), tenant=tenant, return_path="/applications", store=store, config=CONFIG
    ).url
    query = parse_qs(urlparse(url).query)
    ceremony = store.take(query["state"][0])
    assert ceremony is not None

    expected = (
        base64.urlsafe_b64encode(
            hashlib.sha256(ceremony.code_verifier.encode("ascii")).digest()
        )
        .rstrip(b"=")
        .decode()
    )
    assert query["code_challenge"] == [expected]


def test_the_state_is_stored_hashed_never_in_the_clear(
    store: Any,
) -> None:
    """A dump, a replica or a logged query plan must not yield a usable state."""
    tenant = _tenant()
    url = service.begin_login(
        object(), tenant=tenant, return_path="/applications", store=store, config=CONFIG
    ).url
    state = parse_qs(urlparse(url).query)["state"][0]
    assert state_hash(state) in store._rows
    assert state not in store._rows


def test_two_logins_never_share_a_state(store: Any) -> None:
    tenant = _tenant()
    states = {
        parse_qs(
            urlparse(
                service.begin_login(
                    object(),
                    tenant=tenant,
                    return_path="/applications",
                    store=store,
                    config=CONFIG,
                ).url
            ).query
        )["state"][0]
        for _ in range(50)
    }
    assert len(states) == 50


# ── What the callback refuses ───────────────────────────────────────────────


def _seed(store: Any, tenant: Any, *, state: str) -> None:
    """`tenant` is unused now and kept for the call sites' readability: the
    store is constructed per request with the tenant it belongs to, so a double
    that keyed rows by tenant would be modelling its own bookkeeping rather
    than the RLS policy that actually isolates them (see `conftest.py`)."""
    store.put(
        LoginState(
            state_id=state,
            nonce="n" * 22,
            code_verifier="v" * 43,
            redirect_uri=CONFIG.redirect_url,
            issued_at=int(time.time()),
            return_to="/applications",
        ),
        ttl_seconds=600,
    )


def test_an_unknown_state_is_refused_without_contacting_the_provider(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Consume first. A replayed or forged callback costs a round trip to the
    identity provider if the ordering is the other way round, which turns the
    login endpoint into a lever on the provider."""
    contacted: list[str] = []
    monkeypatch.setattr(
        oidc,
        "complete_ceremony",
        lambda *a, **k: contacted.append("yes"),  # type: ignore[return-value]
    )
    with pytest.raises(service.LoginRefused):
        service.complete_login(
            object(),
            tenant=_tenant(),
            state="never-issued",
            stored_state="never-issued",
            code="anything",
            store=store,
            config=CONFIG,
        )
    assert not contacted


def test_a_state_works_exactly_once(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second presentation is refused, and refused the same way as a forged
    one — a caller must not be able to tell "already used" from "never
    existed"."""
    tenant = _tenant()
    _seed(store, tenant, state="s")
    monkeypatch.setattr(
        oidc,
        "complete_ceremony",
        lambda *a, **k: oidc.VerifiedSubject(issuer=CONFIG.issuer, subject="sub-1"),
    )
    monkeypatch.setattr(service, "finalize_external_login", lambda *a, **k: None)

    with pytest.raises(service.LoginRefused):
        service.complete_login(
            object(),
            tenant=tenant,
            state="s",
            stored_state="s",
            code="c",
            store=store,
            config=CONFIG,
        )
    # The ceremony is gone even though the login FAILED downstream: consuming
    # is what makes a state single-use, and a state returned to the pool on
    # failure would be a state an attacker can retry.
    assert len(store) == 0
    with pytest.raises(service.LoginRefused):
        service.complete_login(
            object(),
            tenant=tenant,
            state="s",
            stored_state="s",
            code="c",
            store=store,
            config=CONFIG,
        )


def test_an_expired_ceremony_is_refused(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = _tenant()
    store.put(
        LoginState(
            state_id="s",
            nonce="n" * 22,
            code_verifier="v" * 43,
            redirect_uri=CONFIG.redirect_url,
            issued_at=int(time.time()),
            return_to="/applications",
        ),
        ttl_seconds=-1,
    )
    with pytest.raises(service.LoginRefused):
        service.complete_login(
            object(),
            tenant=tenant,
            state="s",
            stored_state="s",
            code="c",
            store=store,
            config=CONFIG,
        )


def test_tenant_scoping_is_not_asserted_here() -> None:
    """Deliberately empty, and recorded so the gap is a decision.

    This file used to assert that one tenant could not consume another's
    ceremony, against the in-memory double. That proved only the double's own
    key tuple. The store is now constructed per request holding its tenant, so
    scoping is a SQL predicate and an RLS policy — neither of which a
    dictionary can stand in for.

    The real property is proven against a migrated PostgreSQL with RLS FORCEd,
    in `tests/db/test_login_state_isolation.py`. Moving an assertion to where
    it can be true is not losing coverage; keeping it here would have been
    keeping the appearance of it.
    """


def test_an_unbound_subject_is_refused_and_nothing_is_provisioned(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No JIT provisioning and no email linking.

    `finalize_external_login` returning `None` is the whole answer: this
    assembly turns it into a refusal and never into a party, a credential, or a
    fallback lookup on an email claim.
    """
    tenant = _tenant()
    _seed(store, tenant, state="s")
    monkeypatch.setattr(
        oidc,
        "complete_ceremony",
        lambda *a, **k: oidc.VerifiedSubject(
            issuer=CONFIG.issuer, subject="never-bound"
        ),
    )
    monkeypatch.setattr(service, "finalize_external_login", lambda *a, **k: None)

    with pytest.raises(service.LoginRefused):
        service.complete_login(
            object(),
            tenant=tenant,
            state="s",
            stored_state="s",
            code="c",
            store=store,
            config=CONFIG,
        )


def test_a_provider_failure_is_the_same_refusal_as_an_unbound_subject(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One exception type, no reason field.

    A caller able to distinguish "bad nonce" from "no such subject" is an
    oracle for whoever can drive a login.
    """
    tenant = _tenant()
    _seed(store, tenant, state="s")

    def _boom(*args: object, **kwargs: object) -> object:
        raise oidc.OidcError("the ID token's nonce does not match this ceremony")

    monkeypatch.setattr(oidc, "complete_ceremony", _boom)
    with pytest.raises(service.LoginRefused):
        service.complete_login(
            object(),
            tenant=tenant,
            state="s",
            stored_state="s",
            code="c",
            store=store,
            config=CONFIG,
        )


def test_the_refusal_type_carries_no_reason_a_caller_could_branch_on() -> None:
    assert not [
        name for name in vars(service.LoginRefused) if not name.startswith("__")
    ], (
        "LoginRefused grew an attribute. Every refusal must be the same "
        "refusal — see the module docstring on subject-enumeration oracles."
    )


# ── The algorithm allow-list ────────────────────────────────────────────────


def test_no_symmetric_algorithm_is_accepted() -> None:
    """`HS*` would let a verifier check a token against a value the attacker
    may already hold — in a confidential client, potentially the client secret
    itself. `none` needs no explanation."""
    assert all(alg[0] in {"R", "E", "P"} for alg in oidc.ALLOWED_ALGORITHMS)
    for rejected in ("none", "HS256", "HS384", "HS512"):
        assert rejected not in oidc.ALLOWED_ALGORITHMS


def test_the_required_claim_set_covers_issuer_audience_and_lifetime() -> None:
    assert {"iss", "sub", "aud", "exp", "iat"} <= set(oidc.REQUIRED_CLAIMS)
