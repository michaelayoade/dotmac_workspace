"""Make the kernel importable without a database, and hold the test doubles.

## Why `DATABASE_URL` is set here

`dotmac_kernel.db` builds its SQLAlchemy engines at IMPORT time, from
`settings.database_url` — and `create_engine("")` raises rather than deferring,
so `import dotmac_kernel.deps` fails outright when `DATABASE_URL` is unset. Every
test in this repository imports the launcher, which imports `deps`, so without
this the suite could not even collect.

The URL below is deliberately unreachable and deliberately syntactically valid.
An engine is lazy about CONNECTING, so a parseable URL is all an import needs,
and a parseable-but-dead one means a test that accidentally opens a connection
fails loudly instead of finding something real. `setdefault`, so a run that
supplies a genuine URL (the `tests/db` canaries) keeps it.

This is the whole reason nothing outside `tests/db` may touch a database: the
static suite is about structure and refusals, and the tenancy properties are
only true against a real, migrated PostgreSQL with RLS.

## Why the in-memory state store lives HERE and not in the package

A per-process ceremony store is wrong in production for a reason that does not
announce itself: a login starts on one worker and finishes on another, so a
Workspace behind more than one process would complete a login only when the
load balancer happened to pick the same worker twice. The failure is
intermittent, unreproducible, and looks like flakiness rather than like a
design defect.

Shipping such a class and then guarding against SELECTING it would put the
wrong answer one configuration value away from a production deployment. Keeping
it in `conftest.py` puts it outside the wheel entirely: there is nothing to
select, nothing to import by accident, and no environment variable that could
reach it. `tests/test_state_store_is_shared.py` enforces the "not in `src/`"
half by AST, and it is delivered as a FIXTURE rather than an importable module
so that no test needs a `sys.path` assumption to reach it.

It is also not a lesser implementation of the same contract, and cannot be: the
single-use guarantee in `PostgresStateStore` is a property of one SQL statement
under READ COMMITTED, and the nearest single-threaded analogue is the
dictionary `pop` below. That is enough for the flow tests that need somewhere
to put a ceremony; it is not evidence of the property, which is proven against
a real PostgreSQL in `tests/db/test_state_store_atomicity.py`.

## What this double deliberately no longer models

Tenant scoping. `PostgresStateStore` is constructed per request and holds the
tenant, so scoping lives in a SQL predicate and an RLS policy — neither of
which a dictionary can stand in for. A double that keyed its rows by tenant
would look like it proved isolation while proving only its own bookkeeping;
`tests/db/test_login_state_isolation.py` proves the real thing against a
migrated database with RLS FORCEd.

Provider-binding pinning is likewise the real store's, and for the same
reason — it is a column it writes and a check it makes on the way out.
"""

from __future__ import annotations

import base64
import os
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

os.environ.setdefault(
    "DATABASE_URL", "postgresql+psycopg://unused:unused@127.0.0.1:1/unused"
)

# Imported AFTER the URL above is set — see the first section of this docstring.
from dotmac_auth_oidc import (
    PER_REQUEST_STATE_STORE,
    LoginState,
    OIDCClient,
    RelyingPartyConfig,
)

from dotmac_workspace.identity.config import ProviderConfig
from dotmac_workspace.identity.state_store import state_hash

#: The identity this test suite's provider double asserts. Shared so a test
#: cannot accidentally build a client for one issuer and a token for another.
ISSUER = "https://idp.example.net"
CLIENT_ID = "dotmac-workspace"
REDIRECT_URL = "https://ws.example.net/login/callback"
PROVIDER_BINDING = "primary"
KID = "test-key-1"

#: The assembly-side view of the same registration. Passed to the service as
#: `config=` so no test depends on environment variables, and kept beside the
#: provider double so the two cannot describe different providers.
CONFIG = ProviderConfig(
    issuer=ISSUER,
    client_id=CLIENT_ID,
    redirect_url=REDIRECT_URL,
    provider_binding=PROVIDER_BINDING,
    scopes="openid",
    discovery_url=f"{ISSUER}/.well-known/openid-configuration",
    http_timeout_seconds=10.0,
    metadata_ttl_seconds=900,
    ceremony_ttl_seconds=600,
    clock_skew_seconds=60,
)


class InMemoryStateStore:
    """Satisfies `StateStore` — `put`/`take`. Never reachable from `src/`.

    The same two methods `dotmac_auth_oidc.state.StateStore` declares, so a
    test written against this double keeps meaning the same thing after the
    published package replaces the local client.
    """

    def __init__(self) -> None:
        self._rows: dict[str, tuple[LoginState, datetime]] = {}

    def put(self, state: LoginState, *, ttl_seconds: int) -> None:
        self._rows[state_hash(state.state_id)] = (
            state,
            datetime.now(UTC) + timedelta(seconds=ttl_seconds),
        )

    def take(self, state_id: str) -> LoginState | None:
        """`pop` — the nearest single-threaded analogue of `DELETE … RETURNING`.

        Expiry is checked here for the same reason the SQL checks it in the
        statement: a ceremony that has run out of time must be refused whether
        or not anything has swept it.
        """
        found = self._rows.pop(state_hash(state_id), None)
        if found is None:
            return None
        state, expires_at = found
        if expires_at <= datetime.now(UTC):
            return None
        return state

    def __len__(self) -> int:
        return len(self._rows)


@pytest.fixture
def store() -> InMemoryStateStore:
    """A fresh ceremony store per test — state must never leak between them."""
    return InMemoryStateStore()


# ── Standing in for an identity provider ────────────────────────────────────
#
# The point of these doubles is what they DO NOT replace. `dotmac-auth-oidc`'s
# discovery, JWKS handling, algorithm allow-list, PKCE check and ID-token
# verification all run for real; only the network underneath them is fake, via
# the package's own injectable `Transport`.
#
# Stubbing the verifier instead would be the defect the package's dossier
# records about ERP's suite, where `_validate_id_token` is monkeypatched out of
# every test and the security core has therefore never been executed. A pilot
# that proved the wheel by not running it would prove nothing.


@pytest.fixture(scope="session")
def signing_key() -> Any:
    """A throwaway RSA key. Generated per session, never written to disk, and
    not a secret in any meaningful sense — it exists for the length of a test
    run and signs tokens for an issuer that does not exist."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeIdentityProvider:
    """A `Transport` that serves discovery and a key set, and mints ID tokens.

    `nonce` is settable because a real provider learns it from the
    authorization request. A test that has started a ceremony reads the nonce
    back out of its store and sets it here, which is exactly the information
    flow the real thing has — and getting it wrong is how the package's nonce
    check fires, which is a property worth being able to exercise.
    """

    def __init__(self, key: Any, *, issuer: str, audience: str) -> None:
        self._key = key
        self._issuer = issuer
        self._audience = audience
        self.nonce = ""
        self.subject = "sub-1"
        self.claim_overrides: dict[str, Any] = {}
        self.discovery_fetches = 0

    @property
    def jwks(self) -> dict[str, Any]:
        numbers = self._key.public_key().public_numbers()

        def b64(value: int) -> str:
            raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

        return {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": KID,
                    "use": "sig",
                    "alg": "RS256",
                    "n": b64(numbers.n),
                    "e": b64(numbers.e),
                }
            ]
        }

    def get_json(self, url: str, *, timeout: float) -> dict[str, object]:
        if url.endswith("/.well-known/openid-configuration"):
            self.discovery_fetches += 1
            return {
                "issuer": self._issuer,
                "authorization_endpoint": f"{self._issuer}/authorize",
                "token_endpoint": f"{self._issuer}/token",
                "jwks_uri": f"{self._issuer}/jwks",
            }
        if url.endswith("/jwks"):
            return self.jwks
        raise AssertionError(f"unexpected GET {url}")

    def post_form(
        self, url: str, *, data: dict[str, str], auth: Any, timeout: float
    ) -> dict[str, object]:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self._issuer,
            "sub": self.subject,
            "aud": self._audience,
            "exp": now + 300,
            "iat": now,
            "nonce": self.nonce,
        }
        claims.update(self.claim_overrides)
        private_pem = self._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        token = jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": KID})
        return {"id_token": token, "token_type": "Bearer"}


@pytest.fixture
def idp(signing_key: Any) -> FakeIdentityProvider:
    return FakeIdentityProvider(signing_key, issuer=ISSUER, audience=CLIENT_ID)


@pytest.fixture
def rp_client(idp: FakeIdentityProvider) -> OIDCClient:
    """A REAL `OIDCClient` from the published wheel, on a fake network.

    Built with `PER_REQUEST_STATE_STORE` exactly as `relying_party` builds the
    production one, so the store-per-call seam is exercised rather than
    bypassed.
    """
    return OIDCClient(
        RelyingPartyConfig(
            issuer=ISSUER,
            client_id=CLIENT_ID,
            client_secret="a-test-client-secret",
            redirect_uri=REDIRECT_URL,
            provider_binding=PROVIDER_BINDING,
            scopes=("openid",),
            discovery_url=f"{ISSUER}/.well-known/openid-configuration",
        ),
        state_store=PER_REQUEST_STATE_STORE,
        transport=idp,
    )
