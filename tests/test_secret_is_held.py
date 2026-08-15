"""The OIDC client secret is loaded ONCE, at startup, and held (ADR-0009).

Three properties, each proven a different way because each fails differently:

1. **It is installed from a startup hook**, not at import and not on demand.
   Asserted against the composed `ProductAssemblySpec`, so a hook that stopped
   being registered fails here rather than at the first login.
2. **The source is read exactly once**, however many times the secret is read
   afterwards. Proven behaviourally with a counting `SecretSource` — a real
   load count, not an inspection of the code that does the loading.
3. **Nothing on the request path reads the environment or refreshes.** An AST
   sweep over the modules a request actually reaches, with its sensitivity
   proof beside it.

Property 2 is the one worth having: an implementation could satisfy 1 and 3 and
still fetch per call if `client_secret()` went back to the source. It does not,
and this is how that is known rather than believed.
"""

from __future__ import annotations

import ast
import inspect
from collections.abc import Mapping
from pathlib import Path

import pytest
from dotmac_kernel import secret_sources

from dotmac_workspace.assembly import build_spec
from dotmac_workspace.identity import (
    config,
    oidc,
    secret_bootstrap,
    service,
    session,
    state_store,
)
from dotmac_workspace.identity import web as identity_web

#: The modules an HTTP request actually reaches. `config` and
#: `secret_bootstrap` are absent on purpose: reading the environment is exactly
#: their job, and it happens inside the lifespan.
REQUEST_PATH_MODULES = (identity_web, service, oidc, session, state_store)

#: Reading the environment on a request path is the defect ADR-0011 removed
#: from settings resolution; `refresh_secrets` and `install_secret_source` are
#: rotation and startup, and neither belongs to a request.
FORBIDDEN_ON_REQUEST_PATH = frozenset(
    {"getenv", "environ", "refresh_secrets", "install_secret_source"}
)


class _CountingSource:
    """A `SecretSource` that records how often it was actually read."""

    def __init__(self) -> None:
        self.loads = 0

    def load(self) -> Mapping[str, str]:
        self.loads += 1
        return {secret_bootstrap.CLIENT_SECRET_NAME: "not-a-real-secret"}


@pytest.fixture(autouse=True)
def _clean_secret_state():
    """Leave the process as it was found.

    Both holders are process-global by design — that is what "held" means — so
    a test that installs one and walks away has changed the next test's world.
    """
    yield
    secret_sources.clear_secret_source()
    config.install(None)


def _code_identifiers(source: str) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.alias):
            names.add(node.name.rsplit(".", 1)[-1])
            if node.asname:
                names.add(node.asname)
    return names


# ── 1. installed from the startup seam ──────────────────────────────────────


def test_the_secret_is_installed_by_a_startup_hook() -> None:
    """Inside the lifespan, before the first request — not at import.

    Reading it at import would run during `alembic`, during every CLI
    invocation and during test collection, none of which needs it.
    """
    spec = build_spec()
    assert secret_bootstrap.install_workspace_secrets in tuple(spec.startup_hooks)


def test_a_misconfigured_provider_fails_the_startup_CHECK() -> None:
    """Fatal in production, a warning in development — the kernel's policy.

    A Workspace whose members cannot log in should not start and look healthy;
    a developer running the launcher without an identity provider should get a
    warning and a working process.
    """
    spec = build_spec()
    assert config.configuration_errors in tuple(spec.startup_checks)


# ── 2. read once, however often it is used ──────────────────────────────────


def test_the_source_is_read_once_no_matter_how_often_the_secret_is_read() -> None:
    source = _CountingSource()
    secret_sources.install_secret_source(source)
    assert source.loads == 1, "install must load eagerly, not lazily"

    for _ in range(25):
        assert secret_bootstrap.client_secret() == "not-a-real-secret"

    assert source.loads == 1, (
        "the client secret was re-read from its source while serving. It must "
        "be HELD: a store outage an hour after boot cannot be allowed to take "
        "the login path down, and a store that is merely slow must not put its "
        "latency on every callback (ADR-0009)."
    )


def test_a_missing_secret_is_a_loud_refusal_and_never_an_empty_default() -> None:
    """`require_secret` raises rather than returning "" — a blank client secret
    would be sent to the provider and fail as an authentication error nobody
    traces back to configuration."""
    secret_sources.clear_secret_source()
    with pytest.raises(secret_sources.MissingSecretError):
        secret_bootstrap.client_secret()


def test_the_environment_source_raises_rather_than_returning_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty mapping is indistinguishable from "nothing is configured", and
    would turn a missing secret into a silent misconfiguration."""
    monkeypatch.delenv(secret_bootstrap.CLIENT_SECRET_ENV, raising=False)
    monkeypatch.delenv(secret_bootstrap.CLIENT_SECRET_FILE_ENV, raising=False)
    with pytest.raises(secret_sources.SecretSourceError):
        secret_bootstrap.EnvironmentSecretSource().load()


def test_no_accessor_ever_returns_the_value_in_a_log_or_a_name_list() -> None:
    """Names are safe to print; values are not. The kernel's contract, relied
    on here: `secret_names()` is the only enumeration and it lists names."""
    secret_sources.install_secret_source(_CountingSource())
    assert secret_sources.secret_names() == (secret_bootstrap.CLIENT_SECRET_NAME,)
    assert "not-a-real-secret" not in " ".join(secret_sources.secret_names())


# ── 3. nothing on the request path reads the environment ────────────────────


def test_the_request_path_never_reads_the_environment_or_refreshes() -> None:
    offenders: dict[str, set[str]] = {}
    for module in REQUEST_PATH_MODULES:
        path = Path(inspect.getfile(module))
        found = FORBIDDEN_ON_REQUEST_PATH & _code_identifiers(
            path.read_text(encoding="utf-8")
        )
        if found:
            offenders[path.name] = found
    assert not offenders, (
        f"a request-path module reads configuration at request time: "
        f"{offenders}. Configuration and secret material are read once, in the "
        "startup hook, and held — see `config.py` and `secret_bootstrap.py`, "
        "which are the two modules deliberately excluded from this sweep."
    )


def test_the_environment_guard_does_not_fire_on_prose() -> None:
    """`oidc.py` and `service.py` discuss `WORKSPACE_OIDC_*` variables and the
    held-not-fetched rule at length. A guard that flagged that discussion would
    be satisfied most cheaply by deleting it."""
    prose = (
        '"""This module never calls os.getenv; the environ is read at\n'
        'startup by config.load()."""\n'
        "# refresh_secrets is a rotation operation and belongs to an operator.\n"
        'NOTE = "os.environ, getenv, refresh_secrets"\n'
    )
    assert not (FORBIDDEN_ON_REQUEST_PATH & _code_identifiers(prose))


def test_the_environment_guard_does_fire_on_a_real_read() -> None:
    """Sensitivity. A sweep that can never fail is not evidence."""
    for source in (
        "import os\nx = os.getenv('WORKSPACE_OIDC_ISSUER')\n",
        "import os\nx = os.environ['WORKSPACE_OIDC_ISSUER']\n",
        "from dotmac_kernel.secret_sources import refresh_secrets\nrefresh_secrets()\n",
    ):
        assert FORBIDDEN_ON_REQUEST_PATH & _code_identifiers(source), source


def test_config_is_read_from_a_held_value_not_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Whatever startup installed is what every request sees.

    Changing the environment afterwards must not change the answer — that is
    what "held" means, and it is also what makes the settings screen (and the
    logs) able to state what is actually in effect.
    """
    monkeypatch.setenv(config.ISSUER_ENV, "https://idp.example.net")
    monkeypatch.setenv(config.CLIENT_ID_ENV, "workspace")
    monkeypatch.setenv(config.REDIRECT_URL_ENV, "https://ws.example.net/login/callback")
    held = config.install(config.load())
    assert held is not None
    assert held.issuer == "https://idp.example.net"

    monkeypatch.setenv(config.ISSUER_ENV, "https://attacker.example")
    assert config.provider().issuer == "https://idp.example.net"

    config.install(None)
