"""Federated login for the Tenant Workspace — its own front door.

The Workspace authenticates its own members against ONE deployment-configured
external OIDC provider, mints its OWN `dmws_session`, and shares nothing with
any application it lists (ADR-0021 §1). This package is that front door and
nothing else: it is not an identity provider, it holds no passwords, and it
never mints a credential for a target application.

Read `web.py` for the surface, `service.py` for the flow, `oidc.py` for the
protocol, `state_store.py` for the ceremony state, and `session.py` for what a
`dmws_session` actually is.
"""
