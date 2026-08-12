# dotmac_workspace — hard rules

This assembly is a **security boundary between three planes**. Most of the rules
below exist because breaking one of them does not fail loudly; it quietly moves
an authority.

Decision of record: **ADR-0021** in `dotmac_starter_mt/docs/adr/`. If this file
and that ADR ever disagree, the ADR wins — fix the drift here.

## 1. Directory visibility is not authorization

A binding says the tenant HAS an application. It never says who may enter one.

- The launcher renders a plain link. It **never mints, signs, appends or
  exchanges a token** for a target application.
- It **never reads or writes a grant** — there is none to read; the directory
  has no authorization column, by construction in the module.
- It **never filters tiles by what the viewer may do in the target.** Filtering
  is by binding state alone. Hiding a tile looks like a courtesy and is in fact
  this Workspace pre-empting a decision that belongs to the target, using a
  cached role catalogue whose staleness state exists precisely because it must
  not gate anything.

Enforced by `tests/test_launcher_is_not_authorization.py`.

## 2. No shared database, session, cookie or guard

- The session cookie is `dmws_session`. Never `access_token` — that is what
  every product portal reads, and a shared name under one parent domain would
  make the isolation a deployment coincidence rather than a property.
- The Workspace database is its own. No product DSN appears in this repository
  and nothing here connects to one.
- Cross-application integration is **API or webhook only**. Importing a product
  data plane (`app`, `vendor_cp`, `dotmac_sub`, `dotmac_erp`) is forbidden and
  tested.

## 3. Compose `create_app`; never hand-build the application

ADR-0015, fleet-wide. An assembly that builds its own FastAPI app silently
declines every control the kernel performs inside `create_app` — academy shipped
a tenant lockdown that was configured, asserted in config validation, and never
armed. Reading a kernel setting is not adopting the behaviour behind it.

## 4. Never re-implement token validation

`dotmac_kernel.deps.authenticate_request` is the one seam. The Workspace guard
calls it. An auth-tightening fix (expiry, tenant claims, revocation) must land
there once and reach here for free.

## 5. Adapters are thin

`web.py` validates, authorizes the viewer, and delegates. No `db.query`, no
`select(`, no business logic. Domain logic belongs to the module's service.

## 6. Pinned dependencies, never paths

`dotmac-kernel` and `dotmac-application-directory` are pinned exactly, from the
Forgejo index (ADR-0005). **Never commit a path or editable dependency** — this
repository does not live beside the packages it consumes. To test unreleased
versions, build wheels and `pip install` them into the venv without touching
`pyproject.toml`; see the README.

## 7. Everything by config

Every environment-specific value is an overridable knob with a documented
default (`Makefile` `?=`, env vars with defaults). Never hardcode a port, host,
image name or path.

## 8. What must not be built here

- No proprietary identity provider — federated login is external OIDC.
- No global party/person database.
- No shared session or cookie service.
- No generic data-federation module.
- No second audit, messaging, inbox, idempotency, permissions or entitlement
  mechanism — the kernel owns all six.
- No connector registry — Sub's integration platform is the product-first source
  when API/event transport is needed.
- **No access-allocation domain module here.** `dotmac-application-access` is a
  released module when it exists, not assembly code. It is deferred (ADR-0021
  §5) until the kernel has a generic signed-document mechanism; do not work
  around that by writing grant handling into this assembly.

## Validation before any commit

```sh
make check   # ruff lint + format check + mypy
make test    # pytest
```

Tests run on Git-hosted CI. Static checks may run locally; local runs are not
test evidence.
