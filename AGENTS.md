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

## 4. Never re-implement token validation, and never re-implement authorization

`dotmac_kernel.deps.authenticate_request` is the one seam for *who are you?*.
The Workspace guard calls it. An auth-tightening fix (expiry, tenant claims,
revocation) must land there once and reach here for free.

`dotmac_kernel.deps.permission_guard`, over `deps.authorize_party`, is the one
seam for *may you?*. The launcher declares `workspace.applications.read` on its
manifest and guards `GET /applications` with it. Do **not** query
`PartyRoleGrant`/`Role` here to reach the same answer — enforced by
`tests/test_adoption_blockers.py::test_the_guard_does_not_hand_roll_a_role_check`.

The two refusals are deliberately different and must stay different:
unauthenticated is a **302 to `/login`**; authenticated-but-unauthorized is a
**403**. A redirect on an authorization failure tells a signed-in user to sign
in and loops against a login that finds a valid session.

## 4a. A module declares database effects; this assembly binds the revision

A composed module lineage names the EFFECTS it needs
(`ModuleManifest.requires`) and never a foreign revision, because the answer
differs per assembly. This assembly answers in
`src/dotmac_workspace/migration_bindings.py`, installed by `alembic/env.py`
before the revision map is built and exported to Alembic's graph commands
through `DOTMAC_MIGRATION_BINDINGS`.

Never edit a module's migration to name one of our revisions, and never treat a
binding as fact: `require_prerequisites` proves each effect against the live
catalog before any DDL runs, and `make test-db` asserts the applied result.

## 5. Adapters are thin

`web.py` validates, authorizes the viewer, and delegates. No `db.query`, no
`select(`, no business logic. Domain logic belongs to the module's service.

## 6. Pinned dependencies, never paths

`dotmac-kernel` and `dotmac-application-directory` are pinned exactly, from the
Forgejo index (ADR-0005). **Never commit a path or editable dependency** — this
repository does not live beside the packages it consumes. To test unreleased
versions, build wheels and `pip install` them into the venv without touching
`pyproject.toml`; see the README.

An unpublished pin is a **finding to report**, never a reason to relax the pin.
The `from-wheel` CI job exists partly to make that failure loud: it installs the
built wheel into a clean virtualenv and resolves its pins from the index, so a
version that is only written down fails there rather than in production.

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
make check         # ruff lint + format check + mypy
make test          # static and unit tests, no database
make test-db-up    # disposable Postgres + all three lineages applied
make test-db       # composed-migration and tenant-isolation canaries
make test-db-down
```

Tests run on Git-hosted CI. Static checks may run locally; local runs are not
test evidence. `tests/db` must never skip itself when its database is absent —
a canary that skips proves nothing while the job goes green.

## 9. The Governance profile is pinned, and the workflow runs the same revision

`.dotmac/standards-profile.json` pins the accepted `dotmac_governance` revision
and `.github/workflows/engineering-standards.yml` executes that same commit. A
profile pinning one revision while the workflow runs another is a governance
model in name only. The check reads the repository's observed Git origin, so it
cannot pass until this repository has a remote.
