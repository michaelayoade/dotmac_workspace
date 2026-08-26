# dotmac_workspace

The **Tenant Workspace** — the customer's cross-application plane.

A Dotmac customer who is a tenant of several applications needs somewhere to
answer one question that spans them: *which of my people may use which of my
applications.* That question is asked by a customer administrator, not by a
Dotmac operator, and before this assembly existed it had nowhere to live.

Decision of record: **ADR-0021**, in `dotmac_starter_mt/docs/adr/`.

## Three planes

```
Vendor CP ── signed app entitlements ──> Tenant Workspace
                                               │
                                     access allocations
                              ┌────────────────┼───────────────┐
                              v                v               v
                            Sub          Backoffice         Academy
                      local enforcement local enforcement local enforcement
```

| Plane | Represents | Owns |
|---|---|---|
| Vendor control plane | Dotmac / vendor operators | contracts, licences, deployments, commercial availability |
| **Tenant Workspace (this repo)** | the customer / operator | their cross-application administration **intent** |
| Target application | the running product | its effective local roles, permissions and domain data |

Authority flows down and never up. A target application never asks this
Workspace whether a request is authorized; it decides for itself, from its own
tables.

## The invariant this repository exists to keep

> **A vendor-control-plane compromise must not automatically grant access
> inside customer applications.**

Three properties hold it up, and each has to hold on its own:

1. The vendor plane's signed artefacts convey **commercial availability**, never
   person-to-role assignment. An attacker holding the vendor signing key can
   make an application *available* to a tenant — a billing problem, not a breach.
2. This Workspace shares **no database, session, cookie or guard** with any
   application. Its session cookie is `dmws_session`, deliberately not the
   `access_token` every product portal reads.
3. The target application is the **only writer of its own effective role
   grants**.

## Directory visibility is not authorization

The launcher shows a tile per connected application. A tile means *your tenant
has this application*. It does **not** mean the person looking at the screen may
enter — when they follow the link, the target application authenticates and
authorizes them itself.

So the launcher never mints a token for a target, never reads or writes a grant,
and never hides a tile based on what the viewer may do *there*. That last one is
deliberate and counter-intuitive: hiding a tile would look like a courtesy and
would in fact be this Workspace pre-empting a decision that belongs to the
target — using a cached role catalogue that carries a staleness state precisely
because it must not gate anything.

Reaching the *screen* is a separate decision, and this Workspace does own that
one. `GET /applications` is guarded by the declared permission
**`workspace.applications.read`**, enforced through
`dotmac_kernel.deps.permission_guard` layered over the Workspace's own
`dmws_session` cookie:

| Caller | Answer |
|---|---|
| no session | 302 to `/login` |
| a session without the permission | **403** — never a redirect |
| authorized | the launcher renders |

A refusal that redirected would tell a signed-in user to sign in, and loop
against a login that finds a valid session. And the permission gates the screen
and stops there: it filters no tile and asserts nothing about any target
application.

`tests/test_launcher_is_not_authorization.py` and
`tests/test_launcher_authorization.py` enforce all of it.

## Signing in

The Workspace has its own front door. Not a proprietary identity provider —
AGENTS.md §8 forbids one — but a relying party for **one deployment-configured
external OIDC provider**, with its own cookie and its own session.

```
GET  /login            the front door
POST /login            starts a ceremony, sends the browser to the provider
GET  /login/callback   completes it, or refuses
POST /logout           revokes the session (a POST, under the CSRF header bridge)
```

Six properties, and each of them is somewhere you can check:

1. **Its own cookie, its own session.** `dmws_session`, host-only — no `Domain`
   attribute, ever — `HttpOnly`, `SameSite=Lax`. The row is a kernel
   `AuthSession`, so `dotmac_kernel.deps.authenticate_request` remains the ONE
   validation seam and a kernel auth fix reaches this plane for free.
2. **The callback uses `finalize_external_login`, never
   `resolve_external_identity`.** Kernel `0.1.0a64` added the former because
   the latter, followed by issuing a session, leaves a window: an administrator
   disables a binding, the disable commits, and a session derived from the
   identity it revoked is minted behind it. Both audit trails look correct;
   only the ordering makes them incompatible. The finalizer holds the binding's
   row lock across the decision AND the session, so a login and a concurrent
   disable serialize — one of them blocks and then refuses.
3. **Ceremony state is shared and atomic.** `public.workspace_login_states`,
   consumed by one `DELETE … RETURNING`, so a login started on one worker
   completes on another and a state works exactly once. There is no in-memory
   store in the package at all: the test double lives in `tests/conftest.py`,
   outside the wheel, where nothing can select it.
4. **The `state` parameter is opaque.** A 256-bit random id. The PKCE verifier
   (S256), the nonce and the return path stay server-side and never travel.
5. **The OIDC client secret is HELD, never dereferenced** (ADR-0009). A startup
   hook installs a `SecretSource` once, inside the lifespan; afterwards reading
   it is a dictionary lookup. Nothing on a request path reads the environment
   or contacts a store.
6. **Binding is explicit.** No JIT provisioning and no email linking. An
   unbound subject is refused — the refusal is logged with the subject, which
   is how an operator learns what to bind.

Configuration, all knobs with documented defaults
(`src/dotmac_workspace/identity/config.py`):

```sh
WORKSPACE_OIDC_ISSUER=https://idp.example.net/realms/dotmac
WORKSPACE_OIDC_CLIENT_ID=dotmac-workspace
WORKSPACE_OIDC_REDIRECT_URL=https://ws.example.net/login/callback
WORKSPACE_OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc-client-secret   # or _SECRET
```

A deployment that keeps the secret elsewhere writes its own `SecretSource` and
installs it; the store client stays out of this repository, exactly as the
kernel keeps it out of itself.

**One provider, and no registration table.** A multi-provider table is out of
scope and is a separate contract to be decided from real demand — it brings its
own lifecycle (who may add one, where its secret half lives under ADR-0009,
what happens to bindings that name a deleted row) and deciding that from
imagination produces a wire format somebody has to unpick in the field.

**The protocol client is the published package.** This slice was the pilot that
`dotmac-auth-oidc 0.1.0a1` was waiting for; once it published, the Workspace-local
`identity/oidc.py` was deleted and the exact pin adopted (blocker B6, closed
2026-08-15). Nothing here re-implements the ceremony.

### Bootstrapping the first member

Federated login refuses an unbound subject, and this assembly composes no
parties or RBAC surface — so the first member is created by the operator CLI:

```sh
dotmac-workspace member add --tenant acme \
    --email ada@acme.example --first-name Ada --last-name Lovelace
dotmac-workspace bind --tenant acme --email ada@acme.example \
    --subject <the provider's sub> --by michael@dotmac --reason "ticket 4417"
dotmac-workspace bindings --tenant acme
```

The subject is opaque; the way to find it is to have the person attempt a
sign-in first, which logs `issuer … subject … is not bound`. That ordering is
deliberate — the binding is then made against a subject the provider actually
asserted, not one typed from a directory export.

### What disabling a binding does, and does not

`dotmac-workspace disable` deactivates a binding and keeps the row with its
evidence. **No further session can be derived from it** — the disable takes the
same row lock the login holds, so a login in flight either already committed or
blocks and then refuses. **A session already issued from it stays valid until it
expires.**

Closing that last gap needs session provenance —
`auth_sessions.external_identity_binding_id` — and `auth_sessions` is a KERNEL
table. It is reported as a kernel follow-up rather than implemented here; a
Workspace-owned shadow table would have made this plane a second writer of
session revocation, in a different transaction from the kernel's disable. See
`docs/ADOPTION-BLOCKERS.md` § B2.

## What this wave ships, and what it does not

**Ships:** the app launcher over `dotmac-application-directory` — the tenant's
connected-application portfolio, its binding lifecycle, and its reconciliation
state.

**Does not ship:** access requests, approvals, delegation policy, signed grant
sets, acknowledgement, drift. That is `dotmac-application-access`, deferred by
ADR-0021 §5.

The reason is worth stating plainly, because the gap is real: an
`AccessGrantSet` must be signed, and the kernel's proven signed envelope is
private and hard-wired to the licence schema. That leaves three moves — import
the private verifier, disguise a grant as a licence, or copy the envelope — and
all three are wrong. The right move is a generic signed-document mechanism in
the kernel, which ADR-0017's moratorium blocks today. So **a tenant
administrator can see their portfolio and cannot yet allocate access from
here**; granting a colleague access to an application is still done in that
application.

Deferring a module is cheap. Unpicking a wire format in the field is not.

## Composition

```python
ProductAssemblySpec(
    name="dotmac_workspace",
    modules=(identity_feature, launcher_feature, dotmac_application_directory.module),
    web_enabled=True,
    startup_checks=(configuration_errors,),   # fatal in production, a warning in dev
    startup_hooks=(install_workspace_secrets,),  # the OIDC secret, held from boot
)
```

Built with `dotmac_kernel.create_app`, never by hand — ADR-0015's fleet-wide
rule, and this is the worst application in the fleet to break it in, because its
whole job is a security boundary.

Migrations compose three separately-owned lineages into one revision graph: the
kernel's, the application-directory module's, and this repository's. Two of the
three are installed packages, so they are located through their owners' public
`versions_dir()` rather than hard-coded paths.

Ordering is composed logically, not physically. A module lineage declares the
database EFFECTS it needs — `dotmac-application-directory` requires
`tenant_scope_catalog.v1` and `module_database_roles.v1` — and never names a
foreign revision, because the answer differs per assembly. This assembly answers
in `src/dotmac_workspace/migration_bindings.py`, installed by `alembic/env.py`
before the revision map is built. A binding is not belief: `require_prerequisites`
re-proves each effect against the live catalog before any DDL runs, so a wrong
entry fails at `alembic upgrade` rather than in production. `make test-db-up`
applies all three lineages against a disposable PostgreSQL and `make test-db`
asserts the result.

## Dependencies are pinned, never paths

`dotmac-kernel` and `dotmac-application-directory` are pinned exactly and
resolved only from the private Forgejo index (ADR-0005). **No path or editable
dependency is ever committed here** — this assembly lives in a different
repository from the packages it consumes, and a path dependency would make the
build depend on a sibling checkout.

### Testing against an unpublished version

Both current pins — `dotmac-kernel 0.1.0a70` and
`dotmac-application-directory 0.1.0a3` — are on the index, and `poetry.lock` is
committed. The recipe below is for the NEXT time a pin runs ahead of a release:
build the wheel and install it version-pinned, rather than relaxing the pin or
adding a cross-repository path dependency.

```sh
# in dotmac_starter_mt
poetry build -C packages/dotmac-application-directory

# here — install the wheel into the venv WITHOUT editing pyproject.toml
poetry run pip install \
  ../dotmac_starter_mt/packages/dotmac-application-directory/dist/*.whl
poetry run pytest --ignore=tests/db
```

`make check` and `make test` work normally once both are on the index.

## Status: production adopter

The Workspace became `dotmac-application-directory`'s first production consumer
in the 2026-08-16 real-IdP pilot at `workspace.dotmac.io`. It exact-pins
`dotmac-application-directory 0.1.0a3`, composes its lineage, and exercised the
directory-backed launcher across two workers. Starter records the module as
`adopted`; one consumer does not earn `reuse-proven`.

Directory visibility is not authorization. This Workspace owns its OIDC
boundary and its host-only `dmws_session`; each target application owns its own
authorization and session. The launcher remains a plain-link reader, and no
application-access or shared-session authority has been added here.

**B1 is cleared**: `dotmac-kernel 0.1.0a62` added the authentication-neutral
permission seam, so the launcher declares and enforces
`workspace.applications.read` instead of authenticating without authorizing.

The kernel pin is now `0.1.0a70`: Workspace's two audit writers name the
canonical `(actor_type, actor_id)` pair explicitly, and the consumed kernel no
longer derives either field from `actor_party_id`. The caller migration and the
strict callee therefore ship as one adoption, with no compatibility fallback.

**B2 is cleared**: `/login`, its callback and `dmws_session` exist (see "Signing
in" above), so `/applications` is reachable end to end. Kernel 0.1.0a67 owns
session provenance on `auth_sessions`; disabling a binding selectively revokes
the sessions it produced without a Workspace-owned shadow mechanism.

**B3 is cleared**: both pins are published and `poetry.lock` is committed.
**B4 is cleared**: the remote exists, `main` is protected, and the quality,
PostgreSQL, from-wheel, and engineering-standards jobs have all produced green
results. Main run `31962357233` is the current recorded result.

## Commands

| | |
|---|---|
| `make check` | ruff lint + format check + mypy |
| `make test` | static and unit tests (no database) |
| `make test-db-up` | start the disposable Postgres and apply all three lineages |
| `make test-db` | composed-migration and tenant-isolation canaries |
| `make test-db-down` | stop and erase it |
| `make from-wheel-boot` | build the wheel, install it clean, boot from it |
| `make dev` | run the development server |
| `make migrate` | compose all three lineages and upgrade |
| `make migrate-graph` | print the composed revision graph |

Tests run on Git-hosted CI. Local static checks are not test evidence.
