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
  make the isolation a deployment coincidence rather than a property. Its name
  lives once, in `dotmac_workspace.session_contract`.
- **The cookie carries no `Domain` attribute, ever.** Host-only is the line that
  makes the isolation a property of the code rather than of how it happens to be
  deployed; a `Domain=`-scoped cookie under a shared parent would be sent to
  every product portal underneath it. Enforced by
  `tests/test_login_surface.py::test_the_session_cookie_carries_no_domain_attribute`.
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

## 3a. The browser surface is DECLARED, in `assembly.py`, and nowhere else

Kernel `0.1.0a97` makes a browser facet typed and refuses to compose one it has
to infer. The rules, each pinned by `tests/test_web_facet.py`:

- The facet code is `staff_admin`. It is the only code the v1 adapter accepts,
  not a name this repository chooses.
- The authentication profile names `dmws_session`. Never bind the kernel's
  `TENANT_COOKIE_AUTHENTICATION`; it reads `access_token`, which this assembly
  never sets.
- `admission_permission` is a coarse boundary and does NOT replace the five
  per-route permission codes. Collapsing them into it grants every admitted
  member `workspace.identity.manage`.
- `/logout` is an entry route. It keeps `require_workspace_auth` and escapes
  only facet admission, so a member without `workspace.portal.access` can still
  leave.
- `url_prefix` is a reservation, not a route prefix, and may not be `/`.
- The facet's shell is `templates/layouts/workspace.html`, and it is currently
  the second spelling of the document `page.render_page` composes — a bypass of
  `page.py`'s one-shell rule, recorded as CE-001 in `docs/CONTROL_EXCEPTIONS.md`
  and held from drifting by `tests/test_web_facet_shell.py`.

Why each rule exists, and what breaks quietly without it, is in `README.md`
§ "The browser facet".

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

## 4b. The login path: one entry point, one ceremony, one held secret

Federated login is `src/dotmac_workspace/identity/`. Five rules, each with the
failure it prevents and the test that keeps it:

1. **`finalize_external_login`, never `resolve_external_identity`.** The read
   is legitimate for an admin screen and never on a path that ends in a
   session: resolving and then issuing leaves a window in which an
   administrator disables a binding, the disable commits, and a session derived
   from the revoked identity is minted behind it — with both audit trails
   looking correct, because the ordering that makes them incompatible is what
   neither records. The finalizer holds the binding's row lock across the
   decision AND the session. There must be **no resolve-then-issue path
   anywhere**; `tests/test_no_resolve_then_issue.py` AST-forbids one across all
   of `src/`, and also forbids a `commit()` inside `complete_login`, because the
   commit is what releases the lock and it belongs to `dotmac_kernel.db`.
2. **Ceremony state is shared and atomic.** PostgreSQL, consumed by ONE
   `DELETE … RETURNING`. Never a `SELECT` then a `DELETE` — two callbacks would
   both see the row and both proceed with one PKCE verifier. **No per-process
   store may exist in `src/` at all**, not even one guarded against selection:
   the test double lives in `tests/conftest.py`, outside the wheel.
   `tests/test_state_store_is_shared.py` and
   `tests/db/test_state_store_atomicity.py`.
3. **The `state` parameter is an opaque id.** PKCE `S256` (never `plain`) and a
   nonce; the verifier, the nonce and the return path never travel. A return
   path that made the round trip is an open redirect waiting for someone to
   rewrite it.
4. **The OIDC client secret is HELD, never dereferenced** (ADR-0009). Installed
   once by a startup hook, inside the lifespan. Nothing on a request path reads
   the environment, refreshes a source, or contacts a store —
   `tests/test_secret_is_held.py` proves the load count is one and sweeps the
   request-path modules by AST.
5. **Explicit binding only.** No JIT provisioning, no email linking, no reading
   of provider roles/groups/scopes. An unbound subject is refused, and every
   refusal is the same refusal — a caller that could tell "no such subject" from
   "disabled binding" is a subject-enumeration oracle.

Session **provenance** (`auth_sessions.external_identity_binding_id`) belongs to
the KERNEL. Do not add a Workspace-owned equivalent: it would make this plane a
second writer of session revocation in a different transaction from the kernel's
disable. Record `binding_id` in the audit event and report the kernel change.

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

## 6a. Compose the ecosystem packages; never hand-roll what one owns

Fleet-wide standing rule. Before building anything, ask which published Dotmac
package already owns it — `dotmac-ui` (tokens, stylesheet, components, the
accessibility contract), `dotmac-kernel` (app factory, auth, RLS, migrations,
permissions, settings, idempotency), `dotmac-auth-oidc` (the relying party),
`dotmac-application-directory` (the portfolio) — and compose it through its
**published surface**, exact-pinned. Never copy a file, monkey-patch, or fork
(ADR-0006's extraction rule). If a package nearly fits, improve it or add a
declared extension point; a local reimplementation is how a product falls
behind a security fix in the thing it copied.

This is not tidiness. This assembly served **every screen unstyled** through
the entire pilot: the spec's `packaged_static_dirs` and `assembly_static_dir`
slots were simply never filled, nothing failed, and no test noticed. That is
the shape of the defect — not a crash, but a product quietly ceasing to be
part of the fleet.

Namespaces are part of the contract. `.dmui-*` belongs to `dotmac-ui` and only
classes it declares may ship; this assembly's own markup uses `.dmws-*`.
Author against `var(--dmui-<role>)`, never a raw hex, so a retuned token
reaches every surface at once. `tests/test_design_system.py` enforces both,
each with a sensitivity proof.

## 7. Everything by config

Every environment-specific value is an overridable knob with a documented
default (`Makefile` `?=`, env vars with defaults). Never hardcode a port, host,
image name or path.

## 8. What must not be built here

- No proprietary identity provider — federated login is external OIDC. No
  password login, no credential store, no `UserCredential` written here.
- **No multi-provider registration table.** One deployment-configured provider,
  named by environment. A table of providers an administrator creates is a
  separate contract with its own lifecycle — who may add one, where its secret
  half lives under ADR-0009, what happens to the bindings naming a deleted row,
  and how a tenant-created provider interacts with `provider_binding` being the
  TRUSTED half of the kernel's resolution tuple. Decide it from real demand or
  not at all; a wire format invented from imagination is one somebody has to
  unpick in the field.
- No global party/person database. The bootstrap CLI creates members in ONE
  tenant, through the kernel's tenant-scoped session, and nowhere else.
- No shared session or cookie service.
- No generic data-federation module.
- No second audit, messaging, inbox, idempotency, permissions or entitlement
  mechanism — the kernel owns all six.
- Every call to `write_audit_event` names the canonical actor pair explicitly:
  `actor_type` plus `actor_id`. `actor_party_id` is accountability enrichment,
  not permission to depend on a kernel compatibility derivation. The Workspace
  has authenticated the Party at both current call sites, so the pair is
  `("user", str(party.id))`.
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
make test-db       # composed-migration, tenant-isolation and login canaries
make test-db-down
```

Tests run on Git-hosted CI. Static checks may run locally; local runs are not
test evidence. `tests/db` must never skip itself when its database is absent —
a canary that skips proves nothing while the job goes green.

### Writing a concurrency canary

Copy the shape in `tests/db/test_state_store_atomicity.py`; do not invent one.
Two THREADS with their own connections, a `threading.Barrier` after both
advisory reads, and EVERY wait bounded — `SET LOCAL lock_timeout`, `SET LOCAL
statement_timeout`, `Barrier.wait(timeout=)`, `Future.result(timeout=)`. Workers
RETURN outcomes and the test asserts on the collected results, because an
assertion raised inside a thread fails that thread and not the test. Probe the
PROPERTY (exactly one consumed), never a proxy that depends on who won. And note
that `set_config('app.current_tenant', …, true)` is TRANSACTION-local: a
`commit()` discards it, so fixtures seed in their own short-lived sessions.

### Writing an architecture guard

Match an AST node or a syntax-specific call site — never grep for a concept in
source text. Three guards in this programme have flagged the comment explaining
the very invariant they enforce, and the cheapest way to satisfy such a guard is
to delete the explanation. Every guard here is paired with **two** tests: one
proving it does not fire on prose describing the absence, and one proving it
does fire on the real thing. A detector that can never fail is not evidence.

## 9. The Governance profile is pinned, and the workflow runs the same revision

`.dotmac/standards-profile.json` pins the accepted `dotmac_governance` revision
and `.github/workflows/engineering-standards.yml` executes that same commit. A
profile pinning one revision while the workflow runs another is a governance
model in name only. The check reads the repository's observed Git origin, so it
cannot pass until this repository has a remote.
