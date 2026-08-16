# Adoption blockers

**This repository is not deployed, and is therefore still not a consumer of
anything.** `dotmac-application-directory` stays `audit-complete` with ZERO
production consumers until every blocker below is cleared AND the Workspace
actually runs in production — the second half of that sentence is the one that
matters now, because the first half is nearly done.

What changed on 2026-08-15: B2 closed, so the launcher is reachable end to end
for the first time. What did not change: nothing here runs anywhere. "It can be
reached" and "it is in production" are different claims, and only the first one
is now true.

Recorded here rather than in a ticket because ADR-0018's rule applies: an
exemption must state an enforceable premise, or the region is unmonitored rather
than exempt. `tests/test_adoption_blockers.py` fails if this file stops naming
the permission code, or stops naming B2 and the cookie — so the gap cannot
quietly disappear, in either direction. That test is a two-directional ratchet
by design: when B2 closed, the assertion that the surface was UNREACHABLE was
inverted rather than deleted, because keeping it would have forced this file to
keep claiming a gap the code no longer has.

Status at a glance:

| | | |
|---|---|---|
| B1 | no cookie-compatible permission seam | **cleared** 2026-08-15 |
| B2 | nothing issues `dmws_session`, no `/login` | **cleared** 2026-08-15 |
| B3 | pinned dependencies not published | **cleared** 2026-08-15 |
| B4 | no remote, no lock, no CI evidence | **partly cleared** — remote and lock yes, results pending |
| B5 | kernel `testing` extra declared and unused | cleared 2026-08-12 |
| B6 | the OIDC protocol client is implemented here, not consumed | **cleared 2026-08-15** — `dotmac-auth-oidc 0.1.0a1` published, pinned, local copy deleted |

That follow-up is now CLOSED. **Session provenance**
(`auth_sessions.external_identity_binding_id`) shipped in kernel `0.1.0a67`,
this assembly pins it exactly and stamps the column when it issues a session,
and disabling a binding revokes the sessions it produced. See B2 below.

## B1 — There is no cookie-compatible permission seam in the kernel

**Cleared 2026-08-15, by a kernel change rather than by a local workaround.**

`dotmac-kernel 0.1.0a62` added `dotmac_kernel.deps.permission_guard`, the
authentication-neutral half of `require_permission`: a route-dependency factory
that takes the surface's OWN authenticated-party dependency and returns a guard
resolving a declared permission through `deps.authorize_party`. The kernel never
learns this plane's cookie name; this plane never learns how a permission binds
to roles. Both halves stay with their owner, which is the property B1 was
holding out for.

So the launcher now:

- declares **`workspace.applications.read`** on its `FeatureManifest`
  (`src/dotmac_workspace/launcher/feature.py`), which makes it the single owning
  module for that code; and
- guards `GET /applications` with `permission_guard(...,
  authenticated_party=require_workspace_auth)`
  (`src/dotmac_workspace/launcher/guard.py`).

Three outcomes, and the middle one is the load-bearing one:

| Caller | Answer | Why |
|---|---|---|
| no `dmws_session` cookie, or an invalid one | 302 to `/login` | `require_workspace_auth` raises `WebAuthRedirect`. "Who are you?" is a question signing in can answer. |
| authenticated, lacks the permission | **403** | Never a redirect. The caller is already signed in, so a login page would find a valid session and send them back — a bounce at best, a loop at worst. |
| authorized | the launcher renders | |

The permission code stamped on the guard is validated by `create_app` against
the catalogue built from installed manifests, so a typo'd or undeclared code
stops the boot rather than surfacing as a mystery 403 on first use.

**What did NOT change:** hand-rolling the role query here is still forbidden and
still enforced. `tests/test_adoption_blockers.py
::test_the_guard_does_not_hand_roll_a_role_check` AST-forbids `PartyRoleGrant`,
`Role`, `select`, `execute`, `scalars` and `query` in `guard.py`. That test was
written to press for a kernel seam; the seam arrived; the test stays, because
the wrong fix is still available to whoever edits that file next.

Also unchanged: **the permission gates the SCREEN, not the tiles.** It says
nothing about any target application and filters no tile. Directory visibility
is not authorization (ADR-0021 §3), and an authorization decision on this side
must not quietly become an opinion about the other side.

## B2 — Nothing issues `dmws_session`, and there is no `/login`

**Cleared 2026-08-15.** `/applications` is reachable end to end for the first
time: it redirects to a `/login` that exists, and a member who completes the
ceremony arrives back holding a `dmws_session` this repository issued.

What now exists (`src/dotmac_workspace/identity/`):

| | |
|---|---|
| `GET /login` | the front door; one control, and it is a POST |
| `POST /login` | starts a ceremony and sends the browser to the provider |
| `GET /login/callback` | completes it, or refuses |
| `POST /logout` | revokes the session, under the CSRF header bridge |

Six properties hold it up, and each is enforced somewhere:

1. **Its own cookie and its own session.** `dmws_session`, host-only (no
   `Domain` attribute, ever), `HttpOnly`, `SameSite=Lax`. The row is a kernel
   `AuthSession`, so `dotmac_kernel.deps.authenticate_request` stays the ONE
   validation seam and an auth-tightening kernel fix still reaches this plane
   for free. Nothing is shared with any application (ADR-0021 §1).
2. **`finalize_external_login`, never `resolve_external_identity`.** Kernel
   `0.1.0a64` exists because resolving and then issuing leaves a window in
   which an administrator disables a binding and still gets a live session
   derived from it, with both audit trails looking correct. The callback takes
   the binding under a row lock and mints the session in the SAME transaction,
   so the login and a concurrent disable serialize. `tests/
   test_no_resolve_then_issue.py` AST-forbids the racy pair anywhere in `src/`.
3. **Shared, atomic ceremony state.** `public.workspace_login_states`, consumed
   by one `DELETE … RETURNING`, so a login started on one worker completes on
   another and a state works exactly once. There is no in-memory store in the
   package at all — the test double lives in `tests/conftest.py`, outside the
   wheel, where no configuration can reach it.
4. **Opaque state, PKCE S256, and a nonce.** The `state` parameter is a 256-bit
   random; the verifier, the nonce and the return path never travel.
5. **The client secret is HELD.** Loaded once by a startup hook (ADR-0009),
   read afterwards as a dictionary lookup. Nothing on the request path reads
   the environment or contacts a store.
6. **Explicit binding only.** No JIT provisioning and no email linking — an
   unbound subject is refused. `dotmac-workspace bind` is how an operator
   creates one, with `bound_by` and `reason` required.

### The follow-up this repository could not do — done in kernel a67

The kernel's `external_identity` docstring carried a deferred contract:
`auth_sessions.external_identity_binding_id`, so that disabling a binding could
SELECTIVELY revoke the sessions derived from it — never a global logout.

**That column lives on a KERNEL table** (`public.auth_sessions`), so this
repository could not add it. It was reported rather than implemented, and the
report named the release it was owed from. It shipped in `0.1.0a67`, and this
assembly adopted it in the same week:

- the kernel pin moves to `0.1.0a67` exactly;
- `session.issue` REQUIRES `binding_id` — no default, because every session here
  comes from a federated login and a default would exist only to let a caller
  forget the thing that makes revocation possible;
- the value passed is `identity.binding_id`, the FINALIZER's answer, not a value
  the caller had in hand. The two differ when a subject resolves to a different
  binding than expected, and the column must record which binding actually
  authorised the login (kernel contract point 2);
- `tests/db/test_session_revoked_on_binding_disable.py` proves the consequence
  through this assembly's own code path: login, disable, and the session is then
  refused by `authenticate_request` — the same validator that guards every page.

What was deliberately NOT done while waiting, and would have looked like
progress: a Workspace-owned shadow table. It would have made this plane a second
writer of session revocation, in a different transaction from the kernel's
disable — precisely the "two calls a caller can do half of" the kernel contract
forbids, and then a migration off a parallel authority when a67 landed. Waiting
cost nothing and the pin moved instead.

`binding_id` is still recorded in the `workspace.login.succeeded` audit event,
and that is not redundant with the column. The column is current state: which
binding a LIVE session came from, gone when the row goes. The audit event is
history: that a session was issued from that binding at a moment in time, and it
survives both the revocation and the row.

**The consequence, restated:** disabling a binding now stops any further session
being derived from it AND revokes the ones already issued, in one kernel call,
under one row lock. It is no longer true that a session outlives the identity it
came from.


## B3 — The pinned dependencies are not published

**Cleared (2026-08-15).**

- `dotmac-kernel 0.1.0a64` is published and resolves from the Forgejo index.
- `dotmac-application-directory 0.1.0a3` is published and resolves.

`poetry.lock` is generated and committed, and both pins install.

The kernel pin MOVED from a63 to a64 for the login path, and the move was the
alternative to a workaround rather than an upgrade for its own sake: a63 has
`resolve_external_identity` and no locking finalizer, so a callback built on it
would have had to resolve and then issue — reproducing the exact window a64
exists to close. The pin moved; the code did not work around it.

The history is worth keeping, because it is why the version is a3 rather than
a2. When this repository first pinned the directory, **no version of it existed
on the index** — the package had never been published. The first publish attempt
then failed in the release wheel smoke: `import dotmac_application_directory`
required a `DATABASE_URL`, because its service imported `dotmac_kernel.db` at
module scope and that module builds its engine on import. a2 was superseded by
a3 rather than rebuilt under the same number, so two artifacts could never both
claim to be a2.

This repository did not work around the gap: it neither relaxed the pin nor
added a cross-repository path dependency, both of which would have produced a
green-looking branch built on a dependency that did not exist.

Do not work around this by relaxing a pin or adding a path dependency
(AGENTS.md §6). Build the wheel locally and install it into the venv without
touching `pyproject.toml` — see the README. The `from-wheel` CI job installs the
built wheel into a clean virtualenv and resolves its pins from the index, so an
unpublished pin fails there, loudly, rather than being quietly substituted.

One shape change in 0.1.0a2 that this repository already accommodates: its
lineage root declares `requires=("tenant_scope_catalog.v1",
"module_database_roles.v1")` instead of naming a foreign revision, so the
ASSEMBLY answers those requirements — `src/dotmac_workspace/migration_bindings.py`,
installed by `alembic/env.py` and exported to Alembic's graph commands through
`DOTMAC_MIGRATION_BINDINGS`. It also floors the kernel at `>=0.1.0a56`, which
`0.1.0a64` satisfies.

## B4 — No remote, no lock, no CI evidence

**Partly cleared.** The remote exists, `main` is protected and requires a pull
request with four green jobs, and `poetry.lock` is committed. What remains is
what always remained: a claim about CI is a claim about a RESULT, and each job's
first genuine run is the only thing that turns a written job into evidence.

Added:

- `.dotmac/standards-profile.json` and
  `.github/workflows/engineering-standards.yml` — the pinned Governance profile
  and job, as every other Dotmac repository carries. The profile pins the same
  accepted revision the workflow executes.
- `.github/workflows/ci.yml` gained three jobs: **quality** (ruff, format, mypy
  and the DB-free tests), **postgres** (all three lineages composed against a
  real PostgreSQL, then the composed-migration and tenant-isolation canaries in
  `tests/db`), and **from-wheel** (build the wheel, install it into a clean
  virtualenv, boot it from a directory with no source tree, serve `/health`).
- `docker-compose.test.yml` and `make test-db-up` / `make test-db` /
  `make test-db-down`, so a CI run and a laptop run configure one thing.

The **postgres** job also now runs the two login canaries added with B2:
`tests/db/test_state_store_atomicity.py`, which drives two threads through the
same ceremony and asserts that exactly one consumed it, and
`tests/db/test_login_state_isolation.py`, which proves the tenant boundary on
`workspace_login_states` through the ONLINE role.

Still open:

1. **Results, not files.** Every property proven by `tests/db` is proven only
   by a green `postgres` job; a run that has not happened is not evidence, and
   nothing in this repository may claim otherwise.
2. **The `from-wheel` job has the least history.** It is the only job that
   exercises the built artifact — package data, `__file__`-relative paths, a
   dependency satisfied only by the dev group — and the class of failure it
   catches is invisible everywhere else.

## B6 — The OIDC protocol client is implemented here, not consumed

**Cleared 2026-08-15, by publishing the shared package and deleting the copy.**

`src/dotmac_workspace/identity/oidc.py` is gone. `dotmac-auth-oidc 0.1.0a1` is
pinned exactly, resolved from the Forgejo index, and
`identity/relying_party.py` — about eighty lines, most of them explaining
lifetimes — is all that replaced it.

### The circle, and how it broke

This blocker recorded a genuine deadlock. The package was unpublished because it
had no pilot consumer; this repository could not be that consumer because
`poetry add --source forgejo dotmac-auth-oidc` answered *"Could not find a
matching version"*, and relaxing a pin or adding a cross-repository path
dependency is forbidden (AGENTS.md §6, and B3 is the record of what that costs).

It broke in the order this entry predicted, with one addition it did not:

1. **The pilot ran first, against a local wheel** — which is what the starter's
   release lane was holding out for. Absence from its allowlist was the safety
   mechanism, not an oversight.
2. **The pilot changed the package.** This was the unpredicted step and the
   valuable one. `PostgresStateStore` holds one request's `Session`, because
   `dotmac_kernel.db` owns when that transaction commits (hard rule 8) — so the
   package's client, which must be built once to keep its `ProviderCache`, could
   not hold the store. Starter PR #194 added a per-ceremony `state_store`
   argument and a `PER_REQUEST_STATE_STORE` declaration. Publishing before that
   would have shipped a surface no honest consumer could use, and the only way
   to find that out was to try to be one.
3. **Then publication**, verified from the index and tagged
   `dotmac-auth-oidc-v0.1.0a1`.
4. **Then the deletion**, here, in the change that pinned it.

### What this repository kept, and why

`identity/state_store.py` stays. It is the Workspace's own atomic store — the
thing the package's `StateStore` protocol expects a consumer to SUPPLY — and it
now satisfies that protocol structurally, importing `LoginState` and `StateStore`
from the package rather than restating them. A local Protocol with the same two
methods would be a second contract free to drift.

`httpx` and `pyjwt` left the runtime dependencies with the implementation. The
assembly no longer speaks HTTP to an identity provider or verifies a signature,
and declaring the libraries that do would claim a capability this code does not
have. `pyjwt` reappears in the dev group, where the tests use it to mint signed
ID tokens for a provider double so the package's REAL verification runs.

### What did not change

The login-CSRF defence. `tests/test_login_csrf.py` was written against the local
implementation and passes unchanged against the published wheel — which is the
evidence the swap preserved the property rather than inheriting a claim about
it. Its one structural assertion was INVERTED: it used to require
`compare_digest` in `service.complete_login` and now requires its absence, plus
proof that the pair is still forwarded and that the pinned package still demands
both halves.

## B5 — The kernel `testing` extra was declared and unused

Cleared 2026-08-12. The dependency declared `extras = ["testing"]`, pulling the
kernel's test kit into the **runtime** dependency set for tests that never used
it. Removed — an unused extra is surface a deployment carries and nobody checks.
