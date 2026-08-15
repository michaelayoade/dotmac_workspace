# Adoption blockers

**This repository is a local scaffold. It is not shipped, not deployed, and not
a consumer of anything.** `dotmac-application-directory` stays `audit-complete`
with ZERO production consumers until every blocker below is cleared and the
Workspace actually runs in production.

Recorded here rather than in a ticket because ADR-0018's rule applies: an
exemption must state an enforceable premise, or the region is unmonitored rather
than exempt. `tests/test_adoption_blockers.py` fails if this file stops naming
the permission code, or stops recording that the surface is unreachable — so the
gap cannot quietly disappear, in either direction.

Status at a glance:

| | | |
|---|---|---|
| B1 | no cookie-compatible permission seam | **cleared** 2026-08-15 |
| B2 | nothing issues `dmws_session`, no `/login` | **open** — a separate workstream |
| B3 | pinned dependencies not published | **half cleared** — kernel yes, directory no |
| B4 | no remote, no lock, no CI evidence | **written, unproven** |
| B5 | kernel `testing` extra declared and unused | cleared 2026-08-12 |

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

**Open. This is what keeps the repository a scaffold.**

`require_workspace_auth` redirects to `/login`, which does not exist. No route in
this repository mints or sets the `dmws_session` cookie. So `/applications` is
still unreachable end to end: it redirects, and the redirect target 404s.

The Workspace needs its own login path — its own cookie, its own session — built
on `dotmac_kernel.deps.authenticate_request` (the shared validation seam) rather
than on a re-implementation, and, for the federated case, on the
external-identity binding added in `dotmac-kernel 0.1.0a63`
(`dotmac_kernel.external_identity`). That is a separate workstream and is
deliberately not started here.

Until B2 clears the launcher must not be exposed to a real tenant — no longer
because it is unguarded, but because nobody can get past the guard.

## B3 — The pinned dependencies are not published

**Half cleared.**

- `dotmac-kernel 0.1.0a63` **is published** and resolves from the Forgejo index.
- `dotmac-application-directory 0.1.0a2` **is not on the index.** Neither is any
  other version of it — the package name has no releases there at all.

So `poetry lock` cannot resolve, and **there is still no lock file**. The pins in
`pyproject.toml` are correct and deliberate; the index has not caught up.

Do not work around this by relaxing a pin or adding a path dependency
(AGENTS.md §6). Build the wheel locally and install it into the venv without
touching `pyproject.toml` — see the README. The `from-wheel` CI job fails at its
install step for exactly this reason today, and that is the correct behaviour: an
unpublished pin should be a loud failure, never a quiet substitution.

One shape change in 0.1.0a2 that this repository already accommodates: its
lineage root declares `requires=("tenant_scope_catalog.v1",
"module_database_roles.v1")` instead of naming a foreign revision, so the
ASSEMBLY answers those requirements — `src/dotmac_workspace/migration_bindings.py`,
installed by `alembic/env.py` and exported to Alembic's graph commands through
`DOTMAC_MIGRATION_BINDINGS`. It also floors the kernel at `>=0.1.0a56`, which
`0.1.0a63` satisfies.

## B4 — No remote, no lock, no CI evidence

**Written, unproven.** The jobs now exist. None of them has ever run.

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

Still open, and each blocks the next:

1. **No lock file.** It cannot be generated until B3 clears — `poetry lock`
   fails on the unpublished module.
2. **No Git remote.** The Governance engine reads the observed origin and
   default branch and compares them to the profile's `repository` block, so the
   standards job cannot pass without one. The profile itself parses and verifies
   cleanly against the pinned engine when an origin is supplied.
3. **No run of any workflow.** Every claim in this file about CI is a claim
   about a file, not about a result.

## B5 — The kernel `testing` extra was declared and unused

Cleared 2026-08-12. The dependency declared `extras = ["testing"]`, pulling the
kernel's test kit into the **runtime** dependency set for tests that never used
it. Removed — an unused extra is surface a deployment carries and nobody checks.
