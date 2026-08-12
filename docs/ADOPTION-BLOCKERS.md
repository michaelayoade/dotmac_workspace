# Adoption blockers

**This repository is a local scaffold. It is not shipped, not deployed, and not
a consumer of anything.** `dotmac-application-directory` stays `audit-complete`
with ZERO production consumers until every blocker below is cleared and the
Workspace actually runs in production.

Recorded here rather than in a ticket because ADR-0018's rule applies: an
exemption must state an enforceable premise, or the region is unmonitored rather
than exempt. `tests/test_adoption_blockers.py` fails if this file stops naming
the permission code, so the gap cannot quietly disappear.

## B1 — There is no cookie-compatible permission seam in the kernel

**Severity: blocks deployment.** This is the one that needs a kernel decision.

`require_workspace_auth` authenticates a Workspace member and establishes tenant
scope. It performs **no authorization check**: any authenticated person in the
tenant reaches `/applications`. The intended decision is
**`workspace.applications.read`**, declared by the launcher's manifest and
enforced through a public kernel seam.

That seam does not exist:

| Seam | Why it does not fit |
|---|---|
| `dotmac_kernel.deps.require_permission` | Layered over `require_user_auth`, which reads the **bearer** `Authorization` header and raises a bare 401. A cookie-authenticated page gets a 401 instead of a redirect, and no cookie is read at all. |
| `dotmac_kernel.web_deps.require_web_auth` | Cookie-based and does check a role — but it reads the cookie literally named `access_token`, which is the one this Workspace must not share (ADR-0021 §1), and it hardcodes `"admin"` rather than consulting a declared permission. Its own docstring records this as a phase-3 TODO. |

**The fix is not to hand-roll the role query here.** Duplicating kernel
authorization logic in an assembly is how a plane falls behind a kernel security
fix — the failure ADR-0015 recorded against academy, where a control was
configured, asserted in config validation, and never armed. What is needed is a
kernel seam that resolves a declared permission for a **cookie-authenticated**
party, at which point the launcher declares `workspace.applications.read` and
depends on it.

Until then the launcher must not be exposed to a real tenant.

## B2 — Nothing issues `dmws_session`, and there is no `/login`

`require_workspace_auth` redirects to `/login`, which does not exist. No route
in this repository mints or sets the `dmws_session` cookie. So `/applications`
is unreachable end to end: it redirects, and the redirect target 404s.

The Workspace needs its own login path — its own cookie, its own session — built
on `dotmac_kernel.deps.authenticate_request` (the shared validation seam) rather
than on a re-implementation.

## B3 — The pinned dependencies are not published

`dotmac-kernel 0.1.0a43` and `dotmac-application-directory 0.1.0a1` are not on
the Forgejo index. They land with the `dotmac_starter_mt` pull requests this
repository was created alongside, in that order: kernel first, then the module.

Until both are published this repository **cannot install, cannot run its own
suite, and has no lock file**. Do not work around this by relaxing the pins or
adding a path dependency — build wheels locally instead (see the README).

## B4 — No remote, no lock, no CI evidence

There is no git remote, no `poetry.lock`, and the CI workflow has never run.
`.github/workflows/ci.yml` is written but unproven.

Before a remote is established:

- commit a lock file, generated **after** B3 clears;
- add the pinned Governance profile and job (`.dotmac/standards-profile.json`
  and the `engineering-standards.yml` workflow), as every other Dotmac
  repository carries;
- require **from-wheel boot** evidence — the app imports and starts from the
  published wheels, not from a sibling checkout;
- require **live composed-migration** evidence — all three lineages applied
  against a real PostgreSQL, since nothing here has ever run a migration.

## B5 — The kernel `testing` extra was declared and unused

Cleared 2026-08-12. The dependency declared `extras = ["testing"]`, pulling the
kernel's test kit into the **runtime** dependency set for tests that never used
it. Removed — an unused extra is surface a deployment carries and nobody checks.
