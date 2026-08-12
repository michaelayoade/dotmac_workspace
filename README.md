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

`tests/test_launcher_is_not_authorization.py` enforces all of it.

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
    modules=(launcher_feature, dotmac_application_directory.module),
    web_enabled=True,
)
```

Built with `dotmac_kernel.create_app`, never by hand — ADR-0015's fleet-wide
rule, and this is the worst application in the fleet to break it in, because its
whole job is a security boundary.

Migrations compose three separately-owned lineages into one revision graph: the
kernel's, the application-directory module's, and this repository's. Two of the
three are installed packages, so they are located through their owners' public
`versions_dir()` rather than hard-coded paths.

## Dependencies are pinned, never paths

`dotmac-kernel` and `dotmac-application-directory` are pinned exactly and
resolved only from the private Forgejo index (ADR-0005). **No path or editable
dependency is ever committed here** — this assembly lives in a different
repository from the packages it consumes, and a path dependency would make the
build depend on a sibling checkout.

### Before those versions are published

`dotmac-application-directory 0.1.0a1` and `dotmac-kernel 0.1.0a43` are not on
the index yet — they land with the `dotmac_starter_mt` pull requests this
repository was created alongside. Until then, test against locally built wheels
rather than relaxing the pins:

```sh
# in dotmac_starter_mt
poetry build -C packages/dotmac-application-directory
poetry build -C packages/dotmac-kernel

# here — install the wheels into the venv WITHOUT editing pyproject.toml
poetry run pip install \
  ../dotmac_starter_mt/packages/dotmac-kernel/dist/dotmac_kernel-0.1.0a43-*.whl \
  ../dotmac_starter_mt/packages/dotmac-application-directory/dist/*.whl
poetry run pytest
```

`make check` and `make test` work normally once both are on the index.

## Status: local scaffold, not a consumer

**Nothing here is deployed, and this repository is not yet a consumer of
`dotmac-application-directory`** — the module's dossier correctly records zero
production consumers. `docs/ADOPTION-BLOCKERS.md` lists what must clear first;
the one needing a kernel decision is **B1**: there is no cookie-compatible
permission seam, so the launcher guard authenticates without authorizing and
`/applications` must not be exposed to a real tenant. `/login` does not exist
yet either (B2), so the surface is unreachable end to end.

## Commands

| | |
|---|---|
| `make check` | ruff lint + format check + mypy |
| `make test` | pytest |
| `make dev` | run the development server |
| `make migrate` | compose all three lineages and upgrade |
