# The Workspace deployment descriptor

`deploy/product.toml` is the Workspace's `ProductDeploymentSpec.v1`, implemented
by the published `dotmac-deployment-foundation==0.2.0a2` facility (Starter
ADR-0070). The package is exact-pinned as a dev dependency from Dotmac's private
Forgejo index; `poetry.lock` carries the wheel and sdist hashes the index
returned, which is what makes "published" a fact here rather than a claim. Its
annotated release tag peels to Starter commit
`55750e104df3dd94b6f9f70bf8c8db53986394c7`, and
`.github/workflows/deployment-conformance.yml` calls the Starter-owned reusable
gate at that SAME immutable commit — deliberately, because a2's only code change
and that revision's workflow change are two halves of one fix.

The pinned CLI deterministically renders, from that one descriptor:

- `deploy/rendered/docker-compose.yml`;
- `deploy/rendered/nginx/workspace.fixture.invalid.conf`;
- `deploy/rendered/otel-collector.yaml`;
- `deploy/rendered/alerts.rules.yml`.

Never hand-edit a rendered file. `make deploy-check` is a BYTE comparison, and a
reviewer is meant to read every deployment change as a diff.

## What this adoption claims

**Declarative input and a CI gate. Not the deployment engine.**

Saying so plainly is the point. The rendered project is not the Workspace's
runtime topology, the shared executor is not in the deploy path, and nothing
here deploys anything. Exactly ONE thing has moved out of the old world and into
this descriptor: the **image identity**.

## Host-neutral, and why that is the shape

`[ingress].host` is `workspace.fixture.invalid` — a reserved, permanently
non-resolvable name (RFC 2606 §2). The deployment's real host is **not in this
repository** and must not be committed to it.

That is not squeamishness. An artefact that names one deployment is about one
deployment, and a host name in Git is a fact about the world that nothing in Git
can keep true. The real host arrives at **authorization time** from the
environment inventory; the production vhost is rendered then, and that render's
digest is what binds into the execution plan and the receipt. CI never sees the
production name, so CI cannot leak it — and `render --check` against the fixture
is a byte comparison rather than a judgement call about a file nobody can
reproduce.

Two guards hold it, and both carry a **sensitivity proof** — the production
hostname is planted into a throwaway copy and each guard is required to report
it (`tests/test_deployment_descriptor.py`):

1. the descriptor's ingress host must sit under a reserved TLD; and
2. no deployment artefact — the descriptor, the product manifest, the
   thresholds, everything under `deploy/rendered/`, the nginx template, the root
   `docker-compose.yml`, and the `Makefile` — may name a real host. The one
   permitted exception is `registry.dotmac.io`, because the image has to come
   from somewhere, and it is listed by name so that adding a second one is a
   reviewable moment rather than a quiet edit.

`make nginx-render` now REFUSES without `NGINX_PUBLIC_HOST`. It used to default
to the production host, which is exactly how a default becomes an identity.

## The image: a digest, or nothing

The deploy path used to run

```
image: ${WORKSPACE_IMAGE:-registry.dotmac.io/dotmac/workspace}:${WORKSPACE_TAG:-latest}
```

so a bare `docker compose up -d` on a host with no `.env` pulled whatever
`:latest` meant that morning. A tag is a registry POINTER: the bytes it names
can be repushed after they were tested, which makes "the image we verified" and
"the image the host runs" two different facts that look identical in every log.

Now:

- the root `docker-compose.yml` declares `${WORKSPACE_IMAGE:?…}` — **no tag, no
  default**. An unpinned host refuses to start;
- `WORKSPACE_TAG` is retired, from the compose file and from `.env.example`;
- `deploy/rendered/docker-compose.yml` is the AUTHORITY for which image runs,
  and `scripts/resolve_deploy_image.sh` is the only supported way to get it onto
  the deploy path. It refuses anything that is not `name@sha256:<64 hex>`, and
  it refuses the all-zero placeholder **by name**;
- the descriptor itself cannot hold a tag: `ProductDeploymentSpec` refuses one at
  parse time, and `check_image_is_pinned_by_digest` refuses it again.

### The placeholder, and the ratchet that keeps it honest

`deploy/product.toml` currently pins the all-zero placeholder digest, because
**the Workspace has no image publication lane**. No CI run has ever built,
pushed and resolved a registry digest for `registry.dotmac.io/dotmac/workspace`,
so there is no candidate this repository can name. Writing a digest it could not
derive would be worse than the placeholder: it would READ as a pin while naming
an artefact nobody verified.

Nothing accepts the placeholder. The resolver refuses it, so **the Workspace
cannot be deployed from this descriptor as it stands** — which is the correct
failure. The deployment is an immutable digest, or it is nothing.

The conformance gate sets `require-real-digests: false`, and that exemption
states an enforceable premise rather than a promise:
`test_the_placeholder_exemption_states_an_enforceable_premise` fails the moment a
real digest lands without the gate being armed, and fails equally if the gate is
disarmed while the digest is real. ERP left this same flag off after its sentinel
was replaced and nothing noticed for weeks — an all-zero digest PARSES, so with
the gate off and no ratchet, nothing at all prevents a silent regression.

**To close it:** publish a candidate image, put its registry digest and the
source revision it was built from into `deploy/product.toml`, `make
deploy-render`, and set `require-real-digests: true`. The test will tell you if
you forget the last step.

## Current boundary — what is NOT the live path

`docs/PILOT-RUNBOOK.md` and the root `docker-compose.yml` remain the executing
deployment. These are measured refusals rather than omissions:

- **The rendered project has no `secrets:` block.** The Workspace's OIDC client
  secret reaches the container as a mounted FILE, written from OpenBao by the
  deploy path. `ProductDeploymentSpec.v1` has no vocabulary for a Compose file
  secret, so the rendered service declares
  `WORKSPACE_OIDC_CLIENT_SECRET_FILE` and nothing mounts anything at that path.
  The rendered project would start and fail to read its own client secret.
- **The rendered vhost is not the live vhost, and swapping it would be a
  security regression.** `deploy/nginx/workspace.conf.template` sends
  `Referrer-Policy: no-referrer`, deliberately stricter than the application's
  own value, because the OIDC callback URL carries an authorization code and a
  referrer header would hand it to whatever the page links to next. The rendered
  site sends `strict-origin-when-cross-origin`. It also serves TLS 1.3 only
  where the live site serves 1.2 and 1.3, and declares a warm-candidate upstream
  on `127.0.0.1:18001` that nothing here runs. The template stays the vhost
  source; the rendered file is conformance evidence.
- **The recovery contract is declared but not fully BOUND** — see "The recovery
  contract gap" below. The dataset is declared; the executor, the receipt and
  four of the seven required verification elements have no typed field to live
  in.
- **No telemetry.** `[telemetry]` declares `logs`, `metrics` and `traces` all
  false, because the Workspace runs no collector and no agent. A rendered
  `otel-collector.yaml` beside a deployment that ships nothing reads, to anyone
  who does not check, as telemetry.
- **The alert rules are renderable DEFINITIONS, not alerting.** The facility's
  own renderer states the fleet position: 64 catalogued, 22 producer-backed, and
  **zero** connected to an evaluator or a routing path. `deploy/alerts/thresholds.json`
  exists because every placeholder must resolve before the file can render at
  all; supplying a value is not a claim of coverage.
- **Resource limits are declared BOUNDS, not measurements.** Nothing in this
  repository profiles the Workspace and the running deployment declares no
  limits at all. The descriptor's comment says so where the numbers are.
- **The shared executor is not in the deploy path.** `dotmac-deploy deploy` has
  never run against the Workspace, and this adoption does not propose that it
  should until the gaps above close.

## The recovery contract gap — why this PR is red

The ownership split Michael specified:

> Workspace owns and declares its logical PostgreSQL dataset. The fleet recovery
> facility owns execution. A typed receipt binds checksum, verification results,
> isolated restore proof, and freshness. The shared physical host is INVENTORY,
> not dataset identity.
>
> Acceptance must FAIL when the executor is only prose, when the receipt is
> absent or stale, or when verification omits any of: roles, ownership,
> memberships, effective privileges, migration heads, schema, or data.

**`ProductDeploymentSpec.v1` at 0.2.0a2 cannot express it.** Three of the four
requirements have no typed field, and this was measured rather than assumed —
`tests/test_deployment_descriptor.py::test_foundation_a2_cannot_bind_the_recovery_contract`
reproduces every refusal below.

| requirement | 0.2.0a2 | observed |
|---|---|---|
| the executing owner | **absent** | `executed_by` → `unknown key(s) ['executed_by']` |
| a receipt, and its freshness | **absent** | `receipt` / `receipt_path` → unknown key; `dotmac-deploy backup` takes no arguments, so no receipt reaches the gate |
| verify `roles` | **refused** | `unknown verification(s) ['roles']` |
| verify `ownership` | **refused** | `unknown verification(s) ['ownership']` |
| verify `memberships` | **refused** | `unknown verification(s) ['memberships']` |
| verify `effective_privileges` | **refused** | `unknown verification(s) ['effective_privileges']` |
| verify `schema` / data / `migration_heads` | present | `BackupDataset.VERIFICATIONS` is exactly `("schema", "row_counts", "migration_heads")` |
| logical dataset identity | present | `code` + `kind` + `material`; nothing names a host |

`test_the_externally_executed_recovery_contract_is_fully_bound` therefore
**fails**, deliberately and without `xfail`. An `xfail` would let the suite go
green, and a green suite would present this adoption as finished while the
recovery contract is unbound.

### Why the missing four are not cosmetic

This repository already paid for the lesson. Its restore drill found that role
MEMBERSHIPS are cluster-level and absent from a database dump: a restored
database served `permission denied for table tenants` while holding a complete
copy of the data — schema present, rows present, unusable. PR #15 then
established that a privilege must be proved on **effective** privileges rather
than a `GRANT` listing, because a role reaching a table through a membership
reads as having no access and the assertion goes green over exactly the leak it
exists to detect. `roles`, `ownership`, `memberships` and `effective_privileges`
are the four elements that catch that class, and they are the four a2 refuses.

### The smallest published-contract change that would close it

Additive, so no existing descriptor breaks — which by the facility's own version
rule makes it a MINOR release rather than a major:

1. **`BackupDataset.VERIFICATIONS` gains four members** — `roles`, `ownership`,
   `memberships`, `effective_privileges`. Widening an allow-list breaks no
   descriptor that parses today.
2. **`BackupDataset.executed_by`** — an optional owner code, defaulting to the
   deployment itself, with the values that mean "this deployment's `Effects`"
   and "an external facility". When it names an external owner, the derived plan
   should omit the `backup` and `verify_backup` steps rather than attributing
   them to an executor that will never run.
3. **A receipt binding.** `BackupDataset.receipt` naming a file, plus a
   `RecoveryReceipt.v1` shape carrying the dataset, the write-time checksum, a
   verification result per declared element, an isolated-restore proof and a
   `produced_at`. Then `dotmac-deploy backup` reads it and **refuses on an
   absent or stale one**, which is what makes `restore_proof_max_age_days`
   enforceable instead of decorative.
4. **A cadence field** — `BackupDataset.interval_seconds`, so `assess()` stops
   taking the interval as a caller argument defaulting to a day for a dataset
   dumped hourly.

Points 3 and 4 are where the real value is: without them
`restore_proof_max_age_days` is a bound with nothing to evaluate against.

**Not done, on purpose:** the unpublished `0.3.0a1` carries `RehearsalReceipt.v1`
and `DeploymentProvenance.v1`. Borrowing them would pin a consumer to types no
index serves — the shape this whole programme refuses — and inventing a
Workspace-local encoding would satisfy this file's text while misdescribing who
executes the backup. Neither was done.

## Running the checks

```bash
make deploy-validate    # parse and check the descriptor
make deploy-check       # byte-compare deploy/rendered against the descriptor
make deploy-plan        # the ordered plan, with the mutation boundary marked
make deploy-image       # the image the deploy path may run, or the refusal
poetry run pytest tests/test_deployment_descriptor.py
```

Regenerate only with the exact pinned release:

```bash
make deploy-render
```
