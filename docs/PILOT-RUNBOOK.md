# The real-IdP pilot — what it proves, and how to run it

The Workspace's login authenticated a real member during the 2026-08-16 pilot.
Its CI also proves the protocol against a provider double that mints tokens with
a throwaway key; this runbook remains the repeatable procedure for meeting a
real Keycloak, a real browser and a real member.

**Status: executed successfully in production on 2026-08-16.**

`https://idp.dotmac.io/realms/dotmac` is serving: valid TLS, the permanent
issuer, RS256 keys in JWKS, and the `dotmac-workspace` client already
configured to the table in section 2. Section 2 is therefore a description of
what exists, not instructions to follow — re-running it would be re-creating a
client that is already there.

The Workspace runs at `workspace.dotmac.io`. The pilot used two application
workers and proved real discovery/login, cross-worker ceremony consumption,
replay refusal, login-CSRF protection, explicit-binding refusal, selective
session revocation, and logout. Sections 4 onward are retained as the rerunnable
operator procedure, not as evidence that work is still pending.

## What this pilot is actually testing

Not "does OIDC work". The package's own suite already runs signature
verification, the algorithm allow-list, PKCE and the nonce check against a real
key pair, and the Workspace's suite runs them from a consumer's side. Those are
proven. The risks below could only be settled by a real deployment; the
2026-08-16 pilot supplied that evidence:

| production risk | what the pilot settled it with |
|---|---|
| discovery against a real realm | Keycloak's document, not our fixture's four fields |
| `kid` rotation | rotate the realm's signing key mid-session and sign in again |
| clock skew in the wild | two hosts, two clocks, no `freeze_time` |
| the cookie policy under a real proxy | `Secure` decided by a forwarded header we actually receive |
| the ceremony store across workers | more than one uvicorn worker, login started on one and finished on another |
| an operator's binding workflow | somebody who is not the author creating a binding from the CLI |

The last row is the one most likely to produce a surprise, and it is the reason
a pilot is a person doing this rather than a script.

---

## 1. Prerequisites

- The Workspace host: `94.72.104.67`, hostname `workspace`, key-only SSH from
  this Mac and seabone. Root credential in `secret/dotmac/hosts/workspace`.
- A DNS name resolving to it, and TLS terminating in front — the redirect URI
  must be `https`, and the package refuses an `http` token endpoint outright.
- Reachability from the app host to the fleet Postgres (`db-primary`) and to the
  Keycloak host.
- A Forgejo read token for the image build, from OpenBao
  (`secret/dotmac/forgejo/read-token#value`). Used through BuildKit's
  `--secret`, never as a build argument — see the `Dockerfile` header for why.

## 2. Keycloak: the realm and the client

One realm, one client. The settings below are not defaults, and three of them
are the difference between a pilot and a liability.

| setting | value | why |
|---|---|---|
| Client ID | `dotmac-workspace` | matches `WORKSPACE_OIDC_CLIENT_ID` |
| Client authentication | **On** (confidential) | a public client has no secret, so anyone with the client id can complete a ceremony |
| Standard flow | **On** | Authorization Code |
| Implicit flow | **Off** | returns tokens in the URL fragment — history, referrer, logs |
| Direct access grants | **Off** | password grant; the Workspace holds no passwords and must not learn any |
| Service accounts | **Off** | nothing here acts as itself |
| PKCE method | **S256** | `plain` sends the verifier in the authorization request, which is the interception PKCE exists to defeat |
| Valid redirect URI | `https://workspace.dotmac.io/login/callback` | EXACT. No wildcard, no trailing `*` |
| Web origins | `+` or empty | the Workspace makes no cross-origin call to Keycloak |

A wildcard redirect URI deserves its own sentence: `https://workspace.dotmac.io/*`
would let anyone who can get an authorization request issued redirect the code
to any path on the host, and the pilot would still appear to work.

The client secret is ALREADY in OpenBao at

    secret/dotmac/workspace/oidc/client-secret#value

alongside `client_id`, `realm`, `issuer` and `redirect_uri`. It was captured
straight from the admin API into the store and has never been pasted into a
terminal, a compose file or `.env`.

`idp:/opt/keycloak/verify.sh` asserts the realm and client settings above
against the COMPLETE client object, so drift is detectable rather than assumed.
Run it before the pilot rather than re-reading the table.

## 3. The database

The Workspace owns one database on `db-primary`, and two roles:

- an **admin** role that runs migrations and holds DDL;
- an **online** role the container uses, which holds no DDL at all.

That split is what makes "no migrations on boot" enforceable rather than
conventional — the running app *cannot* alter its own schema even if a future
change tried to.

    make migrate    # as the ADMIN role, from the deploy path, before the new image starts

Composing three lineages (kernel, application-directory, assembly) is what
`alembic.ini` and `migration_bindings.py` already handle; the pilot does not
introduce anything new here.

## 4. Build and deploy

**The deploy path runs an immutable digest, never a tag.** This changed with the
deployment-foundation adoption and it changes this procedure — see
`deploy/README.md`. `WORKSPACE_TAG` is gone, `:latest` is unreachable, and the
root compose file has no default: an unpinned host refuses to start rather than
silently running whatever the tag meant this morning.

Build and push a candidate:

    DOCKER_BUILDKIT=1 docker build \
      --secret id=forgejo_netrc,src="$HOME/.netrc" \
      -t "registry.dotmac.io/dotmac/workspace:${TAG}" .
    docker push "registry.dotmac.io/dotmac/workspace:${TAG}"

Resolve the DIGEST that push produced — the tag was only a handle to move the
bytes; from here nothing refers to it again:

    docker buildx imagetools inspect --raw \
      "registry.dotmac.io/dotmac/workspace:${TAG}" | sha256sum

Record that digest and the source revision it was built from in
`deploy/product.toml` (`[image] reference` and `source_revision`), run
`make deploy-render`, set `require-real-digests: true` in
`.github/workflows/deployment-conformance.yml`, and merge. The descriptor is the
image authority; the deploy path reads it, and nothing else may.

Then on the host: `.env` from `.env.example` with the four required values, the
client secret written from OpenBao to the path `WORKSPACE_OIDC_CLIENT_SECRET_PATH`
names, and

    WORKSPACE_IMAGE="$(scripts/resolve_deploy_image.sh)" docker compose up -d workspace

`resolve_deploy_image.sh` reads the reference out of
`deploy/rendered/docker-compose.yml` and refuses anything that is not
`name@sha256:<64 hex>` — including the all-zero placeholder the descriptor
carries until the step above is done. A refusal here means the descriptor has no
candidate yet, not that the script is broken.

**Recreate, never restart, after an environment change.** `docker compose
restart` re-runs the existing container with its old environment; only `up -d`
re-renders it. This has bitten the fleet before.

## 5. Seed the first member — the step people forget

There is **no self-registration and no JIT provisioning**. A verified subject
that no binding names resolves to nothing and the login is refused. So before
anybody can sign in, an operator creates the party and the binding:

    # `--tenant` is the tenant SLUG, not its uuid.
    docker compose exec workspace dotmac-workspace member add \
      --tenant "$TENANT_SLUG" --email person@dotmac.io \
      --first-name Their --last-name Name

    docker compose exec workspace dotmac-workspace bind \
      --tenant "$TENANT_SLUG" --email person@dotmac.io \
      --subject "$KEYCLOAK_SUBJECT" \
      --by "you@dotmac.io" --reason "pilot member, ticket NNNN"

    docker compose exec workspace dotmac-workspace bindings --tenant "$TENANT_SLUG"

`KEYCLOAK_SUBJECT` is the `sub` claim — not the username, not the email. It is
opaque and stable, and binding on anything a human chose is how an account is
taken over by whoever changes their email next.

The CLI's own docstring recommends the ordering that actually works in practice:
have the member **attempt a sign-in first**, then read the subject out of the
refusal. The refusal logs `issuer … subject … is not bound` server-side for
exactly this reason, and it beats copying an opaque id out of the Keycloak
console by hand.

`--by` and `--reason` have no defaults, deliberately: the kernel rejects a blank
and a CLI default would turn evidence into boilerplate, which is the same as
having none.

## 6. What to verify, in order

1. **`/login` renders** over TLS, and the response sets no session cookie.
2. **A full sign-in works** for the bound member, landing on `/applications`.
3. **`dmws_session` and `dmws_login_state` both carry `Secure`** — if not, the
   proxy's forwarded headers are not reaching the app and `FORWARDED_ALLOW_IPS`
   is wrong. Check this before anything else; a wrong value here silently
   downgrades every cookie.
4. **The ceremony cookie is gone** after the callback, on success and on
   failure.
5. **An unbound member is refused**, and the log names their subject.
6. **Two workers, one login.** Set the replica count above one and sign in
   repeatedly; a per-process ceremony store would fail a share of attempts at
   random. This is the property the PostgreSQL store exists for and the one a
   single-worker pilot would not test.
7. **Rotate the realm's signing key**, then sign in again without restarting the
   Workspace. The bounded forced JWKS refetch on an unknown `kid` should absorb
   it. If this fails, the pilot has found something CI could not.
8. **Disable the binding while the member is signed in** and confirm their
   session stops working immediately — kernel a65's selective revocation,
   against a real session rather than a canary:

       docker compose exec workspace dotmac-workspace disable \
         --tenant "$TENANT_SLUG" --binding-id "$BINDING_ID"

   Then re-bind and sign in again, which also exercises the reactivation path.

## 7. Rollback

There is no data migration to reverse and no product depends on the Workspace,
so rollback is `docker compose down` plus removing the DNS record. The database
can stay: it holds ceremonies (which expire), sessions (which can be revoked)
and bindings (which are evidence worth keeping).

If the pilot fails on something structural, the honest move is to leave the
Workspace down and record what was found. It has no users to disappoint yet, and
that is exactly why it is the right first deployment.

## 8. What this does NOT earn

Publishing `dotmac-auth-oidc` was earned by a consumer merging against the
released wheel. **`reuse-proven` needs a second real consumer**, and this pilot
is still the first one — a successful deployment makes the first consumer more
credible, not more numerous. ERP's deletion does not count either: removing an
implementation that was never live retires a duplicate without demonstrating
reuse. That boundary is recorded in the package's `EXTRACTION.toml`.
