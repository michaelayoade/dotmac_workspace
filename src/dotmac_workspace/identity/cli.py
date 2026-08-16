"""`dotmac-workspace` — bootstrap and recovery, not day-to-day administration.

A thin argparse adapter over `bootstrap.py` (AGENTS.md §5): it parses, opens a
tenant-scoped session through the kernel, delegates, and prints. It contains no
query and makes no decision.

## This is the recovery path. The supported path is the browser.

`operator/web.py` serves Members and Identity screens, and routine work belongs
there: it authorizes each act against a declared permission, records the acting
operator as the binding evidence rather than trusting a typed `--by`, and
refuses the changes that would lock the tenant out.

This command does none of that, and deliberately so. It reaches the database
directly, it accepts whatever `--by` it is given, and it will happily strand a
tenant. Those are the properties you want from a recovery tool and exactly the
properties you do not want from an everyday one. Reach for it in three cases:

1. **Bootstrap.** The first member cannot be created from a surface that is
   behind the login they do not yet have.
2. **Lockout.** Nobody can sign in, so the browser path is unavailable. This is
   the case the UI's stranding refusals exist to make rare — and the case that
   is the reason this command is kept rather than deleted.
3. **An API-only deployment.** `web_enabled=False` mounts no screens at all.

Using it for routine changes is not forbidden; it just means the act is
attributed to whatever `--by` was typed, and is a shell session on the
application host rather than an authorized request.

## Typical first run

    export WORKSPACE_OIDC_ISSUER=https://idp.example.net/realms/dotmac
    export WORKSPACE_OIDC_CLIENT_ID=dotmac-workspace
    export WORKSPACE_OIDC_REDIRECT_URL=https://ws.example.net/login/callback

    dotmac-workspace member add --tenant acme \\
        --email ada@acme.example --first-name Ada --last-name Lovelace
    dotmac-workspace bind --tenant acme --email ada@acme.example \\
        --subject 8f1c… --by "michael@dotmac" --reason "ACME onboarding, ticket 4417"
    dotmac-workspace bindings --tenant acme

`--subject` is the provider's `sub` claim for that person, which is opaque and
not guessable. The way to find it is to have them attempt a sign-in first: the
refusal logs `issuer … subject … is not bound`, server-side, precisely so this
command has something to be given. That ordering is deliberate — it means a
binding is made against a subject the provider actually asserted, rather than
one somebody typed from a directory export.

## Why the session comes from the kernel

`dotmac_kernel.db.tenant_session_by_slug` looks the tenant up and then sets the
row-level-security scope on the SAME session. Doing it by hand is a trap the
fleet has already fallen into: `tenants` is not tenant-scoped, so the lookup
succeeds with no scope set, and a command that forgets the second step gets a
working query followed by silence — which is how an academy audit command
reported a clean estate it could not see.

## What this command cannot do

It cannot set a password (there are none), cannot mint a session or a token,
and cannot grant anything in a target application. A Workspace role grant says
what a member may do HERE; every target application decides its own access from
its own tables, and no command in this repository can reach across that line.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from uuid import UUID

from dotmac_kernel.db import tenant_session_by_slug
from dotmac_kernel.exceptions import ConflictError, NotFoundError

from dotmac_workspace.identity import bootstrap, config


def _issuer_and_binding(
    issuer: str | None, provider_binding: str | None
) -> tuple[str, str]:
    """Fill the provider halves from configuration when not given explicitly.

    Defaulting from the deployment's own configuration is the point: an
    operator binding an identity for the provider this Workspace federates to
    should not have to retype its issuer, and a typo there produces a binding
    that resolves for nobody and looks correct in every listing.
    """
    configured = config.load()
    resolved_issuer = (issuer or "").strip() or (
        configured.issuer if configured else ""
    )
    resolved_binding = (provider_binding or "").strip() or (
        configured.provider_binding if configured else config.DEFAULT_PROVIDER_BINDING
    )
    if not resolved_issuer:
        raise SystemExit(
            "no issuer given and none configured — pass --issuer or set "
            f"{config.ISSUER_ENV}"
        )
    return resolved_issuer, resolved_binding


def _add_member(args: argparse.Namespace) -> int:
    with tenant_session_by_slug(args.tenant) as (db, tenant):
        party = bootstrap.ensure_member(
            db,
            tenant=tenant,
            email=args.email,
            first_name=args.first_name,
            last_name=args.last_name,
        )
        bootstrap.grant_role(db, tenant=tenant, party=party)
        print(
            f"member {party.email} ({party.id}) in tenant {tenant.slug}, "
            f"holding role {bootstrap.DEFAULT_ROLE_SLUG!r}"
        )
    return 0


def _bind(args: argparse.Namespace) -> int:
    issuer, provider_binding = _issuer_and_binding(args.issuer, args.provider_binding)
    with tenant_session_by_slug(args.tenant) as (db, tenant):
        party = bootstrap.find_member(db, tenant=tenant, email=args.email)
        if party is None:
            print(
                f"no person party with email {args.email!r} in tenant "
                f"{tenant.slug} — run `member add` first",
                file=sys.stderr,
            )
            return 2
        try:
            binding = bootstrap.bind_identity(
                db,
                tenant=tenant,
                party=party,
                provider_binding=provider_binding,
                issuer=issuer,
                subject=args.subject,
                bound_by=args.by,
                reason=args.reason,
            )
        except (ConflictError, ValueError) as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return 2
        print(
            f"bound {binding.subject} at {binding.issuer} "
            f"(provider binding {binding.provider_binding!r}) to "
            f"{party.email} — binding {binding.id}"
        )
    return 0


def _bindings(args: argparse.Namespace) -> int:
    with tenant_session_by_slug(args.tenant) as (db, tenant):
        rows = bootstrap.list_bindings(db, tenant=tenant)
        if not rows:
            print(f"no external identity bindings in tenant {tenant.slug}")
            return 0
        for row in rows:
            state = "active" if row.is_active else "disabled"
            print(
                f"{row.id}  {state:<8}  {row.provider_binding}  "
                f"{row.issuer}  {row.subject}  bound_by={row.bound_by}"
            )
    return 0


def _disable(args: argparse.Namespace) -> int:
    with tenant_session_by_slug(args.tenant) as (db, tenant):
        try:
            binding = bootstrap.disable_binding(
                db, tenant=tenant, binding_id=UUID(args.binding_id)
            )
        except (NotFoundError, ValueError) as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return 2
        # This message told the operator the opposite of what had just
        # happened. It was written before kernel a67 and said sessions already
        # issued "stay valid until it expires" — during the first real pilot a
        # signed-in member was cut off mid-session while this line claimed they
        # would not be. An operator trusting it would have gone looking for
        # another lever to pull, or worse, assumed the member still had access.
        print(
            f"disabled binding {binding.id}. No further session can be derived "
            "from it, AND every session already issued from it has been "
            "revoked — the member is signed out now, not when their token "
            "expires. Both happen in one transaction under the binding's row "
            "lock, so a login racing this either loses and is refused, or wins "
            "and is revoked a moment later (kernel a67)."
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dotmac-workspace",
        description=(
            "Operator bootstrap for the DotMac Tenant Workspace: members, "
            "their role, and their external identity bindings."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    member = sub.add_parser("member", help="member commands")
    member_sub = member.add_subparsers(dest="member_command", required=True)
    add = member_sub.add_parser(
        "add",
        help="create a person party (idempotent) and grant it the workspace role",
    )
    add.add_argument("--tenant", required=True, help="tenant slug")
    add.add_argument("--email", required=True)
    add.add_argument("--first-name", required=True)
    add.add_argument("--last-name", required=True)
    add.set_defaults(handler=_add_member)

    bind = sub.add_parser(
        "bind", help="bind a verified external subject to an existing member"
    )
    bind.add_argument("--tenant", required=True, help="tenant slug")
    bind.add_argument("--email", required=True, help="the member's email")
    bind.add_argument("--subject", required=True, help="the provider's `sub` claim")
    bind.add_argument("--issuer", help=f"defaults to ${config.ISSUER_ENV}")
    bind.add_argument(
        "--provider-binding",
        help=f"defaults to ${config.PROVIDER_BINDING_ENV}",
    )
    # No defaults, deliberately. The kernel requires both and rejects a blank;
    # a CLI default would turn evidence into boilerplate, which is the same as
    # having none.
    bind.add_argument("--by", required=True, help="who decided this binding")
    bind.add_argument("--reason", required=True, help="why — a ticket, a request")
    bind.set_defaults(handler=_bind)

    bindings = sub.add_parser(
        "bindings", help="list this tenant's bindings, including disabled ones"
    )
    bindings.add_argument("--tenant", required=True, help="tenant slug")
    bindings.set_defaults(handler=_bindings)

    disable = sub.add_parser(
        "disable", help="deactivate a binding, keeping the row and its evidence"
    )
    disable.add_argument("--tenant", required=True, help="tenant slug")
    disable.add_argument("--binding-id", required=True)
    disable.set_defaults(handler=_disable)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = args.handler
    return int(handler(args))


if __name__ == "__main__":  # pragma: no cover - console-script entry point
    raise SystemExit(main())


__all__ = ["build_parser", "main"]
