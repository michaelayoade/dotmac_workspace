"""Operator bootstrap: the acts that must happen before anyone can log in.

## Why this exists at all

Federated login refuses an unbound subject, by design — no automatic
provisioning, no email matching. That is the right posture and it has an
obvious consequence: **the first member cannot log in until an operator binds
them**, and nothing in this assembly's HTML surface can do it, because that
surface is behind the very login being bootstrapped.

This module is the way in. It is the domain half; `cli.py` is the argparse
adapter over it (AGENTS.md §5 — a CLI is an adapter like any other).

## The four acts, and why all four are needed

A Workspace deployment composes the launcher and the application directory. It
does NOT compose a parties feature or an RBAC surface — those are a product
data plane's, and ADR-0021 keeps this plane thin. So a fresh tenant has a
`tenants` row and nothing else, and reaching `/applications` needs:

1. a **person party** to be (`ensure_member`),
2. an **admin role grant**, because `workspace.applications.read` declares
   `default_roles=("admin",)` and a member holding no role satisfies no
   permission (`grant_role`),
3. an **external identity binding**, so the provider's subject resolves to that
   party (`bind_identity`), and
4. nothing else. There is no fourth act, and that is the point — no password is
   set, no credential is created, and no token is minted anywhere in this file.

## Binding is evidenced, and disabling keeps the row

`bind_external_identity` requires `bound_by` and `reason`, and the CLI has no
default for either. Somebody with authority decided that this external subject
is this person; the row records who and why, and that record is the whole basis
on which a later audit can ask whether the decision was sound.

`disable_binding` deactivates and retains. It does NOT release the subject —
the row keeps occupying the unique key, so the same external subject cannot
afterwards be pointed at a different party while it exists. That is deliberate:
silently freeing the tuple would make "disable" a step on the path to handing
an external identity to somebody else.

**It also does not revoke existing sessions.** A member who is signed in stays
signed in until their session expires. Disabling guarantees only that no
FURTHER session is derived from the binding — `finalize_external_login` and
this call take the same row lock, so a login in flight either already committed
or blocks here and then refuses. Closing the remaining gap needs session
provenance on a KERNEL table; see `docs/ADOPTION-BLOCKERS.md`.
"""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from dotmac_kernel.exceptions import NotFoundError
from dotmac_kernel.external_identity import (
    bind_external_identity,
    disable_external_identity_binding,
)
from dotmac_kernel.identity import normalize_email, person_display_name
from dotmac_kernel.models import (
    ExternalIdentityBinding,
    Party,
    PartyPerson,
    PartyRoleGrant,
    PartyType,
    Role,
    Tenant,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from dotmac_workspace.launcher.guard import APPLICATIONS_READ_PERMISSION

#: The role the launcher's permission declares as its default holder. DERIVED
#: from the declaration rather than repeated as a literal: a bootstrap that
#: granted `"admin"` from its own string would keep granting it after the
#: permission moved to a different default, and the symptom would be a member
#: who signs in successfully and gets a 403 on the only page there is.
DEFAULT_ROLE_SLUG = APPLICATIONS_READ_PERMISSION.default_roles[0]


def find_member(db: Session, *, tenant: Tenant, email: str) -> Party | None:
    """The person party with this email in this tenant, or `None`.

    Matches on the NORMALIZED email, because `parties` is uniquely indexed on
    `lower(email)` and a case-mismatched lookup would silently miss a row the
    database considers the same one.
    """
    return db.scalars(
        select(Party)
        .where(Party.tenant_id == tenant.id)
        .where(Party.email == normalize_email(email))
        .where(Party.party_type == PartyType.person)
    ).first()


def ensure_member(
    db: Session,
    *,
    tenant: Tenant,
    email: str,
    first_name: str,
    last_name: str,
) -> Party:
    """The person party for `email`, created if absent. Idempotent.

    Creates the subtype profile in the same call, because a `person` party
    without a `party_persons` row is a half-created identity that every reader
    afterwards has to defend against.

    No credential is created. This plane has no password login and must not
    grow one — federated login is external OIDC (AGENTS.md §8).
    """
    existing = find_member(db, tenant=tenant, email=email)
    if existing is not None:
        return existing

    party = Party(
        tenant_id=tenant.id,
        party_type=PartyType.person,
        display_name=person_display_name(first_name, last_name),
        email=normalize_email(email),
        is_active=True,
    )
    db.add(party)
    db.flush()
    db.add(PartyPerson(party_id=party.id, first_name=first_name, last_name=last_name))
    db.flush()
    return party


def grant_role(
    db: Session, *, tenant: Tenant, party: Party, role_slug: str = DEFAULT_ROLE_SLUG
) -> Role:
    """Ensure the role exists in this tenant and that `party` holds it.

    Idempotent in both halves: the role is created only if this tenant has none
    by that slug, and the grant only if it is absent. Running the bootstrap
    twice is a no-op rather than a unique-constraint failure, which matters for
    a command an operator will re-run while getting the other arguments right.
    """
    role = db.scalars(
        select(Role).where(Role.tenant_id == tenant.id).where(Role.slug == role_slug)
    ).first()
    if role is None:
        role = Role(tenant_id=tenant.id, slug=role_slug, name=role_slug.title())
        db.add(role)
        db.flush()

    held = db.scalars(
        select(PartyRoleGrant)
        .where(PartyRoleGrant.tenant_id == tenant.id)
        .where(PartyRoleGrant.party_id == party.id)
        .where(PartyRoleGrant.role_id == role.id)
    ).first()
    if held is None:
        db.add(PartyRoleGrant(tenant_id=tenant.id, party_id=party.id, role_id=role.id))
        db.flush()
    return role


def bind_identity(
    db: Session,
    *,
    tenant: Tenant,
    party: Party,
    provider_binding: str,
    issuer: str,
    subject: str,
    bound_by: str,
    reason: str,
) -> ExternalIdentityBinding:
    """Bind a verified external subject to `party`. Delegates to the kernel.

    A thin pass-through on purpose: every rule about what a binding means —
    one identity per party per provider, a subject bound to at most one party,
    re-binding as the way to restore a disabled row, the evidence pair — is the
    kernel's and must have exactly one implementation.
    """
    return bind_external_identity(
        db,
        tenant=tenant,
        party=party,
        provider_binding=provider_binding,
        issuer=issuer,
        subject=subject,
        bound_by=bound_by,
        reason=reason,
    )


def list_bindings(db: Session, *, tenant: Tenant) -> Sequence[ExternalIdentityBinding]:
    """Every binding in this tenant, active or not.

    Disabled rows are INCLUDED. They are the ones an operator is usually
    looking for — a disabled binding still occupies the subject's unique key,
    so "why can I not bind this subject" is answered by a row that a
    active-only listing would have hidden.
    """
    return list(
        db.scalars(
            select(ExternalIdentityBinding)
            .where(ExternalIdentityBinding.tenant_id == tenant.id)
            .order_by(
                ExternalIdentityBinding.provider_binding,
                ExternalIdentityBinding.subject,
            )
        ).all()
    )


def disable_binding(
    db: Session, *, tenant: Tenant, binding_id: UUID
) -> ExternalIdentityBinding:
    """Deactivate a binding, keeping the row. Delegates to the kernel.

    Raises `NotFoundError` for an id that is not this tenant's — a cross-tenant
    id is a miss, not an error confirming that the id is real.
    """
    return disable_external_identity_binding(db, tenant=tenant, binding_id=binding_id)


__all__ = [
    "DEFAULT_ROLE_SLUG",
    "NotFoundError",
    "bind_identity",
    "disable_binding",
    "ensure_member",
    "find_member",
    "grant_role",
    "list_bindings",
]
