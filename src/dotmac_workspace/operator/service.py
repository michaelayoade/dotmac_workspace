"""Operator administration — the domain half of the supported surface.

`bootstrap.py` is the *first* member's way in and stays exactly that: the acts
an operator performs from a shell before anyone can sign in. This module is what
happens afterwards, from the browser, by somebody who is already signed in — so
it adds the reads that a screen needs and the two writes the CLI never had
(revoking a role, and listing who holds what).

## The invariant this module exists to protect

> A tenant must always retain at least one member who can BOTH sign in and
> manage members.

That is not the same as "at least one admin". A member with the admin role and
no active binding cannot sign in; a member with an active binding and no role
gets a 403 on every screen. Either alone is a locked-out tenant whose only way
back is a shell on the app host — which is precisely the situation the CLI is
kept for, and precisely the situation a supported UI should not create by
accident.

So `revoke_role` and `disable_binding_for` both refuse the last one, and say
why. `would_strand_tenant` is the single implementation of that question; two
copies of it would eventually disagree about what "stranded" means.

The refusal is deliberately not overridable from the browser. An operator who
genuinely means to strand the tenant — decommissioning it, say — does it from
the CLI, which is the recovery path and is honest about what it is.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

from dotmac_kernel.exceptions import ConflictError, NotFoundError
from dotmac_kernel.models import (
    ExternalIdentityBinding,
    Party,
    PartyRoleGrant,
    PartyType,
    Role,
    Tenant,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from dotmac_workspace.identity.bootstrap import (
    DEFAULT_ROLE_SLUG,
    bind_identity,
    disable_binding,
    ensure_member,
    find_member,
    grant_role,
)

#: The role that carries the operator permissions. Derived from the same
#: constant the launcher's permission declares, so "which role administers this
#: workspace" has one answer in the codebase rather than one per module.
ADMIN_ROLE_SLUG = DEFAULT_ROLE_SLUG


@dataclass(frozen=True, slots=True)
class MemberRow:
    """One member, with everything a screen needs to decide what to offer.

    Assembled here rather than in `web.py` so the page stays a thin adapter and
    the N+1 that a template would otherwise cause happens once, in SQL.
    """

    party: Party
    role_slugs: tuple[str, ...]
    binding: ExternalIdentityBinding | None

    @property
    def can_sign_in(self) -> bool:
        """Both halves, because either alone is a member who cannot work.

        This is the property the stranding check counts, and the one an operator
        most often gets wrong: a freshly added member looks complete on the
        screen and cannot log in, because nobody bound them yet.
        """
        return (
            self.party.is_active
            and ADMIN_ROLE_SLUG in self.role_slugs
            and self.binding is not None
            and self.binding.is_active
        )


def list_members(db: Session, *, tenant: Tenant) -> list[MemberRow]:
    """Every person party in this tenant, with roles and binding attached.

    Inactive parties are INCLUDED. An operator looking for "why can this person
    not sign in" needs to see them; filtering them out answers the question with
    silence.
    """
    parties = list(
        db.scalars(
            select(Party)
            .where(Party.tenant_id == tenant.id)
            .where(Party.party_type == PartyType.person)
            .order_by(Party.display_name)
        ).all()
    )
    if not parties:
        return []

    party_ids = [party.id for party in parties]

    grants: dict[UUID, list[str]] = {}
    for party_id, slug in db.execute(
        select(PartyRoleGrant.party_id, Role.slug)
        .join(Role, Role.id == PartyRoleGrant.role_id)
        .where(PartyRoleGrant.tenant_id == tenant.id)
        .where(PartyRoleGrant.party_id.in_(party_ids))
        .order_by(Role.slug)
    ).all():
        grants.setdefault(party_id, []).append(slug)

    bindings: dict[UUID, ExternalIdentityBinding] = {}
    for binding in db.scalars(
        select(ExternalIdentityBinding)
        .where(ExternalIdentityBinding.tenant_id == tenant.id)
        .where(ExternalIdentityBinding.party_id.in_(party_ids))
        # An active binding wins over a disabled one for the same party, so the
        # screen shows the row that actually governs sign-in rather than
        # whichever the database happened to return first.
        .order_by(ExternalIdentityBinding.is_active.desc())
    ).all():
        bindings.setdefault(binding.party_id, binding)

    return [
        MemberRow(
            party=party,
            role_slugs=tuple(grants.get(party.id, ())),
            binding=bindings.get(party.id),
        )
        for party in parties
    ]


def list_roles(db: Session, *, tenant: Tenant) -> Sequence[Role]:
    """Roles defined in this tenant, ordered by slug."""
    return list(
        db.scalars(
            select(Role).where(Role.tenant_id == tenant.id).order_by(Role.slug)
        ).all()
    )


def would_strand_tenant(db: Session, *, tenant: Tenant, losing_party_id: UUID) -> bool:
    """Would removing this member's ability to administer leave nobody able to?

    Counts members who can BOTH sign in and administer — see `MemberRow
    .can_sign_in`. The party being changed is excluded from the count, which is
    what makes this answer "after the change" rather than "right now".
    """
    return not any(
        row.can_sign_in
        for row in list_members(db, tenant=tenant)
        if row.party.id != losing_party_id
    )


def add_member(
    db: Session,
    *,
    tenant: Tenant,
    email: str,
    first_name: str,
    last_name: str,
    role_slug: str = ADMIN_ROLE_SLUG,
) -> Party:
    """Create (or find) a member and grant them a role.

    Delegates both halves to `bootstrap`, which already owns them. The member
    still cannot sign in afterwards — they have no binding — and the screen says
    so rather than leaving the operator to discover it at their first login.
    """
    party = ensure_member(
        db, tenant=tenant, email=email, first_name=first_name, last_name=last_name
    )
    grant_role(db, tenant=tenant, party=party, role_slug=role_slug)
    return party


def revoke_role(db: Session, *, tenant: Tenant, party_id: UUID, role_slug: str) -> None:
    """Remove a role grant. Refuses to strand the tenant.

    The write the CLI never had, and the reason this needs a stranding check at
    all: `grant_role` is idempotent and harmless, while revocation is the half
    that can end with nobody able to get back in.
    """
    party = db.scalars(
        select(Party).where(Party.tenant_id == tenant.id).where(Party.id == party_id)
    ).first()
    if party is None:
        raise NotFoundError("No such member in this tenant.")

    role = db.scalars(
        select(Role).where(Role.tenant_id == tenant.id).where(Role.slug == role_slug)
    ).first()
    if role is None:
        raise NotFoundError(f"This tenant has no role {role_slug!r}.")

    if role_slug == ADMIN_ROLE_SLUG and would_strand_tenant(
        db, tenant=tenant, losing_party_id=party_id
    ):
        raise ConflictError(
            "Refusing: this is the last member who can both sign in and "
            "administer this workspace. Removing it would lock everyone out, "
            "and the only way back would be a shell on the application host. "
            "Grant another member the role and bind them first."
        )

    grant = db.scalars(
        select(PartyRoleGrant)
        .where(PartyRoleGrant.tenant_id == tenant.id)
        .where(PartyRoleGrant.party_id == party_id)
        .where(PartyRoleGrant.role_id == role.id)
    ).first()
    if grant is None:
        return  # Idempotent: already not held.
    db.delete(grant)
    db.flush()


def bind_member(
    db: Session,
    *,
    tenant: Tenant,
    email: str,
    subject: str,
    issuer: str,
    provider_binding: str,
    bound_by: str,
    reason: str,
) -> ExternalIdentityBinding:
    """Bind an external subject to an existing member.

    `bound_by` is supplied by the CALLER from the authenticated session, never
    by the browser — see `web.py`. The member must already exist: creating one
    implicitly here would turn a binding mistake (a mistyped email) into a new
    half-formed identity rather than an error.
    """
    party = find_member(db, tenant=tenant, email=email)
    if party is None:
        raise NotFoundError(
            f"No member with email {email!r} in this workspace. Add them first."
        )
    return bind_identity(
        db,
        tenant=tenant,
        party=party,
        provider_binding=provider_binding,
        issuer=issuer,
        subject=subject,
        bound_by=bound_by,
        reason=reason,
    )


def disable_binding_for(
    db: Session, *, tenant: Tenant, binding_id: UUID
) -> ExternalIdentityBinding:
    """Disable a binding, refusing to strand the tenant.

    Since kernel 0.1.0a67 this ALSO revokes every session that binding issued,
    so the member is signed out immediately rather than at token expiry. That
    consequence is why the stranding check applies here and not only to roles:
    disabling the last usable binding locks the tenant out within the second.
    """
    binding = db.scalars(
        select(ExternalIdentityBinding)
        .where(ExternalIdentityBinding.tenant_id == tenant.id)
        .where(ExternalIdentityBinding.id == binding_id)
    ).first()
    if binding is None:
        raise NotFoundError("No such binding in this workspace.")

    if binding.is_active and would_strand_tenant(
        db, tenant=tenant, losing_party_id=binding.party_id
    ):
        raise ConflictError(
            "Refusing: this is the last binding that lets anyone sign in and "
            "administer this workspace. Disabling it would sign that member out "
            "immediately and leave no way back except a shell on the "
            "application host. Bind another administrator first."
        )
    return disable_binding(db, tenant=tenant, binding_id=binding_id)


__all__ = [
    "ADMIN_ROLE_SLUG",
    "ConflictError",
    "MemberRow",
    "NotFoundError",
    "add_member",
    "bind_member",
    "disable_binding_for",
    "list_members",
    "list_roles",
    "revoke_role",
    "would_strand_tenant",
]
