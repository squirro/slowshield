"""UI sign-in: who is looking at the UI, and what they may do (docs/authentication.md).

Every provider (OIDC now, SAML and Tailscale later) ends in the same `Principal`, so features only ever ask for a role.
The package proxy never looks at any of this.
"""

from __future__ import annotations

from dataclasses import dataclass

ROLES = ("viewer", "user", "admin")
RANK = {role: i for i, role in enumerate(ROLES)}


@dataclass(frozen=True, slots=True)
class Principal:
    """The person behind a UI request. Anonymous when nobody signed in (`user_id is None`)."""

    role: str = "viewer"
    user_id: int | None = None
    name: str | None = None
    email: str | None = None
    session: str | None = None  # the session's ID hash

    @property
    def signed_in(self) -> bool:
        return self.user_id is not None

    @property
    def label(self) -> str:
        """How the UI and the audit log name this person."""
        return self.name or self.email or (f"user {self.user_id}" if self.user_id is not None else "anonymous")

    def can(self, role: str) -> bool:
        return RANK[self.role] >= RANK[role]


ANONYMOUS = Principal()
