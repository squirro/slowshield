"""From the IdP's claims to a SlowShield role: one generic rule set for every IdP (docs/authentication.md).

An admin rule that matches makes an Admin, else a user rule makes a User, else the default role applies. Email rules
count only for a verified address. The IdP decides: the role is worked out again at every sign-in and recheck.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from slowshield.config import AuthConfig


@dataclass(frozen=True, slots=True)
class Role:
    role: str
    source: str  # claim:<values> | email:<rule> | default
    warning: str | None = None  # e.g. a group claim the IdP left out because it was too big


def claim(claims: dict[str, Any], path: str) -> Any:
    """A claim by name, or by dotted path into nested objects (`realm_access.roles`). A name that exists as it is wins,
    so URL-like claim names with dots still work."""
    if path in claims:
        return claims[path]
    node: Any = claims
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def claim_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def email_verified(claims: dict[str, Any]) -> bool:
    """Only an explicit true counts (some IdPs send the string "true"). Entra ID sends nothing: never verified."""
    v = claims.get("email_verified")
    return v is True or (isinstance(v, str) and v.lower() == "true")


def _email_match(email: str, rules: list[str]) -> str | None:
    address = email.strip().lower()
    for rule in rules:
        r = rule.strip().lower()
        if r == address or (r.startswith("*@") and address.endswith(r[1:])):
            return rule
    return None


def missing_required(claims: dict[str, Any], rules: list[str]) -> str | None:
    """The first `claim=value` rule the claims don't meet (a list claim meets it when it contains the value)."""
    for rule in rules:
        name, _, value = rule.partition("=")
        have = claim(claims, name.strip())
        values = claim_values(have) if not isinstance(have, bool | int | float) else [str(have).lower()]
        if value.strip() not in values:
            return rule
    return None


def decide(auth: AuthConfig, claims: dict[str, Any]) -> Role:
    oidc = auth.oidc
    warning = None
    granted: list[str] = []
    if oidc.roles_claim:
        top = oidc.roles_claim.split(".", 1)[0]
        names = claims.get("_claim_names")
        if claim(claims, oidc.roles_claim) is None and isinstance(names, dict) and top in names:
            warning = (
                f"the IdP left out the {top!r} claim because it is too big (Entra ID's group overage): map roles "
                "through app roles instead"
            )
        granted = claim_values(claim(claims, oidc.roles_claim))
    email = claims.get("email") if isinstance(claims.get("email"), str) else None
    verified = email is not None and email_verified(claims)
    for role, values, emails in (("admin", oidc.admin_values, auth.admin_emails),
                                 ("user", oidc.user_values, auth.user_emails)):  # fmt: skip
        hits = [v for v in values if v in granted]
        if hits:
            return Role(role, "claim:" + ",".join(hits), warning)
        if verified and email is not None and (rule := _email_match(email, emails)):
            return Role(role, f"email:{rule}", warning)
    return Role(auth.default_role, "default", warning)
