"""The leader's policy on a follower: what a bundle may change, and the config the follower then runs with.

The follower merges the leader's bundle into its own config (`effective`):

- **Stricter wins** against the policy keys this instance sets itself (`LoadedConfig.explicit`); its defaults don't
  count. Its own exceptions keep their authority over the leader's default delay, but a stricter rule from the
  leader for the same package still applies.
- **The floor** (`shieldwall.min_delay_days`, 1 day by default) bounds every delay from the leader, exceptions for
  single versions included.

A bundle that loosens what applies now (`loosens`) waits out a hold-down; meanwhile the stricter of both applies
(`tightest`). Tightening never waits.
"""

from __future__ import annotations

import dataclasses
import math
from dataclasses import dataclass
from typing import Any

import msgspec

from slowshield.config import ECOSYSTEMS, ExceptionRule, LoadedConfig, OciUpstream, rule_tables

POLICY_HOLD = 3600.0  # seconds a loosening policy waits before it applies
MAX_DELAY_DAYS = 3650.0


class BundleError(ValueError):
    pass


class Bundle(msgspec.Struct, forbid_unknown_fields=False):
    version: int
    default_delay_days: float
    fail_open: bool
    enforce_age_on_download: bool
    issued: float = 0.0
    fail_open_by_ecosystem: dict[str, bool] = {}
    exceptions: list[ExceptionRule] = []

    @classmethod
    def parse(cls, doc: Any) -> Bundle:
        """A bundle from the leader, checked: a signed bundle can still carry nonsense."""
        try:
            b = msgspec.convert(doc, cls, strict=True)
        except msgspec.ValidationError as exc:
            raise BundleError(f"malformed policy: {exc}") from exc
        delays = [b.default_delay_days, *(e.delay_days for e in b.exceptions)]
        if not all(math.isfinite(d) and 0 <= d <= MAX_DELAY_DAYS for d in delays):
            raise BundleError("policy delay out of range")
        if not set(b.fail_open_by_ecosystem) <= set(ECOSYSTEMS):
            raise BundleError("policy names an unknown ecosystem")
        if len(b.exceptions) > 10_000 or b.version < 1:
            raise BundleError("policy out of bounds")
        return b

    def to_json(self) -> str:
        return msgspec.json.encode(self).decode()

    @classmethod
    def from_json(cls, text: str) -> Bundle:
        return msgspec.json.decode(text, type=cls)

    def fail_open_for(self, eco: str) -> bool:
        return self.fail_open_by_ecosystem.get(eco, self.fail_open)


@dataclass(slots=True)
class _Rules:
    """A bundle's delays as lookup tables (names normalised by the follower's own registry settings)."""

    default: float
    pkg: dict[tuple[str, str], float]
    ver: dict[tuple[str, str, str], float]

    @classmethod
    def of(cls, b: Bundle, oci: OciUpstream) -> _Rules:
        pkg, ver = rule_tables(b.exceptions, oci)
        return cls(b.default_delay_days, pkg, ver)

    def rule(self, key: tuple[str, ...]) -> float | None:
        """The rule that applies to a package (eco, name) or a version (eco, name, version), if any."""
        if len(key) == 3:
            v = self.ver.get(key)
            if v is not None:
                return v
        return self.pkg.get((key[0], key[1]))

    def delay(self, key: tuple[str, ...]) -> float:
        v = self.rule(key)
        return self.default if v is None else v

    def keys(self) -> set[tuple[str, ...]]:
        return {*self.pkg, *self.ver}


def loosens(old: Bundle, new: Bundle, oci: OciUpstream) -> list[str]:
    """What in `new` is looser than `old`: a lower delay anywhere, fail-open turned on, or the download check off."""
    a, b = _Rules.of(old, oci), _Rules.of(new, oci)
    out: list[str] = []
    if b.default < a.default:
        out.append(f"default delay {a.default:g} → {b.default:g} days")
    out.extend(
        f"{'/'.join(key)}: {a.delay(key):g} → {b.delay(key):g} days"
        for key in sorted(a.keys() | b.keys())
        if b.delay(key) < a.delay(key)
    )
    out.extend(f"fail open for {eco}" for eco in ECOSYSTEMS if new.fail_open_for(eco) and not old.fail_open_for(eco))
    if old.enforce_age_on_download and not new.enforce_age_on_download:
        out.append("no age check on downloads")
    return out


def tightest(old: Bundle, new: Bundle, oci: OciUpstream) -> Bundle:
    """The stricter of two bundles, value by value, carrying `new`'s version."""
    a, b = _Rules.of(old, oci), _Rules.of(new, oci)
    rules = [
        ExceptionRule(ecosystem=key[0], package=key[1], version=key[2] if len(key) == 3 else None,  # ty: ignore[invalid-argument-type]
                      delay_days=max(a.delay(key), b.delay(key)))
        for key in sorted(a.keys() | b.keys())
    ]  # fmt: skip
    return Bundle(
        version=new.version,
        issued=new.issued,
        default_delay_days=max(a.default, b.default),
        fail_open=old.fail_open and new.fail_open,
        fail_open_by_ecosystem={eco: old.fail_open_for(eco) and new.fail_open_for(eco) for eco in ECOSYSTEMS},
        enforce_age_on_download=old.enforce_age_on_download or new.enforce_age_on_download,
        exceptions=rules,
    )


def effective(local: LoadedConfig, bundle: Bundle) -> LoadedConfig:
    """This instance's config with the leader's policy merged in."""
    raw = local.raw
    floor = raw.shieldwall.min_delay_days
    oci = raw.upstreams.oci
    own_default = raw.default_delay_days if "default_delay_days" in local.explicit else None
    mine = _Rules.of(Bundle(version=1, default_delay_days=0, fail_open=True, enforce_age_on_download=False,
                            exceptions=raw.exceptions), oci)  # fmt: skip
    theirs = _Rules.of(bundle, oci)

    def merged(key: tuple[str, ...]) -> float:
        own, leader = mine.rule(key), theirs.rule(key)
        if leader is not None:
            leader = max(leader, floor)
        if own is not None:  # this instance's exception: the leader's default can't loosen or tighten it
            return own if leader is None else max(own, leader)
        assert leader is not None  # noqa: S101 - keys come from either side's rules
        return max(leader, own_default or 0.0)

    pkg = {key: merged(key) for key in {*mine.pkg, *theirs.pkg}}
    ver = {key: merged(key) for key in {*mine.ver, *theirs.ver}}
    default = max(bundle.default_delay_days, floor, own_default or 0.0)

    own_fail_open = raw.fail_open if "fail_open" in local.explicit else True
    upstreams = raw.upstreams
    for eco in ECOSYSTEMS:
        up = getattr(upstreams, eco)
        own = up.fail_open if up.fail_open is not None else own_fail_open
        upstreams = msgspec.structs.replace(
            upstreams, **{eco: msgspec.structs.replace(up, fail_open=own and bundle.fail_open_for(eco))}
        )
    enforce = bundle.enforce_age_on_download or (
        raw.enforce_age_on_download if "enforce_age_on_download" in local.explicit else False
    )
    new_raw = msgspec.structs.replace(
        raw,
        default_delay_days=default,
        fail_open=own_fail_open and bundle.fail_open,
        enforce_age_on_download=enforce,
        upstreams=upstreams,
        exceptions=[
            ExceptionRule(ecosystem=k[0], package=k[1], version=k[2] if len(k) == 3 else None, delay_days=d)  # ty: ignore[invalid-argument-type]
            for k, d in sorted({**pkg, **ver}.items())
        ],
    )
    return dataclasses.replace(local, raw=new_raw, _pkg_rules=pkg, _ver_rules=ver)


def describe(local: LoadedConfig, bundle: Bundle | None) -> list[dict[str, Any]]:
    """The policy for the Shield wall page: each key as this instance sets it (None: not set), as the leader sets it,
    and what applies."""
    raw = local.raw
    eff = effective(local, bundle).raw if bundle is not None else raw
    return [
        {
            "key": key,
            "local": getattr(raw, key) if key in local.explicit else None,
            "leader": getattr(bundle, key) if bundle is not None else None,
            "applied": getattr(eff, key),
        }
        for key in ("default_delay_days", "fail_open", "enforce_age_on_download")
    ]
