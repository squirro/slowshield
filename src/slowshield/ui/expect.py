"""The Setup page's "What to expect" table and its firewall host list.

The status codes are the ones the services answer with (their `_too_new` and `_blocked` responses, which
tests/integration/test_ui.py reads): a too-new download is `403`, or `425 Too Early` for Maven, NuGet, Composer and
RubyGems (each service's docstring says why); a block is `451`, except for container registries, where every refusal
is `403 DENIED`.
"""

from __future__ import annotations

from dataclasses import dataclass

from slowshield.config import LoadedConfig
from slowshield.ecosystems import IDS


@dataclass(frozen=True, slots=True)
class Expect:
    """One ecosystem's row. Text fields may hold `code` in backticks; `{days}` is the delay."""

    eco: str
    in_range: str  # what the resolver does when the newest version in a range is too new
    pinned: int  # the status a lockfile pin or direct download of a too-new version gets
    pinned_how: str  # what the client shows with it
    blocked: int  # the status for a blocked version
    blocked_how: str
    note: str = ""  # at most one short sentence


EXPECT: dict[str, Expect] = {
    e.eco: e
    for e in (
        Expect("pypi", "picks an older version", 403, "", 451, ""),
        Expect("npm", "picks an older version", 403, "", 451, ""),
        Expect(
            "go", "fails: `go.mod` names exact versions", 403, "prints the reason", 451, "",
            "`go get` and `@latest` pick the newest version that is old enough.",
        ),
        Expect(
            "maven", "picks an older version", 425, "status line only", 451, "",
            "Most builds pin exact versions, so they get the `425`.",
        ),
        Expect("cargo", "marked yanked: picks an older version", 403, "names the version to use", 451, "also yanked"),
        Expect(
            "nuget", "next version up, warning `NU1603`", 425, "status line only", 451, "",
            "Make `NU1603` an error: `Directory.Build.props` under Per tool.",
        ),
        Expect("composer", "picks an older version", 425, "names the version to use", 451, "",
               "Needs Composer 2.10 or later."),
        Expect(
            "rubygems", "picks an older version", 425, "Bundler: “can no longer be found”", 451, "",
            "Each platform gem counts from its own push time.",
        ),
        Expect(
            "oci", "a tag resolves to the image it had {days} days ago", 403, "the reason in the message",
            403, "the reason in the message", "containerd 2.2 and older print only `403 Forbidden`.",
        ),
    )
}  # fmt: skip

# Hosts a client goes to without SlowShield that aren't in the config: Maven's built-in name for Central (SlowShield
# fetches from repo1.maven.org), and GitHub, where Packagist's dist URLs point (api.github.com redirects to codeload).
CLIENT_ONLY_HOSTS: dict[str, tuple[str, ...]] = {
    "maven": ("repo.maven.apache.org",),
    "composer": ("api.github.com", "codeload.github.com"),
}


def rows(cfg: LoadedConfig, days: str) -> list[dict[str, object]]:
    """The table in ECOSYSTEMS order, with whether each ecosystem is enabled and serves brand-new packages."""
    out = []
    for eco in IDS:
        e = EXPECT[eco]
        out.append(
            {
                "eco": eco,
                "enabled": getattr(cfg.raw.upstreams, eco).enabled,
                "in_range": e.in_range.replace("{days}", days),
                "pinned": e.pinned,
                "pinned_how": e.pinned_how,
                "blocked": e.blocked,
                "blocked_how": e.blocked_how,
                "fail_open": cfg.fail_open_for(eco),
                "note": e.note,
            }
        )
    return out


def firewall_hosts(cfg: LoadedConfig) -> list[tuple[str, list[str]]]:
    """Per enabled ecosystem, the hosts to block at the firewall: the ones SlowShield fetches from, and the ones
    clients use that SlowShield doesn't. Each host once, under the first ecosystem that names it."""
    upstreams = cfg.raw.upstreams
    seen: set[str] = set()
    out = []
    for eco, hosts in upstreams.hosts().items():
        if not getattr(upstreams, eco).enabled:
            continue
        new = [h for h in (*hosts, *CLIENT_ONLY_HOSTS.get(eco, ())) if h not in seen]
        seen.update(new)
        if new:
            out.append((eco, new))
    return out
