#!/usr/bin/env python3
"""Generate the Grafana-managed alert rules for SlowShield (stdlib only).

    python3 observability/build_alerts.py          # write grafana/provisioning/alerting/rules.yaml
    python3 observability/build_alerts.py --check  # exit 1 if the committed file is stale

Each rule: one PromQL query (A) + a threshold expression (C). The YAML is emitted as JSON, which is
valid YAML and keeps this generator dependency-free.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

OUT = Path(__file__).resolve().parent / "grafana" / "provisioning" / "alerting" / "rules.yaml"
# Each rule links to the "### <Title>" section of the alert runbook (GitHub anchors are lower-cased).
RUNBOOK = "https://github.com/squirro/slowshield/blob/main/docs/operations.md"
PROM_UID = "slowshield-prometheus"


def rule(
    uid: str,
    title: str,
    expr: str,
    *,
    op: str,
    threshold: float,
    for_: str,
    severity: str,
    summary: str,
    description: str,
    no_data: str = "OK",
    window: int = 900,
    anchor: str,
) -> dict[str, Any]:
    return {
        "uid": uid,
        "title": title,
        "condition": "C",
        "data": [
            {
                "refId": "A",
                "relativeTimeRange": {"from": window, "to": 0},
                "datasourceUid": PROM_UID,
                "model": {"refId": "A", "expr": expr, "instant": True, "intervalMs": 1000, "maxDataPoints": 43200},
            },
            {
                "refId": "C",
                "datasourceUid": "__expr__",
                "model": {
                    "refId": "C",
                    "type": "threshold",
                    "expression": "A",
                    "conditions": [{"evaluator": {"type": op, "params": [threshold]}}],
                },
            },
        ],
        "for": for_,
        "noDataState": no_data,
        "execErrState": "Error",
        "isPaused": False,
        "labels": {"severity": severity, "service": "slowshield"},
        "annotations": {
            "summary": summary,
            "description": description,
            "runbook_url": f"{RUNBOOK}#{anchor}",
        },
    }


SRV = "http_server_request_duration_seconds"
CLI = "http_client_request_duration_seconds"
META_ROUTES = 'http_route=~".*simple/\\\\{project\\\\}/|(/npm)?/\\\\{package\\\\}"'

GROUPS: list[dict[str, Any]] = [
    {
        "name": "slowshield-security",
        "interval": "1m",
        "rules": [
            rule(
                "slowshield-tamper-detected",
                "TamperDetected",
                'sum by (slowshield_ecosystem, slowshield_event) (increase(slowshield_security_events_total{slowshield_event=~"tampered|integrity_mismatch"}[10m]))',
                op="gt",
                threshold=0,
                for_="0s",
                severity="critical",
                window=600,
                anchor="tamperdetected",
                summary="An artifact's bytes did not match its fingerprint ({{ $labels.slowshield_ecosystem }})",
                description="SlowShield aborted a download because the bytes differed from the first-seen SHA-256 or the "
                "registry's published digest. Check the SlowShield UI → Security for the artifact and client; treat as a "
                "possible supply-chain compromise until explained.",
            ),
            rule(
                "slowshield-malware-blocked",
                "MalwareBlocked",
                'sum by (slowshield_ecosystem) (increase(slowshield_security_events_total{slowshield_event="blocked"}[10m]))',
                op="gt",
                threshold=0,
                for_="0s",
                severity="warning",
                window=600,
                anchor="malwareblocked",
                summary="Someone tried to install a known-malicious {{ $labels.slowshield_ecosystem }} package",
                description="A request for a package on the threat-feed blocklist was refused with HTTP 451. The install was "
                "prevented; find the requesting machine (client IP) in the SlowShield UI → Security and check how the "
                "dependency got there.",
            ),
            rule(
                "slowshield-fail-open-spike",
                "FailOpenSpike",
                'sum(increase(slowshield_decisions_total{slowshield_decision="fail_open"}[1h]))',
                op="gt",
                threshold=50,
                for_="10m",
                severity="warning",
                window=3600,
                anchor="failopenspike",
                summary="Many brand-new packages are being served without the delay (fail-open)",
                description="More than 50 fail-open responses in the last hour: packages with no version older than the delay "
                "were served anyway. Usually new internal or newly adopted packages; a sudden spike can also be dependency "
                "confusion or typosquatting. Review the Leaderboards → Fail-open list.",
            ),
        ],
    },
    {
        "name": "slowshield-feeds",
        "interval": "1m",
        "rules": [
            rule(
                "slowshield-feed-disabled",
                "FeedDisabled",
                'max by (feed, reason) (slowshield_feed_enabled{reason!="disabled"})',
                op="lt",
                threshold=1,
                for_="15m",
                severity="warning",
                anchor="feeddisabled",
                summary="Threat feed {{ $labels.feed }} is not running ({{ $labels.reason }})",
                description="reason=missing_token: set GITHUB_TOKEN (or GITHUB_TOKEN_FILE) and restart SlowShield. "
                "reason=error: the last sync failed — check SlowShield logs and the UI → Feeds page. Known malware from this "
                "source is not being blocked.",
            ),
            rule(
                "slowshield-feed-stale",
                "FeedStale",
                "(time() - max by (feed) (slowshield_feed_last_success_timestamp_seconds)) "
                'unless on (feed) max by (feed) (slowshield_feed_enabled{reason="disabled"})',
                op="gt",
                threshold=10800,
                for_="10m",
                severity="warning",
                anchor="feedstale",
                summary="Threat feed {{ $labels.feed }} has not synced successfully for over 3 hours",
                description="No successful sync for more than 3× the default poll interval (60 min). New malware advisories "
                "are not being applied. Check upstream reachability (osv-vulnerabilities.storage.googleapis.com / "
                "api.github.com) and the SlowShield logs.",
            ),
            rule(
                "slowshield-feed-errors",
                "FeedErrors",
                "sum by (feed) (increase(slowshield_feed_errors_total[1h]))",
                op="gt",
                threshold=2,
                for_="0s",
                severity="warning",
                window=3600,
                anchor="feederrors",
                summary="Threat feed {{ $labels.feed }} failed repeatedly in the last hour",
                description="More than two failed sync runs within an hour. See the last error on the SlowShield UI → Feeds page.",
            ),
        ],
    },
    {
        "name": "slowshield-service",
        "interval": "1m",
        "rules": [
            rule(
                "slowshield-down",
                "SlowShieldDown",
                "absent(slowshield_build_info)",
                op="gt",
                threshold=0,
                for_="5m",
                severity="critical",
                window=600,
                anchor="slowshielddown",
                summary="No SlowShield instance is reporting telemetry",
                description="slowshield_build_info has been absent for 5 minutes: SlowShield is down or cannot reach the "
                "collector (Alloy). Package installs through the proxy are probably failing.",
            ),
            rule(
                "slowshield-no-leader",
                "NoLeader",
                "sum(slowshield_leader)",
                op="lt",
                threshold=1,
                for_="10m",
                severity="warning",
                anchor="noleader",
                summary="No SlowShield worker holds the leader lock",
                description="Feeds, cache eviction and retention run only on the leader. Check that the data volume is "
                "writable (leader.lock).",
            ),
            rule(
                "slowshield-upstream-errors",
                "UpstreamErrorRate",
                f'sum by (server_address) (histogram_count(rate({CLI}{{http_response_status_code=~"5..|0|429"}}[5m]))) '
                f"/ sum by (server_address) (histogram_count(rate({CLI}[5m])))",
                op="gt",
                threshold=0.05,
                for_="10m",
                severity="warning",
                window=600,
                anchor="upstreamerrorrate",
                summary="More than 5% of requests to {{ $labels.server_address }} fail",
                description="Upstream 5xx/429 responses or transport errors. SlowShield serves stale metadata where it can, but "
                "new metadata and uncached artifacts fail. Check the registry status page and egress connectivity.",
            ),
            rule(
                "slowshield-http-5xx",
                "Http5xxRate",
                f'sum(histogram_count(rate({SRV}{{http_response_status_code=~"5.."}}[5m]))) / sum(histogram_count(rate({SRV}[5m])))',
                op="gt",
                threshold=0.02,
                for_="10m",
                severity="warning",
                window=600,
                anchor="http5xxrate",
                summary="More than 2% of SlowShield responses are server errors",
                description="Clients see 5xx from SlowShield. Look at the Upstream & Performance dashboard and the logs.",
            ),
            rule(
                "slowshield-high-latency",
                "HighLatency",
                f"histogram_quantile(0.99, sum(rate({SRV}{{{META_ROUTES}}}[5m])))",
                op="gt",
                threshold=1,
                for_="10m",
                severity="warning",
                window=600,
                anchor="highlatency",
                summary="p99 metadata latency above 1 s",
                description="PyPI index / npm packument responses are slow. Usually slow upstream or an overloaded instance "
                "(check event-loop lag and CPU).",
            ),
            rule(
                "slowshield-db-backlog",
                "DBWriterBacklog",
                "max(slowshield_db_writer_queue)",
                op="gt",
                threshold=5000,
                for_="5m",
                severity="warning",
                anchor="dbwriterbacklog",
                summary="SQLite write queue is backing up",
                description="More than 5000 pending database operations for 5 minutes: the data volume is too slow or the "
                "database is locked.",
            ),
            rule(
                "slowshield-artifact-cache-over-limit",
                "ArtifactCacheOverLimit",
                'max by (instance) (slowshield_cache_size_bytes{cache="artifact"}) '
                '/ max by (instance) (slowshield_cache_limit_bytes{cache="artifact"})',
                op="gt",
                threshold=1.05,
                for_="30m",
                severity="warning",
                anchor="artifactcacheoverlimit",
                summary="Artifact cache exceeds its size limit",
                description="The cache normally oscillates between 90% and 100% of its limit (eviction runs every minute). "
                "Staying above 105% for 30 minutes means eviction is failing — check the data volume and logs.",
            ),
        ],
    },
]


def document() -> dict[str, Any]:
    return {
        "apiVersion": 1,
        "groups": [{"orgId": 1, "folder": "SlowShield", **g} for g in GROUPS],
    }


def render() -> str:
    header = "# Generated by observability/build_alerts.py - edit the generator, not this file.\n"
    return header + json.dumps(document(), indent=2) + "\n"


def main(argv: list[str]) -> int:
    body = render()
    if "--check" in argv:
        if not OUT.is_file() or OUT.read_text() != body:
            print("stale alert rules (run build_alerts.py)")
            return 1
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(body)
    print("wrote", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
