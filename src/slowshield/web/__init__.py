"""Shared HTTP helpers: JSON error responses, client-IP resolution, content negotiation."""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from typing import Any

import msgspec
from starlette.responses import Response
from starlette.types import Scope

_json = msgspec.json.Encoder()


class JSONResponse(Response):
    media_type = "application/json"

    def render(self, content: Any) -> bytes:
        return _json.encode(content)


def error(status: int, code: str, *, headers: dict[str, str] | None = None, **fields: Any) -> Response:
    body = {"error": code, **{k: v for k, v in fields.items() if v is not None}}
    return JSONResponse(body, status_code=status, headers={"Cache-Control": "no-store", **(headers or {})})


def not_found() -> Response:
    return error(404, "not_found")


def route_path(scope: Scope) -> str:
    """Path relative to the mount point (Starlette keeps the full path and extends `root_path`)."""
    path: str = scope["path"]
    root = scope.get("root_path", "")
    if root and path.startswith(root) and (len(path) == len(root) or path[len(root)] == "/"):
        return path[len(root) :]
    return path


def header(scope: Scope, name: bytes) -> str | None:
    for k, v in scope.get("headers", ()):
        if k == name:
            return v.decode("latin-1")
    return None


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def client_ip(scope: Scope, trusted: Sequence[Network]) -> str | None:
    """Peer address, or the right-most untrusted X-Forwarded-For hop when the peer is a trusted proxy."""
    client = scope.get("client")
    peer = client[0] if client else None
    if peer is None:
        return None
    if not _is_trusted(peer, trusted):
        return peer
    xff = header(scope, b"x-forwarded-for")
    if not xff:
        return peer
    hops = [h.strip() for h in xff.split(",") if h.strip()]
    for hop in reversed(hops):
        if not _is_trusted(hop, trusted):
            return _valid_ip(hop) or peer
    return _valid_ip(hops[0]) if hops else peer


def _valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        return None


def _is_trusted(addr: str, trusted: Sequence[Network]) -> bool:
    try:
        ip = ipaddress.ip_address(addr.strip("[]"))
    except ValueError:
        return False
    return any(ip in net for net in trusted)


def accept_prefers(accept: str | None, offered: Sequence[str], default: str) -> str:
    """Pick the best media type from `offered` per the Accept header (q-values, exact or `*/*`)."""
    if not accept:
        return default
    entries: list[tuple[str, float]] = []
    for raw in accept.split(","):
        parts = [p.strip() for p in raw.split(";")]
        q = 1.0
        for p in parts[1:]:
            if p.startswith("q="):
                try:
                    q = float(p[2:])
                except ValueError:
                    q = 0.0
        entries.append((parts[0].lower(), q))
    best, best_q = default, 0.0
    for cand in offered:  # server preference order breaks ties
        q, specificity = 0.0, -1
        for mtype, mq in entries:
            if mtype == cand:
                s = 2
            elif mtype.endswith("/*") and mtype != "*/*" and cand.startswith(mtype[:-1]):
                s = 1
            elif mtype == "*/*":
                s = 0
            else:
                continue
            if s > specificity:
                specificity, q = s, mq
        if q > best_q:
            best, best_q = cand, q
    return best
