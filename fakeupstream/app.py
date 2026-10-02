"""Starlette app serving the fake catalog as PyPI, npm, OSV and GitHub endpoints, plus control hooks."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import time
import zipfile
from collections import Counter
from collections.abc import AsyncIterator, Iterator
from html import escape
from typing import Any
from urllib.parse import unquote

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from fakeupstream.catalog import DAY, Advisory, Blob, Catalog, iso, iso_s, pep503

JSON_V1 = "application/vnd.pypi.simple.v1+json"


class State:
    def __init__(self, now: float, seed: int, perf: bool) -> None:
        self.args = (now, seed, perf)
        self.reset()

    def reset(self) -> None:
        now, seed, perf = self.args
        self.catalog = Catalog(now=now, seed=seed, perf=perf)
        self.tampered: set[str] = set()
        self.latency_ms = 0
        self.failures: dict[str, int] = {}
        self.hits: Counter[str] = Counter()
        self.last_headers: dict[str, dict[str, str]] = {}


def _etag(body: bytes) -> str:
    return '"' + hashlib.blake2b(body, digest_size=10).hexdigest() + '"'


def _maybe_304(request: Request, body: bytes, media_type: str, headers: dict[str, str] | None = None) -> Response:
    tag = _etag(body)
    h = {"ETag": tag, **(headers or {})}
    if request.headers.get("if-none-match") == tag:
        return Response(status_code=304, headers=h)
    return Response(body, media_type=media_type, headers=h)


class Injector:
    """Latency, failure injection and hit counting for every request."""

    def __init__(self, app: ASGIApp, state: State) -> None:
        self.app = app
        self.state = state

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope["path"]
        st = self.state
        if not path.startswith("/_control"):
            st.hits[path] += 1
            st.last_headers[path] = {k.decode(): v.decode() for k, v in scope.get("headers", ())}
            if st.latency_ms:
                await asyncio.sleep(st.latency_ms / 1000)
            for prefix, status in st.failures.items():
                if path.startswith(prefix):
                    await PlainTextResponse(f"injected failure {status}", status_code=status)(scope, receive, send)
                    return
        await self.app(scope, receive, send)


def create_app(*, now: float | None = None, seed: int = 1, perf: bool = False) -> ASGIApp:
    state = State(time.time() if now is None else now, seed, perf)

    def base(request: Request) -> str:
        return str(request.base_url).rstrip("/")

    # ---- PyPI ---------------------------------------------------------------------------------

    async def simple_root(request: Request) -> Response:
        names = sorted(state.catalog.pypi)
        if JSON_V1 in request.headers.get("accept", ""):
            body = json.dumps({"meta": {"api-version": "1.4"}, "projects": [{"name": n} for n in names]}).encode()
            return Response(body, media_type=JSON_V1)
        links = "".join(f'<a href="{n}/">{n}</a>\n' for n in names)
        return Response(f"<!DOCTYPE html><html><body>{links}</body></html>", media_type="text/html")

    async def simple_project(request: Request) -> Response:
        raw = request.path_params["name"]
        name = pep503(raw)
        if raw != name:
            return Response(status_code=301, headers={"Location": f"/pypi/simple/{name}/"})
        proj = state.catalog.pypi.get(name)
        if proj is None:
            return PlainTextResponse("not found", status_code=404)
        b = base(request)
        files = []
        for pfiles in proj.versions.values():
            for f in pfiles:
                d = f.blob.digests()
                meta: Any = {"sha256": f.metadata.digests()["sha256"]} if f.metadata else False
                files.append(
                    {
                        "filename": f.filename,
                        "url": f"{b}/files{f.path}",
                        "hashes": {"sha256": d["sha256"]},
                        "requires-python": f.requires_python,
                        "size": f.blob.size,
                        "upload-time": iso(f.upload_time),
                        "yanked": f.yanked,
                        "core-metadata": meta,
                        "data-dist-info-metadata": meta,
                    }
                )
        accept = request.headers.get("accept", "")
        if JSON_V1 in accept:
            doc = {
                "meta": {"api-version": "1.4", "_last-serial": 1000 + len(files)},
                "name": name,
                "versions": list(proj.versions),
                "files": files,
                "project-status": {"status": "active"},
            }
            return _maybe_304(request, json.dumps(doc).encode(), JSON_V1, {"Vary": "Accept"})
        rows = []
        for f in files:
            attrs = f'href="{escape(f["url"])}#sha256={f["hashes"]["sha256"]}"'
            if f["requires-python"]:
                attrs += f' data-requires-python="{escape(f["requires-python"])}"'
            rows.append(f"<a {attrs}>{escape(f['filename'])}</a><br>")
        html = f"<!DOCTYPE html><html><body><h1>Links for {name}</h1>{''.join(rows)}</body></html>"
        return _maybe_304(request, html.encode(), "text/html", {"Vary": "Accept"})

    async def pypi_file(request: Request) -> Response:
        path = "/packages/" + request.path_params["path"]
        cat = state.catalog
        blob: Blob | None = None
        if path in cat.files_by_path:
            blob = cat.files_by_path[path].blob
        elif path in cat.meta_by_path:
            blob = cat.meta_by_path[path].metadata
        if blob is None:
            return PlainTextResponse("not found", status_code=404)
        return _stream(blob, tampered=path in state.tampered or "/files" + path in state.tampered)

    # ---- npm --------------------------------------------------------------------------------------

    def packument(request: Request, name: str) -> dict[str, Any]:
        pkg = state.catalog.npm[name]
        b = base(request) + "/npm"
        versions: dict[str, Any] = {}
        time_map: dict[str, str] = {"created": iso(pkg.created)}
        modified = pkg.created
        for v, info in pkg.versions.items():
            d = info.blob.digests()
            dist: dict[str, Any] = {
                "tarball": f"{b}/{name}/-/{pkg.basename}-{v}.tgz",
                "shasum": d["sha1"],
                "fileCount": 2,
                "unpackedSize": info.blob.size,
                "signatures": [{"keyid": "SHA256:fake", "sig": "MEUCIQDfakesignature"}],
            }
            if info.integrity:
                dist["integrity"] = "sha512-" + d["sha512_b64"]
            manifest: dict[str, Any] = {
                "name": name,
                "version": v,
                "description": f"fake package {name}",
                "main": "index.js",
                "license": "MIT",
                "dependencies": {},
                "scripts": {"test": "true"},
                "_npmUser": {"name": "fake", "email": "fake@example.com"},
                "dist": dist,
            }
            if info.install_script:
                manifest["scripts"]["postinstall"] = "node -e 1"
            if info.deprecated:
                manifest["deprecated"] = info.deprecated
            versions[v] = manifest
            time_map[v] = iso(info.published)
            modified = max(modified, info.published)
        time_map["modified"] = iso(modified)
        return {
            "_id": name,
            "_rev": "1-fake",
            "name": name,
            "description": f"fake package {name}",
            "dist-tags": dict(pkg.tags),
            "versions": versions,
            "time": time_map,
            "maintainers": [{"name": "fake", "email": "fake@example.com"}],
            "readme": f"# {name}\n",
            "license": "MIT",
        }

    async def npm(request: Request) -> Response:
        raw_path = request.scope.get("raw_path", b"").decode("latin-1")
        rest = unquote(raw_path.split("/npm/", 1)[1]) if "/npm/" in raw_path else request.path_params["rest"]
        if rest == "-/npm/v1/keys":
            return JSONResponse({"keys": [{"keyid": "SHA256:fake", "keytype": "ecdsa-sha2-nistp256", "key": "fake"}]})
        if rest.startswith("-/npm/v1/security/"):
            return JSONResponse({})
        if "/-/" in rest:
            path = "/" + rest
            hit = state.catalog.tarballs.get(path)
            if hit is None:
                return PlainTextResponse("not found", status_code=404)
            return _stream(hit[1].blob, tampered=path in state.tampered, media_type="application/octet-stream")
        name = rest
        if name not in state.catalog.npm:
            return JSONResponse({"error": "Not found"}, status_code=404)
        body = json.dumps(packument(request, name)).encode()
        return _maybe_304(request, body, "application/json")

    async def npm_post(request: Request) -> Response:
        await request.body()
        return JSONResponse({"audited": True})

    # ---- OSV -----------------------------------------------------------------------------------------

    def osv_doc(a: Advisory) -> dict[str, Any]:
        affected: dict[str, Any] = {"package": {"ecosystem": a.ecosystem, "name": a.package}}
        if a.versions:
            affected["versions"] = a.versions
        if a.ranges:
            events = []
            for introduced, fixed in a.ranges:
                events.append({"introduced": introduced or "0"})
                if fixed:
                    events.append({"fixed": fixed})
            affected["ranges"] = [{"type": "SEMVER" if a.ecosystem == "npm" else "ECOSYSTEM", "events": events}]
        doc: dict[str, Any] = {
            "id": a.id,
            "modified": iso(a.modified),
            "published": iso(a.modified - DAY),
            "summary": a.summary,
            "details": a.summary,
            "affected": [affected],
        }
        if a.withdrawn:
            doc["withdrawn"] = iso(a.modified)
        return doc

    def osv_for(eco: str) -> list[Advisory]:
        return [a for a in state.catalog.advisories if a.source == "osv" and a.ecosystem == eco]

    async def osv_zip(request: Request) -> Response:
        eco = request.path_params["eco"]
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for a in osv_for(eco):
                zf.writestr(f"{a.id}.json", json.dumps(osv_doc(a)))
            zf.writestr("README.txt", "fake osv snapshot")
            zf.writestr("MAL-9999-BROKEN.json", "{not json")
        return _maybe_304(request, buf.getvalue(), "application/zip")

    async def osv_csv(request: Request) -> Response:
        eco = request.path_params["eco"]
        rows = sorted(osv_for(eco), key=lambda a: a.modified, reverse=True)
        lines = [f"{iso(a.modified)[:-1]}123Z,{a.id}" for a in rows]
        return PlainTextResponse("\n".join(lines) + "\n", media_type="text/csv")

    async def osv_one(request: Request) -> Response:
        eco, vid = request.path_params["eco"], request.path_params["id"]
        for a in osv_for(eco):
            if a.id == vid:
                return JSONResponse(osv_doc(a))
        return PlainTextResponse("not found", status_code=404)

    # ---- GitHub --------------------------------------------------------------------------------------

    async def gh_advisories(request: Request) -> Response:
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer ") or auth == "Bearer bad":
            return JSONResponse({"message": "Requires authentication"}, status_code=401)
        q = request.query_params
        eco = q.get("ecosystem")
        withdrawn = q.get("is_withdrawn") == "true"
        since = q.get("updated", "").removeprefix(">=")
        items = [
            a
            for a in state.catalog.advisories
            if a.source == "github" and (eco is None or a.ecosystem == eco) and a.withdrawn == withdrawn
        ]
        if since:
            items = [a for a in items if iso_s(a.modified) >= since]
        items.sort(key=lambda a: a.modified, reverse=q.get("direction") != "asc")
        per_page = int(q.get("per_page", "30"))
        start = int(q.get("after", "0") or 0)
        page = items[start : start + per_page]
        headers = {}
        if start + per_page < len(items):
            params = dict(q)
            params["after"] = str(start + per_page)
            from urllib.parse import urlencode

            headers["Link"] = f'<{base(request)}/github/advisories?{urlencode(params)}>; rel="next"'
        out = [
            {
                "ghsa_id": a.id,
                "summary": a.summary,
                "html_url": f"https://github.com/advisories/{a.id}",
                "type": "malware",
                "updated_at": iso_s(a.modified),
                "withdrawn_at": iso_s(a.modified) if a.withdrawn else None,
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": a.ecosystem, "name": a.package},
                        "vulnerable_version_range": a.gh_range,
                        "first_patched_version": None,
                    }
                ],
            }
            for a in page
        ]
        return JSONResponse(out, headers=headers)

    # ---- control -------------------------------------------------------------------------------------

    async def ctl_reset(request: Request) -> Response:
        state.reset()
        return JSONResponse({"ok": True})

    async def ctl_tamper(request: Request) -> Response:
        path = request.query_params["path"]
        state.tampered.add(path.removeprefix("/files") if path.startswith("/files/") else path.removeprefix("/npm"))
        return JSONResponse({"ok": True, "tampered": sorted(state.tampered)})

    async def ctl_latency(request: Request) -> Response:
        state.latency_ms = int(request.query_params.get("ms", "0"))
        return JSONResponse({"ok": True})

    async def ctl_fail(request: Request) -> Response:
        prefix = request.query_params["prefix"]
        status = int(request.query_params.get("status", "503"))
        if status == 0:
            state.failures.pop(prefix, None)
        else:
            state.failures[prefix] = status
        return JSONResponse({"ok": True})

    async def ctl_publish(request: Request) -> Response:
        q = request.query_params
        state.catalog.publish(q.get("ecosystem", "pypi"), q["name"], q["version"], float(q.get("age_days", "0")))
        return JSONResponse({"ok": True})

    async def ctl_advisory(request: Request) -> Response:
        d = await request.json()
        state.catalog.advisories = [
            a for a in state.catalog.advisories if not (a.source == d.get("source", "osv") and a.id == d["id"])
        ]
        state.catalog.advisories.append(
            Advisory(
                source=d.get("source", "osv"),
                ecosystem=d["ecosystem"],
                id=d["id"],
                package=d["package"],
                modified=float(d.get("modified", state.catalog.now)),
                versions=list(d.get("versions", [])),
                ranges=[tuple(r) for r in d.get("ranges", [])],
                gh_range=d.get("gh_range"),
                withdrawn=bool(d.get("withdrawn", False)),
                summary=d.get("summary", ""),
            )
        )
        return JSONResponse({"ok": True})

    async def ctl_hits(request: Request) -> Response:
        prefix = request.query_params.get("prefix", "")
        return JSONResponse({p: n for p, n in state.hits.items() if p.startswith(prefix)})

    async def ctl_info(request: Request) -> Response:
        cat = state.catalog
        return JSONResponse(
            {
                "now": cat.now,
                "pypi": {
                    name: {v: [{"filename": f.filename, "path": f.path} for f in fs] for v, fs in p.versions.items()}
                    for name, p in cat.pypi.items()
                },
                "npm": {name: list(p.versions) for name, p in cat.npm.items()},
            }
        )

    routes = [
        Route("/pypi/simple/", simple_root),
        Route("/pypi/simple/{name}/", simple_project),
        Route("/files/packages/{path:path}", pypi_file),
        Route("/npm/{rest:path}", npm, methods=["GET"]),
        Route("/npm/{rest:path}", npm_post, methods=["POST"]),
        Route("/osv/{eco}/all.zip", osv_zip),
        Route("/osv/{eco}/modified_id.csv", osv_csv),
        Route("/osv/{eco}/{id}.json", osv_one),
        Route("/github/advisories", gh_advisories),
        Route("/_control/reset", ctl_reset, methods=["POST"]),
        Route("/_control/tamper", ctl_tamper, methods=["POST"]),
        Route("/_control/latency", ctl_latency, methods=["POST"]),
        Route("/_control/fail", ctl_fail, methods=["POST"]),
        Route("/_control/publish", ctl_publish, methods=["POST"]),
        Route("/_control/advisory", ctl_advisory, methods=["POST"]),
        Route("/_control/hits", ctl_hits),
        Route("/_control/info", ctl_info),
        Route("/healthz", lambda r: PlainTextResponse("ok")),
        Route("/redirect", lambda r: Response(status_code=302, headers={"Location": r.query_params["to"]})),
        Route(
            "/blob",
            lambda r: Response(b"x" * int(r.query_params.get("n", "10")), media_type="application/octet-stream"),
        ),
    ]
    app = Starlette(routes=routes)
    app.state.fake = state
    return Injector(app, state)


def _stream(blob: Blob, *, tampered: bool, media_type: str = "application/octet-stream") -> Response:
    def gen() -> Iterator[bytes]:
        yield from blob.chunks(tampered=tampered)

    async def agen() -> AsyncIterator[bytes]:
        for chunk in gen():
            yield chunk

    return StreamingResponse(agen(), media_type=media_type, headers={"Content-Length": str(blob.size)})
