"""Static checks on the container definitions (run in the normal test suite, no Docker needed)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTAINERS = ROOT / "containers"
OWNED = ("slowshield", "caddy", "fakeupstream")
AL2023 = re.compile(r"^public\.ecr\.aws/amazonlinux/amazonlinux:2023(-minimal)?@sha256:[0-9a-f]{64}$")


def _shared(text: str) -> str:
    start = re.search(r"^ARG AL2023=", text, re.MULTILINE)
    end = re.search(r"^FROM deps-\$\{BUILD_CACHE\} AS deps$", text, re.MULTILINE)
    assert start and end
    return text[start.start() : end.end()]


def test_fakeupstream_shares_the_dependency_layers() -> None:
    app = (CONTAINERS / "slowshield" / "Dockerfile").read_text()
    fake = (CONTAINERS / "fakeupstream" / "Dockerfile").read_text()
    assert _shared(app) == _shared(fake), "keep the stages up to `deps` byte-identical (shared BuildKit layers)"


def test_every_stage_is_amazon_linux_or_scratch() -> None:
    for dockerfile in (CONTAINERS / name / "Dockerfile" for name in OWNED):
        text = dockerfile.read_text()
        assert not re.search(r"^#\s*syntax=", text, re.MULTILINE), f"{dockerfile}: use BuildKit's built-in frontend"
        args = dict(re.findall(r"^ARG (AL2023)=(\S+)$", text, re.MULTILINE))
        assert AL2023.match(args["AL2023"]), f"{dockerfile}: base image must be AL2023 pinned by digest"
        stages = {m.group(2) for m in re.finditer(r"^FROM (\S+) AS (\S+)$", text, re.MULTILINE)}
        for m in re.finditer(r"^FROM (\S+)", text, re.MULTILINE):
            ref = m.group(1)
            assert ref in {"${AL2023}", "scratch"} or ref in stages or ref.startswith("deps-"), (
                f"{dockerfile}: FROM {ref}"
            )
        for m in re.finditer(r"COPY --from=(\S+)", text):
            assert m.group(1) in stages, f"{dockerfile}: COPY --from={m.group(1)} must reference an internal stage"


def test_runtime_images_are_non_root_without_shell_entrypoints() -> None:
    for name in OWNED:
        text = (CONTAINERS / name / "Dockerfile").read_text()
        final = text[text.rindex("FROM scratch") :]
        assert "USER 65532:65532" in final
        entry = re.search(r"^ENTRYPOINT (\[.*\])$", final, re.MULTILINE)
        assert entry is not None and "sh" not in entry.group(1).split('"')[1::2], f"{name}: exec-form entrypoint"


def test_build_cache_off_uses_no_cache_mounts() -> None:
    text = (CONTAINERS / "slowshield" / "Dockerfile").read_text()
    off = text[text.index("FROM toolchain AS deps-off") : text.index("FROM deps-${BUILD_CACHE} AS deps")]
    assert "--mount=type=cache" not in off
    after = text[text.index("FROM deps-${BUILD_CACHE} AS deps") :]
    assert "--mount=type=cache" not in after


def test_dockerignore_excludes_local_state() -> None:
    entries = {line.strip() for line in (ROOT / ".dockerignore").read_text().splitlines()}
    assert {".git", ".venv", "perf/results"} <= entries
    assert ".baseline" in entries or ".baseline/" in entries
