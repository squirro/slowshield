# SlowShield application image.
#
# Golden rule: every stage is Amazon Linux 2023 (pinned by digest) or `scratch` holding AL2023 RPMs.
# There is no `# syntax=` directive on purpose: BuildKit's built-in Dockerfile frontend is used, so no
# third-party frontend image is pulled into the build.
#
#   docker buildx build --file containers/slowshield/Dockerfile -t slowshield:dev .
#   docker buildx build --file containers/slowshield/Dockerfile --build-arg PYTHON_VARIANT=3.15t -t slowshield:dev-ft .
#   docker buildx build --file containers/slowshield/Dockerfile --build-arg BUILD_CACHE=off ...   # release builds
#
# BUILD_CACHE=on uses BuildKit cache mounts for uv/cargo downloads; BUILD_CACHE=off selects stages that
# use no cache mounts at all. The stages up to and including `deps` are kept byte-identical to
# containers/fakeupstream/Dockerfile so both images share the expensive layers (checked by
# tests/e2e/test_dockerfiles.py).

ARG AL2023=public.ecr.aws/amazonlinux/amazonlinux:2023@sha256:12052e9b5d3fd85769abbdd863dd038e1890c9ace31d5fdbe1afa78eda97d061
ARG BUILD_CACHE=on

# ---- rootfs: glibc, CA bundle, tzdata, os-release, user 65532; no shell, no package manager -----
FROM ${AL2023} AS rootfs
COPY containers/rootfs/build-rootfs.sh /usr/local/bin/build-rootfs.sh
RUN /usr/local/bin/build-rootfs.sh

# ---- toolchain: compilers for wheels not yet published for 3.15, and uv (hash-pinned) -------------
FROM ${AL2023} AS toolchain
RUN dnf -y -q install --setopt=install_weak_deps=False gcc gcc-c++ make rust cargo binutils python3-pip \
 && dnf -q clean all && rm -rf /var/cache/dnf
COPY containers/slowshield/uv-requirements.txt /tmp/uv-requirements.txt
RUN python3 -m pip install --quiet --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/uv-requirements.txt
ENV UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_PYTHON_PREFERENCE=only-managed \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_NO_PROGRESS=1 \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    CARGO_PROFILE_RELEASE_STRIP=symbols
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./

# ---- deps (interpreter + third-party packages), with or without cache mounts ----------------------
FROM toolchain AS deps-on
ARG PYTHON_VARIANT=3.15
ARG TARGETARCH
RUN --mount=type=cache,id=slowshield-uv-${TARGETARCH},target=/cache/uv \
    --mount=type=cache,id=slowshield-cargo-${TARGETARCH},target=/cache/cargo \
    UV_CACHE_DIR=/cache/uv CARGO_HOME=/cache/cargo UV_PYTHON="$PYTHON_VARIANT" \
    sh -c 'uv python install --no-bin "$UV_PYTHON" && uv sync --locked --no-dev --no-install-project'

FROM toolchain AS deps-off
ARG PYTHON_VARIANT=3.15
RUN UV_NO_CACHE=1 CARGO_HOME=/tmp/cargo UV_PYTHON="$PYTHON_VARIANT" \
    sh -c 'uv python install --no-bin "$UV_PYTHON" && uv sync --locked --no-dev --no-install-project && rm -rf /tmp/cargo'

FROM deps-${BUILD_CACHE} AS deps

# ---- app: install SlowShield itself (non-editable) and prune ---------------------------------------
FROM deps AS app
ARG PYTHON_VARIANT=3.15
COPY src ./src
RUN UV_NO_CACHE=1 UV_PYTHON="$PYTHON_VARIANT" uv sync --locked --no-dev --no-editable
COPY containers/slowshield/prune.sh /usr/local/bin/prune.sh
RUN /usr/local/bin/prune.sh \
 && /app/.venv/bin/python -c "import slowshield.app, granian, pyreqwest, msgspec, uvloop, sys; \
print('import check ok', sys.version.split()[0], 'gil=%s' % getattr(sys, '_is_gil_enabled', lambda: True)())"
# License texts, notices and the changelog shown on /ui/about.
COPY LICENSE NOTICE *.md /app/share/doc/

# ---- runtime ---------------------------------------------------------------------------------------
FROM scratch
ARG SLOWSHIELD_VERSION=dev
ARG SLOWSHIELD_GIT_SHA=unknown
ARG PYTHON_VARIANT=3.15

COPY --from=rootfs /rootfs/ /
COPY --from=app /opt/python /opt/python
COPY --from=app /app/.venv /app/.venv
COPY --from=app /app/share /app/share

# glibc malloc: two arenas instead of one per thread (to_thread workers), and blocks of 128 KiB or more
# (upstream documents, rendered bodies) mmap'd and returned to the OS when freed instead of kept as heap.
# Under a cold-cache install burst this halves worker memory (measured: 520 -> 231 MiB peak).
ENV PATH=/app/.venv/bin:/usr/bin:/usr/sbin \
    LANG=C.UTF-8 \
    MALLOC_ARENA_MAX=2 \
    MALLOC_MMAP_THRESHOLD_=131072 \
    MALLOC_TRIM_THRESHOLD_=131072 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONSAFEPATH=1 \
    PYTHONUNBUFFERED=1 \
    SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt \
    SLOWSHIELD_DATA_DIR=/data \
    SLOWSHIELD_BIND=0.0.0.0:8080 \
    SLOWSHIELD_DOCS_DIR=/app/share/doc \
    SLOWSHIELD_LOG_FORMAT=json \
    SLOWSHIELD_VERSION=${SLOWSHIELD_VERSION} \
    SLOWSHIELD_GIT_SHA=${SLOWSHIELD_GIT_SHA}

LABEL org.opencontainers.image.title="SlowShield" \
      org.opencontainers.image.description="Supply-chain defence proxy for PyPI and npm: delays new releases, blocks known malware, detects tampering." \
      org.opencontainers.image.source="https://github.com/squirro/slowshield" \
      org.opencontainers.image.url="https://github.com/squirro/slowshield" \
      org.opencontainers.image.vendor="Squirro AG" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${SLOWSHIELD_VERSION}" \
      org.opencontainers.image.revision="${SLOWSHIELD_GIT_SHA}" \
      org.opencontainers.image.base.name="public.ecr.aws/amazonlinux/amazonlinux:2023" \
      io.slowshield.python="${PYTHON_VARIANT}"

USER 65532:65532
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["slowshield", "healthcheck"]
ENTRYPOINT ["slowshield"]
CMD ["serve"]
