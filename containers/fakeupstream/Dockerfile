# fakeupstream: deterministic fake PyPI / npm / OSV / GitHub registry for e2e and performance tests.
# Test infrastructure only (never deployed). Same Amazon Linux 2023 base and interpreter as the app.
#
#   docker buildx build --file containers/fakeupstream/Dockerfile -t slowshield-fakeupstream:dev .
#   docker run --rm -p 9000:9000 slowshield-fakeupstream:dev --host 0.0.0.0 --port 9000 [--perf] [--now <unix>]
#
# Everything from `ARG AL2023=` down to `FROM deps-${BUILD_CACHE} AS deps` must stay byte-identical to
# containers/slowshield/Dockerfile, so both images share the compiled dependency layers
# (enforced by tests/e2e/test_dockerfiles.py).

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

FROM deps AS fake
COPY fakeupstream /app/fakeupstream
COPY containers/slowshield/prune.sh /usr/local/bin/prune.sh
RUN /usr/local/bin/prune.sh \
 && cd /app && /app/.venv/bin/python -c "import fakeupstream.app, granian, starlette; print('fakeupstream import ok')"

FROM scratch
COPY --from=rootfs /rootfs/ /
COPY --from=fake /opt/python /opt/python
COPY --from=fake /app/.venv /app/.venv
COPY --from=fake /app/fakeupstream /app/fakeupstream
ENV PATH=/app/.venv/bin:/usr/bin \
    LANG=C.UTF-8 \
    PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt
LABEL org.opencontainers.image.title="SlowShield fakeupstream" \
      org.opencontainers.image.description="Deterministic fake registries for SlowShield tests (not for production)." \
      org.opencontainers.image.source="https://github.com/squirro/slowshield" \
      org.opencontainers.image.licenses="Apache-2.0"
USER 65532:65532
WORKDIR /app
EXPOSE 9000
ENTRYPOINT ["python", "-m", "fakeupstream"]
CMD ["--host", "0.0.0.0", "--port", "9000"]
