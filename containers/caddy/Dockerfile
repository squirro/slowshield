# Caddy edge image for SlowShield (TLS termination, HTTP/3, ACME).
#
# Golden rule: every stage is Amazon Linux 2023 (pinned by digest) or `scratch` holding AL2023 RPMs.
#
# Caddy is built from source (containers/caddy/build: upstream's cmd/caddy main with the standard
# modules, go.mod/go.sum committed) with the official Go toolchain, because no Caddy release yet carries
# Go's October 2026 HTTP/2 fixes (Go 1.26.9, golang.org/x/net v0.60.0). AL2023's own golang package is
# older than that, so the Go tarball from go.dev/dl is used, pinned by its SHA-256 per build architecture.
# Modules come from proxy.golang.org and are checked against go.sum (and Go's checksum database); the build
# is cross-compiled on the build platform, never under emulation. Flags and tags match upstream's release.
# Back to the official, cosign-signed release binary once a Caddy release ships with these fixes.
# Bump Caddy and Go with containers/caddy/bump_caddy.py.
#
#   docker buildx build --file containers/caddy/Dockerfile -t slowshield-caddy:dev .

ARG AL2023=public.ecr.aws/amazonlinux/amazonlinux:2023@sha256:12052e9b5d3fd85769abbdd863dd038e1890c9ace31d5fdbe1afa78eda97d061
# BUILD_CACHE=on keeps Go's module and build caches in BuildKit cache mounts; off (release builds) uses none.
ARG BUILD_CACHE=on

FROM ${AL2023} AS rootfs
COPY containers/rootfs/build-rootfs.sh /usr/local/bin/build-rootfs.sh
RUN /usr/local/bin/build-rootfs.sh

# ---- go: the official Go toolchain for the build platform, and the build module -------------------
FROM --platform=${BUILDPLATFORM} ${AL2023} AS go
ARG BUILDARCH
ARG GO_VERSION=1.26.10
ARG GO_SHA256_AMD64=ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5
ARG GO_SHA256_ARM64=3f4227ce7b206a513e794f1393adb473a07b46e94d18bd15d1c684bbb7319797
RUN dnf -y -q install --setopt=install_weak_deps=False tar gzip && dnf -q clean all
RUN set -eu; \
    case "${BUILDARCH}" in \
      amd64) sum="${GO_SHA256_AMD64}" ;; \
      arm64) sum="${GO_SHA256_ARM64}" ;; \
      *) echo "unsupported build architecture: ${BUILDARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/go.tgz "https://go.dev/dl/go${GO_VERSION}.linux-${BUILDARCH}.tar.gz"; \
    echo "${sum}  /tmp/go.tgz" | sha256sum -c -; \
    tar -xzf /tmp/go.tgz -C /usr/local; \
    rm /tmp/go.tgz; \
    /usr/local/go/bin/go version
ENV PATH=/usr/local/go/bin:${PATH} \
    GOPATH=/go \
    GOMODCACHE=/go/pkg/mod \
    GOCACHE=/root/.cache/go-build \
    GOTOOLCHAIN=local \
    GOPROXY=https://proxy.golang.org \
    GOSUMDB=sum.golang.org \
    GOFLAGS=-mod=readonly \
    CGO_ENABLED=0
WORKDIR /src
COPY containers/caddy/build/go.mod containers/caddy/build/go.sum containers/caddy/build/main.go ./

# ---- caddy: cross-compiled for TARGETARCH, with or without cache mounts ----------------------------
# Same as upstream's release (.goreleaser.yml): -trimpath, -s -w, tags nobadger,nomysql,nopgx; plus an
# empty build ID. `caddy version` reports the caddy/v2 module version from the binary's build info.
FROM go AS caddy-on
ARG TARGETARCH
RUN --mount=type=cache,id=slowshield-gomod,target=/go/pkg/mod \
    --mount=type=cache,id=slowshield-gobuild,target=/root/.cache/go-build \
    set -eu; \
    GOOS=linux GOARCH="${TARGETARCH}" go build -trimpath -buildvcs=false -tags nobadger,nomysql,nopgx \
      -ldflags '-s -w -buildid=' -o /out/caddy .; \
    cp "$(go list -m -f '{{.Dir}}' github.com/caddyserver/caddy/v2)/LICENSE" /out/LICENSE; \
    go mod verify; \
    go version -m /out/caddy | grep -E 'caddy: go|/caddy/v2\s|golang.org/x/net\s'

FROM go AS caddy-off
ARG TARGETARCH
RUN set -eu; \
    GOOS=linux GOARCH="${TARGETARCH}" go build -trimpath -buildvcs=false -tags nobadger,nomysql,nopgx \
      -ldflags '-s -w -buildid=' -o /out/caddy .; \
    cp "$(go list -m -f '{{.Dir}}' github.com/caddyserver/caddy/v2)/LICENSE" /out/LICENSE; \
    go version -m /out/caddy | grep -E 'caddy: go|/caddy/v2\s|golang.org/x/net\s'

FROM caddy-${BUILD_CACHE} AS caddy

# ---- assemble: binary, config and checks on the target platform -----------------------------------
FROM ${AL2023} AS assemble
# Keep in step with github.com/caddyserver/caddy/v2 in build/go.mod (bump_caddy.py does both).
ARG CADDY_VERSION=2.11.7
COPY --from=caddy /out/caddy /out/usr/bin/caddy
COPY --from=caddy /out/LICENSE /out/usr/share/licenses/caddy/LICENSE
RUN set -eu; \
    mkdir -p /out/config/caddy /out/var/log/caddy /out/certs; \
    /out/usr/bin/caddy version; \
    /out/usr/bin/caddy version | grep -q "^v${CADDY_VERSION} "
COPY containers/caddy/Caddyfile /out/etc/caddy/Caddyfile
COPY containers/caddy/tls/ /out/etc/caddy/tls/
COPY containers/caddy/snippets/ /out/etc/caddy/snippets/
COPY containers/caddy/metrics/ /out/etc/caddy/metrics/
COPY containers/caddy/tracing/ /out/etc/caddy/tracing/
COPY containers/caddy/logs/ /out/etc/caddy/logs/
COPY containers/caddy/local-http/ /out/etc/caddy/local-http/
RUN chown -R 65532:65532 /out/config /out/var/log/caddy \
 && XDG_DATA_HOME=/tmp/d XDG_CONFIG_HOME=/tmp/c /out/usr/bin/caddy fmt /out/etc/caddy/Caddyfile >/dev/null \
 && for mode in internal acme files; do \
      SLOWSHIELD_TLS_MODE=$mode CADDY_METRICS=on CADDY_TRACING=on CADDY_ACCESS_LOG_FILE=on \
      XDG_DATA_HOME=/tmp/d XDG_CONFIG_HOME=/tmp/c \
      /out/usr/bin/caddy adapt --config /out/etc/caddy/Caddyfile --adapter caddyfile >/dev/null || exit 1; \
    done

FROM scratch
ARG CADDY_VERSION=2.11.7
ARG SLOWSHIELD_VERSION=dev
ARG SLOWSHIELD_GIT_SHA=unknown
COPY --from=rootfs /rootfs/ /
COPY --from=assemble /out/ /

ENV XDG_CONFIG_HOME=/config \
    XDG_DATA_HOME=/data \
    SLOWSHIELD_TLS_MODE=internal \
    SLOWSHIELD_HOSTNAMES=localhost \
    SLOWSHIELD_UPSTREAM=slowshield:8080 \
    TLS_MIN_VERSION=1.3 \
    CADDY_METRICS=off \
    CADDY_TRACING=off \
    CADDY_ACCESS_LOG_FILE=off

LABEL org.opencontainers.image.title="SlowShield Caddy" \
      org.opencontainers.image.description="Caddy ${CADDY_VERSION} TLS edge for SlowShield (Amazon Linux 2023 base, no shell)." \
      org.opencontainers.image.source="https://github.com/squirro/slowshield" \
      org.opencontainers.image.vendor="Squirro AG" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${SLOWSHIELD_VERSION}" \
      org.opencontainers.image.revision="${SLOWSHIELD_GIT_SHA}" \
      org.opencontainers.image.base.name="public.ecr.aws/amazonlinux/amazonlinux:2023" \
      io.slowshield.caddy.version="${CADDY_VERSION}"

USER 65532:65532
WORKDIR /data
VOLUME ["/data", "/config"]
EXPOSE 8080 8443 8443/udp
ENTRYPOINT ["caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
