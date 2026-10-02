# Caddy edge image for SlowShield (TLS termination, HTTP/3, ACME).
#
# Golden rule: every stage is Amazon Linux 2023 (pinned by digest) or `scratch` holding AL2023 RPMs.
# The official, statically linked Caddy release binary is downloaded in an AL2023 stage and verified
# against SHA-512 sums pinned below (update them with containers/caddy/bump_caddy.py, which also
# verifies the release's cosign signature).
#
#   docker buildx build --file containers/caddy/Dockerfile -t slowshield-caddy:dev .

ARG AL2023=public.ecr.aws/amazonlinux/amazonlinux:2023@sha256:12052e9b5d3fd85769abbdd863dd038e1890c9ace31d5fdbe1afa78eda97d061
# Accepted for a uniform CI interface; this image has no cacheable build steps.
ARG BUILD_CACHE=on

FROM ${AL2023} AS rootfs
COPY containers/rootfs/build-rootfs.sh /usr/local/bin/build-rootfs.sh
RUN /usr/local/bin/build-rootfs.sh

FROM ${AL2023} AS fetch
ARG TARGETARCH
# Newest release that has passed SlowShield's own 7-day delay; see bump_caddy.py --min-age-days.
ARG CADDY_VERSION=2.11.6
ARG CADDY_SHA512_AMD64=422771007d505ea97efd1177a4905b2c1a471cd426668f2ace3bcda3d8e30b11f9b1610bfb02c6ad60f2a795f56124f2f5eec6409c17d5a0dd4c21a11375fb94
ARG CADDY_SHA512_ARM64=bd228ea44b6b95720a0c2d7b62886e99cb4a0b05356fe6e058c4a155618c913377b18e686839ae7fcc6c2c05aea2d549fa91f25aa3ef8d43cdead117259577ed
RUN dnf -y -q install --setopt=install_weak_deps=False tar gzip && dnf -q clean all
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) sum="${CADDY_SHA512_AMD64}" ;; \
      arm64) sum="${CADDY_SHA512_ARM64}" ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/caddy.tgz "$url"; \
    echo "${sum}  /tmp/caddy.tgz" | sha512sum -c -; \
    mkdir -p /out/usr/bin /out/usr/share/licenses/caddy /out/config/caddy /out/var/log/caddy /out/certs; \
    tar -xzf /tmp/caddy.tgz -C /tmp caddy LICENSE; \
    install -m 0755 /tmp/caddy /out/usr/bin/caddy; \
    install -m 0644 /tmp/LICENSE /out/usr/share/licenses/caddy/LICENSE; \
    /out/usr/bin/caddy version
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
ARG CADDY_VERSION=2.11.6
ARG SLOWSHIELD_VERSION=dev
ARG SLOWSHIELD_GIT_SHA=unknown
COPY --from=rootfs /rootfs/ /
COPY --from=fetch /out/ /

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
