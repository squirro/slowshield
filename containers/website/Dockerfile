# slowshield.net landing page: static files served by our Amazon Linux 2023 Caddy image.
#
#   docker buildx build -f containers/website/Dockerfile \
#     --build-arg CADDY_IMAGE=slowshield-caddy:ci -t slowshield-website:ci --load .
#
# Golden rule: only Amazon Linux 2023 — the builder is AL2023 and the runtime is the slowshield-caddy
# image (distroless AL2023 rootfs + verified Caddy binary, non-root 65532).

ARG AL2023=public.ecr.aws/amazonlinux/amazonlinux:2023@sha256:12052e9b5d3fd85769abbdd863dd038e1890c9ace31d5fdbe1afa78eda97d061
ARG CADDY_IMAGE=registry.squirro.com/slowshield/slowshield-caddy:latest

FROM ${AL2023} AS build
RUN dnf install -y --setopt=install_weak_deps=False brotli zstd gzip python3 findutils && dnf clean all
WORKDIR /work
COPY website/ website/
COPY brand/ brand/
RUN python3 website/build.py --out /site \
 && find /site -type f \( -name '*.html' -o -name '*.css' -o -name '*.js' -o -name '*.svg' \
      -o -name '*.txt' -o -name '*.xml' -o -name '*.ico' \) -print0 \
    | xargs -0 -I{} sh -c 'gzip -9 -n -k "{}" && brotli -q 11 -k "{}" && zstd -19 -q -k "{}"' \
 && chmod -R a+rX,go-w /site

FROM ${CADDY_IMAGE}
ARG SLOWSHIELD_GIT_SHA=unknown
LABEL org.opencontainers.image.title="slowshield-website" \
      org.opencontainers.image.description="slowshield.net landing page" \
      org.opencontainers.image.source="https://github.com/squirro/slowshield" \
      org.opencontainers.image.revision="${SLOWSHIELD_GIT_SHA}" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build --chown=0:0 /site /srv/site
COPY --chown=0:0 website/Caddyfile /etc/caddy/website.Caddyfile
ENV CANONICAL_HOST=slowshield.net
EXPOSE 8080
USER 65532:65532
CMD ["run", "--config", "/etc/caddy/website.Caddyfile", "--adapter", "caddyfile"]
