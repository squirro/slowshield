#!/usr/bin/env bash
# Assemble a distroless-style root filesystem from Amazon Linux 2023 RPMs.
#
# Runs inside an amazonlinux:2023 builder stage:
#     ROOTFS=/rootfs build-rootfs.sh [extra packages...]
#
# Result: glibc + CA bundle + tzdata + os-release, a non-root user (65532), an RPM database that
# matches what is on disk (so Aikido/Trivy/Grype can inventory the image) and *no* shell, package
# manager or coreutils. Packages that are only pulled in for install-time scriptlets (bash,
# coreutils, p11-kit, ...) are erased from both the filesystem and the RPM database afterwards.
set -euo pipefail

ROOT="${ROOTFS:-/rootfs}"
# Pin the rootfs to exactly the AL2023 release of the (digest-pinned) builder image.
RELEASEVER="${RELEASEVER:-$(rpm -q system-release --qf '%{VERSION}')}"
APP_UID="${APP_UID:-65532}"
APP_USER="${APP_USER:-slowshield}"

BASE=(filesystem setup basesystem glibc glibc-common glibc-minimal-langpack libgcc ca-certificates tzdata system-release)
KEEP=("${BASE[@]}" gpg-pubkey "$@")

mkdir -p "$ROOT"
dnf -y -q \
  --installroot="$ROOT" \
  --releasever="$RELEASEVER" \
  --setopt=install_weak_deps=False \
  --setopt=tsflags=nodocs \
  --nodocs \
  install "${BASE[@]}" "$@"

# Erase everything not on the keep list (scriptlets already ran; skip them on removal).
mapfile -t installed < <(rpm --root "$ROOT" -qa --qf '%{NAME}\n' | sort -u)
remove=()
for pkg in "${installed[@]}"; do
  keep=0
  for k in "${KEEP[@]}"; do
    [[ "$pkg" == "$k" ]] && keep=1 && break
  done
  ((keep)) || remove+=("$pkg")
done
if ((${#remove[@]})); then
  rpm --root "$ROOT" -e --nodeps --noscripts --notriggers "${remove[@]}"
fi

dnf -q --installroot="$ROOT" clean all
rm -rf "$ROOT"/var/cache/* "$ROOT"/var/log/* "$ROOT"/var/lib/dnf "$ROOT"/tmp/* \
       "$ROOT"/usr/share/doc "$ROOT"/usr/share/man "$ROOT"/usr/share/info \
       "$ROOT"/etc/yum.repos.d "$ROOT"/etc/dnf
# Locale archives beyond C.UTF-8 are not needed by a service that logs JSON in UTF-8.
find "$ROOT"/usr/share/locale -mindepth 1 -maxdepth 1 -type d ! -name 'en*' -exec rm -rf {} + 2>/dev/null || true

# Non-root runtime identity (also used by the Caddy image).
echo "${APP_USER}:x:${APP_UID}:${APP_UID}:${APP_USER}:/nonexistent:/sbin/nologin" >> "$ROOT/etc/passwd"
echo "${APP_USER}:x:${APP_UID}:" >> "$ROOT/etc/group"
echo "${APP_USER}:!!:19000::::::" >> "$ROOT/etc/shadow" 2>/dev/null || true

install -d -m 1777 "$ROOT/tmp"
install -d -m 0755 -o "$APP_UID" -g "$APP_UID" "$ROOT/data"

echo "rootfs ready: $(du -sh "$ROOT" | cut -f1), releasever $RELEASEVER, packages:"
rpm --root "$ROOT" -qa | sort
