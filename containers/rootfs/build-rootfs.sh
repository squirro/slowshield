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

# Roots Mozilla no longer trusts but AL2023's ca-certificates still ships go on p11-kit's blocklist, and the
# bundles are extracted again while p11-kit is still in the root (it is erased below). emSign ECC Root CA - G3 has
# eight intermediates with compromised keys (GHSA-6q48-6c7w-9gw2); Mozilla dropped emSign ECC Root CA - C3 and
# emSign Root CA - C1 too (certifi 2026.10.23). Remove an entry once ca-certificates no longer ships its root.
DISTRUST="$ROOT/etc/pki/ca-trust/source/blocklist"
install -d "$DISTRUST"
cat > "$DISTRUST/emsign-ecc-root-ca-g3.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG
EwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNo
bm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0g
RzMwHhcNMTgwMjE4MTgzMDAwWhcNNDMwMjE4MTgzMDAwWjBrMQswCQYDVQQGEwJJ
TjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9s
b2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMw
djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjpQy4LRL1KPOxst3iAhKAnjlfSU2fySU0
WXTsuwYc58Byr+iuL+FBVIcUqEqy6HyC5ltqtdyzdc6LBtCGI79G1Y4PPwT01xyS
fvalY8L1X44uT6EYGQIrMgqCZH0Wk9GjQjBAMB0GA1UdDgQWBBR8XQKEE9TMipuB
zhccLikenEhjQjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAwNpADBmAjEAvvNhzwIQHWSVB7gYboiFBS+DCBeQyh+KTOgNG3qxrdWB
CUfvO6wIBHxcmbHtRwfSAjEAnbpV/KlK6O3t5nYBQnvI+GDZjVGLVTv7jHvrZQnD
+JbNR6iC8hZVdyR+EhCVBCyj
-----END CERTIFICATE-----
PEM
cat > "$DISTRUST/emsign-ecc-root-ca-c3.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIICKzCCAbGgAwIBAgIKe3G2gla4EnycqDAKBggqhkjOPQQDAzBaMQswCQYDVQQG
EwJVUzETMBEGA1UECxMKZW1TaWduIFBLSTEUMBIGA1UEChMLZU11ZGhyYSBJbmMx
IDAeBgNVBAMTF2VtU2lnbiBFQ0MgUm9vdCBDQSAtIEMzMB4XDTE4MDIxODE4MzAw
MFoXDTQzMDIxODE4MzAwMFowWjELMAkGA1UEBhMCVVMxEzARBgNVBAsTCmVtU2ln
biBQS0kxFDASBgNVBAoTC2VNdWRocmEgSW5jMSAwHgYDVQQDExdlbVNpZ24gRUND
IFJvb3QgQ0EgLSBDMzB2MBAGByqGSM49AgEGBSuBBAAiA2IABP2lYa57JhAd6bci
MK4G9IGzsUJxlTm801Ljr6/58pc1kjZGDoeVjbk5Wum739D+yAdBPLtVb4Ojavti
sIGJAnB9SMVK4+kiVCJNk7tCDK93nCOmfddhEc5lx/h//vXyqaNCMEAwHQYDVR0O
BBYEFPtaSNCAIEDyqOkAB2kZd6fmw/TPMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMDA2gAMGUCMQC02C8Cif22TGK6Q04ThHK1rt0c
3ta13FaPWEBaLd4gTCKDypOofu4SQMfWh0/434UCMBwUZOR8loMRnLDRWmFLpg9J
0wD8ofzkpf9/rdcw0Md3f76BB1UwUCAU9Vc4CqgxUQ==
-----END CERTIFICATE-----
PEM
cat > "$DISTRUST/emsign-root-ca-c1.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIIDczCCAlugAwIBAgILAK7PALrEzzL4Q7IwDQYJKoZIhvcNAQELBQAwVjELMAkG
A1UEBhMCVVMxEzARBgNVBAsTCmVtU2lnbiBQS0kxFDASBgNVBAoTC2VNdWRocmEg
SW5jMRwwGgYDVQQDExNlbVNpZ24gUm9vdCBDQSAtIEMxMB4XDTE4MDIxODE4MzAw
MFoXDTQzMDIxODE4MzAwMFowVjELMAkGA1UEBhMCVVMxEzARBgNVBAsTCmVtU2ln
biBQS0kxFDASBgNVBAoTC2VNdWRocmEgSW5jMRwwGgYDVQQDExNlbVNpZ24gUm9v
dCBDQSAtIEMxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz+upufGZ
BczYKCFK83M0UYRWEPWgTywS4/oTmifQz/l5GnRfHXk5/Fv4cI7gklL35CX5VIPZ
HdPIWoU/Xse2B+4+wM6ar6xWQio5JXDWv7V7Nq2s9nPczdcdioOl+yuQFTdrHCZH
3DspVpNqs8FqOp099cGXOFgFixwR4+S0uF2FHYP+eF8LRWgYSKVGczQ7/g/IdrvH
GPMF0Ybzhe3nudkyrVWIzqa2kbBPrH4VI5b2P/AgNBbeCsbEBEV5f6f9vtKppa+c
xSMq9zwhbL2vj07FOrLzNBL834AaSaTUqZX3noleoomslMuoaJuvimUnzYnu3Yy1
aylwQ6BpC+S5DwIDAQABo0IwQDAdBgNVHQ4EFgQU/qHgcB4qAzlSWkK+XJGFehiq
TbUwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAMJKVvoVIXsoounlHfv4LcQ5lkFMOycsxGwYFYDGrK9HWS8mC+M2sO87
/kOXSTKZEhVb3xEp/6tT+LvBeA+snFOvV71ojD1pM/CjoCNjO2RnIkSt1XHLVip4
kqNPEjE2NuLe/gDEo2APJ62gsIq1NnpSob0n9CAnYuhNlCQT5AoE6TyrLshDCUrG
YQTlSTR+08TI9Q/Aqum6VF7zYytPT1DU/rl7mYw9wC68AivTxEDkigcxHpvOJpkT
+xHqmiIMERnHXhuBUDDIlhJu58tBf5E7oke3VIAb3ADMmpDqw8NQBmIMMMAVSKeo
WXzhriKi4gp6D/piq1JM4fHfyr6DDUI=
-----END CERTIFICATE-----
PEM
chroot "$ROOT" /usr/bin/update-ca-trust extract
# The bundle TLS clients read (SSL_CERT_FILE, Go, rustls) must hold none of them.
bundle=$(tr -d '\n' < "$ROOT"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem)
for pem in "$DISTRUST"/*.pem; do
  if [[ "$bundle" == *"$(grep -v -- ----- "$pem" | tr -d '\n')"* ]]; then
    echo "still trusted after update-ca-trust: ${pem##*/}" >&2
    exit 1
  fi
done

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
