#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024-2026 CodePros
#
# Build + install the LATEST OpenSSL 3.x with the FIPS provider, run
# fipsinstall, write an openssl.cnf activating fips+base, and verify.
# Idempotent + re-runnable; ALWAYS upgrades to the latest 3.x release.
set -euo pipefail

PREFIX="${OPENSSL_PREFIX:-/usr/local/ssl}"
JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
WORK="${WORK:-$(mktemp -d)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { printf '\033[0;34m==>\033[0m %s\n' "$*"; }

have_build_tools() {
  command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 \
    && command -v make >/dev/null 2>&1 \
    && command -v perl >/dev/null 2>&1 \
    && { command -v wget >/dev/null 2>&1 || command -v curl >/dev/null 2>&1; }
}

install_prereqs() {
  # Skip the package-manager step entirely when the toolchain is already
  # present (idempotent + survives hosts with a broken third-party apt
  # source). Only shell out to the package manager on a host that is
  # actually missing a build tool.
  if have_build_tools; then
    log "Build prerequisites already present; skipping package-manager install"
    return 0
  fi
  case "$(uname -s)" in
    Linux)
      if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -y
        sudo apt-get install -y build-essential perl wget ca-certificates
      elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y gcc make perl-core wget
      fi ;;
    Darwin)
      command -v brew >/dev/null 2>&1 && brew install perl wget || true ;;
    MINGW*|MSYS*|CYGWIN*)
      log "Windows: install OpenSSL+FIPS via vcpkg (vcpkg install openssl[fips]); skipping source build"
      exit 0 ;;
  esac
}

# Resolve the latest OpenSSL 3.x tag from the GitHub releases API. If the
# API is unreachable/rate-limited, fall back to the system openssl
# version (still a 3.x) so a transient network blip cannot wedge the
# always-latest gate.
resolve_latest() {
  local tag
  tag="$(wget -qO- https://api.github.com/repos/openssl/openssl/releases/latest 2>/dev/null \
    | grep -oE '"tag_name": *"openssl-3\.[0-9.]+"' \
    | grep -oE '3\.[0-9.]+' | head -n1)"
  if [ -z "${tag}" ] && command -v openssl >/dev/null 2>&1; then
    tag="$(openssl version 2>/dev/null | grep -oE '3\.[0-9.]+' | head -n1)"
    [ -n "${tag}" ] && log "GitHub API unavailable; falling back to system openssl version ${tag}" >&2
  fi
  [ -n "${tag}" ] || { echo "could not resolve latest OpenSSL 3.x"; exit 1; }
  echo "${tag}"
}

VER="${OPENSSL_VERSION:-$(resolve_latest)}"
log "Latest OpenSSL 3.x resolved: ${VER}"

# IDEMPOTENCY GATE — ALWAYS check latest (resolve_latest ran above), but
# SKIP the rebuild when BOTH conditions hold:
#   (a) installed openssl version == latest 3.x (${VER}), AND
#   (b) the fips provider is loaded AND reports `status: active`.
# Otherwise rebuild from source. The check uses the SAME active-status
# probe as verify-fips-provider.sh (a plain `grep fips` is NOT enough —
# the provider can be listed but inactive/failed self-test).
if [ -x "${PREFIX}/bin/openssl" ]; then
  CUR="$("${PREFIX}/bin/openssl" version | grep -oE '3\.[0-9.]+' | head -n1 || true)"
  FIPS_ACTIVE=no
  if [ "${CUR}" = "${VER}" ]; then
    if OPENSSL_CONF="${PREFIX}/ssl/openssl.cnf" \
       "${PREFIX}/bin/openssl" list -providers 2>/dev/null \
       | grep -A3 -i '^[[:space:]]*fips$' | grep -qi 'status: active'; then
      FIPS_ACTIVE=yes
    fi
  fi
  if [ "${CUR}" = "${VER}" ] && [ "${FIPS_ACTIVE}" = "yes" ]; then
    log "OpenSSL ${VER} already installed with fips provider ACTIVE at ${PREFIX}; skipping rebuild (verify only)"
    exec bash "${SCRIPT_DIR}/verify-fips-provider.sh"
  fi
  log "Rebuild required (installed=${CUR:-none}, latest=${VER}, fips_active=${FIPS_ACTIVE}); upgrading"
fi

install_prereqs

log "Fetching openssl-${VER}"
cd "${WORK}"
wget -q "https://github.com/openssl/openssl/releases/download/openssl-${VER}/openssl-${VER}.tar.gz"
tar xzf "openssl-${VER}.tar.gz"
cd "openssl-${VER}"

log "Configuring with enable-fips (prefix=${PREFIX})"
./Configure enable-fips --prefix="${PREFIX}" --openssldir="${PREFIX}/ssl" \
  -Wl,-rpath,"${PREFIX}/lib64" -Wl,-rpath,"${PREFIX}/lib"
make -j"${JOBS}"
sudo make install_sw install_ssldirs
sudo make install_fips

# Locate the installed fips module + lib dir (lib64 on most x86_64).
LIBDIR="${PREFIX}/lib64"; [ -d "${LIBDIR}/ossl-modules" ] || LIBDIR="${PREFIX}/lib"

log "Running openssl fipsinstall"
sudo "${PREFIX}/bin/openssl" fipsinstall \
  -out "${PREFIX}/ssl/fipsmodule.cnf" \
  -module "${LIBDIR}/ossl-modules/fips.so"

log "Writing openssl.cnf activating fips + base providers"
sudo tee "${PREFIX}/ssl/openssl.cnf" >/dev/null <<EOF
config_diagnostics = 1
openssl_conf = openssl_init

.include ${PREFIX}/ssl/fipsmodule.cnf

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
fips = fips_sect
base = base_sect

[base_sect]
activate = 1

[algorithm_sect]
default_properties = fips=yes
EOF

log "Verifying"
exec bash "${SCRIPT_DIR}/verify-fips-provider.sh"
