#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024-2026 CodePros
#
# Local pre-push gate. Ensures the OpenSSL FIPS provider is installed
# locally, then compiles the FIPS-linked library and runs the dual-mode
# (std_shim + OpenSSL FIPS) test suite — so every local push exercises the
# FIPS backend like CI's shim and required catalog test jobs, with no
# silent fall-back to the std.crypto shim and no `--no-verify` needed.
#
# Override the OpenSSL prefix with OPENSSL_PREFIX (default /usr/local/ssl).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

PREFIX="${OPENSSL_PREFIX:-/usr/local/ssl}"

# Make the project's pinned Zig toolchain available — pre-commit hooks do
# not inherit the developer's interactive PATH.
if command -v mise >/dev/null 2>&1; then
  zig_dir="$(mise where zig@0.16.0 2>/dev/null || true)"
  [ -n "${zig_dir}" ] && export PATH="${zig_dir}:${PATH}"
fi
if ! command -v zig >/dev/null 2>&1; then
  echo "error: zig 0.16.0 not found on PATH (install it, e.g. 'mise install zig@0.16.0')" >&2
  exit 1
fi

# Is the FIPS provider built and reporting active at ${PREFIX}? (Same probe
# install-openssl-fips.sh / verify-fips-provider.sh use — a bare `grep fips`
# is not enough; the provider can be listed but inactive/failed self-test.)
fips_active() {
  [ -x "${PREFIX}/bin/openssl" ] || return 1
  OPENSSL_CONF="${PREFIX}/ssl/openssl.cnf" "${PREFIX}/bin/openssl" list -providers 2>/dev/null \
    | grep -A3 -i '^[[:space:]]*fips$' | grep -qi 'status: active'
}

if fips_active; then
  echo "==> OpenSSL FIPS provider active at ${PREFIX}"
else
  echo "==> OpenSSL FIPS provider not active at ${PREFIX}; provisioning via 'make deps' (one-time; builds OpenSSL + FIPS provider, may use sudo)..."
  OPENSSL_PREFIX="${PREFIX}" make deps
fi

echo "==> Compile check: FIPS-linked static library"
zig build build -Dopenssl_path="${PREFIX}"

echo "==> Dual-mode tests: std_shim (no OpenSSL link) + OpenSSL FIPS backend"
OPENSSL_PREFIX="${PREFIX}" make test-dual

echo "==> FIPS pre-push gate passed."
