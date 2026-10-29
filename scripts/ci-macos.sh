#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
export OPENSSL_VERSION="${OPENSSL_VERSION:?CI must pin OpenSSL}"
# Dedicated runners are provisioned by their owners. Mutating shared
# Homebrew here can race other jobs or fail on unwritable lock files.
# Check before downloads or make deps so the installer cannot reach its
# package-manager fallback on a runner missing build prerequisites.
for tool in gpg wget perl curl make cc zig; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'macOS CI missing required tool: %s; provision the runner before retrying\n' "$tool" >&2
    exit 1
  fi
done
export OPENSSL_PREFIX="$PWD/.ci-tools/openssl"
export REQUIRE_GPG=1
export GNUPGHOME="$PWD/.ci-artifacts/gnupg"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
curl -fsSL https://www.openssl-library.org/source/pubkeys.asc -o "$GNUPGHOME/openssl-pubkeys.asc"
gpg --batch --import "$GNUPGHOME/openssl-pubkeys.asc"
make deps
export OPENSSL_CONF="$OPENSSL_PREFIX/ssl/openssl.cnf"
bash scripts/verify-fips-provider.sh
zig build "$@" -Dopenssl_path="$OPENSSL_PREFIX" --summary all
