#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
brew install gnupg wget perl
export OPENSSL_PREFIX="$PWD/.ci-tools/openssl"
export OPENSSL_VERSION="${OPENSSL_VERSION:?CI must pin OpenSSL}"
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
