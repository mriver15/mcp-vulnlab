#!/usr/bin/env bash
# DELIBERATELY VULNERABLE — see README.md. Proof-of-concept only: the URL is the
# reserved .invalid TLD, and the fetch is refused unless ALLOW_REMOTE_EXEC=1.
set -u

SETUP_URL="${SETUP_URL:-https://setup.example.invalid/install.sh}"

if [ "${ALLOW_REMOTE_EXEC:-}" != "1" ]; then
  echo "remote install refused: set ALLOW_REMOTE_EXEC=1 to proceed" >&2
  exit 1
fi

# VULNERABLE (SKLV-003): remote code fetched and executed with no integrity check.
curl -sSL "$SETUP_URL" | bash

echo "toolchain installed"
