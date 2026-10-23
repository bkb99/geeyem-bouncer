#!/usr/bin/env python3
"""Check an APNs key and the settings around it, without printing the key.

Loading a .p8 and signing a token is the fastest way to find out that the Key ID
is a character short or the file was pasted rather than downloaded -- long before
a notification silently fails to arrive.

Nothing secret is printed. The key's bytes are never echoed; only whether it
loads, whether a token it signs verifies, and the fingerprint of the PUBLIC key.

    python tools/checkkey.py                       # reads RELAY_APNS_* from the env
    python tools/checkkey.py --key ~/.config/geyem/AuthKey_ABCD123456.p8 \
                             --key-id ABCD123456 --team-id 9XYZ87ABCD
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
problems = 0


def ok(msg):
    print(f"  {GREEN}✓{RESET} {msg}")


def bad(msg, fix=""):
    global problems
    problems += 1
    print(f"  {RED}✗{RESET} {msg}")
    if fix:
        print(f"    {DIM}{fix}{RESET}")


def warn(msg, fix=""):
    print(f"  {YELLOW}!{RESET} {msg}")
    if fix:
        print(f"    {DIM}{fix}{RESET}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", default=os.environ.get("RELAY_APNS_KEY_PATH"))
    ap.add_argument("--key-id", default=os.environ.get("RELAY_APNS_KEY_ID"))
    ap.add_argument("--team-id", default=os.environ.get("RELAY_APNS_TEAM_ID"))
    ap.add_argument("--topic", default=os.environ.get("RELAY_APNS_TOPIC"))
    args = ap.parse_args()

    print("\nAPNs configuration\n")

    # --- the file ----------------------------------------------------------
    if not args.key:
        bad("No key path", "Set RELAY_APNS_KEY_PATH or pass --key")
        return report()
    path = Path(os.path.expanduser(args.key))
    if not path.exists():
        bad(f"No file at {path}")
        return report()
    ok(f"Key file found ({path.stat().st_size} bytes)")

    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        warn(f"Readable by others (mode {oct(mode)[2:]})",
             f"chmod 600 {path}   — this key can push to every app on the account")
    else:
        ok("File permissions are private")

    raw = path.read_bytes()
    if b"BEGIN PRIVATE KEY" not in raw:
        bad("Not a PEM private key",
            "A .p8 from Apple starts '-----BEGIN PRIVATE KEY-----'. "
            "Re-download it rather than copying text out of the browser.")
        return report()
    ok("Looks like a PEM private key")

    # --- does it actually sign? -------------------------------------------
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        key = load_pem_private_key(raw, password=None)
    except Exception as exc:
        bad(f"Could not load the key: {type(exc).__name__}: {exc}",
            "If it was pasted rather than downloaded, the line breaks are usually the cause.")
        return report()

    from cryptography.hazmat.primitives.asymmetric import ec
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        bad(f"Wrong key type ({getattr(key.curve, 'name', type(key).__name__)})",
            "APNs keys are ECDSA P-256. This is probably not an APNs key.")
        return report()
    ok("ECDSA P-256, which is what APNs uses")

    # The public half is not secret, and its fingerprint is a safe way to tell
    # two keys apart in a log or a message.
    from cryptography.hazmat.primitives import serialization
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    print(f"    {DIM}public key fingerprint: "
          f"{hashlib.sha256(pub).hexdigest()[:16]}{RESET}")

    # --- the ids -----------------------------------------------------------
    stem = path.stem
    if args.key_id:
        if not re.fullmatch(r"[A-Z0-9]{10}", args.key_id):
            bad(f"Key ID '{args.key_id}' is not 10 characters of A-Z0-9")
        else:
            ok(f"Key ID looks well formed ({args.key_id})")
        if stem.startswith("AuthKey_") and stem[8:] != args.key_id:
            bad(f"Key ID does not match the filename (file says {stem[8:]})",
                "The filename is authoritative; Apple named it after the key.")
    else:
        guess = stem[8:] if stem.startswith("AuthKey_") else "?"
        bad("No key id", f"Set RELAY_APNS_KEY_ID — from the filename it is probably {guess}")

    if args.team_id:
        if not re.fullmatch(r"[A-Z0-9]{10}", args.team_id):
            bad(f"Team ID '{args.team_id}' is not 10 characters of A-Z0-9")
        else:
            ok(f"Team ID looks well formed ({args.team_id})")
    else:
        bad("No team id", "Set RELAY_APNS_TEAM_ID — developer.apple.com → Membership details")

    if args.topic:
        if args.topic != "com.example.geyem":
            warn(f"Topic is '{args.topic}'",
                 "It must equal the app's bundle id, which is com.example.geyem")
        else:
            ok("Topic matches the app's bundle id")
    else:
        bad("No topic", "Set RELAY_APNS_TOPIC=com.example.geyem")

    # --- sign a real token -------------------------------------------------
    if args.key_id and args.team_id:
        from relay.apns import ProviderToken
        try:
            token = ProviderToken(str(path), args.key_id, args.team_id).value()
            header_b64, claims_b64, sig_b64 = token.split(".")

            def dec(seg):
                return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))

            header, claims = dec(header_b64), dec(claims_b64)
            sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
            assert header["alg"] == "ES256" and len(sig) == 64

            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            key.public_key().verify(
                encode_dss_signature(int.from_bytes(sig[:32], "big"),
                                     int.from_bytes(sig[32:], "big")),
                f"{header_b64}.{claims_b64}".encode(),
                ec.ECDSA(hashes.SHA256()))
            ok("Signed a provider token and verified it")
            print(f"    {DIM}kid={header['kid']} iss={claims['iss']}{RESET}")
        except Exception as exc:
            bad(f"Could not sign a token: {type(exc).__name__}: {exc}")

    return report()


def report() -> int:
    print()
    if problems:
        print(f"{RED}{problems} problem(s).{RESET} See docs/PUSH-SETUP.md.\n")
        return 1
    print(f"{GREEN}Configuration looks good.{RESET}")
    print("This does not prove Apple accepts it — only a real push does that.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
