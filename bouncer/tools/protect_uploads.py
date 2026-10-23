#!/usr/bin/env python3
"""Mark every upload this bouncer made as uncacheable (Cache-Control: no-store).

New uploads are marked when the line that links them is sent (see
relay/gateway.py, `_protect_upload_links`). This does the same for the ones
that were uploaded before that existed, so that deleting one takes effect at
once and not when Cloudflare's four-hour copy runs out.

Only objects whose key is exactly the shape this bouncer makes are touched
(`relay.uploads._KEY_RE`); the otherbot's pictures and backups in the same bucket
are not. Run on the host, with the bouncer's own settings:

    cd ~/geyem && set -a && . ./.env && set +a && venv/bin/python tools/protect_uploads.py [--dry-run]

Prints counts only: the keys are what protects the files.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from relay.uploads import _KEY_RE, UploadConfig, Uploader  # noqa: E402


def main() -> int:
    dry = "--dry-run" in sys.argv[1:]
    config = UploadConfig.from_env()
    if config is None:
        print("uploads are not configured (the five GEYEM_S3_* settings)")
        return 1
    up = Uploader(config)
    if not up.available:
        print("boto3 is not installed")
        return 1

    seen = ours = changed = failed = 0
    token = None
    while True:
        kw = {"Bucket": config.bucket, "Prefix": "20"}
        if token:
            kw["ContinuationToken"] = token
        page = up.client.list_objects_v2(**kw)
        for obj in page.get("Contents", []):
            seen += 1
            if not _KEY_RE.fullmatch(obj["Key"]):
                continue
            ours += 1
            if dry:
                head = up.client.head_object(Bucket=config.bucket, Key=obj["Key"])
                changed += "no-store" not in (head.get("CacheControl") or "")
                continue
            try:
                changed += bool(up.protect(obj["Key"]))
            except Exception as exc:        # one bad object must not stop the rest
                failed += 1
                print(f"failed on one object: {type(exc).__name__}")
        if not page.get("IsTruncated"):
            break
        token = page.get("NextContinuationToken")

    verb = "would change" if dry else "changed"
    print(f"looked at {seen} objects under 20*, {ours} are uploads of this bouncer; "
          f"{verb} {changed}, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
