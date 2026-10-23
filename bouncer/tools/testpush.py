#!/usr/bin/env python3
"""Send a notification to a simulator without involving Apple at all.

`xcrun simctl push` delivers a payload straight to an app on a booted simulator.
That covers everything on the client side -- how the alert looks, what happens
when it is tapped, whether the deep link lands on the right message -- with no
Apple Developer account, no key and no signed build.

What it does NOT test is APNs itself: the JWT, the connection, the device token.
Those need the real thing (docs/PUSH-SETUP.md).

    python tools/testpush.py                     # a channel mention
    python tools/testpush.py --buffer 3 --eid 91
    python tools/testpush.py --device "iPhone 17 Pro"
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from relay.push import Notification

DEFAULT_BUNDLE = "com.example.geyem"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--device", default="booted", help="simulator name or UDID")
    ap.add_argument("--bundle", default=DEFAULT_BUNDLE)
    ap.add_argument("--title", default="#hangout")
    ap.add_argument("--body", default="morgan: riley you around?")
    ap.add_argument("--buffer", type=int, default=1, help="buffer id to deep link to")
    ap.add_argument("--eid", type=int, default=0,
                    help="event id to centre on; 0 just opens the buffer")
    ap.add_argument("--badge", type=int, default=1)
    args = ap.parse_args()

    notification = Notification(
        title=args.title, body=args.body, buffer_id=args.buffer,
        eid=args.eid, network="quakenet", badge=args.badge,
    )
    payload = notification.to_apns_payload(thread_id=f"buffer-{args.buffer}")
    # simctl needs the topic in the payload rather than a header.
    payload["Simulator Target Bundle"] = args.bundle

    with tempfile.NamedTemporaryFile("w", suffix=".apns", delete=False) as f:
        json.dump(payload, f)
        path = f.name

    print(json.dumps(payload, indent=2))
    result = subprocess.run(
        ["xcrun", "simctl", "push", args.device, args.bundle, path],
        capture_output=True, text=True,
    )
    Path(path).unlink(missing_ok=True)

    if result.returncode != 0:
        print(f"\nfailed: {result.stderr.strip()}", file=sys.stderr)
        print("\nIs a simulator booted, and is the app installed on it?", file=sys.stderr)
        return 1
    print(f"\nsent to {args.device}. Background the app first -- a notification for "
          f"an app in the foreground is handled, not shown as a banner.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
