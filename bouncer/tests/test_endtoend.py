#!/usr/bin/env python3
"""End to end: fake ircd -> bouncer -> websocket client, and back again.

Proves the whole chain without touching a real network: a line said on IRC
reaches a websocket client, and a line sent by a websocket client reaches IRC.
The send half in particular can only be tested here -- verifying it against
QuakeNet would mean posting into #hangout.

    python tests/test_endtoend.py
"""

import asyncio
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aiohttp

from relay.app import Relay
from relay.config import Config, NetworkConfig

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
from fakeircd import FakeIRCd

FAILED = []
pushes = []
# Read receipts (the background push after a read on another device), as
# (payload, the device tokens it went to).
read_pushes = []
PORT_IRC = 6699
PORT_WS = 8799


def check(label, got, want):
    if got != want:
        FAILED.append(f"{label}: got {got!r}, want {want!r}")
        print(f"  FAIL {label}: got {got!r}, want {want!r}")
    else:
        print(f"  ok   {label}")


class Watcher:
    """A second IRC client on the fake server, so we can see what the bouncer sends."""

    def __init__(self, nick):
        self.nick = nick
        self.lines = []

    async def connect(self, port):
        self.reader, self.writer = await asyncio.open_connection("127.0.0.1", port)
        self.writer.write(f"NICK {self.nick}\r\nUSER {self.nick} 0 * :watcher\r\n".encode())
        await self.writer.drain()
        self.task = asyncio.create_task(self._read())

    async def _read(self):
        while True:
            raw = await self.reader.readline()
            if not raw:
                return
            self.lines.append(raw.decode().strip())

    def say(self, target, text):
        self.writer.write(f"PRIVMSG {target} :{text}\r\n".encode())

    def join(self, channel):
        self.writer.write(f"JOIN {channel}\r\n".encode())

    async def wait_for(self, substring, timeout=5.0):
        async def poll():
            while True:
                for line in self.lines:
                    if substring in line:
                        return line
                await asyncio.sleep(0.05)
        try:
            return await asyncio.wait_for(poll(), timeout)
        except asyncio.TimeoutError:
            return None

    def quit(self, reason):
        self.writer.write(f"QUIT :{reason}\r\n".encode())

    def close(self):
        self.task.cancel()
        self.writer.close()


class WSClient:
    def __init__(self):
        self.frames = []

    async def connect(self, session, url, token):
        self.ws = await session.ws_connect(url, headers={"Authorization": f"Bearer {token}"})
        self.task = asyncio.create_task(self._read())

    async def _read(self):
        async for msg in self.ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                self.frames.append(json.loads(msg.data))

    async def send(self, frame):
        await self.ws.send_str(json.dumps(frame))

    async def wait(self, predicate, timeout=6.0):
        async def poll():
            while True:
                for f in self.frames:
                    if predicate(f):
                        return f
                await asyncio.sleep(0.05)
        try:
            return await asyncio.wait_for(poll(), timeout)
        except asyncio.TimeoutError:
            return None

    async def close(self):
        self.task.cancel()
        await self.ws.close()


def is_event(kind=None, text=None, sender=None):
    def pred(f):
        if f.get("type") != "event":
            return False
        e = f["event"]
        if kind and e.get("kind") != kind:
            return False
        if text and text not in (e.get("text") or ""):
            return False
        if sender and e.get("from") != sender:
            return False
        return True
    return pred


async def run():
    ircd = FakeIRCd(port=PORT_IRC)
    await ircd.start()
    print(f"fake ircd on {PORT_IRC}")

    tmp = tempfile.TemporaryDirectory()
    config = Config(
        listen_host="127.0.0.1",
        listen_port=PORT_WS,
        db_path=os.path.join(tmp.name, "e2e.db"),
        initial_backlog=50,
        networks=[NetworkConfig(
            slug="test", name="Test", host="127.0.0.1", port=PORT_IRC,
            nick="relaytest", username="relay", realname="relay",
            channels=["#testing"],
        )],
    )
    relay = Relay(config)
    gateway = None

    # Record pushes instead of sending them. The decision chain is what is being
    # tested here; APNs itself is covered by tests/test_apns.py.
    class RecordingPush:
        async def send(self, notification, devices):
            pushes.append((notification, devices))

        async def send_read(self, receipt, devices):
            read_pushes.append((receipt.to_apns_payload(),
                                sorted(d["apns_token"] for d in devices)))

    relay.hub.push_provider = RecordingPush()
    token = relay.store.create_token("e2e")
    relay_task = asyncio.create_task(relay.run())

    # A second IRC user, in the channel, to talk to the bouncer and to observe it.
    watcher = Watcher("someone")
    await watcher.connect(PORT_IRC)
    await asyncio.sleep(0.3)
    watcher.join("#testing")

    # Wait for the bouncer to be registered and joined before asserting anything.
    session = relay.sessions[0] if relay.sessions else None
    for _ in range(100):
        if relay.sessions and relay.sessions[0].conn.registered:
            session = relay.sessions[0]
            break
        await asyncio.sleep(0.05)
    check("bouncer registered upstream", bool(session and session.conn.registered), True)
    # The flood limiter sends one line every two seconds once its burst is
    # spent, which is right for QuakeNet and would make this file take minutes.
    # Its pace is tested in test_units.py; here it only needs to keep order.
    if session:
        session.conn.send_interval = 0.02
    await asyncio.sleep(0.5)

    async with aiohttp.ClientSession() as http:
        # --- auth -----------------------------------------------------------
        try:
            async with http.get(f"http://127.0.0.1:{PORT_WS}/ws?token=bogus") as resp:
                check("bad token rejected", resp.status, 401)
        except Exception as exc:
            check("bad token rejected", f"raised {exc}", 401)

        # A GOOD token in the query string is refused too, which is the point:
        # a URL is the one place a credential gets copied into a bookmark, a
        # history entry and every proxy log between here and the phone.
        async with http.get(f"http://127.0.0.1:{PORT_WS}/ws?token={token}") as resp:
            check("a valid token in the query string is refused", resp.status, 401)

        # Unauthenticated health must say the service is alive and nothing else.
        # It is publicly reachable once a hostname points at it, and it used to
        # hand out the nick, the network and the message count to anyone asking.
        async with http.get(f"http://127.0.0.1:{PORT_WS}/health") as resp:
            health = await resp.json()
            check("health ok without a token", health["ok"], True)
            check("anonymous health leaks no networks", "networks" in health, False)
            check("anonymous health leaks no nick", "nick" in str(health), False)
            check("anonymous health leaks no message count", "max_eid" in health, False)
            # One boolean more (2026-09-26): on IRC or not, for a monitor.
            check("anonymous health says it is on IRC", health.get("irc"), True)
            check("and nothing else was added", sorted(health), ["irc", "ok", "protocol"])

        async with http.get(f"http://127.0.0.1:{PORT_WS}/health",
                            headers={"Authorization": f"Bearer {token}"}) as resp:
            health = await resp.json()
            check("authenticated health has the detail", "networks" in health, True)

        # Same rule on /health: the query string is not a way in there either.
        async with http.get(f"http://127.0.0.1:{PORT_WS}/health?token={token}") as resp:
            health = await resp.json()
            check("health ignores a query token", "networks" in health, False)

        # Repeated bad tokens get refused rather than answered forever.
        statuses = []
        for _ in range(12):
            try:
                async with http.get(f"http://127.0.0.1:{PORT_WS}/ws?token=bad") as r:
                    statuses.append(r.status)
            except Exception:
                statuses.append(0)
        check("auth attempts are rate limited", 429 in statuses, True)

        # --- attach ---------------------------------------------------------
        # A valid token is unaffected by the failures above: the limiter refuses
        # attempts, not addresses outright, and a good token short-circuits it.
        # (Same address here, which is the point worth proving.)
        gateway = relay.gateway
        gateway._auth_failures.clear()

        # A wrong token at /health counts against the same throttle: the long
        # body and the short one answer "is this token good", and that used
        # to be free there while /ws charged for it.
        for i in range(12):
            async with http.get(f"http://127.0.0.1:{PORT_WS}/health",
                                headers={"Authorization": f"Bearer relay_wrong{i}"}) as r:
                await r.read()
        async with http.get(f"http://127.0.0.1:{PORT_WS}/ws?token=bad") as r:
            check("wrong tokens at /health count toward the /ws throttle", r.status, 429)
        async with http.get(f"http://127.0.0.1:{PORT_WS}/health",
                            headers={"Authorization": f"Bearer {token}"}) as r:
            # 429, not the short body with a 200: that is also what a WRONG
            # token gets, and the web client read it as its token being
            # refused and signed the person out (contract 6).
            body = await r.json()
            check("  and a throttled address is told so at /health: 429, no detail",
                  (r.status, "networks" in body, "error" in body), (429, False, True))
        async with http.get(f"http://127.0.0.1:{PORT_WS}/health") as r:
            check("  while a monitor with no token still gets its 200",
                  (r.status, (await r.json()).get("ok")), (200, True))
        gateway._auth_failures.clear()
        async with http.get(f"http://127.0.0.1:{PORT_WS}/health",
                            headers={"Authorization": f"Bearer {token}"}) as r:
            check("  which the right token gets once the throttle has passed",
                  "networks" in await r.json(), True)

        # --- the browser's way in ------------------------------------------
        # A browser cannot set an Authorization header, but it can name
        # subprotocols, and those travel in a handshake header rather than in
        # the URL. The server selects and echoes the protocol and reads the
        # token out of the second entry.
        sub = await http.ws_connect(
            f"http://127.0.0.1:{PORT_WS}/ws",
            protocols=("geeyem.v1", f"geeyem.token.{token}"))
        check("subprotocol auth connects", sub.closed, False)
        check("the server echoes the protocol", sub.protocol, "geeyem.v1")
        first = await sub.receive()
        check("a subprotocol client gets hello",
              json.loads(first.data).get("type"), "hello")
        await sub.close()

        # Auto-away being taken back publishes a network frame; that used to
        # reach the attaching client BEFORE its hello (2026-09-26).
        relay.store.set_setting("auto_away", True)
        relay.hub.auto_away_active = True
        session.set_auto_away(True)
        back = await http.ws_connect(
            f"http://127.0.0.1:{PORT_WS}/ws",
            headers={"Authorization": f"Bearer {token}"})
        first = json.loads((await back.receive()).data)
        check("with an auto-away to take back, hello is still first",
              first.get("type"), "hello")
        second = json.loads((await back.receive()).data)
        check("  and the away is gone by the time the networks are listed",
              (relay.hub.auto_away_active, session.to_wire()["away"]), (False, None))
        check("  (the frame after hello is not a stray network frame)",
              second.get("type") != "network" or second["network"].get("away") is None, True)
        await back.close()
        relay.store.set_setting("auto_away", False)

        try:
            bad_sub = await http.ws_connect(
                f"http://127.0.0.1:{PORT_WS}/ws",
                protocols=("geeyem.v1", "geeyem.token.relay_not_a_real_token"))
            await bad_sub.close()
            check("a bad subprotocol token is refused", "it connected", 401)
        except aiohttp.WSServerHandshakeError as exc:
            check("a bad subprotocol token is refused", exc.status, 401)
        gateway._auth_failures.clear()

        # --- Origin (G62) ---------------------------------------------------
        # A browser page may connect only from this bouncer's own origin. No
        # Origin at all is not a browser (the iOS app) and is let in.
        own = await http.ws_connect(
            f"http://127.0.0.1:{PORT_WS}/ws", headers={"Origin": f"http://127.0.0.1:{PORT_WS}"},
            protocols=("geeyem.v1", f"geeyem.token.{token}"))
        check("the bouncer's own origin connects", own.closed, False)
        await own.close()
        for origin in ("https://evil.example", "null", f"http://127.0.0.1:{PORT_WS + 1}"):
            try:
                foreign = await http.ws_connect(
                    f"http://127.0.0.1:{PORT_WS}/ws", headers={"Origin": origin},
                    protocols=("geeyem.v1", f"geeyem.token.{token}"))
                await foreign.close()
                check(f"a foreign origin is refused: {origin}", "it connected", 403)
            except aiohttp.WSServerHandshakeError as exc:
                check(f"a foreign origin is refused: {origin}", exc.status, 403)
        # And the page's CSP runs only its own scripts, by hash.
        async with http.get(f"http://127.0.0.1:{PORT_WS}/") as resp:
            csp = resp.headers.get("Content-Security-Policy", "")
            page = await resp.text()
        from relay.gateway import inline_script_hashes
        script_src = next((d for d in csp.split(";") if d.strip().startswith("script-src")), "")
        check("no 'unsafe-inline' for scripts", "unsafe-inline" in script_src, False)
        check("every inline script is allowed by its hash",
              all(f"'sha256-{h}'" in script_src for h in inline_script_hashes(page)), True)
        check("connect-src is this bouncer, not any websocket",
              (" wss: " in csp + " ", " ws: " in csp + " ",
               f"ws://127.0.0.1:{PORT_WS}" in csp), (False, False, True))
        check("the service worker is allowed", "worker-src 'self'" in csp, True)

        # The page is revalidated, not refetched: an ETag of its content, and
        # a 304 for a browser that already has it, carrying the same headers.
        async with http.get(f"http://127.0.0.1:{PORT_WS}/") as resp:
            etag = resp.headers.get("ETag", "")
            check("the page is kept but always asked about",
                  resp.headers.get("Cache-Control"), "no-cache")
        check("the page has a strong ETag",
              (etag.startswith('"'), etag.endswith('"'), len(etag) > 2), (True, True, True))
        for sent in (etag, f"W/{etag}", f'"other", {etag}', "*"):
            async with http.get(f"http://127.0.0.1:{PORT_WS}/",
                                headers={"If-None-Match": sent}) as resp:
                check(f"If-None-Match {sent[:12]}... is a 304 with no body",
                      (resp.status, await resp.read()), (304, b""))
                check("  with the same ETag, caching and policy",
                      (resp.headers.get("ETag"), resp.headers.get("Cache-Control"),
                       "script-src 'sha256-" in resp.headers.get("Content-Security-Policy", ""),
                       resp.headers.get("X-Frame-Options")),
                      (etag, "no-cache", True, "DENY"))
        async with http.get(f"http://127.0.0.1:{PORT_WS}/",
                            headers={"If-None-Match": '"not-this-page"'}) as resp:
            check("a stale ETag gets the whole page",
                  (resp.status, len(await resp.text()) > 1000), (200, True))

        # --- headers on every route, and https (security pass) --------------
        # cloudflared connects from loopback and says how the browser came in.
        via_https = {"X-Forwarded-Proto": "https", "Cf-Visitor": '{"scheme":"https"}'}
        via_http = {"X-Forwarded-Proto": "http", "Cf-Visitor": '{"scheme":"http"}'}
        base = f"http://127.0.0.1:{PORT_WS}"
        async with http.get(base + "/", headers=via_https, allow_redirects=False) as r:
            secure_csp = r.headers.get("Content-Security-Policy", "")
        check("a page served over https allows wss:// to itself and no ws://",
              (f"wss://127.0.0.1:{PORT_WS}" in secure_csp, "ws://" in secure_csp), (True, False))
        for route in ("/", "/health", "/manifest.webmanifest", "/icon-192.png", "/sw.js",
                      "/export/" + "x" * 43, "/ws", "/no-such-page"):
            async with http.get(base + route, headers=via_https, allow_redirects=False) as r:
                h = r.headers
                check(f"{route}: nosniff, no referrer, no framing, own window",
                      (h.get("X-Content-Type-Options"), h.get("Referrer-Policy"),
                       h.get("X-Frame-Options"), h.get("Cross-Origin-Opener-Policy")),
                      ("nosniff", "no-referrer", "DENY", "same-origin"))
                check(f"{route}: powerful features off",
                      "camera=()" in h.get("Permissions-Policy", ""), True)
                check(f"{route}: a Cache-Control", "Cache-Control" in h, True)
                check(f"{route}: HSTS over https",
                      h.get("Strict-Transport-Security"), "max-age=31536000")
                if route != "/sw.js":
                    check(f"{route}: never framed",
                          "frame-ancestors 'none'" in h.get("Content-Security-Policy", ""), True)
            async with http.get(base + route, allow_redirects=False) as r:
                check(f"{route}: no HSTS on a local rig",
                      "Strict-Transport-Security" in r.headers, False)
        async with http.get(base + "/sw.js", headers=via_https) as r:
            check("the service worker gets no policy that would stop it fetching",
                  "Content-Security-Policy" in r.headers, False)
        async with http.get(base + "/health", headers={"Authorization": f"Bearer {token}"}) as r:
            check("authenticated health is never cached", r.headers.get("Cache-Control"),
                  "no-store")
        # Its own caching survives the middleware's no-store default. Bare, it is
        # revalidated; with ?v=<hash> (what the page and manifest link) it is kept
        # for good, since that address can only ever be those bytes.
        async with http.get(base + "/icon-192.png") as r:
            check("an icon keeps its own caching", r.headers.get("Cache-Control"),
                  "no-cache")
        async with http.get(base + "/icon-192.png?v=abc") as r:
            check("  and a versioned icon is kept for good", r.headers.get("Cache-Control"),
                  "public, max-age=31536000, immutable")
        # A page reached over plain http through the tunnel goes to https,
        # before a token can be typed into it. The socket and /health do not.
        async with http.get(base + "/?x=1", headers=via_http, allow_redirects=False) as r:
            check("the page over plain http is sent to https",
                  (r.status, r.headers.get("Location")),
                  (308, f"https://127.0.0.1:{PORT_WS}/?x=1"))
            check("  with no HSTS on the http answer",
                  "Strict-Transport-Security" in r.headers, False)
        async with http.get(base + "/ws", headers=via_http, allow_redirects=False) as r:
            check("the socket is not redirected, it is refused", r.status, 403)
        async with http.get(base + "/health", headers=via_http, allow_redirects=False) as r:
            check("/health is not redirected", r.status, 200)
        # A token over plain http through the tunnel is refused before it is
        # looked at, even a good one; a local rig's plain http is not.
        try:
            plain = await http.ws_connect(
                f"http://127.0.0.1:{PORT_WS}/ws", headers=via_http,
                protocols=("geeyem.v1", f"geeyem.token.{token}"))
            await plain.close()
            check("a socket over plain http through the tunnel is refused", "it connected", 403)
        except aiohttp.WSServerHandshakeError as exc:
            check("a socket over plain http through the tunnel is refused", exc.status, 403)
        async with http.get(base + "/health", headers={**via_http,
                                                       "Authorization": f"Bearer {token}"}) as r:
            check("/health with a token over plain http is refused", r.status, 403)
        async with http.get(base + "/health", headers={**via_https,
                                                       "Authorization": f"Bearer {token}"}) as r:
            check("  and over https it answers in full",
                  (r.status, "networks" in await r.json()), (200, True))
        tunnel = await http.ws_connect(
            f"http://127.0.0.1:{PORT_WS}/ws", headers=via_https,
            protocols=("geeyem.v1", f"geeyem.token.{token}"))
        check("a socket over https through the tunnel connects", tunnel.closed, False)
        await tunnel.close()
        async with http.get(base + "/", allow_redirects=False) as r:
            check("a local rig's plain http is served as it is", r.status, 200)
        gateway._auth_failures.clear()

        client = WSClient()
        await client.connect(http, f"http://127.0.0.1:{PORT_WS}/ws", token)

        hello = await client.wait(lambda f: f.get("type") == "hello")
        check("hello received", hello is not None and hello["protocol"], 1)
        check("no since, no resume", (hello or {}).get("resumed"), False)

        buffers = await client.wait(lambda f: f.get("type") == "buffers")
        names = {b["name"] for b in buffers["buffers"]} if buffers else set()
        check("status buffer present", "*status*" in names, True)
        check("channel buffer present", "#testing" in names, True)
        chan = next((b for b in buffers["buffers"] if b["name"] == "#testing"), None)
        if chan is None:
            FAILED.append("no #testing buffer; cannot continue")
            return
        check("channel marked joined", chan["joined"], True)

        members = await client.wait(lambda f: f.get("type") == "members" and f["buffer"] == chan["id"])
        member_nicks = {m["nick"] for m in members["members"]} if members else set()
        check("member list has both", {"relaytest", "someone"} <= member_nicks, True)

        # --- IRC -> client ---------------------------------------------------
        watcher.say("#testing", "hello from irc")
        got = await client.wait(is_event(kind="message", text="hello from irc"))
        check("irc message reached client", got is not None, True)
        check("sender attributed", got["event"]["from"] if got else None, "someone")
        check("not marked self", got["event"]["self"] if got else None, False)
        check("not a highlight", got["event"]["highlight"] if got else None, False)

        # --- highlight -------------------------------------------------------
        watcher.say("#testing", "relaytest: are you there")
        hl = await client.wait(is_event(text="are you there"))
        check("mention flagged as highlight", hl["event"]["highlight"] if hl else None, True)

        watcher.say("#testing", "relaytesting is a different word")
        nohl = await client.wait(is_event(text="different word"))
        check("substring not a highlight", nohl["event"]["highlight"] if nohl else None, False)

        # --- private message -------------------------------------------------
        watcher.say("relaytest", "psst")
        pm = await client.wait(is_event(kind="message", text="psst"))
        check("pm arrived", pm is not None, True)
        check("pm is a highlight", pm["event"]["highlight"] if pm else None, True)
        newbuf = await client.wait(
            lambda f: f.get("type") == "buffers" or
            (f.get("type") == "event" and f["event"]["buffer"] != chan["id"])
        )
        check("pm landed in its own buffer", pm["event"]["buffer"] != chan["id"] if pm else None, True)
        # The buffer must be announced BEFORE its first event, or a client that
        # has never heard of it drops the line: the phone counted an unread it
        # could not open. Order is checked on the frame list, not by waiting.
        frames = list(client.frames)
        announced = next((i for i, f in enumerate(frames)
                          if f.get("type") == "buffer" and f["buffer"]["kind"] == "query"
                          and f["buffer"]["id"] == pm["event"]["buffer"]), None) if pm else None
        arrived = next((i for i, f in enumerate(frames) if f is pm), None)
        check("query buffer announced", announced is not None, True)
        check("query buffer announced before its first event",
              announced is not None and arrived is not None and announced < arrived, True)

        # --- buffer list on demand -------------------------------------------
        await client.send({"type": "buffers", "req": "bl1"})
        relist = await client.wait(lambda f: f.get("type") == "buffers" and f.get("req") == "bl1")
        check("buffer list re-sent on request", relist is not None, True)
        check("re-sent list includes the channel",
              any(b["id"] == chan["id"] for b in relist["buffers"]) if relist else None, True)

        # --- client -> IRC ---------------------------------------------------
        await client.send({"type": "say", "req": "s1", "buffer": chan["id"],
                           "text": "hello from the app"})
        ok = await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "s1")
        check("say acknowledged", ok is not None, True)
        check("say echo has an eid", bool(ok and ok["event"]["eid"] > 0), True)
        check("say echo marked self", ok["event"]["self"] if ok else None, True)

        seen = await watcher.wait_for("hello from the app")
        check("line actually reached irc", seen is not None, True)
        check("sent under the right nick", "relaytest" in (seen or ""), True)

        # /me
        await client.send({"type": "say", "req": "s2", "buffer": chan["id"], "text": "/me waves"})
        action = await watcher.wait_for("ACTION waves")
        check("/me sent as ctcp action", action is not None, True)

        # --- backlog ---------------------------------------------------------
        await client.send({"type": "backlog", "req": "b1", "buffer": chan["id"], "limit": 100})
        page = await client.wait(lambda f: f.get("type") == "backlog" and f.get("req") == "b1")
        texts = [e["text"] for e in page["events"]] if page else []
        check("backlog contains received line", "hello from irc" in texts, True)
        check("backlog contains sent line", "hello from the app" in texts, True)
        eids = [e["eid"] for e in page["events"]] if page else []
        check("backlog ordered oldest first", eids == sorted(eids), True)

        # --- read markers ----------------------------------------------------
        top = max(eids) if eids else 0
        await client.send({"type": "mark_read", "req": "m1", "buffer": chan["id"], "eid": top})
        marker = await client.wait(lambda f: f.get("type") == "read_marker")
        check("read marker broadcast", marker["eid"] if marker else None, top)
        unread = await client.wait(
            lambda f: f.get("type") == "unread" and
            f["counts"].get(str(chan["id"]), f["counts"].get(chan["id"], {})).get("unread") == 0
        )
        check("unread cleared", unread is not None, True)

        # --- join a new channel ----------------------------------------------
        await client.send({"type": "join", "req": "j1", "channel": "#another"})
        joined = await client.wait(
            lambda f: f.get("type") == "buffer" and f["buffer"]["name"] == "#another"
                      and f["buffer"]["joined"]
        )
        check("join created a joined buffer", joined is not None, True)

        # A second observer, because the first one quits below and the command
        # tests after that still need someone in the channel to see the output.
        watcher2 = Watcher("observer")
        await watcher2.connect(PORT_IRC)
        await asyncio.sleep(0.3)
        watcher2.join("#testing")
        await asyncio.sleep(0.3)

        # --- part / quit propagation ------------------------------------------
        watcher.close()
        gone = await client.wait(is_event(kind="quit", sender="someone"))
        check("quit reached client", gone is not None, True)

        # --- /msg to someone with no buffer yet --------------------------------
        # One frame, no buffer id: the whole point of say-by-target.
        await client.send({"type": "say", "req": "m1", "target": "stranger",
                           "text": "hello stranger"})
        msg_ok = await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "m1")
        check("/msg to a new nick succeeded", msg_ok is not None, True)
        new_buffer = await client.wait(
            lambda f: f.get("type") == "buffer" and f["buffer"]["name"] == "stranger")
        check("/msg created a query buffer", new_buffer is not None, True)
        check("query buffer is a query", new_buffer["buffer"]["kind"] if new_buffer else None, "query")

        # --- /query opens without sending --------------------------------------
        await client.send({"type": "query", "req": "q1", "nick": "someone_else"})
        query_ok = await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "q1")
        check("/query returned a buffer", bool(query_ok and query_ok.get("buffer")), True)
        query_buffer_id = query_ok["buffer"]["id"] if query_ok else 0
        # Opening a window must not message the person.
        await asyncio.sleep(0.4)
        events_in_query = [f for f in client.frames
                           if f.get("type") == "event"
                           and f["event"].get("buffer") == query_buffer_id]
        check("/query sent nothing to the other person", events_in_query, [])

        # --- /me via the explicit action flag ----------------------------------
        await client.send({"type": "say", "req": "a1", "buffer": chan["id"],
                           "text": "nods", "action": True})
        nods = await watcher2.wait_for("ACTION nods")
        check("action flag sends a ctcp action", nods is not None, True)

        # --- /topic ------------------------------------------------------------
        await client.send({"type": "topic", "req": "t1", "buffer": chan["id"],
                           "topic": "a brand new topic"})
        topic_frame = await client.wait(
            lambda f: f.get("type") == "buffer"
            and f["buffer"]["id"] == chan["id"]
            and f["buffer"].get("topic") == "a brand new topic")
        check("/topic updated the buffer", topic_frame is not None, True)

        # --- /nick -------------------------------------------------------------
        await client.send({"type": "nick", "req": "n1", "nick": "renamed"})
        renamed = await client.wait(
            lambda f: f.get("type") == "network" and f["network"]["nick"] == "renamed")
        check("/nick applied once the server confirmed", renamed is not None, True)

        # --- /whois ------------------------------------------------------------
        # One frame carrying the whole reply, with the asking client's req on it.
        # The nine numerics that built it are the bouncer's business.
        status_id = next(b["id"] for b in buffers["buffers"] if b["kind"] == "status")
        await client.send({"type": "whois", "req": "w1", "nick": "observer"})
        whois = await client.wait(
            lambda f: f.get("type") == "whois" and f.get("req") == "w1") or {}
        check("/whois is answered with a whois frame", whois.get("type"), "whois")
        check("whois found the nick", whois.get("found"), True)
        check("whois names the nick", whois.get("nick"), "observer")
        check("whois names the network", whois.get("network"), "test")
        check("whois carries user and host",
              [whois.get("user"), whois.get("host")],
              ["~observer", "observer.users.fake.irc"])
        check("whois carries the realname", whois.get("realname"), "a test user")
        check("whois carries the server", whois.get("server"), "fake.irc")
        check("whois carries the server info", whois.get("server_info"),
              "a server for testing")
        check("whois carries the channels with their prefixes", whois.get("channels"),
              [{"name": "#testing", "prefix": "@"}])
        check("whois carries the idle time", whois.get("idle_seconds"), 42)
        check("whois carries the signon time", whois.get("signon_at"), 1758000000)
        check("whois carries the account", whois.get("account"), "observer")
        # Fields this server said nothing about are present and empty rather
        # than missing, so the card has one shape to render.
        check("whois reports away as nothing", whois.get("away"), None)
        check("whois reports an ordinary user", [whois.get("secure"), whois.get("operator")],
              [False, False])
        # The numerics that built the card must not also appear as server text.
        await asyncio.sleep(0.3)
        leaked = [f for f in client.frames
                  if f.get("type") == "event"
                  and f["event"].get("buffer") == status_id
                  and "a test user" in (f["event"].get("text") or "")]
        check("the whois numerics stayed out of the status buffer", leaked, [])

        # A nick nobody is using is answered too. Silence would leave the card
        # spinning, which is the one outcome worse than "no such nick".
        await client.send({"type": "whois", "req": "w2", "nick": "nobodyhere"})
        missing = await client.wait(
            lambda f: f.get("type") == "whois" and f.get("req") == "w2") or {}
        check("an unknown nick is answered", missing.get("found"), False)
        check("an unknown nick says why", missing.get("error"), "no such nick")

        # --- /close ------------------------------------------------------------
        await client.send({"type": "close", "req": "x1", "buffer": query_buffer_id})
        closed = await client.wait(
            lambda f: f.get("type") == "buffer"
            and f["buffer"]["id"] == query_buffer_id
            and f["buffer"]["archived"])
        check("/close archived the buffer", closed is not None, True)
        # Closed buffers are listed only when asked for (a Closed section).
        await client.send({"type": "buffers", "req": "ba1", "archived": True})
        await client.send({"type": "buffers", "req": "ba2"})
        with_closed = await client.wait(lambda f: f.get("req") == "ba1") or {}
        without = await client.wait(lambda f: f.get("req") == "ba2") or {}
        check("buffers with archived:true lists the closed one, marked",
              [b["archived"] for b in with_closed.get("buffers", []) if b["id"] == query_buffer_id],
              [True])
        check("and the ordinary list still leaves it out",
              [b for b in without.get("buffers", []) if b["id"] == query_buffer_id], [])
        # Archiving must not destroy anything.
        await client.send({"type": "say", "req": "r1", "target": "someone_else",
                           "text": "back again"})
        reopened = await client.wait(
            lambda f: f.get("type") == "buffer"
            and f["buffer"]["id"] == query_buffer_id
            and not f["buffer"]["archived"])
        check("a closed buffer reopens when used again", reopened is not None, True)

        # --- refusals ----------------------------------------------------------
        await client.send({"type": "close", "req": "x2", "buffer": status_id})
        refused = await client.wait(lambda f: f.get("type") == "error" and f.get("req") == "x2")
        check("closing the status buffer is refused", refused is not None, True)

        await client.send({"type": "say", "req": "s9", "buffer": status_id, "text": "hi"})
        refused2 = await client.wait(lambda f: f.get("type") == "error" and f.get("req") == "s9")
        check("talking to the status buffer is refused", refused2 is not None, True)

        # --- malformed frames ---------------------------------------------------
        # Valid JSON that is not an object. This used to raise AttributeError
        # inside the handler meant to report it, taking the connection with it,
        # so the surviving connection is the half worth testing.
        await client.ws.send_str("[1, 2, 3]")
        notobj = await client.wait(lambda f: f.get("type") == "error"
                                   and f.get("message") == "frame must be an object")
        check("a frame that is not an object is reported", notobj is not None, True)
        await client.send({"type": "ping", "req": "alive"})
        alive = await client.wait(lambda f: f.get("type") == "pong" and f.get("req") == "alive")
        check("the connection survives a non-object frame", alive is not None, True)

        await client.send({"type": "mark_read", "req": "bad1",
                           "buffer": "not a number", "eid": 1})
        badint = await client.wait(lambda f: f.get("type") == "error" and f.get("req") == "bad1")
        check("a non-integer buffer is a malformed frame",
              (badint or {}).get("message"), "malformed mark_read frame")

        await client.send({"type": "backlog", "req": "bad2"})       # no buffer at all
        missing = await client.wait(lambda f: f.get("type") == "error" and f.get("req") == "bad2")
        check("a missing field is a malformed frame",
              (missing or {}).get("message"), "malformed backlog frame")

        # A refusal from the session still says what was wrong, in words meant
        # for whoever typed it -- that is not what "malformed" is for.
        await client.send({"type": "say", "req": "bad3", "buffer": chan["id"],
                           "text": "one\ntwo\nthree\nfour\nfive\nsix\n"
                                   "seven\neight\nnine\nten\neleven"})
        toomany = await client.wait(lambda f: f.get("type") == "error" and f.get("req") == "bad3")
        check("too many lines at once is refused",
              "more than 10 lines" in (toomany or {}).get("message", ""), True)

        # --- a message with newlines in it ---------------------------------------
        # IRC has no multi-line message, so one `say` becomes three PRIVMSGs and
        # three events. Handing the newline to the server instead would have
        # been handing it two extra commands.
        before_lines = len(watcher2.lines)
        await client.send({"type": "say", "req": "ml1", "buffer": chan["id"],
                           "text": "first line\nsecond line\nthird line"})
        ml_ok = await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "ml1")
        check("multi-line say acknowledged", ml_ok is not None, True)
        check("the ok carries the first line",
              (ml_ok or {}).get("event", {}).get("text"), "first line")
        await watcher2.wait_for("third line")
        sent = [l for l in watcher2.lines[before_lines:]
                if "PRIVMSG" in l and " line" in l]
        check("three lines reached irc as three PRIVMSGs", len(sent), 3)
        stored_lines = [f for f in client.frames
                        if f.get("type") == "event"
                        and (f["event"].get("text") or "") in
                            ("first line", "second line", "third line")]
        check("each line is its own stored event", len(stored_lines), 3)

        # --- a queued say never holds the client's next frames ----------------
        # The bucket is spent by now, so these wait in the flood queue. Their
        # echo wait used to hold the frame loop 0.5 s each: a ping sent after
        # six of them waited three seconds.
        for i in range(6):
            await client.send({"type": "say", "req": f"q{i}", "buffer": chan["id"],
                               "text": f"queued {i}"})
        started = time.monotonic()
        await client.send({"type": "ping", "req": "after-burst"})
        pong = await client.wait(lambda f: f.get("req") == "after-burst", timeout=5)
        check("a ping behind six queued says is answered at once",
              pong is not None and time.monotonic() - started < 0.4, True)
        oks = [await client.wait(lambda f, r=f"q{i}": f.get("req") == r, timeout=3)
               for i in range(6)]
        check("  and every say still gets its answer", all(f and f["type"] == "ok" for f in oks), True)

        # --- netsplit tagging ---------------------------------------------------
        splitter = Watcher("splitvictim")
        await splitter.connect(PORT_IRC)
        await asyncio.sleep(0.3)
        before_split = len(client.frames)
        splitter.join("#testing")
        await asyncio.sleep(0.4)
        splitter.quit("irc.alpha.net irc.beta.net")
        await asyncio.sleep(0.1)
        splitter.close()
        split_event = await client.wait(is_event(kind="quit", sender="splitvictim"))
        check("netsplit quit arrived", split_event is not None, True)
        # Membership is deltas now (G56): one small frame for the join and one
        # for the quit, never the whole list again.
        membership = [f for f in client.frames[before_split:]
                      if f.get("type", "").startswith("member")]
        check("a join and a quit are two deltas, not two full lists",
              [(f["type"], f.get("member", {}).get("nick") or f.get("nick")) for f in membership],
              [("member_add", "splitvictim"), ("member_remove", "splitvictim")])
        check("netsplit is tagged with both servers",
              (split_event or {}).get("event", {}).get("extra", {}).get("netsplit"),
              ["irc.alpha.net", "irc.beta.net"])

        # An ordinary goodbye must NOT be tagged -- a real message hidden inside
        # a collapsed "netsplit" row is worse than an uncollapsed row.
        normal = Watcher("normalquitter")
        await normal.connect(PORT_IRC)
        await asyncio.sleep(0.3)
        normal.join("#testing")
        await asyncio.sleep(0.4)
        normal.quit("brb dinner.time")
        await asyncio.sleep(0.1)
        normal.close()
        normal_event = await client.wait(is_event(kind="quit", sender="normalquitter"))
        check("ordinary quit is not tagged",
              "netsplit" in ((normal_event or {}).get("event", {}).get("extra", {}) or {}),
              False)

        # --- detach -------------------------------------------------------------
        await client.send({"type": "detach", "req": "d1", "buffer": chan["id"]})
        detached = await client.wait(
            lambda f: f.get("type") == "buffer" and f["buffer"]["id"] == chan["id"]
            and f["buffer"].get("detached"))
        check("detach muted the channel", detached is not None, True)
        # Still joined: muting is about volume, not leaving.
        check("detached channel is still joined",
              (detached or {})["buffer"]["joined"] if detached else None, True)

        watcher2.say("#testing", "ordinary chatter while muted")
        muted = await client.wait(
            lambda f: f.get("type") == "unread"
            and f["counts"].get(str(chan["id"]), f["counts"].get(chan["id"], {})).get("unread") == 0,
            timeout=3.0)
        # A mention no longer un-mutes it (G35): muted stays muted until the
        # user says otherwise. It used to re-attach it for good.
        after_detach = len(client.frames)
        watcher2.say("#testing", "relaytest: still there?")
        await client.wait(is_event(text="still there?"))
        await asyncio.sleep(0.3)
        unmuted = [f for f in client.frames[after_detach:] if f.get("type") == "buffer"
                   and f["buffer"]["id"] == chan["id"] and not f["buffer"].get("detached")]
        check("a mention does not un-mute a muted channel", unmuted, [])
        check("and the store agrees", relay.store.buffer(chan["id"]).detached, True)
        await client.send({"type": "detach", "req": "d2", "buffer": chan["id"], "detached": False})
        await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "d2")

        # --- a mute that ends by itself ----------------------------------------
        await client.send({"type": "detach", "req": "d3", "buffer": chan["id"], "until": 1})
        refused = await client.wait(lambda f: f.get("req") == "d3")
        check("a mute that ends in the past is refused", (refused or {}).get("type"), "error")
        await client.send({"type": "detach", "req": "d4", "buffer": chan["id"], "until": "tomorrow"})
        refused = await client.wait(lambda f: f.get("req") == "d4")
        check("and so is one that is not a time", (refused or {}).get("type"), "error")
        soon = time.time() + 3600
        await client.send({"type": "detach", "req": "d5", "buffer": chan["id"], "until": soon})
        timed = await client.wait(
            lambda f: f.get("type") == "buffer" and f["buffer"]["id"] == chan["id"]
            and f["buffer"].get("muted_until"))
        check("a timed mute carries its end", round((timed or {})["buffer"]["muted_until"]) if timed else None,
              round(soon))
        # Its time comes: the sweep lifts it and tells everybody, as an unmute does.
        after_timed = len(client.frames)
        lifted = await relay.gateway.lift_expired_mutes(now=soon + 1)
        check("the sweep lifts the expired mute", lifted, 1)
        gone = await client.wait(
            lambda f: f.get("type") == "buffer" and f["buffer"]["id"] == chan["id"]
            and not f["buffer"].get("detached") and f["buffer"].get("muted_until") is None)
        check("and announces the channel unmuted", gone is not None, True)
        check("and the store agrees it is unmuted", relay.store.buffer(chan["id"]).detached, False)
        await client.wait(lambda f: f.get("req") == "d5")

        # --- per-buffer settings, mark all read, global settings (G35, G37) ----
        settings = next((f for f in client.frames if f.get("type") == "settings"), {})
        check("settings arrive after hello",
              (client.frames.index(settings) if settings else -1, settings.get("push_preview"),
               settings.get("auto_away"), settings.get("highlight_words")),
              (1, True, False, {"test": []}))
        await client.send({"type": "buffer_settings", "req": "bs1", "buffer": chan["id"],
                           "notify": "all", "pinned": True})
        bs = await client.wait(lambda f: f.get("req") == "bs1") or {}
        check("buffer_settings is ok, with the buffer",
              (bs.get("type"), bs.get("buffer", {}).get("notify"), bs.get("buffer", {}).get("pinned")),
              ("ok", "all", True))
        announced = await client.wait(lambda f: f.get("type") == "buffer"
                                      and f["buffer"]["id"] == chan["id"]
                                      and f["buffer"].get("notify") == "all")
        check("and every client is sent the buffer", announced is not None, True)
        await client.send({"type": "buffer_settings", "req": "bs2", "buffer": chan["id"],
                           "notify": "loud"})
        bad = await client.wait(lambda f: f.get("req") == "bs2") or {}
        check("an unknown level is refused in words",
              (bad.get("type"), "notify must be one of" in bad.get("message", "")), ("error", True))
        await client.send({"type": "buffer_settings", "req": "bs3", "buffer": chan["id"],
                           "notify": "mentions", "pinned": False})
        await client.wait(lambda f: f.get("req") == "bs3")

        await client.send({"type": "set_settings", "req": "ss1",
                           "highlight_words": {"test": ["pizza", "Pizza", " rail gun "]},
                           "push_preview": False})
        ss = await client.wait(lambda f: f.get("req") == "ss1") or {}
        changed = await client.wait(lambda f: f.get("type") == "settings"
                                    and f.get("push_preview") is False) or {}
        check("set_settings is ok and broadcast, words cleaned",
              (ss.get("type"), changed.get("highlight_words")),
              ("ok", {"test": ["pizza", "rail gun"]}))
        watcher2.say("#testing", "who wants pizza")
        pizza = await client.wait(is_event(text="who wants pizza")) or {}
        check("a highlight word is a mention", pizza.get("event", {}).get("highlight"), True)
        await client.send({"type": "set_settings", "req": "ss2", "highlight_words": {"nope": []}})
        nope = await client.wait(lambda f: f.get("req") == "ss2") or {}
        check("an unknown network is refused", (nope.get("type"), nope.get("message")),
              ("error", "unknown network: nope"))
        await client.send({"type": "set_settings", "req": "ss3", "highlight_words": {"test": []},
                           "push_preview": True})
        await client.wait(lambda f: f.get("req") == "ss3")

        # The notification sound is the person's to choose, from a fixed list.
        await client.send({"type": "set_settings", "req": "ss4", "push_sound": "klaxon"})
        bad_sound = await client.wait(lambda f: f.get("req") == "ss4") or {}
        check("an unknown sound is refused", bad_sound.get("type"), "error")
        await client.send({"type": "set_settings", "req": "ss5", "push_sound": "chime"})
        await client.wait(lambda f: f.get("req") == "ss5")
        chosen = await client.wait(lambda f: f.get("type") == "settings"
                                   and f.get("push_sound") == "chime") or {}
        check("a chosen sound is kept and broadcast", chosen.get("push_sound"), "chime")
        check("and the store agrees", relay.store.get_setting("push_sound"), "chime")
        await client.send({"type": "set_settings", "req": "ss6", "push_sound": "default"})
        await client.wait(lambda f: f.get("req") == "ss6")

        # Nick colors: a hue per nick key, merged, never half-applied.
        async def colors(req, value):
            await client.send({"type": "set_settings", "req": req, "nick_colors": value})
            return await client.wait(lambda f: f.get("req") == req) or {}

        check("the settings frame carries nick_colors, empty at first",
              relay.gateway.settings_frame().get("nick_colors"), {})
        ok = await colors("nc1", {"alice": 210, "bob": 30})
        got = await client.wait(lambda f: f.get("type") == "settings"
                                and f.get("nick_colors") == {"alice": 210, "bob": 30}) or {}
        check("colors are set and broadcast", (ok.get("type"), got.get("nick_colors")),
              ("ok", {"alice": 210, "bob": 30}))
        await colors("nc2", {"alice": 0})
        check("one is overwritten and the other left alone",
              relay.store.get_setting("nick_colors"), {"alice": 0, "bob": 30})
        await colors("nc3", {"bob": None, "carol": 359, "nobody": None})
        check("null removes, and merges the rest in",
              relay.store.get_setting("nick_colors"), {"alice": 0, "carol": 359})
        await colors("nc4", {})
        check("an empty merge changes nothing",
              relay.store.get_setting("nick_colors"), {"alice": 0, "carol": 359})
        await client.send({"type": "set_settings", "req": "nc5", "push_sound": "pop"})
        await client.wait(lambda f: f.get("req") == "nc5")
        check("other settings leave the colors alone",
              relay.store.get_setting("nick_colors"), {"alice": 0, "carol": 359})
        await client.send({"type": "set_settings", "req": "nc6", "push_sound": "default"})
        await client.wait(lambda f: f.get("req") == "nc6")
        refused = [
            ("not an object", ["alice"]), ("a key with a space", {"a b": 1}),
            ("an empty key", {"": 1}), ("a control character", {"a\x00b": 1}),
            ("a key over 64 characters", {"x" * 65: 1}), ("a string hue", {"dave": "210"}),
            ("a float hue", {"dave": 210.0}), ("a boolean hue", {"dave": True}),
            ("a negative hue", {"dave": -1}), ("a hue of 360", {"dave": 360}),
            ("one bad value among good ones", {"dave": 10, "erin": 360}),
        ]
        for n, (why, value) in enumerate(refused):
            bad = await colors(f"ncx{n}", value)
            check(f"{why} is refused", bad.get("type"), "error")
        check("and nothing was applied", relay.store.get_setting("nick_colors"),
              {"alice": 0, "carol": 359})
        await client.send({"type": "set_settings", "req": "nc7", "push_preview": "yes",
                           "nick_colors": {"dave": 10}})
        await client.wait(lambda f: f.get("req") == "nc7")
        check("a bad sibling field refuses the colors too",
              relay.store.get_setting("nick_colors"), {"alice": 0, "carol": 359})
        await colors("nc8", {f"n{i}": i % 360 for i in range(998)})
        check("up to the limit is accepted", len(relay.store.get_setting("nick_colors")), 1000)
        over = await colors("nc9", {"one-too-many": 5})
        check("over 1000 is refused in a sentence",
              (over.get("type"), "1000" in over.get("message", "")), ("error", True))
        await colors("nc10", {"one-too-many": 5, "alice": None})
        check("a merge that nets out under the limit is fine",
              len(relay.store.get_setting("nick_colors")), 1000)
        await colors("nc11", {f"n{i}": None for i in range(998)} | {"one-too-many": None})
        check("and they can all be cleared again",
              relay.store.get_setting("nick_colors"), {"carol": 359})

        # The palette is an id the bouncer only stores.
        async def palette(req, value, **more):
            await client.send({"type": "set_settings", "req": req, "nick_palette": value, **more})
            return await client.wait(lambda f: f.get("req") == req) or {}

        check("the settings frame carries nick_palette, default at first",
              relay.gateway.settings_frame().get("nick_palette"), "default")
        ok = await palette("np1", "pastel-2")
        got = await client.wait(lambda f: f.get("type") == "settings"
                                and f.get("nick_palette") == "pastel-2") or {}
        check("a palette id is set and broadcast", (ok.get("type"), got.get("nick_palette")),
              ("ok", "pastel-2"))
        for n, (why, value) in enumerate([
                ("a symbol", "Pastel!"), ("an uppercase id", "Pastel"), ("an empty id", ""),
                ("25 characters", "a" * 25), ("a number", 5), ("a list", ["pastel"]),
                ("a space", "pas tel"), ("an underscore", "pas_tel")]):
            bad = await palette(f"npx{n}", value)
            check(f"{why} is refused", bad.get("type"), "error")
        check("and the palette was not changed", relay.store.get_setting("nick_palette"), "pastel-2")
        await palette("np2", "a" * 24)
        check("24 characters is fine", relay.store.get_setting("nick_palette"), "a" * 24)
        await client.send({"type": "set_settings", "req": "np3", "push_sound": "pop"})
        await client.wait(lambda f: f.get("req") == "np3")
        check("leaving it out leaves it alone", relay.store.get_setting("nick_palette"), "a" * 24)
        await palette("np4", "x", nick_colors={"dave": 360})
        check("a bad sibling refuses the palette too", relay.store.get_setting("nick_palette"),
              "a" * 24)
        await palette("np5", "default", push_sound="default")
        check("and it can go back to default", relay.store.get_setting("nick_palette"), "default")

        watcher2.say("#testing", "something to read")
        await client.wait(is_event(text="something to read"))
        before_mar = len(client.frames)
        await client.send({"type": "mark_all_read", "req": "mar"})
        await client.wait(lambda f: f.get("req") == "mar")
        markers = await client.wait(lambda f: f.get("type") == "unread"
                                    and client.frames.index(f) > before_mar) or {}
        check("mark_all_read leaves nothing unread",
              {v["unread"] for v in markers.get("counts", {}).values()}, {0})
        check("with a read_marker for each buffer",
              chan["id"] in {f["buffer"] for f in client.frames[before_mar:]
                             if f.get("type") == "read_marker"}, True)

        # --- around paging ------------------------------------------------------
        await client.send({"type": "backlog", "req": "ar", "buffer": chan["id"], "limit": 100})
        full = await client.wait(lambda f: f.get("type") == "backlog" and f.get("req") == "ar")
        all_eids = [e["eid"] for e in full["events"]] if full else []
        if len(all_eids) >= 5:
            middle = all_eids[len(all_eids) // 2]
            await client.send({"type": "backlog", "req": "ar2", "buffer": chan["id"],
                               "around_eid": middle, "limit": 6})
            page = await client.wait(lambda f: f.get("type") == "backlog" and f.get("req") == "ar2")
            page_eids = [e["eid"] for e in page["events"]] if page else []
            check("around returned a page", len(page_eids) > 0, True)
            check("around includes the anchor", middle in page_eids, True)
            check("around reaches backwards", any(e < middle for e in page_eids), True)
            check("around reaches forwards", any(e > middle for e in page_eids), True)
            check("around is labelled", page.get("direction") if page else None, "around")
            check("around in the middle is not the start", page.get("complete"), False)
            # At the buffer's own first line: complete, although other buffers
            # hold older eids (G78: it used to compare with eid 1).
            first_eid = relay.store.backlog_after(chan["id"], 0, limit=1)[0].eid
            await client.send({"type": "backlog", "req": "ar3", "buffer": chan["id"],
                               "around_eid": first_eid, "limit": 6})
            start = await client.wait(lambda f: f.get("type") == "backlog" and f.get("req") == "ar3")
            check("around the buffer's first line says complete (not eid 1)",
                  (first_eid > 1, (start or {}).get("complete")), (True, True))
        await client.send({"type": "backlog", "req": "ar4", "buffer": chan["id"], "limit": -1})
        clamped = await client.wait(lambda f: f.get("type") == "backlog" and f.get("req") == "ar4")
        check("a negative limit is one line, not the whole buffer",
              len((clamped or {}).get("events", [])), 1)

        # --- a password typed to a service (G61) --------------------------------
        nickserv = Watcher("NickServ")
        await nickserv.connect(PORT_IRC)
        await asyncio.sleep(0.3)
        await client.send({"type": "say", "req": "ns1", "target": "NickServ",
                           "text": "IDENTIFY hunter2secret"})
        ns_ok = await client.wait(lambda f: f.get("req") == "ns1") or {}
        check("IDENTIFY accepted", ns_ok.get("type"), "ok")
        check("reaches the service as typed",
              await nickserv.wait_for("PRIVMSG NickServ :IDENTIFY hunter2secret") is not None, True)
        check("the echo every device gets is redacted",
              ns_ok.get("event", {}).get("text"), "IDENTIFY ********")
        await client.send({"type": "search", "req": "ns2", "query": "hunter2secret"})
        found = await client.wait(lambda f: f.get("req") == "ns2") or {}
        check("search cannot find it", found.get("results"), [])
        nickserv.close()

        # --- push decision chain -------------------------------------------------
        # The whole point of the bouncer: a mention that arrives while nothing is
        # watching has to become a notification. Uses the recording provider
        # installed below, so this exercises highlight -> has_active_viewer ->
        # push without needing APNs.
        await client.send({"type": "register_push", "req": "p1",
                           "device_token": "DEADBEEF", "platform": "ios",
                           "environment": "sandbox"})
        await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "p1")

        # A device row that is not addressable is a push that fails forever and
        # is only noticed when a notification does not arrive, so the shape is
        # checked here rather than at APNs.
        for req, frame in [
            ("v1", {"device_token": "not hex!", "platform": "ios", "environment": "sandbox"}),
            ("v2", {"device_token": "AB" * 200, "platform": "ios", "environment": "sandbox"}),
            ("v3", {"device_token": "DEADBEEF", "platform": "android", "environment": "sandbox"}),
            ("v4", {"device_token": "DEADBEEF", "platform": "ios", "environment": "staging"}),
        ]:
            await client.send({"type": "register_push", "req": req, **frame})
        for req, label in [("v1", "non-hex device token refused"),
                           ("v2", "an over-long device token is refused"),
                           ("v3", "an unknown platform is refused"),
                           ("v4", "an unknown environment is refused")]:
            bad = await client.wait(lambda f, r=req: f.get("type") == "error" and f.get("req") == r)
            check(label, bad is not None, True)
        check("only the valid device was stored",
              [d["apns_token"] for d in relay.store.devices()], ["DEADBEEF"])

        # Watching this buffer: a mention must NOT push.
        await client.send({"type": "ping", "req": "p2", "presence": "foreground",
                           "focused_buffer": chan["id"]})
        await client.wait(lambda f: f.get("type") == "pong" and f.get("req") == "p2")
        pushes.clear()
        me = session.nick
        watcher2.say("#testing", f"{me}: looking right at you")
        await client.wait(is_event(text="looking right at you"))
        await asyncio.sleep(0.3)
        check("no push while watching the buffer", pushes, [])

        # Backgrounded: the socket may be suspended, so this must push.
        await client.send({"type": "ping", "req": "p3", "presence": "background",
                           "focused_buffer": chan["id"]})
        await client.wait(lambda f: f.get("type") == "pong" and f.get("req") == "p3")
        watcher2.say("#testing", f"{me}: are you there now")
        await client.wait(is_event(text="are you there now"))
        await asyncio.sleep(0.4)
        check("backgrounded mention pushes", len(pushes) >= 1, True)
        if pushes:
            note, devices = pushes[-1]
            check("push names the channel", note.title, "#testing")
            check("push body has the sender and text",
                  "observer" in note.body and "are you there now" in note.body, True)
            check("push carries the buffer for deep linking", note.buffer_id, chan["id"])
            check("push carries an eid to land on", note.eid > 0, True)
            check("push went to the registered device",
                  [d["apns_token"] for d in devices], ["DEADBEEF"])

        # Ordinary chatter, backgrounded, must NOT push -- only mentions do.
        pushes.clear()
        watcher2.say("#testing", "just talking amongst ourselves")
        await client.wait(is_event(text="amongst ourselves"))
        await asyncio.sleep(0.3)
        check("ordinary traffic does not push", pushes, [])

        # A muted channel still pushes a mention (and re-attaches).
        await client.send({"type": "detach", "req": "p4", "buffer": chan["id"]})
        await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "p4")
        pushes.clear()
        watcher2.say("#testing", f"{me}: even though it is muted")
        await client.wait(is_event(text="even though it is muted"))
        await asyncio.sleep(0.4)
        check("a mention in a muted channel still pushes", len(pushes) >= 1, True)

        # --- blocking ------------------------------------------------------------
        # Apple requires a way to block an abusive user; more importantly a block
        # has to actually block. Dropping before storage is what makes it real:
        # stored-but-hidden would still have produced a push notification.
        blocker = Watcher("nuisance")
        await blocker.connect(PORT_IRC)
        await asyncio.sleep(0.3)
        blocker.join("#testing")
        await asyncio.sleep(0.4)

        blocker.say("#testing", "before the block")
        seen = await client.wait(is_event(text="before the block"))
        check("messages arrive before blocking", seen is not None, True)

        await client.send({"type": "ignore", "req": "i1", "nick": "nuisance"})
        blocked_ok = await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "i1")
        check("block accepted", blocked_ok is not None, True)
        listed = await client.wait(lambda f: f.get("type") == "ignores"
                                   and "nuisance" in (f.get("nicks") or []))
        check("block list broadcast to every device", listed is not None, True)

        pushes.clear()
        before = len(client.frames)
        blocker.say("#testing", "after the block")
        blocker.say("#testing", f"{me}: even mentioning you")
        await asyncio.sleep(1.0)
        arrived = [f for f in client.frames[before:]
                   if f.get("type") == "event"
                   and ("after the block" in (f["event"].get("text") or "")
                        or "even mentioning" in (f["event"].get("text") or ""))]
        check("blocked messages never arrive", arrived, [])
        check("a blocked mention does not push", pushes, [])

        # And it is not merely hidden -- it was never written down.
        stored = relay.store.backlog(chan["id"], limit=500)
        check("blocked messages are not stored",
              [e for e in stored if "after the block" in (e.text or "")], [])

        await client.send({"type": "ignore", "req": "i2", "nick": "nuisance",
                           "ignored": False})
        await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "i2")
        blocker.say("#testing", "unblocked again")
        back = await client.wait(is_event(text="unblocked again"))
        check("unblocking restores delivery", back is not None, True)

        await client.send({"type": "ignore", "req": "i3", "nick": session.nick})
        selfblock = await client.wait(lambda f: f.get("type") == "error" and f.get("req") == "i3")
        check("cannot block yourself", selfblock is not None, True)
        blocker.close()

        # --- mentions inbox (G36) -----------------------------------------------
        await client.send({"type": "mentions", "req": "mn1", "limit": 3})
        inbox = await client.wait(lambda f: f.get("type") == "mentions"
                                  and f.get("req") == "mn1") or {}
        eids = [e["eid"] for e in inbox.get("events", [])]
        check("mentions: a page of highlights, newest first",
              (len(eids), eids == sorted(eids, reverse=True),
               all(e["highlight"] for e in inbox.get("events", []))), (3, True, True))
        check("mentions: a full page is not complete", inbox.get("complete"), False)
        await client.send({"type": "mentions", "req": "mn2", "before_eid": eids[-1] if eids else 0,
                           "limit": 200})
        older = await client.wait(lambda f: f.get("type") == "mentions"
                                  and f.get("req") == "mn2") or {}
        check("mentions: paging on reaches the end", older.get("complete"), True)
        check("mentions: across buffers (the PM is there)",
              any(e["text"] == "psst" for e in older.get("events", []) + inbox.get("events", [])),
              True)

        # --- search --------------------------------------------------------------
        # The feature a bouncer uniquely enables: nobody else has the history.
        await client.send({"type": "search", "req": "q1", "query": "hello"})
        found = await client.wait(lambda f: f.get("type") == "search_results"
                                  and f.get("req") == "q1")
        check("search returned results", found is not None, True)
        texts = [r["text"] for r in (found or {}).get("results", [])]
        check("search finds a received line", any("hello from irc" in t for t in texts), True)
        check("search finds a line we sent", any("hello from the app" in t for t in texts), True)
        check("results carry their buffer",
              all("buffer" in r for r in (found or {}).get("results", [])), True)

        # Newest first: recent is what people mean.
        eids = [r["eid"] for r in (found or {}).get("results", [])]
        check("newest first", eids == sorted(eids, reverse=True), True)

        # Membership noise must not come back as a result.
        await client.send({"type": "search", "req": "q2", "query": "joined"})
        noise = await client.wait(lambda f: f.get("type") == "search_results"
                                  and f.get("req") == "q2")
        kinds = {r["kind"] for r in (noise or {}).get("results", [])}
        check("joins are not search results", "join" in kinds, False)

        # Scoped to one buffer.
        await client.send({"type": "search", "req": "q3", "query": "hello",
                           "buffer": chan["id"]})
        scoped = await client.wait(lambda f: f.get("type") == "search_results"
                                   and f.get("req") == "q3")
        check("buffer-scoped search stays in that buffer",
              {r["buffer"] for r in (scoped or {}).get("results", [])} <= {chan["id"]}, True)

        # The query is plain text now (G20): what used to be an FTS5 syntax
        # error is a search for what was typed.
        watcher2.say("#testing", "see https://img.example.com/x.png and what's c++ quinn: #hangout")
        await client.wait(is_event(text="img.example.com"))
        for req, query in (("q4a", "img.example.com"), ("q4b", "what's"), ("q4c", "c++"),
                           ("q4d", "#hangout"), ("q4e", "quinn:"), ("q4f", '"unterminated'),
                           ("q4g", "((")):
            await client.send({"type": "search", "req": req, "query": query})
            answer = await client.wait(lambda f, r=req: f.get("req") == r) or {}
            hits = [r["text"] for r in answer.get("results", [])]
            if query in ('"unterminated', "(("):
                check(f"{query!r} is answered, not refused", answer.get("type"), "search_results")
            else:
                check(f"{query!r} finds the line", any("example" in t for t in hits), True)
        await client.send({"type": "search", "req": "q4h", "query": "example", "from": "OBSERVER"})
        fromhit = await client.wait(lambda f: f.get("req") == "q4h") or {}
        check("from: filters by nick, any case", len(fromhit.get("results", [])), 1)
        await client.send({"type": "search", "req": "q4i", "query": "example", "from": "someone"})
        nothit = await client.wait(lambda f: f.get("req") == "q4i") or {}
        check("from: another nick finds none of it", nothit.get("results"), [])

        await client.send({"type": "search", "req": "q5", "query": "x"})
        short = await client.wait(lambda f: f.get("type") == "error" and f.get("req") == "q5")
        check("one-character searches are refused", short is not None, True)

        # --- operator actions ------------------------------------------------------
        victim = Watcher("targetuser")
        await victim.connect(PORT_IRC)
        await asyncio.sleep(0.3)
        victim.join("#testing")
        await asyncio.sleep(0.4)
        # A message, so a hostmask is on record for the ban to use.
        victim.say("#testing", "hello from the target")
        await client.wait(is_event(text="hello from the target"))

        await client.send({"type": "chanmode", "req": "m1", "buffer": chan["id"],
                           "mode": "+v", "nick": "targetuser"})
        voiced = await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "m1")
        check("voice accepted", voiced is not None, True)
        sent_voice = await watcher2.wait_for("MODE #testing +v targetuser")
        check("voice reached the server", sent_voice is not None, True)

        # A ban must use the hostmask, not the nick: a nick ban is evaded by
        # changing nick.
        await client.send({"type": "chanmode", "req": "m2", "buffer": chan["id"],
                           "mode": "+b", "nick": "targetuser"})
        await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "m2")
        banned = await watcher2.wait_for("MODE #testing +b *!*@")
        check("ban uses a hostmask, not a bare nick", banned is not None, True)

        # Anything outside the allow-list is refused, so a client cannot send
        # arbitrary mode strings to the server.
        await client.send({"type": "chanmode", "req": "m3", "buffer": chan["id"],
                           "mode": "+O", "nick": "targetuser"})
        refused = await client.wait(lambda f: f.get("type") == "error" and f.get("req") == "m3")
        check("disallowed modes are refused", refused is not None, True)

        await client.send({"type": "chanmode", "req": "m4", "buffer": chan["id"],
                           "mode": "nonsense", "nick": "x"})
        refused2 = await client.wait(lambda f: f.get("type") == "error" and f.get("req") == "m4")
        check("malformed modes are refused", refused2 is not None, True)

        await client.send({"type": "kick", "req": "k1", "buffer": chan["id"],
                           "nick": "targetuser", "reason": "bye"})
        kick_ok = await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "k1")
        check("kick accepted", kick_ok is not None, True)
        kicked = await watcher2.wait_for("KICK #testing targetuser")
        check("kick reached the server", kicked is not None, True)

        await client.send({"type": "kick", "req": "k2", "buffer": chan["id"],
                           "nick": session.nick})
        selfkick = await client.wait(lambda f: f.get("type") == "error" and f.get("req") == "k2")
        check("cannot kick yourself", selfkick is not None, True)
        victim.close()

        # --- notice --------------------------------------------------------------
        await client.send({"type": "say", "req": "nt1", "buffer": chan["id"],
                           "text": "a notice line", "notice": True})
        notice_ok = await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "nt1")
        check("notice acknowledged", notice_ok is not None, True)
        check("the echo is stored as a notice, not a message",
              (notice_ok or {}).get("event", {}).get("kind"), "notice")
        notice_seen = await watcher2.wait_for("NOTICE #testing :a notice line")
        check("notice reached irc as a NOTICE, not a PRIVMSG", notice_seen is not None, True)

        # --- away ------------------------------------------------------------------
        # Checked against the fake server's own idea of the peer, not just the
        # frame we get back -- the point is that AWAY actually went out.
        def find_peer(nick):
            return next((p for p in ircd.peers if p.nick.lower() == nick.lower()), None)

        # Freshness is checked by frame index, not just by matching value --
        # `away` defaults to null, so a plain "is None" match could otherwise
        # be satisfied by a frame sent long before this test ran.
        before_aw = len(client.frames)
        await client.send({"type": "away", "req": "aw1", "text": "stepping out"})
        away_ok = await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "aw1")
        check("away accepted", away_ok is not None, True)
        away_network = None
        for _ in range(100):
            new = [f for f in client.frames[before_aw:]
                  if f.get("type") == "network" and f["network"].get("away") == "stepping out"]
            if new:
                away_network = new[0]
                break
            await asyncio.sleep(0.05)
        check("network frame reflects the away message", away_network is not None, True)
        peer = None
        for _ in range(40):
            peer = find_peer(session.nick)
            if peer and peer.away == "stepping out":
                break
            await asyncio.sleep(0.05)
        check("AWAY reached the fake ircd", peer.away if peer else None, "stepping out")

        before_aw2 = len(client.frames)
        await client.send({"type": "away", "req": "aw2"})
        back_ok = await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "aw2")
        check("clearing away accepted", back_ok is not None, True)
        cleared_network = None
        for _ in range(100):
            new = [f for f in client.frames[before_aw2:]
                  if f.get("type") == "network" and f["network"].get("away") is None]
            if new:
                cleared_network = new[0]
                break
            await asyncio.sleep(0.05)
        check("network frame reflects away cleared", cleared_network is not None, True)
        peer = None
        for _ in range(40):
            peer = find_peer(session.nick)
            if peer and peer.away is None:
                break
            await asyncio.sleep(0.05)
        check("a bare AWAY cleared it at the fake ircd", peer.away if peer else "missing", None)

        # --- invite ------------------------------------------------------------------
        await client.send({"type": "invite", "req": "iv1", "channel": "#testing",
                           "nick": "observer"})
        invite_ok = await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "iv1")
        check("invite accepted", invite_ok is not None, True)
        invited = await watcher2.wait_for("INVITE observer")
        check("invite reached the invited nick at the fake ircd", invited is not None, True)

        # --- typing: IRCv3 +typing over TAGMSG -----------------------------------
        # The fake server offers message-tags only when told to, with CAP NEW,
        # so everything above ran on a link without it, as on QuakeNet.
        watcher2.writer.write(b"CAP REQ :message-tags\r\n")
        await client.send({"type": "typing", "req": "ty0", "buffer": chan["id"], "state": "active"})
        await asyncio.sleep(0.3)
        check("without message-tags a typing frame sends nothing",
              [l for l in watcher2.lines if "TAGMSG" in l], [])
        check("  and it is answered by nothing, not even its req",
              [f for f in client.frames if f.get("req") == "ty0"], [])
        me = session.nick
        watcher2.writer.write(f"RAWTO {me} ::fake.irc CAP {me} NEW :message-tags\r\n".encode())
        for _ in range(60):
            if "message-tags" in session.conn.caps:
                break
            await asyncio.sleep(0.05)
        check("the bouncer takes message-tags once it is offered",
              "message-tags" in session.conn.caps, True)
        await client.send({"type": "typing", "buffer": chan["id"], "state": "active"})
        typing_seen = await watcher2.wait_for("TAGMSG #testing")
        check("typing reaches irc as a tagged TAGMSG", typing_seen,
              f"@+typing=active :{me}!u@h TAGMSG #testing")
        await client.send({"type": "typing", "buffer": chan["id"], "state": "active"})
        await client.send({"type": "typing", "buffer": chan["id"], "state": "done"})
        check("then done", await watcher2.wait_for("+typing=done") is not None, True)
        check("and the second active inside three seconds was never sent",
              sum("+typing=active" in l for l in watcher2.lines), 1)

        newest = relay.store.newest_eid(chan["id"])
        counts = relay.store.unread_counts()
        watcher2.writer.write(b"@+typing=active TAGMSG #testing\r\n")
        someone_typing = await client.wait(lambda f: f.get("type") == "typing")
        check("someone else's typing reaches the client", someone_typing,
              {"type": "typing", "buffer": chan["id"], "nick": "observer", "state": "active"})
        watcher2.writer.write(b"@+typing=paused TAGMSG #testing\r\n")
        paused = await client.wait(lambda f: f.get("type") == "typing" and f["state"] == "done")
        check("a pause reaches it as done", paused is not None, True)
        check("and none of it is stored or unread",
              (relay.store.newest_eid(chan["id"]), relay.store.unread_counts()), (newest, counts))

        # --- raw, list, an invite to us (G41, G42) --------------------------------
        await client.send({"type": "raw", "req": "rw1", "line": "MODE #testing +i"})
        raw_ok = await client.wait(lambda f: f.get("req") == "rw1") or {}
        check("a raw line is accepted", raw_ok.get("type"), "ok")
        check("and reaches IRC as typed", await watcher2.wait_for("MODE #testing +i") is not None,
              True)
        for req, line, why in (("rw2", "QUIT :bye", "QUIT would disconnect"),
                               ("rw3", "AUTHENTICATE PLAIN", "the bouncer's to send"),
                               ("rw4", "PRIVMSG #testing :a\r\nQUIT", "one IRC line only")):
            await client.send({"type": "raw", "req": req, "line": line})
            refusal = await client.wait(lambda f, r=req: f.get("req") == r) or {}
            check(f"raw {line.split()[0]} refused: {why}",
                  (refusal.get("type"), why in refusal.get("message", "")), ("error", True))

        # /ctcp is a raw PRIVMSG; its answer comes back as a NOTICE and must be
        # shown, not dropped (the old `if notice: return`).
        await client.send({"type": "raw", "req": "rw5",
                           "line": "PRIVMSG observer :\x01PING 1758320000\x01"})
        await client.wait(lambda f: f.get("req") == "rw5")
        asked = await watcher2.wait_for("\x01PING 1758320000\x01")
        check("a raw CTCP reaches the other side", asked is not None, True)
        watcher2.writer.write(f"NOTICE {session.nick} :\x01PING 1758320000\x01\r\n".encode())
        reply = await client.wait(lambda f: f.get("type") == "event"
                                  and (f["event"].get("extra") or {}).get("ctcp") == "PING") or {}
        check("the CTCP reply is a notice from them, in the status buffer",
              (reply.get("event", {}).get("kind"), reply.get("event", {}).get("from"),
               reply.get("event", {}).get("buffer"), reply.get("event", {}).get("extra")),
              ("notice", "observer", status_id, {"ctcp": "PING", "reply": "1758320000"}))

        watcher2.writer.write(b"FAKECHANNELS 12\r\n")
        await asyncio.sleep(0.2)
        await client.send({"type": "list", "req": "ls1"})
        listing = await client.wait(lambda f: f.get("type") == "channel_list"
                                    and f.get("req") == "ls1") or {}
        users = [c["users"] for c in listing.get("channels", [])]
        check("list answers with channel_list, biggest first",
              (listing.get("network"), len(users) >= 12, users == sorted(users, reverse=True),
               listing.get("complete")), ("test", True, True, True))
        check("real channels are in it too",
              "#testing" in {c["name"] for c in listing.get("channels", [])}, True)

        pushes.clear()
        watcher2.writer.write(f"INVITE {session.nick} #secret\r\n".encode())
        invite = await client.wait(is_event(kind="invite")) or {}
        check("an invite to us is an event in the status buffer",
              (invite.get("event", {}).get("buffer"), invite.get("event", {}).get("from"),
               invite.get("event", {}).get("extra")),
              (status_id, "observer", {"channel": "#secret"}))
        await asyncio.sleep(0.3)
        check("and it pushes", [n.body for n, _ in pushes], ["observer invited you to #secret"])

        # --- names: ask the server, do not just trust the store ---------------------
        before_members = len(client.frames)
        await client.send({"type": "names", "req": "nm1", "buffer": chan["id"]})
        names_ok = await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "nm1")
        check("names request accepted", names_ok is not None, True)
        refreshed = None
        for _ in range(100):
            new_members = [f for f in client.frames[before_members:]
                          if f.get("type") == "members" and f.get("buffer") == chan["id"]]
            if new_members:
                refreshed = new_members[0]
                break
            await asyncio.sleep(0.05)
        check("names triggered a fresh members frame from the server", refreshed is not None, True)

        # --- being kicked ---------------------------------------------------------
        # The kick used to change the database and nothing else: the clients
        # kept a live composer and the old member list, and the next line was
        # stored as said while the server refused it.
        async def wait_after(start, predicate, timeout=6.0):
            for _ in range(int(timeout / 0.05)):
                for i, f in enumerate(client.frames[start:], start):
                    if predicate(f):
                        return i, f
                await asyncio.sleep(0.05)
            return None, None

        me = session.nick
        start = len(client.frames)
        watcher2.writer.write(f"KICK #testing {me} :being loud\r\n".encode())
        i_buf, _ = await wait_after(start, lambda f: f.get("type") == "buffer"
                                    and f["buffer"]["id"] == chan["id"]
                                    and f["buffer"]["joined"] is False)
        i_mem, _ = await wait_after(start, lambda f: f.get("type") == "members"
                                    and f["buffer"] == chan["id"] and f["members"] == [])
        i_kick, kick = await wait_after(start, lambda f: f.get("type") == "event"
                                        and f["event"]["kind"] == "kick")
        check("a kick of us announces joined:false", i_buf is not None, True)
        check("then an empty member list", i_mem is not None and i_mem > (i_buf or 0), True)
        check("then the kick itself", i_kick is not None and i_kick > (i_mem or 0), True)
        check("the kick names who, whom and why",
              ((kick or {}).get("event", {}).get("from"),
               (kick or {}).get("event", {}).get("extra")),
              ("observer", {"target": me, "reason": "being loud"}))

        await client.send({"type": "say", "req": "kk1", "buffer": chan["id"],
                           "text": "am I still here?"})
        refused = await client.wait(lambda f: f.get("type") == "error" and f.get("req") == "kk1")
        check("saying something after the kick is refused in words",
              (refused or {}).get("message"), "You're not in #testing. Rejoin to send.")
        check("and nothing was stored",
              [e.text for e in relay.store.backlog(chan["id"], limit=20)
               if e.text == "am I still here?"], [])

        start = len(client.frames)
        await client.send({"type": "join", "req": "kk2", "channel": "#testing"})
        _, rejoined = await wait_after(start, lambda f: f.get("type") == "buffer"
                                       and f["buffer"]["id"] == chan["id"]
                                       and f["buffer"]["joined"] is True)
        check("rejoining announces joined:true", rejoined is not None, True)

        # --- signing out ------------------------------------------------------------
        await client.send({"type": "register_push", "req": "up1", "device_token": "CAFE01",
                           "platform": "ios", "environment": "sandbox"})
        await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "up1")
        await client.send({"type": "unregister_push", "req": "up2", "device_token": "CAFE01"})
        unreg = await client.wait(lambda f: f.get("req") == "up2")
        check("unregister_push is acknowledged", (unreg or {}).get("type"), "ok")
        check("the device is gone",
              "CAFE01" in [d["apns_token"] for d in relay.store.devices()], False)
        await client.send({"type": "unregister_push", "req": "up3", "device_token": "CAFE01"})
        again = await client.wait(lambda f: f.get("req") == "up3")
        check("signing out twice is not an error", (again or {}).get("type"), "ok")

        # --- second device sees everything -------------------------------------
        second = WSClient()
        await second.connect(http, f"http://127.0.0.1:{PORT_WS}/ws", token)
        second_buffers = await second.wait(lambda f: f.get("type") == "buffers")
        check("second device gets buffer list", second_buffers is not None, True)
        second_backlog = await second.wait(
            lambda f: f.get("type") == "backlog" and f["buffer"] == chan["id"]
        )
        second_texts = [e["text"] for e in second_backlog["events"]] if second_backlog else []
        check("second device gets history it never saw live",
              "hello from the app" in second_texts, True)
        await second.close()

        # --- resume on attach (G57) --------------------------------------------
        # A client that says which eid it holds gets what it missed, per buffer,
        # instead of the newest fifty -- which used to leave a hole it could not
        # see whenever more than fifty lines had gone by.
        # The rejoin above is still settling: the server's answers to it (the
        # channel's modes, its names) land in #testing as events of their own,
        # and one that arrived after `held` sat inside the window checked
        # below and shifted it by one ("missed 101" first, an empty line
        # last). It only lost that race on a busy machine, which is when a
        # deploy runs it. Wait for the log to go quiet before taking the mark.
        settled = -1
        while settled != relay.store.max_eid():
            settled = relay.store.max_eid()
            await asyncio.sleep(0.3)
        held = relay.store.max_eid()
        for i in range(600):
            relay.store.append_event(buffer_id=chan["id"], network_id=session.network_id,
                                     kind="message", sender="someone", text=f"missed {i}")
        quiet_buffer = relay.store.find_buffer(session.network_id, "stranger")
        relay.store.append_event(buffer_id=quiet_buffer.id, network_id=session.network_id,
                                 kind="message", sender="stranger", text="one while you were out")

        resumer = WSClient()
        await resumer.connect(http, f"http://127.0.0.1:{PORT_WS}/ws?since={held}", token)
        rhello = await resumer.wait(lambda f: f.get("type") == "hello") or {}
        check("hello says the resume was honoured", rhello.get("resumed"), True)
        busy = await resumer.wait(lambda f: f.get("type") == "backlog"
                                  and f.get("buffer") == chan["id"]) or {}
        quiet = await resumer.wait(lambda f: f.get("type") == "backlog"
                                   and f.get("buffer") == quiet_buffer.id) or {}
        await resumer.wait(lambda f: False, timeout=0.5)       # let the burst finish
        busy_texts = [e["text"] for e in busy.get("events", [])]
        check("resume: the busy buffer gets the newest 500 it missed",
              (len(busy_texts), busy_texts[:1], busy_texts[-1:]),
              (500, ["missed 100"], ["missed 599"]))
        check("resume: labelled as following the held eid",
              (busy.get("direction"), busy.get("after_eid")), ("after", held))
        check("resume: capped, so not complete", busy.get("complete"), False)
        check("resume: the quiet buffer gets its one line, complete",
              ([e["text"] for e in quiet.get("events", [])], quiet.get("complete")),
              (["one while you were out"], True))
        others = [f["buffer"] for f in resumer.frames if f.get("type") == "backlog"
                  and f["buffer"] not in (chan["id"], quiet_buffer.id)]
        check("resume: buffers with nothing new get no frame", others, [])

        # The hole is pageable the ordinary way: back from the oldest line held.
        oldest = busy["events"][0]["eid"] if busy.get("events") else 0
        await resumer.send({"type": "backlog", "req": "hole", "buffer": chan["id"],
                            "before_eid": oldest, "limit": 500})
        hole = await resumer.wait(lambda f: f.get("type") == "backlog"
                                  and f.get("req") == "hole") or {}
        filled = [e["text"] for e in hole.get("events", []) if e["eid"] > held]
        check("resume: paging before the oldest fills the hole exactly",
              filled, [f"missed {i}" for i in range(100)])
        await resumer.close()

        # A `since` from some other database is ignored: an ordinary burst.
        stranger_db = WSClient()
        await stranger_db.connect(
            http, f"http://127.0.0.1:{PORT_WS}/ws?since={relay.store.max_eid() + 1000}", token)
        shello = await stranger_db.wait(lambda f: f.get("type") == "hello") or {}
        plain = await stranger_db.wait(lambda f: f.get("type") == "backlog"
                                       and f.get("buffer") == chan["id"]) or {}
        check("a since past the newest eid is ignored", shello.get("resumed"), False)
        check("and the burst is the ordinary newest page",
              ("direction" in plain, len(plain.get("events", []))), (False, 50))
        await stranger_db.close()

        # --- errors land where they were asked (G18) --------------------------
        killer = Watcher("killer")
        await killer.connect(PORT_IRC)
        await asyncio.sleep(0.3)
        me = session.nick
        await client.send({"type": "topic", "req": "e1", "buffer": chan["id"], "topic": "mine now"})
        await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "e1")
        killer.writer.write(f"RAWTO {me} ::fake.irc 482 {me} #testing :You're not channel operator\r\n"
                            .encode())
        refusal = await client.wait(lambda f: f.get("type") == "event"
                                    and (f["event"].get("extra") or {}).get("numeric") == "482") or {}
        check("a refused /topic says so in the channel",
              (refusal.get("event", {}).get("buffer"), refusal.get("event", {}).get("text")),
              (chan["id"], "You're not channel operator"))

        # --- an upstream outage, with its reason (G19) -----------------------
        another = next(b for b in client.frames if b.get("type") == "buffer"
                       and b["buffer"]["name"] == "#another")["buffer"]["id"]
        # An away set now must come back by itself after the outage (G25): it
        # used to live only in memory and was never re-sent.
        await client.send({"type": "away", "req": "aw3", "message": "gone fishing",
                           "text": "gone fishing"})
        await client.wait(lambda f: f.get("req") == "aw3")
        start = len(client.frames)
        killer.writer.write(f"KILLPEER {me} :Excess Flood\r\n".encode())
        lost = await client.wait(lambda f: f.get("type") == "network"
                                 and f["network"].get("next_retry_at")) or {}
        check("the network frame carries the server's own reason",
              lost.get("network", {}).get("last_error"),
              f"Closing Link: {me}[127.0.0.1] (Excess Flood)")
        check("and when the next attempt is",
              (lost.get("network", {}).get("next_retry_at") or 0) > time.time() - 1, True)
        down = [f["event"] for f in client.frames[start:] if f.get("type") == "event"
                and (f["event"].get("extra") or {}).get("connection") == "lost"]
        check("every channel we were in gets a Disconnected line",
              sorted((e["buffer"], e["text"]) for e in down),
              sorted([(chan["id"], f"Disconnected: Closing Link: {me}[127.0.0.1] (Excess Flood)"),
                      (another, f"Disconnected: Closing Link: {me}[127.0.0.1] (Excess Flood)")]))
        back = await client.wait(lambda f: f.get("type") == "event"
                                 and f["event"]["buffer"] == chan["id"]
                                 and f["event"].get("text") == "Reconnected", timeout=15) or {}
        check("and a Reconnected line once it is back in",
              back.get("event", {}).get("extra"), {"connection": "restored"})
        healed = await client.wait(lambda f: f.get("type") == "network"
                                   and f["network"]["registered"]
                                   and client.frames.index(f) > start) or {}
        check("once registered again there is no error and no countdown",
              (healed.get("network", {}).get("last_error"),
               healed.get("network", {}).get("next_retry_at")), (None, None))
        check("and the away is still in the network frame",
              healed.get("network", {}).get("away"), "gone fishing")
        peer = None
        for _ in range(60):
            peer = find_peer(session.nick)
            if peer and peer.away == "gone fishing":
                break
            await asyncio.sleep(0.05)
        check("the new connection was marked away again at the ircd",
              peer.away if peer else None, "gone fishing")
        check("and it is saved for a restart",
              relay.store.network_away(session.network_id), "gone fishing")
        await client.send({"type": "away", "req": "aw4", "message": None})
        cleared = await client.wait(lambda f: f.get("req") == "aw4") or {}
        check("message null clears it", (cleared.get("type"),
                                         relay.store.network_away(session.network_id)), ("ok", None))

        # === the October 2026 contract, over a real socket ========================
        # See docs/PROTOCOL.md. Each piece has its unit tests; this is the
        # whole chain: frame in, IRC and SQLite in the middle, frame and push out.
        gateway._auth_failures.clear()
        gateway._all_failures.clear()
        base = f"http://127.0.0.1:{PORT_WS}"
        me = session.nick
        mine = relay.store.list_tokens()[0]["id"]

        # --- hello: apns, build, epoch, token, can_pair --------------------------
        fresh = WSClient()
        await fresh.connect(http, f"{base}/ws", token)
        hello = await fresh.wait(lambda f: f.get("type") == "hello") or {}
        async with http.get(base + "/") as r:
            etag, encoding, vary = (r.headers.get("ETag", ""), r.headers.get("Content-Encoding"),
                                    r.headers.get("Vary"))
            page_text = await r.text()
        check("hello.build is the page's ETag", hello.get("build"), etag.strip('"'))
        check("hello.epoch is the database's", hello.get("epoch"), relay.store.epoch)
        check("hello.token is the one this socket came in with",
              hello.get("token"), {"id": mine, "label": "e2e"})
        check("hello says pairing is here and a push provider is configured",
              (hello.get("can_pair"), hello.get("apns")), (True, True))
        check("hello is the first frame", fresh.frames[0].get("type"), "hello")
        # W-R2: aiohttp asks for gzip, as a browser does, and unpacks it.
        check("the page came gzipped, and is the page",
              (encoding, vary, page_text.startswith("<!doctype html>")),
              ("gzip", "Accept-Encoding", True))
        async with http.get(base + "/", headers={"Accept-Encoding": "identity"}) as r:
            check("someone who cannot take gzip gets it plain, under the same ETag",
                  (r.headers.get("Content-Encoding"), r.headers.get("ETag"),
                   await r.text() == page_text), (None, etag, True))

        # --- say nonce -----------------------------------------------------------
        await fresh.send({"type": "say", "req": "n1", "buffer": chan["id"],
                          "text": "with a nonce\nand a second line", "nonce": "k3J9x"})
        said = await fresh.wait(lambda f: f.get("req") == "n1") or {}
        check("the ok's event carries the nonce",
              (said.get("type"), (said.get("event") or {}).get("extra")),
              ("ok", {"nonce": "k3J9x"}))
        second_line = await fresh.wait(is_event(text="and a second line")) or {}
        check("so does the event for the second line, which ok never mentioned",
              second_line.get("event", {}).get("extra"), {"nonce": "k3J9x"})
        check("and what went to IRC is just the text",
              await watcher2.wait_for(f"PRIVMSG #testing :and a second line") is not None, True)
        await fresh.send({"type": "say", "req": "n2", "buffer": chan["id"],
                          "text": "a nonce that is not one", "nonce": "no spaces allowed!"})
        loose = await fresh.wait(lambda f: f.get("req") == "n2") or {}
        check("a malformed nonce is ignored and the line still goes",
              (loose.get("type"), "extra" in (loose.get("event") or {"extra": 1})), ("ok", False))
        await fresh.send({"type": "backlog", "req": "n3", "buffer": chan["id"], "limit": 3})
        replay = await fresh.wait(lambda f: f.get("req") == "n3") or {}
        check("events replayed from history keep the nonce",
              [(e.get("extra") or {}).get("nonce") for e in replay.get("events", [])],
              ["k3J9x", "k3J9x", None])

        # --- devices: tokens, pair, POST /pair, revoke_token ----------------------
        await fresh.send({"type": "tokens", "req": "t1"})
        listed = await fresh.wait(lambda f: f.get("type") == "tokens" and f.get("req") == "t1") or {}
        only = (listed.get("tokens") or [{}])[0]
        check("tokens lists this device, marked current",
              (len(listed.get("tokens", [])), only.get("id"), only.get("label"),
               only.get("current"), only.get("push")), (1, mine, "e2e", True, True))
        check("its times are whole seconds",
              (type(only.get("created_at")), type(only.get("last_used_at")),
               abs(only.get("last_used_at", 0) - time.time()) < 300), (int, int, True))
        check("and it gives away nothing that works as a credential",
              sorted(only), ["created_at", "current", "id", "label", "last_used_at", "push"])

        await fresh.send({"type": "pair", "req": "p0", "label": "   "})
        nameless = await fresh.wait(lambda f: f.get("req") == "p0") or {}
        check("pair needs a name for the new device", nameless.get("type"), "error")
        await fresh.send({"type": "pair", "req": "p1", "label": "iPad"})
        pair = await fresh.wait(lambda f: f.get("type") == "pair" and f.get("req") == "p1") or {}
        code = pair.get("code", "")
        check("pair answers with a code, its life, and two links",
              (len(code), pair.get("expires_in"), pair.get("url"), pair.get("app_url")),
              (8, 300, f"http://127.0.0.1:{PORT_WS}/#pair={code}",
               # Plain http on loopback names its scheme: the app reads a
               # bare host as https.
               f"geeyem://pair?host=http%3A%2F%2F127.0.0.1%3A{PORT_WS}&code={code}"))

        # The same frame from a socket that came through the tunnel: https,
        # and the public hostname, whatever the bouncer itself listens on.
        tunnelled = WSClient()
        tunnelled.ws = await http.ws_connect(f"{base}/ws", headers={
            "Authorization": f"Bearer {token}", "Host": "irc.example.net", **via_https})
        tunnelled.task = asyncio.create_task(tunnelled._read())
        await tunnelled.send({"type": "pair", "req": "p2", "label": "work laptop"})
        public = await tunnelled.wait(lambda f: f.get("type") == "pair") or {}
        check("through the tunnel the links are https and name the public host",
              (public.get("url"), public.get("app_url")),
              (f"https://irc.example.net/#pair={public.get('code')}",
               f"geeyem://pair?host=irc.example.net&code={public.get('code')}"))
        await tunnelled.close()
        # Behind a local proxy that rewrites Host, the public name is in
        # X-Forwarded-Host (believed from this machine only, as for Origin).
        proxied = WSClient()
        proxied.ws = await http.ws_connect(f"{base}/ws", headers={
            "Authorization": f"Bearer {token}", "X-Forwarded-Host": "chat.example.org",
            **via_https})
        proxied.task = asyncio.create_task(proxied._read())
        await proxied.send({"type": "pair", "req": "p2b", "label": "behind nginx"})
        behind = await proxied.wait(lambda f: f.get("type") == "pair") or {}
        check("behind a proxy that rewrites Host, the links use X-Forwarded-Host",
              behind.get("url"), f"https://chat.example.org/#pair={behind.get('code')}")
        await proxied.close()

        async def redeem(body, **headers):
            async with http.post(base + "/pair", json=body, headers=headers) as r:
                try:
                    answer = await r.json()
                except Exception:
                    answer = await r.text()
                return r.status, answer, r.headers

        status, answer, _ = await redeem({"code": "ZZZZ2222"})
        check("a wrong code is a 404 with a sentence",
              (status, answer), (404, {"error": "That code is not valid or has expired."}))
        status, _, _ = await redeem({"code": code}, Origin="https://evil.example")
        check("a page on another site may not redeem one", status, 403)
        status, _, _ = await redeem({"code": code}, **via_http)
        check("nor may anyone over plain http through the tunnel", status, 403)
        async with http.post(base + "/pair", data=b"not json") as r:
            check("a body that is not a code is a 400", r.status, 400)
        async with http.post(base + "/pair", data=b"x" * 20000) as r:
            check("  and an enormous one is refused unread", r.status, 413)
        async with http.get(base + "/pair") as r:
            check("  and it is POST only", r.status, 405)

        # As typed: lower case, with a dash. From the page's own origin.
        typed = f"{code[:4].lower()}-{code[4:].lower()}"
        status, answer, headers = await redeem({"code": typed}, Origin=base)
        paired_token = answer.get("token", "") if isinstance(answer, dict) else ""
        check("the right code is a token of the new device's own",
              (status, paired_token.startswith("relay_"), answer.get("host"), answer.get("label")),
              (200, True, f"127.0.0.1:{PORT_WS}", "iPad"))
        check("  which no cache may keep", headers.get("Cache-Control"), "no-store")
        status, _, _ = await redeem({"code": code})
        check("a code works once", status, 404)

        paired = WSClient()
        await paired.connect(http, f"{base}/ws", paired_token)
        phello = await paired.wait(lambda f: f.get("type") == "hello") or {}
        ipad = (phello.get("token") or {}).get("id")
        check("the new token attaches, under the name it was paired with",
              (phello.get("token") or {}).get("label"), "iPad")
        await paired.send({"type": "register_push", "req": "pp", "device_token": "BEEF02",
                           "platform": "ios", "environment": "production"})
        await paired.wait(lambda f: f.get("req") == "pp")
        await fresh.send({"type": "tokens", "req": "t2"})
        both = await fresh.wait(lambda f: f.get("req") == "t2") or {}
        check("tokens now lists both devices, each seen from the asker's side",
              [(t["label"], t["current"], t["push"]) for t in both.get("tokens", [])],
              [("e2e", True, True), ("iPad", False, True)])

        # --- an alert names its sender; a read elsewhere takes it down ------------
        relay.hub.read_push_debounce = 0.4
        pushes.clear()
        read_pushes.clear()
        killer.say(me, "are you there")
        pm = await fresh.wait(is_event(text="are you there")) or {}
        pm_buffer, pm_eid = pm.get("event", {}).get("buffer"), pm.get("event", {}).get("eid")
        await asyncio.sleep(0.2)
        check("the alert went to both devices",
              [sorted(d["apns_token"] for d in devices) for _, devices in pushes],
              [["BEEF02", "DEADBEEF"]])
        alert = pushes[0][0].to_apns_payload("t") if pushes else {}
        check("its payload says who it is from", alert.get("relay", {}).get("from"), "killer")
        badge_then = alert.get("aps", {}).get("badge")

        await fresh.send({"type": "mark_read", "req": "r1", "buffer": pm_buffer, "eid": pm_eid})
        await fresh.wait(lambda f: f.get("req") == "r1")
        check("nothing is pushed at once", read_pushes, [])
        await asyncio.sleep(0.7)
        check("then one background push, to the device that did not read it",
              [(p["relay"], devices) for p, devices in read_pushes],
              [({"read": {"buffer": pm_buffer, "eid": pm_eid}}, ["BEEF02"])])
        receipt = read_pushes[0][0]["aps"] if read_pushes else {}
        check("carrying the badge an alert would carry now, one lower than before",
              (receipt, receipt.get("badge")),
              ({"content-available": 1, "badge": relay.store.badge_count()}, badge_then - 1))
        await fresh.send({"type": "mark_read", "req": "r2", "buffer": pm_buffer, "eid": pm_eid})
        await fresh.wait(lambda f: f.get("req") == "r2")
        await asyncio.sleep(0.7)
        check("a mark_read that moves nothing pushes nothing", len(read_pushes), 1)

        # Read on the iPad instead: the push goes the other way.
        read_pushes.clear()
        killer.say(me, "and now")
        again = await paired.wait(is_event(text="and now")) or {}
        await asyncio.sleep(0.1)
        await paired.send({"type": "mark_read", "req": "r3", "buffer": pm_buffer,
                           "eid": again.get("event", {}).get("eid")})
        await paired.wait(lambda f: f.get("req") == "r3")
        await asyncio.sleep(0.7)
        check("the reader's own device is never the one pushed to",
              [devices for _, devices in read_pushes], [["DEADBEEF"]])

        # mark_all_read is one push that says so; close pushes like a read.
        read_pushes.clear()
        killer.say(me, "one more")
        await fresh.wait(is_event(text="one more"))
        await asyncio.sleep(0.1)
        await fresh.send({"type": "mark_all_read", "req": "r4"})
        await fresh.wait(lambda f: f.get("req") == "r4")
        await asyncio.sleep(0.7)
        check("mark_all_read is one push saying everything was read",
              [(p["relay"], p["aps"]["badge"], devices) for p, devices in read_pushes],
              [({"read": {"all": True}}, 0, ["BEEF02"])])
        read_pushes.clear()
        killer.say(me, "last one")
        closing = await fresh.wait(is_event(text="last one")) or {}
        await asyncio.sleep(0.1)
        await fresh.send({"type": "close", "req": "r5", "buffer": pm_buffer})
        await fresh.wait(lambda f: f.get("req") == "r5")
        await asyncio.sleep(0.7)
        check("closing a conversation reads it, and pushes that too",
              [(p["relay"], devices) for p, devices in read_pushes],
              [({"read": {"buffer": pm_buffer, "eid": closing.get("event", {}).get("eid")}},
                ["BEEF02"])])

        # --- revoke_token: its sockets close 1008, its devices go -----------------
        await fresh.send({"type": "revoke_token", "req": "v0", "id": 9999})
        unknown = await fresh.wait(lambda f: f.get("req") == "v0") or {}
        check("revoking a token that is not there is an error", unknown.get("type"), "error")
        await fresh.send({"type": "revoke_token", "req": "v1", "id": ipad})
        revoked = await fresh.wait(lambda f: f.get("req") == "v1") or {}
        check("revoke_token is acknowledged", revoked.get("type"), "ok")
        for _ in range(60):
            if paired.ws.closed:
                break
            await asyncio.sleep(0.05)
        check("the revoked device's socket is closed 1008", paired.ws.close_code, 1008)
        check("its push registration went with it",
              [d["apns_token"] for d in relay.store.devices()], ["DEADBEEF"])
        async with http.get(f"{base}/ws", headers={"Authorization": f"Bearer {paired_token}"}) as r:
            check("and its token no longer attaches", r.status, 401)
        paired.task.cancel()
        gateway._auth_failures.clear()
        gateway._all_failures.clear()

        # Revoking your own token signs this device out: ok first, then 1008.
        await fresh.send({"type": "pair", "req": "p3", "label": "to be signed out"})
        own_pair = await fresh.wait(lambda f: f.get("req") == "p3") or {}
        status, answer, _ = await redeem({"code": own_pair.get("code"), "label": "Riley's iPad"})
        check("the new device may name itself when it redeems",
              (status, answer.get("label")), (200, "Riley's iPad"))
        own = WSClient()
        await own.connect(http, f"{base}/ws", answer["token"])
        ohello = await own.wait(lambda f: f.get("type") == "hello") or {}
        await own.send({"type": "revoke_token", "req": "v2", "id": ohello["token"]["id"]})
        own_ok = await own.wait(lambda f: f.get("req") == "v2", timeout=3) or {}
        for _ in range(60):
            if own.ws.closed:
                break
            await asyncio.sleep(0.05)
        check("revoking your own token answers ok, then closes this socket 1008",
              (own_ok.get("type"), own.ws.close_code), ("ok", 1008))
        own.task.cancel()

        # A code made by a token that has since been revoked is dead too, and
        # wrong codes count against the same throttle as wrong tokens.
        for i in range(10):
            await redeem({"code": f"WRNG{i:04d}".replace("0", "2").replace("1", "3")})
        await fresh.send({"type": "pair", "req": "p4", "label": "too late"})
        late = await fresh.wait(lambda f: f.get("req") == "p4") or {}
        status, answer, _ = await redeem({"code": late.get("code")})
        check("ten wrong codes throttle the address: even a right one is a 429",
              (status, isinstance(answer, dict) and "error" in answer), (429, True))
        async with http.get(base + "/health",
                            headers={"Authorization": f"Bearer {token}"}) as r:
            check("the same throttle /health answers 429 for", r.status, 429)
        gateway._auth_failures.clear()
        gateway._all_failures.clear()
        status, _, _ = await redeem({"code": late.get("code")})
        check("the code was not spent by the refusal", status, 200)

        # --- keyed channels (B-R5) -------------------------------------------------
        killer.writer.write(b"FAKEKEY #locked sesame\r\n")
        await asyncio.sleep(0.2)
        mark = len(fresh.frames)
        await fresh.send({"type": "join", "req": "k1", "network": "test", "channel": "#locked"})
        await fresh.wait(lambda f: f.get("req") == "k1")
        refused = await fresh.wait(lambda f: f.get("type") == "event"
                                   and (f["event"].get("extra") or {}).get("numeric") == "475") or {}
        check("without the key the server says no",
              "Cannot join channel" in (refused.get("event", {}).get("text") or ""), True)
        await fresh.send({"type": "join", "req": "k2", "network": "test", "channel": "#locked",
                          "key": ["not", "text"]})
        bad_key = await fresh.wait(lambda f: f.get("req") == "k2") or {}
        check("a key that is not text is refused", bad_key.get("type"), "error")
        await fresh.send({"type": "join", "req": "k3", "network": "test", "channel": "#locked",
                          "key": "sesame"})
        locked = await fresh.wait(lambda f: f.get("type") == "buffer"
                                  and f["buffer"]["name"] == "#locked"
                                  and f["buffer"]["joined"]) or {}
        check("with the key we are in", locked.get("buffer", {}).get("joined"), True)
        check("the network frame lists the name and says it is keyed",
              (session.to_wire()["channels"][-1], session.to_wire()["keyed"]),
              ("#locked", ["#locked"]))

        # THE BUG: a +k channel answered 475 after every reconnect.
        mark = len(fresh.frames)
        killer.writer.write(f"KILLPEER {me} :Ping timeout\r\n".encode())
        rejoined = await fresh.wait(
            lambda f: f.get("type") == "event" and f["event"].get("text") == "Reconnected"
            and f["event"]["buffer"] == locked.get("buffer", {}).get("id")
            and fresh.frames.index(f) > mark, timeout=20)
        check("after a reconnect the keyed channel is rejoined by itself",
              rejoined is not None, True)
        check("  for real, at the ircd",
              "#locked" in (find_peer(me).channels if find_peer(me) else ()), True)
        after = await fresh.wait(
            lambda f: f.get("type") == "network" and f["network"]["registered"]
            and fresh.frames.index(f) > mark) or {}
        check("the network frame every client got says keyed, and lists names only",
              (after.get("network", {}).get("keyed"),
               "#locked" in after.get("network", {}).get("channels", [])), (["#locked"], True))

        # And through edit_network, as an entry of the channels list.
        killer.writer.write(b"FAKEKEY #vault opensesame\r\n")
        await asyncio.sleep(0.2)
        await fresh.send({"type": "edit_network", "req": "k4", "network": "test",
                          "channels": [*session.to_wire()["channels"], "#vault opensesame"]})
        edited = await fresh.wait(lambda f: f.get("req") == "k4") or {}
        vault = await fresh.wait(lambda f: f.get("type") == "buffer"
                                 and f["buffer"]["name"] == "#vault" and f["buffer"]["joined"])
        check("a \"#chan key\" entry in edit_network joins with the key",
              (edited.get("type"), vault is not None), ("ok", True))
        check("the reply lists names only, with both channels keyed",
              (edited.get("network", {}).get("channels", [])[-2:],
               edited.get("network", {}).get("keyed")),
              (["#locked", "#vault"], ["#locked", "#vault"]))
        everything = json.dumps(fresh.frames + client.frames)
        stored = " ".join((e.text or "") + json.dumps(e.extra)
                          for b in relay.store.buffers(include_archived=True)
                          for e in relay.store.backlog(b.id, limit=500))
        check("no frame any client received holds a key",
              [k for k in ("sesame", "opensesame") if k in everything], [])
        check("and no stored event does", [k for k in ("sesame",) if k in stored], [])
        check("the keys are in the database, with the wanted list",
              relay.store.networks()[0]["channel_keys"],
              {"#locked": "sesame", "#vault": "opensesame"})

        # --- answers to a raw line (B-R4) ------------------------------------------
        await fresh.send({"type": "raw", "req": "b1", "network": "test",
                          "line": "BANLIST #testing"})
        await fresh.wait(lambda f: f.get("req") == "b1")
        ban = await fresh.wait(lambda f: f.get("type") == "event"
                               and (f["event"].get("extra") or {}).get("numeric") == "367") or {}
        end = await fresh.wait(lambda f: f.get("type") == "event"
                               and (f["event"].get("extra") or {}).get("numeric") == "368") or {}
        check("what the server says to a raw line lands in the Server buffer",
              (ban.get("event", {}).get("buffer"), ban.get("event", {}).get("kind"),
               ban.get("event", {}).get("text"), end.get("event", {}).get("text")),
              (status_id, "server", "#testing *!*@bad.example op 1758000000",
               "#testing End of channel ban list"))
        await fresh.close()

        killer.close()
        await client.close()
        watcher2.close()

        # --- shutdown with a client still attached --------------------------------
        # The failure this covers: aiohttp's runner cleanup waits for attached
        # websockets, a phone with a suspended socket never finishes, and
        # systemd SIGKILLed the service after 15 seconds -- so the QUIT upstream
        # never went out and the channel saw a ping timeout instead.
        lingering = WSClient()
        await lingering.connect(http, f"http://127.0.0.1:{PORT_WS}/ws", token)
        await lingering.wait(lambda f: f.get("type") == "hello")

        started = time.monotonic()
        await relay.shutdown()
        check("shutdown finished promptly with a client attached",
              time.monotonic() - started < 5.0, True)
        for _ in range(40):
            if lingering.ws.closed:
                break
            await asyncio.sleep(0.05)
        # 1001 is "going away": the client knows to reconnect rather than
        # waiting out a timeout wondering.
        check("the attached client was closed with 1001", lingering.ws.close_code, 1001)
        lingering.task.cancel()

    relay_task.cancel()
    await ircd.stop()
    tmp.cleanup()


def main():
    asyncio.run(run())
    print()
    if FAILED:
        print(f"{len(FAILED)} FAILURE(S):")
        for f in FAILED:
            print(f"  - {f}")
        return 1
    print("end to end passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
