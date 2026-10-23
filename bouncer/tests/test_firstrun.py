#!/usr/bin/env python3
"""First run: a bouncer with no token sets itself up from a web page.

The page is open only while no device can sign in, and only to whoever has
the setup code from the bouncer's log. It adds the network, mints the first
token, and shows it as a QR code and a geeyem://connect link. Also the two
things a hosted bouncer needs for that to be safe: the QR code drawn here
(relay/qr.py), and `trust_proxy`, which says whose forwarding headers count.

    python tests/test_firstrun.py
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import sys
import tempfile
from html import unescape
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

import aiohttp
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from fakeircd import FakeIRCd
from relay import firstrun, qr
from relay import gateway as gw
from relay.app import Relay
from relay.config import Config

FAILED = []
PORT_IRC = 6731
PORT_WS = 8831
HERE = os.path.dirname(os.path.abspath(__file__))


def check(label, got, want):
    if got != want:
        FAILED.append(f"{label}: got {got!r}, want {want!r}")
        print(f"  FAIL {label}: got {got!r}, want {want!r}")
    else:
        print(f"  ok   {label}")


class Captured(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


def test_qr():
    """The bouncer's encoder draws exactly what CoreImage draws, as the web
    page's encoder does (web/tests/qr.js, the same fixture)."""
    print("qr codes")
    with open(os.path.join(HERE, "fixtures", "qr.json")) as f:
        vectors = json.load(f)
    check("the fixture covers versions 1, 7 and 10",
          {1, 7, 10} <= {v["version"] for v in vectors}, True)
    for v in vectors:
        code = qr.encode(v["text"], v["mask"])
        grid = ["".join(map(str, row)) for row in code.rows]
        check(f"matches the reference, version {v['version']}: {v['text'][:24]}",
              (code.version, code.size, grid), (v["version"], v["version"] * 4 + 17, v["rows"]))
        own = qr.encode(v["text"])
        check("  and picks a mask no worse than the reference's",
              qr.penalty(own.rows) <= qr.penalty(code.rows), True)
    check("213 bytes fit, 214 do not", (qr.encode("x" * 213).version, qr.encode("x" * 214)),
          (10, None))
    link = firstrun.connect_link("a-rather-long-name.fly.dev", "relay_" + "A" * 43)
    check("a connect link with a real-length token fits easily", qr.encode(link).version <= 7, True)
    svg = qr.svg(qr.encode("hello"), 'say "hi"')
    check("the svg has its quiet zone and an escaped label",
          ('viewBox="0 0 29 29"' in svg, 'aria-label="say &quot;hi&quot;"' in svg), (True, True))


def test_units():
    print("setup codes, links, the platform's address")
    check("a code is read however it was copied",
          firstrun.clean_setup_code(" abcd-efgh-jkmn "), "ABCDEFGHJKMN")
    for bad in ("", "ABCD", "A" * 13, None, 12, "A" * 500):
        check(f"not a code: {str(bad)[:8]!r}", firstrun.clean_setup_code(bad), "")
    check("printed in fours", firstrun.format_code("ABCDEFGHJKMN"), "ABCD-EFGH-JKMN")
    check("the setup alphabet is the pairing one", firstrun.SETUP_ALPHABET, gw.PAIR_ALPHABET)

    class NoTokens:
        def __init__(self): self.ids = set()
        def active_token_ids(self): return self.ids

    store = NoTokens()
    setup = firstrun.FirstRun(store)
    check("a fresh code is twelve characters of the alphabet",
          (len(setup.code), all(c in firstrun.SETUP_ALPHABET for c in setup.code)), (12, True))
    check("open while there is no token", setup.open, True)
    check("the right code passes, dashed and lower case",
          setup.check(firstrun.format_code(setup.code).lower()), True)
    check("a wrong one does not", setup.check("ZZZZZZZZZZZZ" if setup.code != "Z" * 12 else "Y" * 12),
          False)
    store.ids = {1}
    check("closed the moment any token exists", setup.open, False)
    store.ids = set()
    setup.finish()
    check("closed for good once finished", (setup.open, setup.check(setup.code)), (False, False))

    check("connect link, https: a bare host",
          firstrun.connect_link("irc.example.net", "relay_abc-_1"),
          "geeyem://connect?host=irc.example.net&token=relay_abc-_1")
    check("connect link, a rig: the scheme, encoded",
          firstrun.connect_link("127.0.0.1:8765", "relay_x", "http"),
          "geeyem://connect?host=http%3A%2F%2F127.0.0.1%3A8765&token=relay_x")

    saved = {k: os.environ.pop(k, None) for k in
             ("FLY_APP_NAME", "RAILWAY_PUBLIC_DOMAIN", "RENDER_EXTERNAL_URL")}
    try:
        check("no platform, no address", firstrun.platform_url(), None)
        os.environ["RENDER_EXTERNAL_URL"] = "https://mine.onrender.com/"
        check("Render's", firstrun.platform_url(), "https://mine.onrender.com")
        os.environ["RAILWAY_PUBLIC_DOMAIN"] = "mine.up.railway.app"
        check("Railway's", firstrun.platform_url(), "https://mine.up.railway.app")
        os.environ["FLY_APP_NAME"] = "mine"
        check("Fly's", firstrun.platform_url(), "https://mine.fly.dev")
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v


def test_trust_proxy():
    """Forwarding headers count from this machine always, and from anywhere
    only with trust_proxy on (a platform's proxy is not on loopback)."""
    print("trust_proxy")
    for key in ("RELAY_TRUST_PROXY", "RELAY_FIRST_RUN"):
        os.environ.pop(key, None)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "config.json")
        with open(path, "w") as f:
            json.dump({}, f)
        cfg = Config.load(path)
        check("both default as before: proxy headers from loopback only, setup on",
              (cfg.trust_proxy, cfg.first_run_setup), (False, True))
        os.environ["RELAY_TRUST_PROXY"] = "1"
        os.environ["RELAY_FIRST_RUN"] = "0"
        try:
            cfg = Config.load(path)
        finally:
            os.environ.pop("RELAY_TRUST_PROXY")
            os.environ.pop("RELAY_FIRST_RUN")
        check("the environment sets them", (cfg.trust_proxy, cfg.first_run_setup), (True, False))

    def request(trust, remote, **headers):
        app = web.Application()
        app[gw.TRUST_PROXY] = trust
        return make_mocked_request("GET", "/", headers=headers, app=app).clone(remote=remote)

    fwd = {"X-Forwarded-Proto": "https", "X-Forwarded-For": "6.6.6.6, 203.0.113.9",
           "X-Forwarded-Host": "mine.fly.dev"}
    plain = request(False, "172.16.5.4", Host="internal:8765", **fwd)
    check("off: a platform address is not believed",
          (gw._forwarded_scheme(plain), gw.Gateway._peer(plain), gw._public_host(plain)),
          (None, "172.16.5.4", "internal:8765"))
    trusted = request(True, "172.16.5.4", Host="internal:8765", **fwd)
    check("on: it is, and the client is the address the proxy appended, not the first",
          (gw._forwarded_scheme(trusted), gw.Gateway._peer(trusted), gw._public_host(trusted)),
          ("https", "203.0.113.9", "mine.fly.dev"))
    check("  and links back to it are https",
          gw._link_scheme(trusted, gw._public_host(trusted)), "https")
    local = request(False, "127.0.0.1", Host="127.0.0.1:8765",
                    **{"X-Forwarded-For": "198.51.100.7, 10.0.0.1"})
    check("loopback (cloudflared) is unchanged: the first entry",
          gw.Gateway._peer(local), "198.51.100.7")
    rig = request(False, "127.0.0.1", Host="127.0.0.1:8765")
    check("a rig on loopback links over http", gw._link_scheme(rig, "127.0.0.1:8765"), "http")


def _form(html):
    return unescape(html)


async def _bouncer(tmp, name, **extra):
    config = Config(listen_host="127.0.0.1", listen_port=PORT_WS,
                    db_path=os.path.join(tmp, f"{name}.db"), networks=[],
                    allow_private_hosts=True, **extra)
    relay = Relay(config)
    return relay


async def _start(relay):
    task = asyncio.create_task(relay.run())
    for _ in range(100):
        await asyncio.sleep(0.05)
        if relay.gateway._runner is not None and relay._lag_task is not None:
            break
    return task


async def _stop(relay, task):
    await relay.shutdown()
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass


async def run_setup():
    print("the setup page, end to end")
    ircd = FakeIRCd(port=PORT_IRC)
    await ircd.start()
    captured = Captured()
    logging.getLogger("relay").addHandler(captured)
    tmp = tempfile.TemporaryDirectory()
    base = f"http://127.0.0.1:{PORT_WS}"
    relay = await _bouncer(tmp.name, "first")
    task = await _start(relay)
    try:
        setup = relay.gateway.setup
        check("a bouncer with no token opens setup", setup is not None and setup.open, True)
        code = setup.code if setup else ""
        check("and prints its code to the log, with where to use it",
              any(firstrun.format_code(code) in line and "/setup" in line
                  for line in captured.lines), True)

        async with aiohttp.ClientSession() as http:
            async with http.get(base + "/", allow_redirects=False) as r:
                check("/ sends the first visitor to /setup (not for good)",
                      (r.status, r.headers.get("Location")), (302, "/setup"))
            async with http.get(base + "/setup") as r:
                page = await r.text()
                csp = r.headers.get("Content-Security-Policy", "")
                check("the form is served, not cached, and posts only to itself",
                      (r.status, r.headers.get("Cache-Control"), "form-action 'self'" in csp,
                       "default-src 'none'" in csp, 'name="code"' in page),
                      (200, "no-store", True, True, True))
                check("  and loads nothing from anywhere else",
                      re.findall(r'(?:src|href)="(https?:[^"]*)"', page), [])

            async def post(fields, **headers):
                async with http.post(base + "/setup", data=fields, headers=headers) as r:
                    return r.status, await r.text(), r.headers

            good = {"code": code, "label": "My iPhone", "network": "other",
                    "host": "127.0.0.1", "port": str(PORT_IRC), "nick": "firstrun",
                    "channels": "#one, #two"}

            status, text, _ = await post({**good, "code": "ZZZZ-ZZZZ-ZZZZ"})
            check("a wrong code is refused, in words, with the form kept",
                  (status, "setup code is not right" in text, 'value="firstrun"' in text),
                  (403, True, True))
            status, _, _ = await post(good, Origin="https://evil.example")
            check("a page on another site may not post it", status, 403)
            status, _, _ = await post(good, **{"X-Forwarded-Proto": "http"})
            check("nor anyone over plain http through a proxy", status, 403)
            status, text, _ = await post({**good, "nick": "9 lives"})
            check("a bad nick is refused before anything is stored",
                  (status, relay.store.active_token_ids(), relay.hub.sessions), (400, set(), {}))
            status, text, _ = await post({**good, "label": "   "})
            check("so is a device with no name", status, 400)
            status, text, _ = await post({**good, "network": "somewhere"})
            check("and a network not on the list", status, 400)
            check("the code still works after all of that", setup.open, True)

            status, text, headers = await post(good)
            check("the right code finishes setup", status, 200)
            check("  and the answer is never cached", headers.get("Cache-Control"), "no-store")
            page = _form(text)
            link = re.search(r'value="(geeyem://connect\?[^"]+)"', page)
            link = link.group(1) if link else ""
            query = parse_qs(urlsplit(link).query)
            token = (query.get("token") or [""])[0]
            check("it shows a geeyem://connect link for this bouncer",
                  (query.get("host"), token.startswith("relay_")),
                  ([f"http://127.0.0.1:{PORT_WS}"], True))
            check("  a token that works, under the name given",
                  relay.store.verify_token(token) is not None
                  and [t["label"] for t in relay.store.list_tokens()] == ["My iPhone"], True)
            check("  as a QR code drawn here", "<svg" in page and "QR code" in page, True)
            check("  of exactly that link",
                  qr.svg(qr.encode(link), "QR code to sign in My iPhone") in text, True)
            scripts = re.findall(r"<script>(.*?)</script>", text, re.S)
            want = "'sha256-" + base64.b64encode(
                hashlib.sha256(scripts[0].encode()).digest()).decode() + "'"
            check("  and its one script is the one its policy allows",
                  (len(scripts), want in headers.get("Content-Security-Policy", "")), (1, True))
            check("the token is in no log line",
                  [line for line in captured.lines if token in line], [])
            check("the network was added and is connecting",
                  ([s.config.host for s in relay.hub.sessions.values()],
                   [s.config.channels for s in relay.hub.sessions.values()]),
                  (["127.0.0.1"], [["#one", "#two"]]))
            check("setup is closed", setup.open, False)

            pair = re.search(r'href="[^"]*#pair=([A-Z0-9]+)"', page)
            async with http.post(base + "/pair", json={"code": pair.group(1) if pair else ""}) as r:
                body = await r.json()
                check("the 'use it in this browser' link pairs this browser as its own device",
                      (r.status, body.get("label"), body.get("token") != token),
                      (200, "Web browser", True))

            status, text, _ = await post(good)
            check("the code does not work twice", status, 404)
            async with http.get(base + "/setup") as r:
                check("the page now says it is done", (r.status, "already set up" in await r.text()),
                      (404, True))
            async with http.get(base + "/", allow_redirects=False) as r:
                check("and / is the web client again", r.status, 200)

            ws = await http.ws_connect(base + "/ws", headers={"Authorization": f"Bearer {token}"})
            hello = json.loads((await ws.receive()).data)
            check("the new token signs in", (hello.get("type"), hello.get("has_networks")),
                  ("hello", True))
            await ws.close()
    finally:
        await _stop(relay, task)
        logging.getLogger("relay").removeHandler(captured)

    print("when setup does not open, or closes by itself")
    relay = await _bouncer(tmp.name, "claimed")
    relay.store.create_token("from the shell")
    task = await _start(relay)
    try:
        check("not with a token already there", relay.gateway.setup, None)
        async with aiohttp.ClientSession() as http:
            async with http.get(base + "/setup") as r:
                check("  /setup is a 404", r.status, 404)
    finally:
        await _stop(relay, task)

    relay = await _bouncer(tmp.name, "off", first_run_setup=False)
    task = await _start(relay)
    try:
        check("not when first_run_setup is off", relay.gateway.setup, None)
    finally:
        await _stop(relay, task)

    relay = await _bouncer(tmp.name, "shell-later")
    task = await _start(relay)
    try:
        code = relay.gateway.setup.code
        relay.store.create_token("made by hand meanwhile")
        async with aiohttp.ClientSession() as http:
            async with http.post(base + "/setup", data={"code": code, "label": "x",
                                                         "network": "none"}) as r:
                check("a token made any other way closes it", r.status, 404)
    finally:
        await _stop(relay, task)

    print("the throttle")
    relay = await _bouncer(tmp.name, "throttle")
    task = await _start(relay)
    try:
        code = relay.gateway.setup.code
        async with aiohttp.ClientSession() as http:
            for _ in range(gw.AUTH_MAX_FAILURES):
                async with http.post(base + "/setup", data={"code": "WRONGWRONGWR"}) as r:
                    pass
            async with http.post(base + "/setup", data={"code": code, "label": "x",
                                                         "network": "none"}) as r:
                check("after ten wrong codes even the right one waits a minute",
                      (r.status, relay.store.active_token_ids()), (429, set()))
            relay.gateway._auth_failures.clear()
            relay.gateway._all_failures.clear()
            async with http.post(base + "/setup", data={"code": code, "label": "x",
                                                         "network": "none"}) as r:
                text = await r.text()
                check("and is not spent by it; with no network, it says so",
                      (r.status, "No network yet" in text, relay.hub.sessions), (200, True, {}))
    finally:
        await _stop(relay, task)
        await ircd.stop()
        tmp.cleanup()


def main():
    test_qr()
    test_units()
    test_trust_proxy()
    asyncio.run(run_setup())
    print()
    if FAILED:
        print(f"{len(FAILED)} FAILURE(S):")
        for f in FAILED:
            print(f"  - {f}")
        return 1
    print("first run passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
