#!/usr/bin/env python3
"""A client with no networks configures one itself.

The app ships knowing its bouncer, the way IRCCloud knows irccloud.com, and asks
the user for a nickname and a server rather than for infrastructure. That only
works if the bouncer takes network configuration over the wire instead of only
from config.json, which is what this exercises.

    python tests/test_onboarding.py
"""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

import aiohttp

from fakeircd import FakeIRCd
from relay.app import Relay, _slugify
from relay.config import Config

FAILED = []
PORT_IRC = 6711
PORT_WS = 8811


def check(label, got, want):
    if got != want:
        FAILED.append(f"{label}: got {got!r}, want {want!r}")
        print(f"  FAIL {label}: got {got!r}, want {want!r}")
    else:
        print(f"  ok   {label}")


class WS:
    def __init__(self): self.frames = []

    async def connect(self, session, url, token):
        self.ws = await session.ws_connect(url, headers={"Authorization": f"Bearer {token}"})
        self.task = asyncio.create_task(self._read())

    async def _read(self):
        async for msg in self.ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                self.frames.append(json.loads(msg.data))

    async def send(self, frame): await self.ws.send_str(json.dumps(frame))

    async def wait(self, pred, timeout=8.0):
        async def poll():
            while True:
                for f in self.frames:
                    if pred(f): return f
                await asyncio.sleep(0.05)
        try: return await asyncio.wait_for(poll(), timeout)
        except asyncio.TimeoutError: return None

    async def close(self):
        self.task.cancel(); await self.ws.close()


def test_cli_zero_networks():
    """`relay run` used to refuse outright when config.json had no networks at
    all, which made the onboarding flow this file exercises unreachable from
    the command line -- there was no way to get the bouncer up far enough for
    a client to add one. This drives the real CLI entry point, not Relay.run()
    directly, because the refusal lived in __main__.py, one layer up."""
    print("cli with zero networks")
    with tempfile.TemporaryDirectory() as tmp:
        cfg_path = os.path.join(tmp, "config.json")
        with open(cfg_path, "w") as f:
            json.dump({
                "listen_host": "127.0.0.1",
                "listen_port": 8822,
                "db_path": os.path.join(tmp, "cli.db"),
                "networks": [],
            }, f)

        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        proc = subprocess.Popen(
            [sys.executable, "-m", "relay", "-c", cfg_path, "run"],
            cwd=repo_root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            # The old refusal happened before the event loop even started, so
            # if it were still there the process would already be gone by now.
            time.sleep(1.5)
            check("the bouncer is still running with zero networks", proc.poll(), None)
        finally:
            proc.terminate()
            try:
                _, err = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, err = proc.communicate()
        check("it says it is waiting for a client", "waiting for a client to add one" in err, True)


def test_slugify():
    print("slugs")
    check("spaces become dashes", _slugify("Quake Net"), "quake-net")
    check("punctuation collapses", _slugify("irc.example.com"), "irc-example-com")
    check("case folds", _slugify("LiberaChat"), "liberachat")
    check("never empty", _slugify("!!!"), "network")


async def run():
    ircd = FakeIRCd(port=PORT_IRC)
    await ircd.start()
    tmp = tempfile.TemporaryDirectory()

    # A bouncer with NO networks at all -- a fresh install.
    config = Config(listen_host="127.0.0.1", listen_port=PORT_WS,
                    db_path=os.path.join(tmp.name, "onboard.db"), networks=[])
    relay = Relay(config)
    token = relay.store.create_token("onboarding")
    task = asyncio.create_task(relay.run())
    await asyncio.sleep(1.0)

    async with aiohttp.ClientSession() as http:
        client = WS()
        await client.connect(http, f"http://127.0.0.1:{PORT_WS}/ws", token)

        hello = await client.wait(lambda f: f.get("type") == "hello")
        check("hello says there are no networks yet", hello.get("has_networks"), False)
        check("hello says the client may add one", hello.get("can_add_networks"), True)

        buffers = await client.wait(lambda f: f.get("type") == "buffers")
        check("nothing to show yet", buffers.get("buffers"), [])

        # What people actually type into that screen. A URL, a host with the
        # port stuck on the end, a port that is not one -- each of those would
        # otherwise become a network that quietly never connects, with a DNS
        # error in the status buffer explaining nothing.
        base = {"name": "Bad", "nick": "riley", "tls": False, "port": PORT_IRC}
        for req, extra, label in [
            ("b1", {"host": "irc://irc.example.com"}, "a URL is not a server address"),
            ("b2", {"host": "irc.example.com:6667"}, "a host with a port is refused"),
            ("b3", {"host": "irc.example.com/chat"}, "a host with a path is refused"),
            ("b4", {"host": "two words.net"}, "a host with a space is refused"),
            ("b5", {"host": "x" * 300}, "an absurd host is refused"),
            ("b6", {"host": "irc.example.com", "port": 0}, "port 0 is refused"),
            ("b7", {"host": "irc.example.com", "port": 70000}, "a port past 65535 is refused"),
        ]:
            await client.send({"type": "add_network", "req": req, **base, **extra})
            bad = await client.wait(lambda f, r=req: f.get("type") == "error" and f.get("req") == r)
            check(label, bad is not None, True)
        check("none of them became a network", relay.hub.sessions, {})

        # G62: every field is checked, and the host must be a public address.
        # A nick with a comma, a channel with a space or a CR in anything
        # used to be stored and replayed as extra IRC commands on every
        # reconnect; 127.0.0.1 and the cloud metadata address were dialled.
        for req, extra, label in [
            ("p1", {"host": "127.0.0.1"}, "loopback is refused"),
            ("p2", {"host": "169.254.169.254", "port": 80}, "the metadata address is refused"),
            ("p3", {"host": "10.1.2.3"}, "a private range is refused"),
            ("p4", {"host": "localhost"}, "a name that resolves to loopback is refused"),
            ("p5", {"host": "100.100.1.1"}, "the CGNAT (Tailscale) range is refused"),
            ("v1", {"host": "irc.example.com", "nick": "9lives"}, "a nick starting with a digit"),
            ("v2", {"host": "irc.example.com", "nick": "a,b"}, "a nick with a comma"),
            ("v3", {"host": "irc.example.com", "nick": "x" * 200}, "a 200-character nick"),
            ("v4", {"host": "irc.example.com", "nick": "hu\r\nQUIT"}, "a nick with CR LF"),
            ("v5", {"host": "irc.example.com", "channels": ["#a b"]}, "a channel with a space"),
            ("v6", {"host": "irc.example.com", "channels": ["#a\r\nQUIT"]}, "a channel with CR LF"),
            ("v7", {"host": "irc.example.com", "username": "a b"}, "a username with a space"),
            ("v8", {"host": "irc.example.com", "sasl": {"mechanism": "PLAIN",
                                                         "username": "u"}},
             "SASL PLAIN without a password"),
        ]:
            await client.send({"type": "add_network", "req": req, **base, **extra})
            bad = await client.wait(lambda f, r=req: f.get("req") == r)
            check(label, (bad or {}).get("type"), "error")
            if req == "p2":
                check("  and says why in words", "private network" in (bad or {}).get("message", ""),
                      True)
        check("still no network", relay.hub.sessions, {})

        # A test rig dials its fake server on 127.0.0.1, which needs the rule
        # off: config.json's allow_private_hosts.
        config.allow_private_hosts = True

        # This is the onboarding screen's whole payload: a nick and a server.
        await client.send({"type": "add_network", "req": "n1", "name": "Test Net",
                           "host": "127.0.0.1", "port": PORT_IRC, "tls": False,
                           "nick": "riley", "channels": ["hangout"]})
        ok = await client.wait(lambda f: f.get("type") == "ok" and f.get("req") == "n1")
        check("network accepted", ok is not None, True)
        check("slug derived from the name", ok["network"]["slug"] if ok else None, "test-net")

        registered = await client.wait(
            lambda f: f.get("type") == "network" and f["network"].get("registered"), timeout=15)
        check("connected and registered", registered is not None, True)
        # The Server buffer is announced before the first line in it.
        status_id = ok["network"]["status_buffer"] if ok else None
        seen = [("buffer" if f.get("type") == "buffer" else "event") for f in client.frames
                if (f.get("type") == "buffer" and f["buffer"]["id"] == status_id)
                or (f.get("type") == "event" and f["event"]["buffer"] == status_id)]
        check("the new Server buffer is announced before any event in it",
              seen[:1], ["buffer"])
        check("  and something did happen in it", "event" in seen, True)
        check("using the nick we asked for",
              registered["network"]["nick"] if registered else None, "riley")

        # The channel was given without a '#', the way a person types it.
        joined = await client.wait(
            lambda f: f.get("type") == "buffer" and f["buffer"]["name"] == "#hangout"
            and f["buffer"]["joined"], timeout=15)
        check("joined the channel, # added for us", joined is not None, True)

        # --- the richer network frame (G58/G60) -----------------------------
        net = registered["network"] if registered else {}
        check("the frame carries the settings an edit screen needs",
              {k: net.get(k) for k in ("port", "tls", "username", "realname", "alt_nicks",
                                        "enabled", "source", "has_password", "sasl",
                                        "q_username", "configured_nick")},
              {"port": PORT_IRC, "tls": False, "username": "riley", "realname": "riley",
               "alt_nicks": [], "enabled": True, "source": "client", "has_password": False,
               "sasl": None, "q_username": None, "configured_nick": "riley"})
        isupport = await client.wait(
            lambda f: f.get("type") == "network" and (f["network"].get("isupport") or {}).get("prefix"))
        check("isupport arrives once the server has said",
              (isupport or {}).get("network", {}).get("isupport", {}).get("prefix"), "(ov)@+")

        # --- edit_network: a nick is a NICK on the live link ---------------
        client.frames.clear()
        await client.send({"type": "edit_network", "req": "e1", "network": "test-net",
                           "nick": "rory", "alt_nicks": ["rory_"],
                           "channels": ["#hangout", "#defrag"]})
        ok = await client.wait(lambda f: f.get("req") == "e1")
        check("edit accepted", (ok or {}).get("type"), "ok")
        renamed = await client.wait(lambda f: f.get("type") == "network"
                                    and f["network"]["nick"] == "rory")
        check("the nick changed on the live link", renamed is not None, True)
        check("and is the nick asked for now",
              (renamed or {}).get("network", {}).get("configured_nick"), "rory")
        defrag = await client.wait(lambda f: f.get("type") == "buffer"
                                   and f["buffer"]["name"] == "#defrag" and f["buffer"]["joined"])
        check("a channel added to the list is joined now", defrag is not None, True)
        check("nothing reconnected for a nick change",
              [f for f in client.frames if f.get("type") == "event"
               and "Disconnected" in (f["event"].get("text") or "")], [])

        # A bad edit changes nothing. ("#not fine" alone would be a channel
        # and its key now; a third word makes it nothing a JOIN could carry.)
        await client.send({"type": "edit_network", "req": "e2", "network": "test-net",
                           "nick": "ok", "channels": ["#fine", "#not fine at all"]})
        bad = await client.wait(lambda f: f.get("req") == "e2")
        check("an edit with one bad field is refused whole", (bad or {}).get("type"), "error")
        check("  and the nick did not change", relay.hub.sessions["test-net"].config.nick, "rory")

        # --- edit_network: the server changes, so the link is rebuilt --------
        client.frames.clear()
        await client.send({"type": "edit_network", "req": "e3", "network": "test-net",
                           "host": "localhost", "realname": "Riley G"})
        ok = await client.wait(lambda f: f.get("req") == "e3")
        check("a host edit is accepted", (ok or {}).get("type"), "ok")
        back = await client.wait(lambda f: f.get("type") == "network"
                                 and f["network"]["registered"]
                                 and f["network"]["host"] == "localhost", timeout=15)
        check("reconnected to the new host", back is not None, True)
        check("with the new real name", (back or {}).get("network", {}).get("realname"), "Riley G")
        said = [f["event"]["text"] for f in client.frames if f.get("type") == "event"
                and "Disconnected" in (f["event"].get("text") or "")]
        check("the channels were told why",
              any("new settings" in t for t in said), True)

        # --- network_connect: off stays off, on connects now -----------------
        client.frames.clear()
        await client.send({"type": "network_connect", "req": "c1", "network": "test-net",
                           "connect": False})
        ok = await client.wait(lambda f: f.get("req") == "c1")
        check("turned off", (ok or {}).get("network", {}).get("enabled"), False)
        off = await client.wait(lambda f: f.get("type") == "network"
                                and not f["network"]["enabled"] and not f["network"]["connected"])
        check("and disconnected", off is not None, True)
        check("with no error for a choice", (off or {}).get("network", {}).get("last_error"), None)
        await asyncio.sleep(3)
        check("and it stays off", relay.hub.sessions["test-net"].conn.connected, False)
        await client.send({"type": "network_connect", "req": "c2", "network": "test-net",
                           "connect": True})
        on = await client.wait(lambda f: f.get("type") == "network" and f["network"]["enabled"]
                               and f["network"]["registered"], timeout=10)
        check("turned on, it connects now", on is not None, True)
        await client.send({"type": "network_connect", "req": "c3", "network": "test-net",
                           "connect": "yes"})
        bad = await client.wait(lambda f: f.get("req") == "c3")
        check("connect must be a boolean", (bad or {}).get("type"), "error")

        # Off again before the restart, to prove off survives it.
        await client.send({"type": "network_connect", "req": "c4", "network": "test-net",
                           "connect": False})
        await client.wait(lambda f: f.get("req") == "c4")

        # It has to survive a restart, or the app would onboard every launch.
        await relay.shutdown()
        task.cancel()
        await client.close()

        relay2 = Relay(config)
        task2 = asyncio.create_task(relay2.run())
        await asyncio.sleep(1.5)
        check("network persisted across a restart",
              "test-net" in relay2.hub.sessions, True)

        client2 = WS()
        await client2.connect(http, f"http://127.0.0.1:{PORT_WS}/ws", token)
        hello2 = await client2.wait(lambda f: f.get("type") == "hello")
        check("second launch skips onboarding", hello2.get("has_networks"), True)
        net2 = await client2.wait(lambda f: f.get("type") == "network")
        check("the edits survived the restart",
              {k: (net2 or {}).get("network", {}).get(k)
               for k in ("host", "configured_nick", "alt_nicks", "realname", "enabled")},
              {"host": "localhost", "configured_nick": "rory", "alt_nicks": ["rory_"],
               "realname": "Riley G", "enabled": False})
        check("and off stayed off", relay2.hub.sessions["test-net"].conn.running, False)

        # Removing it takes the history with it, deliberately.
        await client2.send({"type": "remove_network", "req": "r1", "network": "test-net"})
        removed = await client2.wait(lambda f: f.get("type") == "ok" and f.get("req") == "r1")
        check("network removed", removed is not None, True)
        check("session stopped", "test-net" not in relay2.hub.sessions, True)
        check("buffers gone with it", relay2.store.buffers(), [])

        await client2.close()
        await relay2.shutdown()
        task2.cancel()

    await ircd.stop()
    tmp.cleanup()


def main():
    test_cli_zero_networks()
    test_slugify()
    print("onboarding")
    asyncio.run(run())
    print()
    if FAILED:
        print(f"{len(FAILED)} FAILURE(S):")
        for f in FAILED: print(f"  - {f}")
        return 1
    print("onboarding passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
