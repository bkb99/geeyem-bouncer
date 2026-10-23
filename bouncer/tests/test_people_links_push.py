#!/usr/bin/env python3
"""Wave 4 (bouncer b): ignore masks, routing, query renames, presence, channel
modes, CTCP and DCC, link cards, export and clear, upload errors, web push.

The session-level parts run against a recording hub and parsed lines, like
test_units.py. Link cards run against a real local HTTP server. Export, clear,
web push registration and the new hello fields run end to end: a fake ircd, the
real bouncer and a websocket client, like test_onboarding.py.

    python tests/test_people_links_push.py
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

import aiohttp
from aiohttp import web

from relay.config import Config, NetworkConfig
from relay.ircproto import IgnoreMatcher, normalize_mask, parse_line
from relay.session import NetworkSession
from relay.store import Store

from fakeircd import FakeIRCd

FAILED = []
PORT_IRC = 6751
PORT_WS = 8851


def check(label, got, want):
    if got != want:
        FAILED.append(f"{label}: got {got!r}, want {want!r}")
        print(f"  FAIL {label}: got {got!r}, want {want!r}")
    else:
        print(f"  ok   {label}")


class RecordingHub:
    def __init__(self):
        self.frames = []
        self.clients = set()
        self.pushed = []
        self.webpush = None

    def publish(self, frame):
        self.frames.append(frame)

    async def broadcast(self, frame):
        self.frames.append(frame)

    def has_active_viewer(self, buffer_id):
        return False

    async def push(self, notification):
        self.pushed.append(notification)

    def of(self, type_):
        return [f for f in self.frames if f.get("type") == type_]


def make_session(tmp, nick="me"):
    store = Store(os.path.join(tmp, "s.db"))
    hub = RecordingHub()
    session = NetworkSession(
        NetworkConfig(slug="t", name="T", host="h", port=6667, nick=nick), store, hub)
    session.conn.nick = nick
    session.conn.registered = True
    sent = []
    session.conn.send_command = lambda *a, **k: (sent.append((a, k)), True)[1]
    return store, hub, session, sent


def lines_sent(sent):
    return [a for a, _k in sent]


async def feed(session, *lines):
    for line in lines:
        await session._on_message(parse_line(line))


# --- G63: ignore masks ----------------------------------------------------------

def test_masks():
    print("ignore masks (G63)")
    check("a bare nick is nick!*@*", normalize_mask("bob"), "bob!*@*")
    check("user@host is *!user@host", normalize_mask("~b@spam.host"), "*!~b@spam.host")
    check("nick!user is nick!user@*", normalize_mask("bob!~b"), "bob!~b@*")
    m = IgnoreMatcher(["*!*@spam.host", "Riley[m]", "b?b!*@*"])
    check("host mask matches any nick on it", m.matches("anyone", "x", "spam.host"), True)
    check("and not another host", m.matches("anyone", "x", "good.host"), False)
    check("[ is a nick character, not a class", m.matches("riley{m}", "u", "h"), True)
    check("? is one character", (m.matches("bob"), m.matches("bab"), m.matches("boob")),
          (True, True, False))
    check("case folds", IgnoreMatcher(["*!*@SPAM.host"]).matches("x", "y", "spam.HOST"), True)

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session, sent = make_session(tmp)
            await feed(session, ":me!u@h JOIN #c", ":s 353 me = #c :me alice spam",
                       ":s 366 me #c :End")
            chan = store.find_buffer(session.network_id, "#c").id

            await session.set_ignored("*!*@spam.host", True)
            check("the list keeps the mask as typed", hub.of("ignores")[-1]["nicks"],
                  ["*!*@spam.host"])
            before = len(store.backlog(chan, limit=500))
            await feed(session,
                       ":spam!s@spam.host PRIVMSG #c :buy now",
                       ":spam!s@spam.host NICK :spam2",
                       ":spam2!s@spam.host PRIVMSG #c :buy again",
                       ":spam2!s@spam.host PART #c :bye",
                       ":spam2!s@spam.host JOIN #c",
                       ":spam2!s@spam.host PRIVMSG me :hello friend",
                       ":spam2!s@spam.host QUIT :gone")
            check("nothing from the masked host is stored, through a nick change",
                  len(store.backlog(chan, limit=500)), before)
            check("no query was opened for them", store.find_buffer(session.network_id, "spam2"),
                  None)
            check("but the member list still follows them",
                  [f["type"] for f in hub.frames if f["type"].startswith("member_")][-4:],
                  ["member_update", "member_remove", "member_add", "member_remove"])
            await feed(session, ":alice!a@good.host PRIVMSG #c :hi all")
            check("others are still stored", store.backlog(chan, limit=1)[-1].text, "hi all")

            # A bare nick follows its person through a nick change.
            await session.set_ignored("pest", True)
            await feed(session, ":pest!p@else JOIN #c", ":pest!p@else NICK :pest_",
                       ":pest_!p@else PRIVMSG #c :still me")
            check("a nick ignore holds through a nick change",
                  store.backlog(chan, limit=1)[-1].text, "hi all")
            await session.set_ignored("pest", False)
            await feed(session, ":pest_!p@else PRIVMSG #c :free")
            check("unblocking lets them back", store.backlog(chan, limit=1)[-1].text, "free")

            for bad, why in (("*", "everyone"), ("*!*@*", "everyone"), ("*!*@*.*", "everyone"),
                             ("*!*@*.*.*", "everyone"), ("*@*.*", "everyone"), ("me", "yourself"),
                             ("me!*@*", "yourself"), ("a b", "space")):
                try:
                    await session.set_ignored(bad, True)
                    refused = None
                except ValueError as exc:
                    refused = str(exc)
                check(f"refused: {bad!r}", refused is not None, True)
            await session.set_ignored("*!*@*.example", True)
            await session.set_ignored("*!~*@*", True)
            check("a mask with a real word in it is still taken",
                  {"*!*@*.example", "*!~*@*"} <= set(hub.of("ignores")[-1]["nicks"]), True)
            store.close()

    asyncio.run(run())


# --- G64: STATUSMSG, services, broadcasts ---------------------------------------

def test_routing():
    print("STATUSMSG, services and broadcasts (G64)")

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session, sent = make_session(tmp)
            await feed(session, ":me!u@h JOIN #c", ":s 353 me = #c :me @op",
                       ":s 366 me #c :End")
            chan = store.find_buffer(session.network_id, "#c")

            await feed(session, ":ChanServ!s@services.net NOTICE @#c :me: ops only, see this")
            e = store.backlog(chan.id, limit=1)[-1]
            check("an @#chan notice lands in #chan, marked",
                  (e.kind, e.sender, e.extra), ("notice", "ChanServ", {"statusmsg": "@"}))
            check("no query called @#c", store.find_buffer(session.network_id, "@#c"), None)
            check("it is still a highlight (it named me)", e.highlight, True)

            hub.pushed.clear()
            status = session.status_buffer.id
            await feed(session, ":NickServ!NickServ@services. NOTICE me :This nickname is registered")
            e = store.backlog(status, limit=1)[-1]
            check("a NickServ notice lands in the status buffer",
                  (e.kind, e.sender, e.text, e.highlight),
                  ("notice", "NickServ", "This nickname is registered", False))
            check("no NickServ query", store.find_buffer(session.network_id, "NickServ"), None)
            await feed(session, ":Q!TheQBot@CServe.quakenet.org NOTICE me :You are now logged in")
            check("Q without Q auth: status too",
                  (store.backlog(status, limit=1)[-1].sender,
                   store.find_buffer(session.network_id, "Q")), ("Q", None))
            await feed(session, ":oper!o@staff NOTICE $*.quakenet.org :server restart at noon")
            e = store.backlog(status, limit=1)[-1]
            check("a $mask broadcast lands in status",
                  (e.text, e.extra), ("server restart at noon", {"broadcast": "$*.quakenet.org"}))
            check("none of them pushed", hub.pushed, [])
            store.set_buffer_settings(status, notify="all")
            await feed(session, ":MemoServ!m@services. NOTICE me :You have 1 new memo")
            check("not even with the status buffer on notify all", hub.pushed, [])

            # An open query with a service keeps the conversation together.
            ns = store.get_or_create_buffer(session.network_id, "NickServ", "query")
            await feed(session, ":NickServ!NickServ@services. NOTICE me :Password accepted")
            e = store.backlog(ns.id, limit=1)[-1]
            check("with a NickServ query open, its reply goes there",
                  (e.text, e.highlight), ("Password accepted", False))
            check("still no push", hub.pushed, [])

            # Sending to ops: "say" with statusmsg, or a target of "@#c".
            sent.clear()
            loop = asyncio.get_running_loop()

            def fake_send(*a, **k):
                sent.append((a, k))
                if k.get("on_sent"):
                    loop.call_soon(k["on_sent"])
                return True
            session.conn.send_command = fake_send
            store.set_joined(chan.id, True)
            event = await session.say(chan.id, "ops, look", statusmsg="@")
            check("say statusmsg goes to @#c", lines_sent(sent)[-1], ("PRIVMSG", "@#c", "ops, look"))
            check("and its echo is in #c, marked", (event["buffer"], event.get("extra")),
                  (chan.id, {"statusmsg": "@"}))
            await session.say(text="by target", target="@#c")
            check("a target of @#c is the same", lines_sent(sent)[-1], ("PRIVMSG", "@#c", "by target"))
            check("still no @#c buffer", store.find_buffer(session.network_id, "@#c"), None)
            for bad in ("!", "@@@"):
                try:
                    await session.say(chan.id, "x", statusmsg=bad)
                    refused = False
                except ValueError:
                    refused = True
                check(f"statusmsg {bad!r} refused", refused, True)
            store.close()

    asyncio.run(run())


# --- G65: query rename and merge --------------------------------------------------

def test_query_rename():
    print("query rename and merge (G65)")

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session, sent = make_session(tmp)
            await feed(session, ":dave!d@h PRIVMSG me :hi there")
            q = store.find_buffer(session.network_id, "dave")
            hub.frames.clear()
            await feed(session, ":dave!d@h NICK :davezzz")
            renamed = store.buffer(q.id)
            check("the query follows the new nick", renamed.name, "davezzz")
            check("one buffer frame for it, renamed",
                  [f["buffer"]["name"] for f in hub.of("buffer")], ["davezzz"])
            nick_events = [f["event"] for f in hub.of("event") if f["event"]["kind"] == "nick"]
            check("a nick line in the query",
                  [(e["buffer"], e["from"], e["text"]) for e in nick_events],
                  [(q.id, "dave", "davezzz")])
            check("no second query", store.find_buffer(session.network_id, "dave"), None)
            await feed(session, ":davezzz!d@h PRIVMSG me :still me")
            check("the next line lands in the same query",
                  store.backlog(q.id, limit=1)[-1].text, "still me")

            # Merge: a query already exists for the new nick.
            await feed(session, ":eve!e@h PRIVMSG me :one")        # eve's query
            await feed(session, ":eve_!e@h PRIVMSG me :two")       # eve_'s query
            old = store.find_buffer(session.network_id, "eve")
            new = store.find_buffer(session.network_id, "eve_")
            store.mark_read(new.id, store.newest_eid(new.id))       # read eve_'s
            hub.frames.clear()
            await feed(session, ":eve!e@h NICK :eve_")
            check("the old query is gone", store.buffer(old.id), None)
            check("buffer_removed names it", [f["buffer"] for f in hub.of("buffer_removed")],
                  [old.id])
            check("the survivor was announced first",
                  [f["type"] for f in hub.frames if f["type"] in ("buffer", "buffer_removed")],
                  ["buffer", "buffer_removed"])
            texts = [e.text for e in store.backlog(new.id, limit=10)]
            check("its history has both, in order, then the nick line",
                  texts, ["one", "two", "eve_"])
            counts = store.unread_counts()[new.id]
            check("eve's unread line still counts as unread", counts["unread"] >= 1, True)
            store.close()

    asyncio.run(run())


# --- G84: presence -----------------------------------------------------------------

def test_presence():
    print("presence: away and online (G84)")

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session, sent = make_session(tmp)
            await feed(session, ":me!u@h JOIN #c", ":s 353 me = #c :me alice bob",
                       ":s 366 me #c :End")
            chan = store.find_buffer(session.network_id, "#c").id
            check("a join queues MODE and WHO in the background",
                  [(b[1], b[2]) for b in session._background],
                  [("MODE", ("#c",)), ("WHO", ("#c",))])
            check("and neither went out ahead of anything", lines_sent(sent), [])

            # WHO: bob is gone (G).
            hub.frames.clear()
            await feed(session,
                       ":s 352 me #c ~a a.host s alice H :0 Alice",
                       ":s 352 me #c ~b b.host s bob G :0 Bob",
                       ":s 352 me #c ~m m.host s me H :0 Me",
                       ":s 315 me #c :End of /WHO list.")
            members = hub.of("members")[-1]["members"]
            check("the WHO sends the channel's list with away marks",
                  {m["nick"]: m["away"] for m in members},
                  {"me": False, "alice": False, "bob": True})
            hub.frames.clear()
            await feed(session, ":s 352 me #c ~b b.host s bob G :0 Bob", ":s 315 me #c :End")
            check("an unchanged WHO sends nothing", hub.frames, [])

            # Queries: presence from ISON.
            await session.open_query("bob")
            await session.open_query("ghost")
            session._poll_presence()
            isons = [b for b in session._background if b[1] == "ISON"]
            check("one ISON for both open queries", [b[2] for b in isons], [("bob ghost",)])
            isons[0][3]()                           # written to the socket
            hub.frames.clear()
            await feed(session, ":s 303 me :bob")
            got = {f["buffer"]["name"]: f["buffer"]["presence"] for f in hub.of("buffer")}
            check("bob is away (online, and G), ghost offline", got,
                  {"bob": "away", "ghost": "offline"})

            # away-notify: a bare AWAY clears it.
            hub.frames.clear()
            await feed(session, ":bob!b@b.host AWAY")
            check("AWAY clears: a member_update with away false",
                  [(f["nick"], f["away"]) for f in hub.of("member_update")], [("bob", False)])
            check("and the query shows online",
                  [f["buffer"]["presence"] for f in hub.of("buffer")], ["online"])
            await feed(session, ":bob!b@b.host AWAY :lunch")
            check("AWAY :msg sets it", hub.of("member_update")[-1]["away"], True)
            hub.frames.clear()
            await feed(session, ":bob!b@b.host QUIT :bye")
            check("a quit makes the query offline",
                  [f["buffer"]["presence"] for f in hub.of("buffer")], ["offline"])
            hub.frames.clear()
            await feed(session, ":ghost!g@h PRIVMSG me :boo")
            check("a message makes its sender online",
                  [f["buffer"]["presence"] for f in hub.of("buffer")][-1], "online")

            # The reclaim ISON and the presence ISON do not answer each other.
            session._ison_pending.clear()
            session._ison_written("reclaim", [])
            session._ison_written("presence", ["ghost"])
            hub.frames.clear()
            await feed(session, ":s 303 me :", ":s 303 me :")
            check("answers are taken in the order asked",
                  [f["buffer"]["presence"] for f in hub.of("buffer")], ["offline"])

            # MONITOR where the server has it.
            await feed(session, ":s 005 me MONITOR=100 :are supported")
            session._background.clear()
            session._background_keys.clear()
            session._poll_presence()
            monitors = [(b[1], b[2][0], sorted(b[2][1].split(","))) for b in session._background]
            check("MONITOR + instead of ISON", monitors, [("MONITOR", "+", ["bob", "ghost"])])
            session._background.clear()
            session._background_keys.clear()
            session._poll_presence()
            check("and a quiet minute sends nothing", list(session._background), [])
            hub.frames.clear()
            await feed(session, ":s 730 me :ghost!g@h,bob!b@b.host")
            check("730 sets online",
                  {f["buffer"]["name"]: f["buffer"]["presence"] for f in hub.of("buffer")},
                  {"ghost": "online", "bob": "online"})
            hub.frames.clear()
            await feed(session, ":s 731 me :ghost")
            check("731 sets offline",
                  [(f["buffer"]["name"], f["buffer"]["presence"]) for f in hub.of("buffer")],
                  [("ghost", "offline")])

            # Nothing known after a disconnect.
            hub.frames.clear()
            session.conn.registered = False
            await session._on_disconnected("gone")
            check("a disconnect makes every query's presence unknown",
                  {f["buffer"]["name"]: f["buffer"]["presence"] for f in hub.of("buffer")
                   if f["buffer"]["kind"] == "query"}, {"bob": None, "ghost": None})

            # The background line waits for an idle send queue.
            session.conn.registered = True
            session._background.clear()
            session._background_keys.clear()
            session._queue_background("x", "WHO", "#c")
            session._queue_background("x", "WHO", "#c")
            check("the same question is never waiting twice", len(session._background), 1)

            # With away-notify negotiated (CAP, on the other branch), no WHO.
            session._background.clear()
            session._background_keys.clear()
            store.set_joined(chan, True)
            store.replace_members(chan, [("me", ""), ("alice", "")])
            session._poll_away()
            check("without away-notify the poll sends WHO",
                  [b[1] for b in session._background], ["WHO"])
            session._background.clear()
            session._background_keys.clear()
            session.caps = {"away-notify", "server-time"}
            session._poll_away()
            check("with away-notify it does not", list(session._background), [])
            store.close()

    asyncio.run(run())


# --- G70: channel modes --------------------------------------------------------------

def test_modes():
    print("channel modes (G70)")

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session, sent = make_session(tmp)
            await feed(session, ":s 005 me PREFIX=(ov)@+ CHANMODES=b,k,l,imnpst :ok",
                       ":me!u@h JOIN #c", ":s 353 me = #c :me alice", ":s 366 me #c :End")
            chan = store.find_buffer(session.network_id, "#c").id
            wire = session.buffer_to_wire(store.buffer(chan))
            check("modes unknown until the 324", wire["modes"], None)
            hub.frames.clear()
            await feed(session, ":s 324 me #c +ntk sekrit", ":s 329 me #c 1758000000")
            check("324 sets them, with no key on the wire",
                  [f["buffer"]["modes"] for f in hub.of("buffer")], ["+ntk"])
            hub.frames.clear()
            await feed(session, ":alice!a@h MODE #c +m-k+l sekrit 20")
            check("a MODE line updates them after its event",
                  [f["type"] for f in hub.frames if f["type"] in ("event", "buffer")],
                  ["event", "buffer"])
            check("+m-k+l", hub.of("buffer")[-1]["buffer"]["modes"], "+ntml")
            hub.frames.clear()
            await feed(session, ":alice!a@h MODE #c +o-v+b me alice *!*@x")
            check("people and lists are not modes", hub.of("buffer"), [])
            await feed(session, ":me!u@h PART #c")
            check("leaving forgets them", session.buffer_to_wire(store.buffer(chan))["modes"], None)
            check("a query has presence, not modes",
                  sorted(session.buffer_to_wire(
                      store.get_or_create_buffer(session.network_id, "bob", "query"))),
                  sorted(list(store.buffer(chan).to_wire("t")) + ["presence"]))
            store.close()

    asyncio.run(run())


# --- G72: CTCP and DCC ---------------------------------------------------------------

def test_ctcp():
    print("CTCP answers and DCC offers (G72)")

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session, sent = make_session(tmp)
            status = session.status_buffer.id
            await feed(session, ":bob!b@h PRIVMSG me :\x01VERSION\x01",
                       ":bob!b@h PRIVMSG me :\x01PING 123\x01",
                       ":bob!b@h PRIVMSG me :\x01CLIENTINFO\x01",
                       ":bob!b@h PRIVMSG me :\x01TIME\x01",
                       ":bob!b@h PRIVMSG me :\x01VERSION\x01")
            check("VERSION, PING and CLIENTINFO are answered; TIME and the repeat are not",
                  lines_sent(sent), [
                      ("NOTICE", "bob", "\x01VERSION geeyem\x01"),
                      ("NOTICE", "bob", "\x01PING 123\x01"),
                      ("NOTICE", "bob", "\x01CLIENTINFO ACTION CLIENTINFO PING VERSION\x01"),
                  ])
            logged = [(e.kind, e.text, e.extra) for e in store.backlog(status, limit=10)]
            check("each request is a server line in status", logged, [
                ("server", "bob asked for your VERSION",
                 {"ctcp": "VERSION", "from": "bob", "answered": True}),
                ("server", "bob pinged you", {"ctcp": "PING", "from": "bob", "answered": True}),
                ("server", "bob asked for your CLIENTINFO",
                 {"ctcp": "CLIENTINFO", "from": "bob", "answered": True}),
                ("server", "bob asked for your TIME (not answered)",
                 {"ctcp": "TIME", "from": "bob", "answered": False}),
            ])
            check("none pushed", hub.pushed, [])
            sent.clear()
            await feed(session, ":bob!b@h PRIVMSG #c :\x01VERSION\x01")
            check("a channel CTCP is not answered", lines_sent(sent), [])

            await feed(session, ':carol!c@h PRIVMSG me :\x01DCC SEND "holiday photo.jpg" '
                                '3232235777 5000 1234\x01')
            q = store.find_buffer(session.network_id, "carol")
            e = store.backlog(q.id, limit=1)[-1]
            check("a DCC SEND is a notice in the query",
                  (e.kind, e.sender, e.text, e.extra, e.highlight),
                  ("notice", "carol", "carol offered a file (DCC is not supported)",
                   {"dcc": "SEND", "file": "holiday photo.jpg"}, False))
            check("announced before the event",
                  [f["type"] for f in hub.frames if f["type"] in ("buffer", "event")][-2:],
                  ["buffer", "event"])
            check("five CTCPs in ten seconds is the overall limit",
                  len(session._ctcp_recent), 5)
            session._ctcp_recent.clear()
            await feed(session, ":dan!d@h PRIVMSG me :\x01DCC CHAT chat 3232235777 5001\x01")
            e = store.backlog(store.find_buffer(session.network_id, "dan").id, limit=1)[-1]
            check("a DCC CHAT says chat", (e.text, e.extra),
                  ("dan offered a chat (DCC is not supported)", {"dcc": "CHAT"}))
            check("and never pushed", hub.pushed, [])
            store.close()

    asyncio.run(run())


# --- G71: link cards --------------------------------------------------------------------

PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00"
       b"\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x03\x01\x01\x00\xc9\xfe"
       b"\x92\xef\x00\x00\x00\x00IEND\xaeB`\x82")

PAGE = """<!doctype html><html><head>
<meta charset="utf-8"><title>Fallback title</title>
<meta property="og:title" content="Rail &amp; rockets">
<meta property="og:description" content="  A page
 about   railguns. ">
<meta property="og:site_name" content="Quake World">
<meta property="og:image" content="/img.png">
</head><body><meta property="og:title" content="not this"></body></html>"""


async def start_site():
    hits = []

    async def page(request):
        hits.append(request.path)
        return web.Response(text=PAGE, content_type="text/html")

    async def plain(request):
        return web.Response(text="<html><head><title> Just a title </title></head></html>",
                            content_type="text/html")

    async def img(request):
        hits.append(request.path)
        return web.Response(body=PNG, content_type="image/png")

    async def svg(request):
        return web.Response(text="<svg xmlns='http://www.w3.org/2000/svg'><script>x</script></svg>",
                            content_type="image/png")    # lies about its type

    async def big(request):
        return web.Response(body=PNG + b"\0" * (2 * 1024 * 1024 + 10), content_type="image/png")

    async def hop(request):
        n = int(request.match_info["n"])
        target = "/page" if n == 0 else f"/hop/{n - 1}"
        raise web.HTTPFound(target)

    async def to_private(request):
        raise web.HTTPFound("http://127.0.0.2:9/secret")

    async def text(request):
        return web.Response(text="just text", content_type="text/plain")

    async def slow(request):
        await asyncio.sleep(3)
        return web.Response(text=PAGE, content_type="text/html")

    app = web.Application()
    for path, handler in (("/page", page), ("/plain", plain), ("/img.png", img),
                          ("/evil.png", svg), ("/big.png", big), ("/hop/{n}", hop),
                          ("/private", to_private), ("/text", text), ("/slow", slow)):
        app.router.add_get(path, handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, f"http://127.0.0.1:{port}", hits


def test_link_previews():
    print("link cards (G71)")
    from relay import netguard
    from relay.previews import LinkPreviews, parse_card, sniff_image

    card = parse_card(PAGE, "https://www.example.com/a/b")
    check("OpenGraph wins over <title>, entities and spaces cleaned", card, {
        "title": "Rail & rockets", "description": "A page about railguns.",
        "site": "Quake World", "image": "https://www.example.com/img.png"})
    check("a page with only a title",
          parse_card("<title>T</title>", "https://www.site.org/")["site"], "site.org")
    check("an SVG is never an image", sniff_image(b"<svg xmlns='x'/>"), None)

    # A hostile page cannot hold the loop: only the head is parsed, at most
    # PARSE_MAX of it, and at most MAX_PARSE_EVENTS tags and runs of text.
    import time as _time
    from relay.previews import card_from_body, head_of
    check("cut at </head>", head_of("<title>a</title></HEAD><body><meta>"), "<title>a</title>")
    check("or at <body>", head_of("<title>a</title><BODY class=x>"), "<title>a</title>")
    head = b"<html><head><title>huge</title>"
    worst = 0.0
    for filler in (b"<" * (1 << 20), b"<x>" * 350000, b"<a " + b"x=1 " * 260000,
                   b'<meta name="a" content="b">' * 39000, b"</head><body>" + b"<p>" * 350000):
        started = _time.perf_counter()
        card = card_from_body((head + filler)[: 1 << 20], "text/html", "https://x.example/")
        worst = max(worst, _time.perf_counter() - started)
        if card["title"] != "huge":
            check("a hostile page keeps its title", card["title"], "huge")
    check("no hostile 1 MB page takes 60 ms to parse", worst < 0.06, True)
    check("a card still comes from a real head",
          card_from_body(b"<html><head><script>" + b"x;" * 50000 + b'</script>'
                         b'<meta property="og:title" content="OG"></head><body>',
                         "text/html", "https://x.example/")["title"], "OG")
    for address, public in (("127.0.0.1", False), ("10.1.2.3", False), ("169.254.169.254", False),
                            ("100.64.0.1", False), ("224.0.0.1", False), ("::1", False),
                            ("::ffff:127.0.0.1", False), ("fd00::1", False),
                            ("1.1.1.1", True), ("2606:4700::1111", True)):
        check(f"{address} public: {public}", netguard.address_is_public(address), public)

    # Security pass 2026-09-22: the host is judged in the form aiohttp will
    # connect to, ports are the web's, and a push endpoint is a push service.
    def refused(fn, *args, **kw):
        try:
            fn(*args, **kw)
            return False
        except ValueError:
            return True
    for url in ("http://①②⑦.0.0.1:80/s", "http://①②⑦.0.0.1/s", "http://[::ffff:7f00:1]/",
                "http://93.184.216.34:6379/", "https://93.184.216.34:22/", "http://1.1.1.1:25/"):
        check(f"preview refuses {url}", refused(netguard.check_url, url, allow_private=False), True)
    for url in ("http://93.184.216.34/", "https://example.com/a", "https://example.com:443/"):
        check(f"preview allows {url}", refused(netguard.check_url, url, allow_private=False), False)
    for url in ("https://evil.example/push", "https://fcm.googleapis.com.evil.example/x",
                "https://fcm.googleapis.com:8443/fcm/send/x", "http://fcm.googleapis.com/fcm/send/x",
                "https://①②⑦.0.0.1/x"):
        check(f"push refuses {url}", refused(netguard.check_push_endpoint, url, allow_private=False), True)
    for url in ("https://fcm.googleapis.com/fcm/send/abc", "https://updates.push.services.mozilla.com/wpush/v2/x",
                "https://web.push.apple.com/QX", "https://wns2-par02p.notify.windows.com/w/?token=x"):
        check(f"push allows {url}", refused(netguard.check_push_endpoint, url, allow_private=False), False)

    async def run():
        runner, base, hits = await start_site()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                store = Store(os.path.join(tmp, "p.db"))
                open_ = LinkPreviews(store, allow_private_hosts=True)
                card = await open_.preview(base + "/page")
                check("a card from a local page (the rig's escape on)",
                      (card["title"], card["description"], card["site"]),
                      ("Rail & rockets", "A page about railguns.", "Quake World"))
                check("its picture is a bouncer URL", card["image"].startswith("/p/"), True)
                again = await open_.preview(base + "/page")
                check("cached: a second ask fetches nothing", hits.count("/page"), 1)
                check("and says the same", again, card)
                _p, mac, digest = card["image"].split("/")[1:]
                found = await open_.image(mac, digest)
                check("the picture is served, typed from its bytes", found, ("image/png", PNG))
                check("a wrong MAC is nothing", await open_.image("0" * 32, digest), None)
                check("an unknown hash is nothing", await open_.image(mac, "1" * 32), None)
                bad = open_.image_path(base + "/evil.png").split("/")[2:]
                check("SVG dressed as PNG is refused", await open_.image(*bad), None)
                big = open_.image_path(base + "/big.png").split("/")[2:]
                check("a picture over 2 MB is refused", await open_.image(*big), None)
                check("three redirects are followed",
                      (await open_.preview(base + "/hop/2"))["title"], "Rail & rockets")

                async def refusal(previews, url):
                    try:
                        await previews.preview(url)
                    except ValueError as exc:
                        return str(exc)
                    return None

                check("four are not", await refusal(open_, base + "/hop/3"),
                      "That link redirects too many times.")
                check("a plain text link has no card", await refusal(open_, base + "/text"),
                      "That link is not a page.")
                check("only http and https", await refusal(open_, "ftp://example.com/x"),
                      "Only http and https links have previews.")
                check("a title alone is enough", (await open_.preview(base + "/plain"))["title"],
                      "Just a title")
                open_.timeout = 1.0
                check("a slow page times out", await refusal(open_, base + "/slow"),
                      "That page took too long to answer.")

                closed = LinkPreviews(store, allow_private_hosts=False)
                check("without the escape, 127.0.0.1 is refused",
                      await refusal(closed, "http://127.0.0.1:9/page"),
                      "That address is on a private network.")
                check("and a name that resolves to it",
                      await refusal(closed, "http://localhost/page"),
                      "That address is on a private network.")
                check("and the metadata service",
                      await refusal(closed, "http://169.254.169.254/latest/meta-data/"),
                      "That address is on a private network.")

                # Every hop is checked, not just the first: pretend 127.0.0.1 is
                # public, and a redirect from it to 127.0.0.2 is still refused.
                real = netguard.address_is_public
                real_ports = netguard.WEB_PORTS
                netguard.address_is_public = lambda a: a == "127.0.0.1"
                # The rig's site is not on 80 or 443; let its port count as web.
                netguard.WEB_PORTS = real_ports + (int(base.rsplit(":", 1)[1]),)
                try:
                    hopper = LinkPreviews(store, allow_private_hosts=False)
                    check("the first hop is allowed",
                          (await hopper.preview(base + "/page"))["title"], "Rail & rockets")
                    check("a redirect to a private address is refused",
                          await refusal(hopper, base + "/private"),
                          "That address is on a private network.")
                    await hopper.close()
                finally:
                    netguard.address_is_public = real
                    netguard.WEB_PORTS = real_ports
                await open_.close()
                await closed.close()
                store.close()
        finally:
            await runner.cleanup()

    asyncio.run(run())


# --- G74: web push crypto ------------------------------------------------------------------

def _decrypt_webpush(body: bytes, receiver_key, auth: bytes) -> bytes:
    """RFC 8291 decryption, written out here independently of relay/webpush.py,
    so a test passing means the two sides agree with the RFC, not with
    each other."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    salt, rs, idlen = body[:16], int.from_bytes(body[16:20], "big"), body[20]
    sender_public = body[21:21 + idlen]
    ciphertext = body[21 + idlen:]
    assert rs == 4096 and len(ciphertext) <= rs
    receiver_public = receiver_key.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint)
    shared = receiver_key.exchange(
        ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), sender_public))
    ikm = HKDF(hashes.SHA256(), 32, auth,
               b"WebPush: info\x00" + receiver_public + sender_public).derive(shared)
    cek = HKDF(hashes.SHA256(), 16, salt, b"Content-Encoding: aes128gcm\x00").derive(ikm)
    nonce = HKDF(hashes.SHA256(), 12, salt, b"Content-Encoding: nonce\x00").derive(ikm)
    plain = AESGCM(cek).decrypt(nonce, ciphertext, None)
    plain = plain.rstrip(b"\x00")
    assert plain.endswith(b"\x02"), "last-record delimiter"
    return plain[:-1]


def _verify_vapid(authorization: str, audience: str) -> dict:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    def unb64(s):
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    assert authorization.startswith("vapid ")
    fields = dict(part.strip().split("=", 1) for part in authorization[6:].split(","))
    header, claims, signature = fields["t"].split(".")
    public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64(fields["k"]))
    raw = unb64(signature)
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    public.verify(der, f"{header}.{claims}".encode(), ec.ECDSA(hashes.SHA256()))
    decoded = json.loads(unb64(claims))
    assert decoded["aud"] == audience, decoded
    assert json.loads(unb64(header)) == {"typ": "JWT", "alg": "ES256"}
    return decoded


def make_browser():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = ec.generate_private_key(ec.SECP256R1())
    auth = os.urandom(16)
    p256dh = key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
    return key, auth, {"p256dh": b64(p256dh), "auth": b64(auth)}


def test_webpush_crypto():
    print("web push: RFC 8291 and VAPID (G74)")
    from relay.push import Notification
    from relay.hub import Hub
    from relay.webpush import VapidKey, WebPushSender

    class Transport:
        def __init__(self, status=201):
            self.posts, self.status = [], status

        async def post(self, url, headers, body):
            self.posts.append((url, headers, body))
            return self.status, ""

    class NoAPNs:
        def __init__(self): self.sent = []
        async def send(self, notification, devices): self.sent.append(notification)

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "w.db"))
            key = VapidKey(store)
            check("the key pair is kept", VapidKey(store).public_b64, key.public_b64)
            check("the public key is an uncompressed P-256 point",
                  (len(key.public_bytes), key.public_bytes[0]), (65, 4))

            transport = Transport()
            sender = WebPushSender(store, subject="mailto:riley@example.com", transport=transport)
            apns = NoAPNs()
            hub = Hub(store, apns)
            hub.webpush = sender
            token = store.create_token("web")
            token_id = store.verify_token(token)
            browser, auth, keys = make_browser()
            endpoint = "https://fcm.googleapis.com/fcm/send/abc123"
            store.register_webpush(token_id, endpoint, keys["p256dh"], keys["auth"],
                                   subject="https://bouncer.example")
            store.register_device(token_id, "ab" * 32, "ios", "sandbox")

            n = Notification(title="#q3", body="bob: riley, you there?", buffer_id=3, eid=91,
                             network="quakenet", badge=2)
            await hub.push(n)
            await asyncio.sleep(0.05)
            check("APNs and web push both got it", (len(apns.sent), len(transport.posts)), (1, 1))
            url, headers, body = transport.posts[0]
            check("posted to the endpoint", url, endpoint)
            check("aes128gcm, with a TTL and high urgency",
                  (headers["Content-Encoding"], headers["TTL"], headers["Urgency"]),
                  ("aes128gcm", "3600", "high"))
            claims = _verify_vapid(headers["Authorization"], "https://fcm.googleapis.com")
            check("the VAPID JWT verifies against k, for the push service's origin",
                  claims["sub"], "https://bouncer.example")
            check("k is the key hello hands out",
                  headers["Authorization"].split("k=")[1], sender.public_key)
            payload = json.loads(_decrypt_webpush(body, browser, auth))
            check("the browser can decrypt it, and it says what APNs says", payload, {
                "title": "#q3", "body": "bob: riley, you there?", "buffer": 3, "eid": 91,
                "network": "quakenet", "badge": 2, "quiet": False, "silent": False, "tag": "buffer-3",
                "category": "message"})

            await hub.push(Notification(title="#q3", body="again", buffer_id=3, eid=92,
                                        network="quakenet"))
            await asyncio.sleep(0.05)
            second = json.loads(_decrypt_webpush(transport.posts[1][2], browser, auth))
            check("a follow-up in the quiet window is quiet there too",
                  (second["quiet"], transport.posts[1][1]["Urgency"]), (True, "normal"))
            check("each push has its own salt and key",
                  transport.posts[0][2][:86] != transport.posts[1][2][:86], True)

            transport.status = 410
            await hub.push(Notification(title="x", body="y", buffer_id=4, eid=93, network="q"))
            await asyncio.sleep(0.05)
            check("a 410 forgets the subscription", store.webpush_subscriptions(), [])

            store.register_webpush(token_id, endpoint, keys["p256dh"], keys["auth"])
            store.revoke_token(token_id)
            check("revoking the token forgets its browsers", store.webpush_subscriptions(), [])
            store.close()

    asyncio.run(run())


# --- G75: upload errors --------------------------------------------------------------------

def test_upload_errors():
    print("upload errors in words (G75)")
    from relay.uploads import NOT_SET_UP, UploadConfig, Uploader

    up = Uploader(UploadConfig("http://127.0.0.1:9901", "b", "x", "x", "https://img.example"))

    def refusal(**kw):
        try:
            up.presign(**{"filename": "a.jpg", "content_type": "image/jpeg", "size": 10, **kw})
        except ValueError as exc:
            return str(exc)
        return None

    check("too big", refusal(size=100 * 1024 * 1024), "That file is too big (max 25 MB).")
    check("empty", refusal(size=0), "That file is empty.")
    check("a type not on the list", refusal(content_type="text/html"),
          "That kind of file can't be uploaded here.")
    up.available = False
    check("no boto3: not set up", refusal(), NOT_SET_UP)


# --- end to end: hello, export, clear, register_webpush, uploads -------------------------

class WS:
    def __init__(self):
        self.frames = []

    async def connect(self, http, token, origin=None):
        headers = {"Authorization": f"Bearer {token}"}
        if origin:
            headers["Origin"] = origin
            # The page is the bouncer's own, served through a proxy under that
            # name: /ws refuses a browser Origin that is not the bouncer's own
            # host (wave 4, section 9), and the proxy says which host that is.
            headers["X-Forwarded-Host"] = origin.split("://", 1)[-1]
        self.ws = await http.ws_connect(f"http://127.0.0.1:{PORT_WS}/ws", headers=headers)
        self.task = asyncio.create_task(self._read())

    async def _read(self):
        async for msg in self.ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                self.frames.append(json.loads(msg.data))

    async def send(self, frame):
        await self.ws.send_str(json.dumps(frame))

    async def wait(self, pred, timeout=6.0):
        async def poll():
            while True:
                for f in self.frames:
                    if pred(f):
                        return f
                await asyncio.sleep(0.03)
        try:
            return await asyncio.wait_for(poll(), timeout)
        except asyncio.TimeoutError:
            return None

    async def reply(self, req, timeout=6.0):
        return await self.wait(lambda f: f.get("req") == req and f["type"] in ("ok", "error")
                               or (f.get("req") == req and f["type"] == "link_preview"), timeout)

    async def close(self):
        self.task.cancel()
        await self.ws.close()


class FakeIRCdModes(FakeIRCd):
    """tools/fakeircd.py plus the three questions the bouncer now asks by
    itself: MODE #chan (324), WHO (352/315) and ISON (303)."""

    def _command(self, peer, line):
        words = line.split(" :", 1)[0].split()
        cmd = words[0].upper() if words else ""
        if cmd == "MODE" and len(words) == 2 and words[1].startswith("#"):
            peer.send(f":{self.name} 324 {peer.nick} {words[1]} +nt")
            return
        if cmd == "WHO" and len(words) > 1:
            for p in self.members(words[1]):
                flags = "G" if p.away else "H"
                peer.send(f":{self.name} 352 {peer.nick} {words[1]} u h {self.name} "
                          f"{p.nick} {flags} :0 {p.nick}")
            peer.send(f":{self.name} 315 {peer.nick} {words[1]} :End of /WHO list.")
            return
        if cmd == "ISON":
            asked = line.split(" ", 1)[1].lstrip(":").split() if " " in line else []
            online = [p.nick for n in asked for p in self.peers if p.nick.lower() == n.lower()]
            peer.send(f":{self.name} 303 {peer.nick} :{' '.join(online)}")
            return
        super()._command(peer, line)


async def _endtoend():
    from relay.app import Relay

    ircd = FakeIRCdModes(port=PORT_IRC)
    await ircd.start()
    tmp = tempfile.TemporaryDirectory()
    env_keys = ("GEYEM_S3_ENDPOINT", "GEYEM_S3_BUCKET", "GEYEM_S3_ACCESS_KEY",
                "GEYEM_S3_SECRET_KEY", "GEYEM_S3_PUBLIC_BASE")
    saved_env = {k: os.environ.pop(k, None) for k in env_keys}
    config = Config(listen_host="127.0.0.1", listen_port=PORT_WS,
                    db_path=os.path.join(tmp.name, "e.db"), allow_private_hosts=True,
                    networks=[NetworkConfig(slug="local", name="Local", host="127.0.0.1",
                                            port=PORT_IRC, nick="riley", channels=["#t"])])
    relay = Relay(config)
    run_task = asyncio.create_task(relay.run())
    pushes = []

    async def push_endpoint(request):
        pushes.append((dict(request.headers), await request.read()))
        return web.Response(status=201)

    papp = web.Application()
    papp.router.add_post("/push/{id}", push_endpoint)
    prunner = web.AppRunner(papp)
    await prunner.setup()
    psite = web.TCPSite(prunner, "127.0.0.1", 0)
    await psite.start()
    pport = psite._server.sockets[0].getsockname()[1]

    try:
        for _ in range(50):
            if relay.sessions:
                break
            await asyncio.sleep(0.05)
        await relay.sessions[0].conn.wait_registered(5)
        token = relay.store.create_token("e2e")
        async with aiohttp.ClientSession() as http:
            ws = WS()
            await ws.connect(http, token, origin="https://bouncer.example")
            hello = await ws.wait(lambda f: f["type"] == "hello")
            check("hello: link_previews", hello.get("link_previews"), True)
            check("hello: webpush_key is a base64url P-256 point",
                  len(base64.urlsafe_b64decode(hello["webpush_key"] + "=")), 65)
            check("hello: no bucket, no uploads", hello.get("can_upload"), False)
            await ws.send({"type": "upload_url", "req": "u1", "filename": "a.jpg",
                           "content_type": "image/jpeg", "size": 10})
            check("an upload with no bucket says so",
                  (await ws.reply("u1")).get("message"), "Uploads aren't set up on this bouncer.")

            chan = await ws.wait(lambda f: f["type"] == "buffer" and f["buffer"]["name"] == "#t"
                                 and f["buffer"].get("modes") is not None, timeout=10)
            check("a joined channel's buffer frame gets its modes (MODE after join)",
                  chan and chan["buffer"]["modes"] is not None, True)
            chan_id = (chan or {}).get("buffer", {}).get("id") or \
                relay.store.find_buffer(relay.sessions[0].network_id, "#t").id

            # Some history to export and clear.
            for i in range(3):
                await ws.send({"type": "say", "req": f"s{i}", "buffer": chan_id,
                               "text": f"railgun line {i}"})
                await ws.reply(f"s{i}")
            # The echo is stored when the line is written, which the flood
            # limiter may hold for a few seconds.
            await ws.wait(lambda f: f["type"] == "event"
                          and f["event"].get("text") == "railgun line 2", timeout=12)
            await ws.send({"type": "export", "req": "x1", "buffer": chan_id, "format": "txt",
                           "tz": "Europe/London"})
            ok = await ws.reply("x1")
            url = ok.get("url", "")
            check("export answers a one-time link", url.startswith("/export/"), True)
            async with http.get(f"http://127.0.0.1:{PORT_WS}{url}") as r:
                body = await r.text()
                disposition = r.headers.get("Content-Disposition", "")
                check("it downloads", r.status, 200)
            check("as a text log",
                  [line.split("] ", 1)[1] for line in body.splitlines() if "railgun" in line],
                  ["<riley> railgun line 0", "<riley> railgun line 1", "<riley> railgun line 2"])
            check("with a filename", "attachment" in disposition and ".txt" in disposition, True)
            async with http.get(f"http://127.0.0.1:{PORT_WS}{url}") as r:
                check("and only once", r.status, 404)
            await ws.send({"type": "export", "req": "x2", "buffer": chan_id, "format": "json"})
            url = (await ws.reply("x2")).get("url", "")
            async with http.get(f"http://127.0.0.1:{PORT_WS}{url}") as r:
                doc = json.loads(await r.text())
            check("json: every event, as the wire has it",
                  [e["text"] for e in doc["events"] if e["kind"] == "message"],
                  ["railgun line 0", "railgun line 1", "railgun line 2"])
            await ws.send({"type": "export", "req": "x3", "buffer": chan_id, "format": "pdf"})
            check("an unknown format is refused", (await ws.reply("x3"))["type"], "error")

            await ws.send({"type": "clear_buffer", "req": "c1", "buffer": chan_id})
            check("clear answers ok", (await ws.reply("c1"))["type"], "ok")
            check("buffer_cleared is broadcast",
                  (await ws.wait(lambda f: f["type"] == "buffer_cleared")) or {},
                  {"type": "buffer_cleared", "buffer": chan_id})
            check("its history is gone", relay.store.count_events(chan_id), 0)
            await ws.send({"type": "search", "req": "q1", "query": "railgun"})
            found = await ws.wait(lambda f: f["type"] == "search_results" and f.get("req") == "q1")
            check("and so are its search rows", found["results"], [])

            # Web push registration.
            browser, auth, keys = make_browser()
            endpoint = f"http://127.0.0.1:{pport}/push/one"
            await ws.send({"type": "register_webpush", "req": "w1",
                           "subscription": {"endpoint": endpoint, "keys": keys}})
            check("a subscription is taken", (await ws.reply("w1"))["type"], "ok")
            await ws.send({"type": "register_webpush", "req": "w2",
                           "subscription": {"endpoint": endpoint,
                                            "keys": {"p256dh": "AAAA", "auth": keys["auth"]}}})
            check("bad keys are refused", (await ws.reply("w2")).get("message"),
                  "That push subscription's keys are not valid.")
            await ws.send({"type": "register_webpush", "req": "w3",
                           "subscription": {"endpoint": "ftp://x/y", "keys": keys}})
            check("a non-http endpoint is refused", (await ws.reply("w3"))["type"], "error")

            # A PM while nothing watches: pushed to the browser.
            ircd_peer = FakePeerClient("dave")
            await ircd_peer.connect()
            ircd_peer.send("PRIVMSG riley :are you there")
            for _ in range(100):
                if pushes:
                    break
                await asyncio.sleep(0.05)
            check("the PM reached the fake push endpoint", len(pushes), 1)
            if pushes:
                headers, body = pushes[0]
                payload = json.loads(_decrypt_webpush(body, browser, auth))
                check("decrypted, it is the PM", (payload["title"], payload["body"]),
                      ("dave", "are you there"))
                claims = _verify_vapid(headers["Authorization"], f"http://127.0.0.1:{pport}")
                check("signed for the socket's origin", claims["sub"], "https://bouncer.example")
            ircd_peer.close()

            await ws.send({"type": "unregister_webpush", "req": "w4", "endpoint": endpoint})
            check("unregister answers ok", (await ws.reply("w4"))["type"], "ok")
            check("and it is gone", relay.store.webpush_subscriptions(), [])

            async with http.get(f"http://127.0.0.1:{PORT_WS}/manifest.webmanifest") as r:
                manifest = await r.json(content_type=None)
            # Addressed by content since 6fbe769 (icon-*.png?v=<hash>); the
            # name is what this checks, the version is test_units' business.
            check("the manifest has a maskable icon",
                  [i["src"].split("?")[0] for i in manifest["icons"]
                   if i.get("purpose") == "maskable"],
                  ["icon-maskable-512.png"])
            async with http.get(f"http://127.0.0.1:{PORT_WS}/") as r:
                csp = r.headers.get("Content-Security-Policy", "")
            check("the page's CSP lets it register its own service worker",
                  "worker-src 'self'" in csp, True)
            await ws.close()
    finally:
        await relay.shutdown()
        run_task.cancel()
        await prunner.cleanup()
        await ircd.stop()
        tmp.cleanup()
        for k, v in saved_env.items():
            if v is not None:
                os.environ[k] = v


class FakePeerClient:
    def __init__(self, nick):
        self.nick = nick

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection("127.0.0.1", PORT_IRC)
        self.send(f"NICK {self.nick}")
        self.send(f"USER {self.nick} 0 * :{self.nick}")
        await asyncio.sleep(0.2)

    def send(self, line):
        self.writer.write(line.encode() + b"\r\n")

    def close(self):
        self.writer.close()


def test_endtoend():
    print("end to end: hello, export, clear, web push (G74, G75, G76)")
    asyncio.run(_endtoend())


def main():
    for fn in (test_masks, test_routing, test_query_rename, test_presence, test_modes,
               test_ctcp, test_link_previews, test_webpush_crypto, test_upload_errors,
               test_endtoend):
        fn()
    print()
    if FAILED:
        print(f"{len(FAILED)} FAILURE(S):")
        for f in FAILED:
            print(f"  - {f}")
        return 1
    print("all people/links/push tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
