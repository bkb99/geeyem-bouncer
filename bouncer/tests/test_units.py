#!/usr/bin/env python3
"""Unit tests for the pure parts: the parser, the casemapper, the highlighter, the store.

Run directly, no pytest:  python tests/test_units.py
"""

import asyncio
import functools
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from relay.config import NetworkConfig
from relay.highlight import HighlightMatcher
from relay.ircproto import (check_channel, check_param, fold, format_line, make_ctcp,
                            netsplit_servers, parse_ctcp, parse_isupport, parse_line,
                            parse_prefix_map, say_budget, split_message, strip_formatting)
from relay.qauth import QAuth, challenge_response, pick_algorithm
from relay.session import NetworkSession
from relay.store import Store

FAILED = []


def check(label, got, want):
    if got != want:
        FAILED.append(f"{label}\n     got:  {got!r}\n     want: {want!r}")
        print(f"  FAIL {label}")
    else:
        print(f"  ok   {label}")


def test_parser():
    print("parser")
    m = parse_line(":nick!user@host PRIVMSG #chan :hello world")
    check("command", m.command, "PRIVMSG")
    check("params", m.params, ["#chan", "hello world"])
    check("prefix nick", m.prefix.nick, "nick")
    check("prefix host", m.prefix.host, "host")

    # A colon inside the trailing text must not start a new parameter.
    m = parse_line(":a!b@c PRIVMSG #chan :see http://example.com/x :thing")
    check("colon in trailing", m.params[1], "see http://example.com/x :thing")

    check("ping", parse_line("PING :server1").params, ["server1"])
    check("no prefix", parse_line("PING :server1").prefix.nick, "")

    # IRCv3 tags, which we do not request but must survive.
    m = parse_line("@time=2026-09-19T12:00:00Z;id=abc :n!u@h PRIVMSG #c :hi")
    check("tag parsed", m.tags.get("time"), "2026-09-19T12:00:00Z")
    check("tagged command", m.command, "PRIVMSG")
    check("tagged text", m.params[1], "hi")

    check("empty line", parse_line(""), None)
    check("numeric", parse_line(":s 001 me :Welcome").command, "001")
    # A missing trailing parameter must read as empty, not raise.
    check("param default", parse_line("PING").param(0), "")


def test_format():
    print("format")
    check("trailing when spaced", format_line("PRIVMSG", "#c", "a b"), "PRIVMSG #c :a b")
    check("no trailing when not", format_line("JOIN", "#c"), "JOIN #c")
    check("empty trailing", format_line("PART", "#c", ""), "PART #c :")
    check("ctcp", make_ctcp("ACTION", "waves"), "\x01ACTION waves\x01")
    check("ctcp parse", parse_ctcp("\x01ACTION waves\x01"), ("ACTION", "waves"))
    check("not ctcp", parse_ctcp("plain text"), None)


def refuses(fn, *args, **kwargs):
    """True when a validator rejected its input. The message is not asserted --
    it is meant for a person, and pinning the wording makes it unchangeable."""
    try:
        fn(*args, **kwargs)
    except ValueError:
        return True
    return False


def test_line_safety():
    print("outbound line safety")
    # THE ATTACK: a newline in anything a client chose is a second command to
    # the server. "hello\r\nJOIN #x" typed into a message box is a JOIN.
    check("newline in a message refused", refuses(check_param, "a\nb", trailing=True), True)
    check("carriage return refused", refuses(check_param, "a\rb", trailing=True), True)
    check("null byte refused", refuses(check_param, "a\0b", trailing=True), True)
    check("ordinary text allowed", check_param("hello there", trailing=True), "hello there")

    # A non-trailing parameter is space-delimited, so a space in one shifts
    # every parameter after it along by a place.
    check("space in a nick refused", refuses(check_param, "two words"), True)
    check("empty nick refused", refuses(check_param, ""), True)
    check("plain nick allowed", check_param("riley"), "riley")
    check("bracketed nick allowed", check_param("riley[m]"), "riley[m]")

    # IRC reads #a,#b as a list, so a comma joins somewhere nobody asked for.
    check("comma in a channel refused", refuses(check_channel, "#a,#b"), True)
    check("newline in a channel refused", refuses(check_channel, "#a\nJOIN #b"), True)
    check("ordinary channel allowed", check_channel("#hangout"), "#hangout")


def test_message_splitting():
    print("message splitting")
    budget = say_budget("#testing")
    check("budget leaves room for the prefix", budget < 512 - 100, True)

    check("a plain line is one line", split_message("hello", budget), ["hello"])
    check("newlines split", split_message("one\ntwo\nthree", budget),
          ["one", "two", "three"])
    check("crlf splits the same way", split_message("one\r\ntwo", budget), ["one", "two"])
    check("bare cr splits too", split_message("one\rtwo", budget), ["one", "two"])
    check("blank lines are dropped", split_message("one\n\n   \ntwo", budget), ["one", "two"])
    check("nothing to say is nothing", split_message("\n\n", budget), [])
    try:
        split_message("before\0after", budget)
        nul = "sent"
    except ValueError as exc:
        nul = str(exc)
    check("a NUL is refused in words, not cut off silently", nul,
          "A message cannot contain a null character.")

    # Too long for one IRC line: split, not truncated. Silent truncation is the
    # failure this replaces -- the end of a sentence disappearing with no sign.
    long_line = ("word " * 200).strip()
    pieces = split_message(long_line, budget)
    check("a long line splits", len(pieces) > 1, True)
    check("every piece fits the budget",
          all(len(p.encode()) <= budget for p in pieces), True)
    check("nothing is lost", "".join(p.strip() for p in pieces).replace(" ", ""),
          long_line.replace(" ", ""))
    check("it splits at spaces", all(not p.endswith(" ") for p in pieces), True)

    # One enormous word has no space to split at, so it splits mid-word rather
    # than sending one huge line the server would cut.
    unbroken = "x" * (budget * 2)
    pieces = split_message(unbroken, budget)
    check("an unbroken run still splits", len(pieces), 2)
    check("the pieces are whole again", "".join(pieces), unbroken)

    # Multibyte: the cut is a byte budget but has to land on a character
    # boundary, or the line ends in half a character.
    emoji = "é" * 400
    pieces = split_message(emoji, budget)
    check("multibyte splits by bytes, not characters",
          all(len(p.encode()) <= budget for p in pieces), True)
    check("no character was cut in half", "".join(pieces), emoji)
    for p in pieces:
        p.encode().decode()          # would raise if a piece were not valid text

    # A paste is not a message. Ten lines is the most one `say` will send.
    check("ten lines is allowed", len(split_message("l\n" * 10, budget)), 10)
    check("eleven lines is refused", refuses(split_message, "l\n" * 11, budget), True)


def test_ctcp_limits():
    print("ctcp rate limiting")
    from relay.config import NetworkConfig
    from relay.hub import Hub
    from relay.session import CTCP_BURST, NetworkSession

    class NoPush:
        async def send(self, notification, devices): pass

    with tempfile.TemporaryDirectory() as tmp:
        store = Store(os.path.join(tmp, "c.db"))
        session = NetworkSession(
            NetworkConfig(slug="t", name="T", host="h", port=6667, nick="me"),
            store, Hub(store, NoPush()))

        # One reply per sender per ten seconds: someone in a loop gets one
        # answer, not one per request.
        check("first request answered", session._ctcp_allowed("pest", now=0.0), True)
        check("second from the same sender dropped",
              session._ctcp_allowed("pest", now=1.0), False)
        check("same sender again after the window",
              session._ctcp_allowed("pest", now=11.0), True)
        # Nick comparison is IRC's, not Python's.
        check("case and rfc1459 folding apply",
              session._ctcp_allowed("PEST", now=12.0), False)

        # And a channel's worth of different people cannot get past the overall
        # limit either, which is the case the per-sender rule does not cover.
        session2 = NetworkSession(
            NetworkConfig(slug="t2", name="T2", host="h", port=6667, nick="me"),
            store, Hub(store, NoPush()))
        answered = [session2._ctcp_allowed(f"nick{i}", now=100.0) for i in range(10)]
        check("burst limited overall", answered.count(True), CTCP_BURST)
        check("the window reopens", session2._ctcp_allowed("nick9", now=111.0), True)
        store.close()


def test_nick_reclaim():
    print("reclaiming the configured nick")
    from relay.config import NetworkConfig
    from relay.hub import Hub
    from relay.ircproto import parse_line
    from relay.session import NetworkSession

    class NoPush:
        async def send(self, notification, devices): pass

    class FakeHub:
        def __init__(self): self.frames = []
        async def broadcast(self, frame): self.frames.append(frame)
        def __getattr__(self, name): return lambda *a, **k: None

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "r.db"))
            session = NetworkSession(
                NetworkConfig(slug="t", name="T", host="h", port=6667, nick="quinn"),
                store, FakeHub())
            sent = []
            session.conn.send_command = lambda *a, **k: sent.append(a)
            session.conn.registered = True
            session.reclaim_interval = 0.02

            # Registered on the fallback: it starts asking.
            session.conn.nick = "quinn_"
            session._start_reclaim()
            check("a fallback nick starts the loop", session._reclaim_task is not None, True)
            await asyncio.sleep(0.1)
            check("it asks with ISON", ("ISON", "quinn") in sent, True)

            # Still taken: the 303 lists it, nothing is sent.
            sent.clear()
            await session._h_303(parse_line(":s 303 quinn_ :QUINN"))
            check("a taken nick is left alone", ("NICK", "quinn") in sent, False)

            # Free: the 303 is empty, and NICK goes out.
            await session._h_303(parse_line(":s 303 quinn_ :"))
            check("a free nick is taken", ("NICK", "quinn") in sent, True)

            # Once we are quinn the loop ends by itself.
            session.conn.nick = "quinn"
            await asyncio.sleep(0.1)
            check("the loop ends once we hold it", session._reclaim_task.done(), True)

            # A nick chosen by hand is never overridden.
            session.conn.nick = "quinn_"
            session._start_reclaim()
            session._cancel_reclaim()
            check("choosing a nick stops the reclaim", session._reclaim_task, None)

            # Registered on the configured nick: nothing to do.
            session.conn.nick = "quinn"
            session._start_reclaim()
            check("holding the nick starts nothing", session._reclaim_task, None)
            store.close()

    asyncio.run(run())


def test_quit_hosts():
    print("quits carry the host, and old ones are backfilled")
    import sqlite3
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "q.db")
        store = Store(path)
        nid = store.upsert_network("t", "T", "h", 6667, False, "me")
        buf = store.get_or_create_buffer(nid, "#c", "channel")
        store.append_event(buffer_id=buf.id, network_id=nid, kind="join", sender="dan",
                           sender_host="1.2.3.4")
        store.append_event(buffer_id=buf.id, network_id=nid, kind="quit", sender="dan",
                           text="bye")
        store.append_event(buffer_id=buf.id, network_id=nid, kind="quit", sender="ghost",
                           text="never seen")
        store.db.execute("DELETE FROM meta WHERE key='quit_hosts'")
        store.close()
        store = Store(path)            # the migration runs on open
        rows = store.db.execute("SELECT sender, sender_host FROM events WHERE kind='quit'"
                                " ORDER BY eid").fetchall()
        check("a quit takes the host of the same person's earlier join",
              rows[0]["sender_host"], "1.2.3.4")
        check("a quit with nothing to go on stays empty", rows[1]["sender_host"], None)
        store.close()


def test_casemapping():
    print("casemapping")
    # The rfc1459 rule QuakeNet uses: []\~ fold to {}|^
    check("brackets fold", fold("Riley[m]"), "riley{m}")
    check("backslash folds", fold("a\\b"), "a|b")
    check("ascii mode leaves brackets", fold("Riley[m]", "ascii"), "riley[m]")


def test_isupport():
    print("isupport")
    params = ["me", "CASEMAPPING=rfc1459", "PREFIX=(ohv)@%+", "CHANTYPES=#&",
              "are supported by this server"]
    tokens = parse_isupport(params)
    check("casemapping", tokens["CASEMAPPING"], "rfc1459")
    check("prefix map", parse_prefix_map(tokens["PREFIX"]), {"@": "o", "%": "h", "+": "v"})
    check("nick not a token", "ME" in tokens, False)


def test_highlight():
    print("highlight")
    h = HighlightMatcher("riley", ["ridged"])
    check("plain mention", h.matches("hey riley you there"), True)
    check("case insensitive", h.matches("RILEY!"), True)
    check("punctuation adjacent", h.matches("riley: look"), True)
    # The bug this rule exists for.
    check("no substring match", h.matches("rileys was a president"), False)
    check("extra word", h.matches("that ridged thing"), True)
    check("unrelated", h.matches("nothing to see"), False)
    check("own line never highlights", h.matches("riley", sender="riley"), False)
    check("private always highlights", h.matches("anything", is_private=True), True)
    # A nick wearing a colour code still has to fire.
    check("through formatting", h.matches("\x0304riley\x03 hi"), True)
    h.set_nick("riley2")
    check("after nick change old", h.matches("riley hi"), False)
    check("after nick change new", h.matches("riley2 hi"), True)


def test_strip():
    print("formatting")
    check("colour stripped", strip_formatting("\x0304,08red\x03 plain"), "red plain")
    check("bold stripped", strip_formatting("\x02bold\x02"), "bold")
    check("newline kept out", strip_formatting("a\x02b"), "ab")


def test_netsplit():
    print("netsplit detection")
    # The shape a split actually produces.
    check("two servers", netsplit_servers("irc.quakenet.org irc.tng.net"),
          ("irc.quakenet.org", "irc.tng.net"))
    check("wildcard form", netsplit_servers("*.net *.split"), ("*.net", "*.split"))
    # False positives are worse than misses: a real goodbye hidden inside a
    # "netsplit" summary is a message the user never sees.
    check("ordinary quit", netsplit_servers("brb dinner.time"), None)
    check("one word", netsplit_servers("bye"), None)
    check("three words", netsplit_servers("a.net b.net c.net"), None)
    check("no dots", netsplit_servers("see ya"), None)
    check("empty", netsplit_servers(""), None)
    check("none", netsplit_servers(None), None)
    check("sentence with dots", netsplit_servers("goodbye... for now"), None)


def test_paging():
    print("backlog paging")
    with tempfile.TemporaryDirectory() as tmp:
        s = Store(os.path.join(tmp, "p.db"))
        nid = s.upsert_network("n", "N", "h", 6667, False, "me")
        buf = s.get_or_create_buffer(nid, "#c", "channel")
        eids = [s.append_event(buffer_id=buf.id, network_id=nid, kind="message",
                               sender="a", text=f"m{i}").eid for i in range(20)]

        # around: history on BOTH sides, which is what a push tap needs.
        mid = eids[10]
        around = s.backlog_around(buf.id, mid, limit=6)
        texts = [e.text for e in around]
        check("around is centred", "m10" in texts, True)
        check("around reaches backwards", "m8" in texts, True)
        check("around reaches forwards", "m12" in texts, True)
        check("around respects the limit", len(around) <= 6, True)
        check("around is oldest first", [e.eid for e in around] == sorted(e.eid for e in around), True)

        after = s.backlog_after(buf.id, eids[5], limit=3)
        check("after starts just past the cursor", [e.text for e in after], ["m6", "m7", "m8"])

        before = s.backlog(buf.id, before_eid=eids[5], limit=3)
        check("before ends just under the cursor", [e.text for e in before], ["m2", "m3", "m4"])

        # around at the very start must not run off the end
        first = s.backlog_around(buf.id, eids[0], limit=6)
        check("around at the beginning is safe", first[0].text, "m0")

        # Resume (G57): everything after an eid when it fits...
        since, complete = s.events_since(buf.id, eids[15], limit=10)
        check("since: everything after the cursor, oldest first",
              [e.text for e in since], ["m16", "m17", "m18", "m19"])
        check("since: complete when it all fits", complete, True)
        # ...and the NEWEST `limit` when it does not, so the hole sits just
        # after what the client held rather than at the live end.
        since, complete = s.events_since(buf.id, eids[2], limit=5)
        check("since: capped to the newest", [e.text for e in since],
              ["m15", "m16", "m17", "m18", "m19"])
        check("since: not complete when capped", complete, False)
        since, complete = s.events_since(buf.id, eids[14], limit=5)
        check("since: exactly the limit is complete", (len(since), complete), (5, True))
        check("since: nothing new is nothing", s.events_since(buf.id, eids[-1], limit=5),
              ([], True))
        s.close()


def test_push_sound():
    print("notification sounds")
    from relay.push import Notification
    from relay.webpush import notification_payload

    def aps(**kw):
        n = Notification(title="#t", body="b", buffer_id=1, eid=2, network="n", **kw)
        return n.to_apns_payload("thread")["aps"]

    check("the default is the system's", aps().get("sound"), "default")
    check("a bundled sound is named by its file", aps(sound="chime").get("sound"), "chime.caf")
    check("none leaves the key out", "sound" in aps(sound="none"), False)
    check("none is still an alert, not a passive one", "interruption-level" in aps(sound="none"), False)
    check("a quiet follow-up has no sound whatever was chosen", "sound" in aps(sound="chime", quiet=True), False)
    check("web push is silent for none only",
          (notification_payload(Notification(title="t", body="b", buffer_id=1, eid=2, network="n",
                                             sound="none"))["silent"],
           notification_payload(Notification(title="t", body="b", buffer_id=1, eid=2, network="n",
                                             sound="chime"))["silent"]), (True, False))
    with tempfile.TemporaryDirectory() as tmp:
        s = Store(os.path.join(tmp, "p.db"))
        check("a fresh store plays the default", s.get_setting("push_sound"), "default")
        s.set_setting("push_sound", "pop")
        check("a chosen sound is on the settings frame", s.settings()["push_sound"], "pop")
        check("nick colors start empty", s.settings()["nick_colors"], {})
        check("the palette starts as the default", s.settings()["nick_palette"], "default")
        s.settings()["nick_colors"]["x"] = 1
        check("and the default cannot be edited through a settings dict",
              s.settings()["nick_colors"], {})
        s.set_setting("nick_colors", {"alice": 210})
        s.set_setting("nick_palette", "pastel")
        s.close()
        s = Store(os.path.join(tmp, "p.db"))
        check("nick colors and palette survive a reopen",
              (s.settings()["nick_colors"], s.settings()["nick_palette"]),
              ({"alice": 210}, "pastel"))
        s.close()


def test_detached():
    print("detached buffers")
    with tempfile.TemporaryDirectory() as tmp:
        s = Store(os.path.join(tmp, "d.db"))
        nid = s.upsert_network("n", "N", "h", 6667, False, "me")
        buf = s.get_or_create_buffer(nid, "#busy", "channel")
        s.append_event(buffer_id=buf.id, network_id=nid, kind="message", sender="a", text="noise")
        s.append_event(buffer_id=buf.id, network_id=nid, kind="message", sender="a",
                       text="you there", highlight=True)

        check("attached counts everything", s.unread_counts()[buf.id],
              {"unread": 2, "highlights": 1})
        s.set_detached(buf.id, True)
        # Muted: ordinary traffic stops lighting a badge, mentions still do.
        check("detached mutes ordinary traffic", s.unread_counts()[buf.id]["unread"], 0)
        check("detached still counts mentions", s.unread_counts()[buf.id]["highlights"], 1)
        check("detached is on the wire", s.buffer(buf.id).to_wire("n")["detached"], True)
        s.set_detached(buf.id, False)
        check("re-attached counts again", s.unread_counts()[buf.id]["unread"], 2)

        # A mute that ends by itself: on the wire while it lasts, gone after.
        s.set_detached(buf.id, True, until=1_000.0)
        check("a timed mute is on the wire", s.buffer(buf.id).to_wire("n")["muted_until"], 1_000.0)
        check("not expired before its time", s.expired_mutes(999.0), [])
        check("expired at its time", s.expired_mutes(1_000.0), [buf.id])
        s.set_detached(buf.id, False)
        check("unmuting clears the time", s.buffer(buf.id).to_wire("n")["muted_until"], None)
        check("and nothing is left to expire", s.expired_mutes(2_000.0), [])
        s.set_detached(buf.id, True)
        check("an untimed mute never expires", s.expired_mutes(10**12), [])
        check("and says so on the wire", s.buffer(buf.id).to_wire("n")["muted_until"], None)
        s.close()


def test_migration():
    print("schema migration")
    import sqlite3
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "old.db")
        # A database made before `detached` existed. CREATE TABLE IF NOT EXISTS
        # will not add the column, so the migration has to.
        db = sqlite3.connect(path)
        db.executescript("""
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE networks (id INTEGER PRIMARY KEY, slug TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
                tls INTEGER NOT NULL DEFAULT 0, nick TEXT NOT NULL, created_at REAL NOT NULL);
            CREATE TABLE buffers (id INTEGER PRIMARY KEY, network_id INTEGER NOT NULL,
                name TEXT NOT NULL, name_lower TEXT NOT NULL, kind TEXT NOT NULL,
                topic TEXT, topic_by TEXT, topic_at REAL, joined INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL, last_seen_eid INTEGER NOT NULL DEFAULT 0,
                archived INTEGER NOT NULL DEFAULT 0, UNIQUE (network_id, name_lower));
            CREATE TABLE events (eid INTEGER PRIMARY KEY AUTOINCREMENT, buffer_id INTEGER NOT NULL,
                network_id INTEGER NOT NULL, ts REAL NOT NULL, kind TEXT NOT NULL, sender TEXT,
                sender_host TEXT, text TEXT, self INTEGER NOT NULL DEFAULT 0,
                highlight INTEGER NOT NULL DEFAULT 0, extra TEXT);
            INSERT INTO meta VALUES ('schema_version', '1');
            INSERT INTO networks VALUES (1,'n','N','h',6667,0,'me',0);
            INSERT INTO buffers (id,network_id,name,name_lower,kind,created_at)
                VALUES (1,1,'#old','#old','channel',0);
            INSERT INTO events (buffer_id,network_id,ts,kind,sender,text)
                VALUES (1,1,0,'message','a','history that must survive');
        """)
        db.commit(); db.close()

        s = Store(path)   # opening it runs the migration
        check("migrated db opens", s.buffer(1) is not None, True)
        check("detached defaults to off", s.buffer(1).detached, False)
        # The point of an additive migration: nothing is lost.
        check("existing backlog survived",
              [e.text for e in s.backlog(1, limit=10)], ["history that must survive"])
        s.set_detached(1, True)
        check("the new column works", s.buffer(1).detached, True)
        from relay.store import SCHEMA_VERSION
        check("version recorded",
              s.db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()["value"],
              str(SCHEMA_VERSION))
        # The v1 database had no network columns either; the migration adds them.
        check("network columns migrated",
              {"channels", "enabled", "source"} <= {r["name"] for r in
                  s.db.execute("PRAGMA table_info(networks)")}, True)
        s.close()


def make_v6_db(path, events=3000):
    """A database in the shape the live bouncer has today: main's schema
    (tests/fixtures/schema_v6.sql), one network, a status buffer, channels
    and queries (one archived, one detached, one with a topic), members,
    a token, a device, an ignore, and `events` lines spread across them --
    written through main's own triggers, so its search index is populated
    the way the live one is."""
    import sqlite3
    here = os.path.dirname(os.path.abspath(__file__))
    db = sqlite3.connect(path)
    db.executescript(open(os.path.join(here, "fixtures", "schema_v6.sql")).read())
    db.executescript("""
        INSERT INTO meta VALUES ('schema_version', '6');
        INSERT INTO networks (id, slug, name, host, port, tls, nick, created_at, username,
                              realname, channels, source, config_channels)
            VALUES (1, 'quakenet', 'QuakeNet', 'irc.quakenet.org', 6667, 0, 'quinn', 0,
                    'quinn', 'quinn', '["#hangout","#defrag"]', 'config',
                    '["#hangout","#defrag"]');
        INSERT INTO buffers (id, network_id, name, name_lower, kind, created_at)
            VALUES (1, 1, '*status*', '*status*', 'status', 0);
        INSERT INTO buffers (id, network_id, name, name_lower, kind, topic, topic_by,
                             topic_at, joined, created_at, last_seen_eid)
            VALUES (2, 1, '#hangout', '#hangout', 'channel', 'frag on', 'morgan',
                    1758000000, 1, 0, 100);
        INSERT INTO buffers (id, network_id, name, name_lower, kind, joined, detached, created_at)
            VALUES (3, 1, '#defrag', '#defrag', 'channel', 1, 1, 0);
        INSERT INTO buffers (id, network_id, name, name_lower, kind, created_at)
            VALUES (4, 1, 'morgan', 'morgan', 'query', 0);
        INSERT INTO buffers (id, network_id, name, name_lower, kind, archived, created_at)
            VALUES (5, 1, 'oldpal', 'oldpal', 'query', 1, 0);
        INSERT INTO members VALUES (2, 'morgan', 'morgan', '@'), (2, 'PuFF', 'puff', '');
        INSERT INTO tokens (id, token_hash, label, created_at) VALUES (1, 'ab', 'phone', 0);
        INSERT INTO devices (token_id, apns_token, platform, environment, updated_at)
            VALUES (1, 'aabb', 'ios', 'sandbox', 0);
        INSERT INTO ignores VALUES (1, 'spambot', 'spambot', 0);
    """)
    rows = []
    for i in range(events):
        buffer_id = (2, 2, 2, 3, 4, 5, 1)[i % 7]
        rows.append((buffer_id, 1, 1758000000 + i, "message" if buffer_id != 1 else "server",
                     ("morgan", "PuFF", "quinn")[i % 3], f"line {i} about railguns and img.example.com",
                     int(i % 3 == 2), int(i % 50 == 0 and buffer_id != 1)))
    db.executemany("INSERT INTO events (buffer_id, network_id, ts, kind, sender, text, self,"
                   " highlight) VALUES (?,?,?,?,?,?,?,?)", rows)
    db.commit()
    db.close()


def test_migration_from_v6():
    """The live database (main's schema, ~3000 events) opens under this code,
    keeps every row, and gains what this code adds -- without a rewrite."""
    print("migration from the deployed schema (v6)")
    import sqlite3
    from relay.store import SCHEMA_VERSION
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "live.db")
        make_v6_db(path)
        before = sqlite3.connect(path)
        snapshot = before.execute("SELECT eid, buffer_id, ts, kind, sender, text, self,"
                                  " highlight FROM events ORDER BY eid").fetchall()
        buffers_before = before.execute("SELECT id, name, kind, topic, joined, detached,"
                                        " archived, last_seen_eid FROM buffers ORDER BY id").fetchall()
        before.close()

        s = Store(path)
        check("every event survives, byte for byte",
              [tuple(r) for r in s.db.execute(
                  "SELECT eid, buffer_id, ts, kind, sender, text, self, highlight"
                  " FROM events ORDER BY eid")] == snapshot, True)
        check("every buffer survives",
              [tuple(r) for r in s.db.execute(
                  "SELECT id, name, kind, topic, joined, detached, archived, last_seen_eid"
                  " FROM buffers ORDER BY id")] == [tuple(r) for r in buffers_before], True)
        check("members, tokens, devices and ignores survive",
              (len(s.members(2)), len(s.list_tokens()), len(s.devices()), s.ignores(1)),
              (2, 1, 1, ["spambot"]))
        check("the schema version is recorded",
              s.db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0],
              str(SCHEMA_VERSION))
        tables = {r[0] for r in s.db.execute("SELECT name FROM sqlite_master")}
        check("the old search index is replaced by the new one",
              ("events_fts" in tables, "events_fts_insert" in tables, "events_search" in tables),
              (False, False, True))
        wire = {b.name: b.to_wire("quakenet") for b in s.buffers(include_archived=True)}
        check("new buffer fields read as their defaults",
              {n: (w["notify"], w["pinned"]) for n, w in wire.items()},
              {"*status*": ("mentions", False), "#hangout": ("mentions", False),
               "#defrag": ("mentions", False), "morgan": ("all", False),
               "oldpal": ("all", False)})
        check("the topic's setter and time were already there, and still are",
              (wire["#hangout"]["topic_by"], wire["#hangout"]["topic_at"]),
              ("morgan", 1758000000))
        check("settings start at their defaults", s.settings(),
              {"push_preview": True, "auto_away": False, "push_sound": "default",
               "nick_colors": {}, "nick_palette": "default"})
        check("highlight words are not owned until a session seeds them",
              s.highlight_words(1), None)
        check("old lines are searchable at once", len(s.search("railguns", limit=200)), 200)
        check("including by a domain", len(s.search("img.example.com", limit=5)), 5)
        e = s.append_event(buffer_id=2, network_id=1, kind="message", sender="x",
                           text="a brand new zebra")
        check("the eid sequence carries on", e.eid, len(snapshot) + 1)
        check("and a new line is indexed", [x.text for x in s.search("zebra")],
              ["a brand new zebra"])
        s.close()

        # Opening it again changes nothing and rebuilds nothing.
        s = Store(path)
        check("a second open is a no-op", len(s.search("zebra")), 1)
        check("with every row still there",
              s.db.execute("SELECT COUNT(*) FROM events").fetchone()[0], len(snapshot) + 1)
        s.close()


def test_qauth():
    print("Q challengeauth")
    # Cross-checked byte for byte against otherbot's _q_challenge_response, which
    # has been authenticating against Q on this account since 2026-08-29.
    import hashlib, hmac

    def reference(user, password, challenge):
        lower = user.translate(str.maketrans("[]\\", "{}|")).lower()
        inner = hashlib.sha256(password[:10].encode()).hexdigest()
        key = hashlib.sha256(f"{lower}:{inner}".encode()).hexdigest()
        return hmac.new(key.encode(), challenge.encode(), hashlib.sha256).hexdigest()

    for user, pw, ch in [("TestUser", "hunter2secret", "abc123"),
                         ("riley[m]", "pw", "nonce"),
                         ("A\\B", "password12345", "xyz"),
                         ("user]x[", "p", "c")]:
        check(f"matches otherbot for {user!r}",
              challenge_response(user, pw, ch), reference(user, pw, ch))

    # Both of these silently produce a response Q rejects, so they get tests.
    check("password truncates at 10",
          challenge_response("u", "0123456789", "c"),
          challenge_response("u", "0123456789ignored", "c"))
    check("username folds rfc1459, not ascii",
          challenge_response("a[b]", "p", "c") == challenge_response("a{b}", "p", "c"), True)
    check("response is 64 hex chars", len(challenge_response("u", "p", "c")), 64)

    check("picks sha256", pick_algorithm("HMAC-SHA-256 HMAC-SHA-1 HMAC-MD5"), "HMAC-SHA-256")
    # A silent downgrade to MD5 is worse than no auth at all.
    check("refuses to downgrade", pick_algorithm("HMAC-MD5 HMAC-SHA-1"), None)

    # THE ATTACK: anyone can send a NOTICE. If a challenge from an arbitrary
    # sender were answered, they could feed a chosen nonce and collect an HMAC
    # under our key -- an offline attack on the password.
    auth = QAuth("me", "secret")
    auth.start()
    forged = auth.handle_notice("CHALLENGE deadbeef HMAC-SHA-256",
                                sender_host="evil.example.com")
    check("ignores a challenge from the wrong host", forged, None)
    lookalike = QAuth("me", "secret")
    lookalike.start()
    check("ignores a host that only contains CServe's (G78)",
          lookalike.handle_notice("CHALLENGE deadbeef HMAC-SHA-256",
                                  sender_host="cserve.quakenet.org.evil.example"), None)

    auth2 = QAuth("me", "secret")
    auth2.start()
    genuine = auth2.handle_notice("CHALLENGE deadbeef HMAC-SHA-256",
                                  sender_host="CServe.quakenet.org")
    check("answers a challenge from CServe", genuine is not None, True)
    check("sends CHALLENGEAUTH, not AUTH",
          genuine[1].startswith("CHALLENGEAUTH me "), True)
    # The password must never appear on the wire in any form.
    check("password is absent from the reply", "secret" in genuine[1], False)
    check("algorithm named", genuine[1].endswith("HMAC-SHA-256"), True)

    check("joins wait while mid-exchange", auth2.awaiting, True)
    auth2.handle_notice("You are now logged in as me.", sender_host="CServe.quakenet.org")
    check("authed state reached", auth2.state, "authed")
    check("joins released once authed", auth2.awaiting, False)

    auth3 = QAuth("me", "wrong")
    auth3.start()
    auth3.handle_notice("Username or password incorrect.", sender_host="CServe.quakenet.org")
    check("failure is recorded", auth3.state, "failed")
    check("joins released after failure", auth3.awaiting, False)

    check("unconfigured auth is inert", QAuth("", "").configured, False)


def test_store():
    print("store")
    with tempfile.TemporaryDirectory() as tmp:
        s = Store(os.path.join(tmp, "t.db"))
        nid = s.upsert_network("q", "QuakeNet", "irc.example", 6667, False, "me")
        check("network idempotent", s.upsert_network("q", "QuakeNet", "irc.example", 6667, False, "me"), nid)

        buf = s.get_or_create_buffer(nid, "#Chan", "channel")
        # Case-folded lookup: the same channel typed differently is one buffer.
        check("buffer folded", s.get_or_create_buffer(nid, "#chan", "channel").id, buf.id)

        e1 = s.append_event(buffer_id=buf.id, network_id=nid, kind="message", sender="a", text="one")
        e2 = s.append_event(buffer_id=buf.id, network_id=nid, kind="message", sender="b",
                            text="two", highlight=True)
        check("eids ascend", e2.eid > e1.eid, True)

        back = s.backlog(buf.id, limit=10)
        check("backlog oldest first", [e.text for e in back], ["one", "two"])
        check("backlog paging", [e.text for e in s.backlog(buf.id, before_eid=e2.eid, limit=10)], ["one"])
        check("highlights view", [e.text for e in s.highlights()], ["two"])

        counts = s.unread_counts()
        check("unread before read", counts[buf.id], {"unread": 2, "highlights": 1})
        s.mark_read(buf.id, e2.eid)
        check("unread after read", s.unread_counts()[buf.id], {"unread": 0, "highlights": 0})
        # A late frame from a second device must not rewind the marker.
        s.mark_read(buf.id, e1.eid)
        check("marker never rewinds", s.buffer(buf.id).last_seen_eid, e2.eid)

        # A future eid -- a stale cursor, a bug, anything the client echoes
        # that outruns what has actually happened -- must not silence messages
        # that have not been sent yet. The marker can only reach what exists.
        s.mark_read(buf.id, e2.eid + 1000)
        check("marker clamped to the newest stored eid", s.buffer(buf.id).last_seen_eid, e2.eid)
        e3 = s.append_event(buffer_id=buf.id, network_id=nid, kind="message", sender="a", text="three")
        check("a message after the bogus mark_read still counts as unread",
              s.unread_counts()[buf.id]["unread"], 1)

        s.replace_members(buf.id, [("alice", "@"), ("bob", ""), ("carol", "+")])
        check("member order", [m["nick"] for m in s.members(buf.id)], ["alice", "carol", "bob"])
        s.rename_member("bob", "robert")
        check("rename", sorted(m["nick"] for m in s.members(buf.id)), ["alice", "carol", "robert"])
        s.remove_member(buf.id, "alice")
        check("remove", len(s.members(buf.id)), 2)

        e4 = s.append_event(buffer_id=buf.id, network_id=nid, kind="message", sender="c",
                            text="me: four", highlight=True)
        q = s.get_or_create_buffer(nid, "pal", "query")
        s.append_event(buffer_id=q.id, network_id=nid, kind="message", sender="pal",
                       text="psst", highlight=True)
        check("mentions: every buffer, newest first (G36)",
              [e.text for e in s.highlights()], ["psst", "me: four", "two"])
        check("mentions: paged by eid", [e.text for e in s.highlights(limit=5, before_eid=e4.eid)],
              ["two"])

        token = s.create_token("test device")
        check("token verifies", s.verify_token(token) is not None, True)
        check("garbage rejected", s.verify_token("relay_nope"), None)
        # Only the hash is stored -- the plaintext must not be findable.
        row = s.db.execute("SELECT token_hash FROM tokens").fetchone()
        check("plaintext not stored", token in row["token_hash"], False)
        tid = s.list_tokens()[0]["id"]
        s.revoke_token(tid)
        check("revoked rejected", s.verify_token(token), None)
        s.close()


def test_search():
    """Plain text in, never a syntax error out; prefixes, no stemming, the
    sender a filter rather than a term (G20, G44)."""
    print("search (G20, G44)")
    from relay.store import search_terms
    check("words and a phrase", [t.text for t in search_terms('rail "exact phrase" quinn:')],
          ["rail", "exact phrase", "quinn:"])
    check("an unpaired quote is not an error",
          [t.text for t in search_terms('"unterminated')], ["unterminated"])
    check("an old client's trailing * is dropped", [t.text for t in search_terms("defrag*")],
          ["defrag"])
    check("punctuation must also be there literally",
          [(t.fts, t.literal) for t in search_terms("c++ rail")],
          [('"c++"*', "c++"), ('"rail"*', None)])
    check("punctuation alone is literal only", [(t.fts, t.literal) for t in search_terms("((")],
          [(None, "((")])
    check("a quote inside a term is escaped for FTS5",
          search_terms('say"hi')[0].fts, '"say"*')

    with tempfile.TemporaryDirectory() as tmp:
        s = Store(os.path.join(tmp, "search.db"))
        nid = s.upsert_network("q", "QuakeNet", "irc.example", 6667, False, "me")
        chan = s.get_or_create_buffer(nid, "#hangout", "channel")
        other = s.get_or_create_buffer(nid, "#defrag", "channel")
        lines = [
            ("bob", "look https://img.example.com/a1b2.png", chan, 1000.0),
            ("alice", "what's the plan tonight", chan, 2000.0),
            ("carol", "anyone here write c++ still", chan, 3000.0),
            ("dave", "come join #hangout later", other, 4000.0),
            ("erin", "quinn: you around?", chan, 5000.0),
            ("frank", "my railgun is broken", chan, 6000.0),
            ("gina", "the railing fell off", chan, 7000.0),
            ("hank", "a rail line", other, 8000.0),
            ("ivan", "I was running late", chan, 9000.0),
            ("jo", "meet at the café", chan, 10000.0),
            ("Bob[m]", "a line from bob with brackets", chan, 11000.0),
            ("kim", "what’s with the curly one", chan, 12000.0),
            ("lee", "c is a letter, not a language", chan, 13000.0),
            ("mo", "smiley ((( here", chan, 14000.0),
        ]
        for sender, text, buf, ts in lines:
            s.append_event(buffer_id=buf.id, network_id=nid, kind="message",
                           sender=sender, text=text, ts=ts)
        s.append_event(buffer_id=chan.id, network_id=nid, kind="join", sender="bob",
                       text="img.example.com")

        def texts(query, **kw):
            return [e.text for e in s.search(query, **kw)]

        # The five from the audit, every one an FTS5 syntax error before.
        check("a domain", texts("img.example.com"),
              ["look https://img.example.com/a1b2.png"])
        check("an apostrophe (straight or curly in the line)", texts("what's"),
              ["what’s with the curly one", "what's the plan tonight"])
        check("c++ finds c++ and not every word starting with c", texts("c++"),
              ["anyone here write c++ still"])
        check("a channel name", texts("#hangout"), ["come join #hangout later"])
        check("a nick with a colon", texts("quinn:"), ["quinn: you around?"])

        check("rail finds railgun and railing: a prefix", sorted(texts("rail")),
              sorted(["my railgun is broken", "the railing fell off", "a rail line"]))
        check("railing does not find railgun or rail: no stemming", texts("railing"),
              ["the railing fell off"])
        check("a half-typed word finds the whole one", texts("runn"), ["I was running late"])
        check("accents are optional", texts("cafe"), ["meet at the café"])
        check("a quoted phrase stays a phrase", texts('"rail line"'), ["a rail line"])
        check("words need not be adjacent", texts("railgun broken"), ["my railgun is broken"])
        check("an unpaired quote searches the word", texts('"railing'), ["the railing fell off"])
        check("punctuation alone still searches", texts("((("), ["smiley ((( here"])
        check("an FTS5 operator is just a word", texts("NOT"), ["c is a letter, not a language"])
        for weird in ("((", "))", '"', "*", "AND", "a:b", "NEAR(", "^x", "-", "'", "{x}"):
            try:
                s.search(weird)
                ok = True
            except Exception:
                ok = False
            check(f"{weird!r} never raises", ok, True)

        # The sender is a filter, not a term.
        check("a nick is not found by the sender column", texts("bob"),
              ["a line from bob with brackets"])
        check("from: an exact nick, IRC case folding", texts("line", sender="bob{M}"),
              ["a line from bob with brackets"])
        check("from alone lists what they said", texts("", sender="erin"), ["quinn: you around?"])
        check("since and until bound the time", texts("rail", since=6500, until=7500),
              ["the railing fell off"])
        check("buffer narrows it", texts("rail", buffer_id=other.id), ["a rail line"])
        check("joins are never results", "join" in {e.kind for e in s.search("img")}, False)
        newest = s.search("rail", limit=2)
        check("newest first, limited", [e.text for e in newest],
              ["a rail line", "the railing fell off"])
        check("before_eid pages on", texts("rail", before_eid=newest[-1].eid),
              ["my railgun is broken"])

        # The C prefilter in front of the exact test for punctuation must never
        # lose a line the exact test would find: formatting codes inside the
        # term, fullwidth forms, curly quotes, case, tabs and double spaces.
        tricky = [
            "bold smile :\x02)\x02 here", "fullwidth smile ：）", "plain :) ascii",
            "C++ in capitals", "tabbed\t:)", "o’reilly curly", "o'reilly straight",
            "colour \x0304c\x03++ code", "spaced  a . b  out", "a.b", "é:)",
        ]
        for text in tricky:
            s.append_event(buffer_id=other.id, network_id=nid, kind="message",
                           sender="Tricky[x]", text=text)
        from relay.store import _has_literal
        for query in (":)", "c++", "o'", "a.b", ")", "é:)", ":) c++"):
            wanted = [t for t in reversed(tricky)
                      if all(_has_literal(t, term) for term in query.split())]
            check(f"the fast path finds what the exact test does: {query!r}",
                  texts(query, buffer_id=other.id), wanted)
        check("from: with brackets folded, fast path", len(texts("", sender="TRICKY{X}")),
              len(tricky))
        check("from: a nick with LIKE's own characters is literal",
              texts("", sender="tri_ky[x]") + texts("", sender="%"), [])
        s.close()


def test_whois_timeout():
    """A lookup nothing ever answers still gets an answer.

    The server here is not slow, it is absent: nothing will ever send the 318
    that ends a WHOIS. Without the deadline the client is left holding a card
    that never fills in, and there is no second chance to tell it otherwise.
    """
    print("whois deadline")

    class FakeHub:
        """Just the one method a session reaches for here."""

        def __init__(self):
            self.frames = []

        async def broadcast(self, frame):
            self.frames.append(frame)

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "whois.db"))
            hub = FakeHub()
            session = NetworkSession(
                NetworkConfig(slug="test", name="Test", host="127.0.0.1",
                              nick="relaytest"),
                store, hub,
            )
            # A whois asked while the network is down is refused in a
            # sentence, the same as anything else that needs a connection.
            try:
                await session.whois("ghost", req="w8")
                refused = False
            except ValueError:
                refused = True
            check("a whois while disconnected is refused", refused, True)

            # Never connected. The flag is what the WHOIS is refused on, and
            # the line itself goes into a send queue nothing is draining.
            session.conn.registered = True
            session.whois_timeout = 0.05
            await session.whois("ghost", req="w9")
            check("the lookup is pending", len(session._whois_pending), 1)
            await asyncio.sleep(0.3)
            check("the lookup was cleaned up", session._whois_pending, {})
            store.close()
            return hub.frames

    frames = asyncio.run(run())
    whois = [f for f in frames if f.get("type") == "whois"]
    check("the deadline answered once", len(whois), 1)
    frame = whois[0] if whois else {}
    check("the deadline echoes the req", frame.get("req"), "w9")
    check("the deadline names the nick", frame.get("nick"), "ghost")
    check("the deadline reports not found", frame.get("found"), False)
    check("the deadline says what happened", frame.get("error"),
          "no reply from the server")


# --- wave 1 ------------------------------------------------------------------
#
# Fakes shared by the tests below. None of them opens a socket: the connection
# is given a writer that records lines, and the session a hub that records
# frames, which is all either of them talks to.

class FakeWriter:
    """Stands in for an asyncio.StreamWriter. Records each line with the time
    it was written; `stall` makes drain() never return, the way a socket to a
    server that stopped reading behaves."""

    def __init__(self, stall=False):
        self.lines = []
        self.stall = stall
        self._never = asyncio.Event()

    def write(self, data):
        self.lines.append((time.monotonic(), data.decode().rstrip("\r\n")))

    async def drain(self):
        if self.stall:
            await self._never.wait()

    def close(self):
        pass

    def sent(self):
        return [line for _, line in self.lines]


class RecordingHub:
    """What a session needs from a hub, recording what it was given."""

    def __init__(self):
        self.frames = []
        self.clients = set()
        self.pushed = []

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


def sender_tasks():
    return [t for t in asyncio.all_tasks() if t.get_name() == "irc-send" and not t.done()]


def test_decode_fallback():
    print("inbound decoding (G32)")
    from relay.ircproto import decode_line
    check("utf-8 stays utf-8", decode_line("café ✓".encode("utf-8")), "café ✓")
    # The bug: these came out as caf� and were stored that way for good.
    check("latin-1 is kept, not replaced",
          decode_line("café naïve Müller".encode("latin-1")), "café naïve Müller")
    check("cp1252 quotes, dashes and the euro sign are kept",
          decode_line("“quoted” – €5".encode("cp1252")), "“quoted” – €5")
    # 0x81 is undefined in cp1252; latin-1 takes any byte, so decoding never fails.
    check("a byte cp1252 does not define still decodes", decode_line(b"a\x81b"), "a\x81b")
    check("no replacement characters, ever",
          "�" in decode_line(b"\xff\xfe\x80 bytes"), False)
    # Per line: one old client's line does not change how the next is read.
    check("plain ascii", decode_line(b"PRIVMSG #c :hi"), "PRIVMSG #c :hi")


def test_flood_bucket():
    """A burst of FLOOD_BURST lines, then one every send_interval. And one
    sender, however many times the connection comes back (G01)."""
    print("flood limiter (G01)")
    from relay.ircconn import FLOOD_BURST, FLOOD_INTERVAL, IRCConnection

    check("burst is small", FLOOD_BURST <= 5, True)
    check("sustained pace is ircu's two seconds a line", FLOOD_INTERVAL >= 2.0, True)

    async def run():
        conn = IRCConnection(host="h", port=1, tls=False, nicks=["me"], username="u",
                             realname="r", on_message=None)
        conn.send_interval = 0.05          # the shape, not the wall-clock time
        writer = FakeWriter()
        conn._writer = writer
        await conn._start_sender(writer)
        # Registration is free: seven lines of CAP/PASS/NICK/USER/SASL before
        # 001 leave the whole burst for the joins after it.
        for line in ("CAP LS 302", "PASS x", "NICK me", "USER u 0 * r", "CAP REQ :sasl",
                     "AUTHENTICATE PLAIN", "AUTHENTICATE eA==", "CAP END"):
            await conn._write_now(line)
        conn._refill()
        check("registration lines spend no tokens", conn._tokens, float(FLOOD_BURST))
        writer.lines.clear()
        conn.registered = True
        for i in range(10):
            conn.send(f"PRIVMSG #c :line {i}")
        await asyncio.sleep(0.05 * 6 + 0.1)
        times = [t for t, _ in writer.lines]
        check("every line went out, in order",
              writer.sent(), [f"PRIVMSG #c :line {i}" for i in range(10)])
        check("the first four go out together", times[3] - times[0] < 0.02, True)
        gaps = [b - a for a, b in zip(times[3:], times[4:])]
        check("after the burst, one line per interval",
              all(g >= 0.05 * 0.8 for g in gaps), True)

        # Protocol replies bypass the queue but not the count: a PONG spends a
        # token, so the next queued line waits for it.
        writer.lines.clear()
        await asyncio.sleep(0.05 * FLOOD_BURST + 0.05)      # bucket refills
        for _ in range(FLOOD_BURST):
            await conn._write_now("PONG :x")
        conn.send("PRIVMSG #c :after the pongs")
        await asyncio.sleep(0.02)
        check("a line queued behind spent tokens waits", len(writer.sent()), FLOOD_BURST)
        await asyncio.sleep(0.08)
        check("and then goes", writer.sent()[-1], "PRIVMSG #c :after the pongs")

        # THE BUG: a sender per connection, none ever stopped. Starting one
        # stops the last, so there is only ever one.
        for _ in range(5):
            w = FakeWriter()
            conn._writer = w
            await conn._start_sender(w)
            check_one = len(sender_tasks())
        check("five reconnects leave exactly one sender", check_one, 1)
        await conn._stop_sender()
        check("stopping leaves none", len(sender_tasks()), 0)

    asyncio.run(run())


def test_join_batching():
    """The post-registration joins go out as few JOIN lines as fit."""
    print("join batching")
    from relay.ircproto import join_lines, targmax
    check("one line for a handful", join_lines(["#a", "#b", "#c"]), ["JOIN #a,#b,#c"])
    check("keyed channels first, keys in order",
          join_lines(["#a", "#k1", "#b", "#k2"], {"#k1": "s1", "#k2": "s2"}),
          ["JOIN #k1,#k2,#a,#b s1,s2"])
    check("TARGMAX=JOIN:2", join_lines(["#a", "#b", "#c", "#d", "#e"], max_targets=2),
          ["JOIN #a,#b", "JOIN #c,#d", "JOIN #e"])
    many = [f"#{'x' * 45}{i:02d}" for i in range(40)]
    lines = join_lines(many)
    check("no line past 510 bytes", max(len(l.encode()) for l in lines) <= 510, True)
    check("every channel once, in order",
          [c for l in lines for c in l.split()[1].split(",")], many)
    check("targmax read", [targmax("NAMES:1,JOIN:3,PRIVMSG:", "JOIN"),
                           targmax("PRIVMSG:4,JOIN:", "JOIN"), targmax(None, "JOIN")],
          [3, None, None])

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            conn = session.conn
            writer = FakeWriter()
            conn._writer, conn.registered, conn.connected = writer, True, True
            await conn._start_sender(writer)
            session._wanted_channels = ["#a", "#b", "#c", "#d", "#e", "#f"]
            session._joined_once = False
            await session._do_joins()
            await asyncio.sleep(0.05)
            check("six channels, one JOIN, sent at once",
                  [l for l in writer.sent() if l.startswith("JOIN")], ["JOIN #a,#b,#c,#d,#e,#f"])
            await conn._stop_sender()
            store.close()

    asyncio.run(run())


def test_reconnect_loop():
    """The real reconnect loop, with the network replaced: the sender count
    across many drops (G01), the backoff resetting after a healthy link (G11),
    and what happens to lines still queued when the link goes (G08)."""
    print("reconnect loop (G01, G11, G08)")
    from relay.ircconn import IRCConnection

    async def run(healthy: bool, drops: int):
        conn = IRCConnection(host="h", port=1, tls=False, nicks=["me"], username="u",
                             realname="r", on_message=None)
        attempts, senders_seen = [], []
        conn._backoff = lambda attempt: (attempts.append(attempt), 0.001)[1]
        fate = {"sent": [], "dropped": []}
        count = {"n": 0}

        async def fake_connect_once():
            count["n"] += 1
            writer = FakeWriter(stall=True)      # a line written is never confirmed
            conn._writer = writer
            conn.connected = True
            await conn._start_sender(writer)
            senders_seen.append(len(sender_tasks()))
            if healthy:
                conn._registered_at = time.monotonic() - 60   # up a minute, then gone
            else:
                conn._registered_at = None                     # refused every time
            if count["n"] == 1:
                for i in range(3):
                    conn.send(f"PRIVMSG #c :queued {i}",
                              on_sent=lambda i=i: fate["sent"].append(i),
                              on_dropped=lambda reason, i=i: fate["dropped"].append((i, reason)))
                await asyncio.sleep(0.02)
            if count["n"] >= drops:
                conn._stopping = True
            raise ConnectionError("dropped")

        conn._connect_once = fake_connect_once
        await conn._run_forever()
        return attempts, senders_seen, fate, len(sender_tasks())

    attempts, senders, fate, left = asyncio.run(run(healthy=False, drops=6))
    check("never more than one sender across six drops", max(senders), 1)
    check("no sender outlives the loop", left, 0)
    check("a link that never registers backs off further each time", attempts, [1, 2, 3, 4, 5])

    attempts, _, fate, _ = asyncio.run(run(healthy=True, drops=6))
    # THE BUG: this was 1, 2, 3, 4, 5 too -- a week-old link's first blip cost
    # as much as the fifth failure in a row.
    check("a healthy link that drops starts the backoff again", attempts, [1, 1, 1, 1, 1])

    check("nothing queued at the drop is claimed as sent", fate["sent"], [])
    check("every queued line is reported not sent",
          sorted(i for i, _ in fate["dropped"]), [0, 1, 2])
    check("with the reason", {r for _, r in fate["dropped"]}, {"connection lost"})


def make_session(tmp, hub=None, nick="me"):
    store = Store(os.path.join(tmp, "s.db"))
    hub = hub or RecordingHub()
    session = NetworkSession(
        NetworkConfig(slug="t", name="T", host="h", port=6667, nick=nick,
                      channels=["#config"]),
        store, hub)
    return store, hub, session


def test_say_echo_on_write():
    """The echo is a line that went out, not a line that was queued (G08), and
    a channel we are not in cannot be sent to (G07)."""
    print("say: echo on write, refusals (G07, G08)")
    import relay.session as session_module

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            conn = session.conn
            writer = FakeWriter()
            conn._writer, conn.registered, conn.connected = writer, True, True
            await conn._start_sender(writer)
            chan = store.get_or_create_buffer(session.network_id, "#c", "channel")
            store.set_joined(chan.id, True)

            # The ordinary case: the queue is empty, the line goes at once, and
            # the ok carries its echo exactly as it always did.
            event = await session.say(chan.id, "hello")
            check("the ok carries the echo", (event or {}).get("text"), "hello")
            check("the line was written", writer.sent()[-1], "PRIVMSG #c hello")
            echoes = [f["event"] for f in hub.of("event") if f["event"]["self"]]
            check("one echo, marked self", [(e["text"], e["self"]) for e in echoes],
                  [("hello", True)])

            # Behind a spent bucket: the ok comes back without an echo, and no
            # echo exists until the line is written.
            session_module.SAY_ECHO_WAIT = 0.05
            conn._tokens, conn.send_interval = 0.0, 100.0
            hub.frames.clear()
            event = await session.say(chan.id, "one\ntwo\nthree")
            check("queued: the ok has no echo yet", event, None)
            check("queued: nothing stored as said", hub.of("event"), [])

            # The link drops with them queued. They are said to be unsent, in
            # the conversation they were meant for, and never as said.
            await conn._stop_sender()
            conn._drop_queued("connection lost")
            events = [f["event"] for f in hub.of("event")]
            check("each queued line is surfaced as not sent",
                  [e["text"] for e in events],
                  ["Not sent (connection lost): one", "Not sent (connection lost): two",
                   "Not sent (connection lost): three"])
            check("in the buffer it was meant for", {e["buffer"] for e in events}, {chan.id})
            check("as a server line, not as something said",
                  {(e["kind"], e["self"]) for e in events}, {("server", False)})
            check("carrying the text on its own for a retry",
                  [e["extra"]["not_sent"] for e in events], ["one", "two", "three"])
            stored = [e for e in store.backlog(chan.id, limit=50) if e.self_]
            check("history holds only what was actually sent",
                  [e.text for e in stored], ["hello"])

            # A channel we are not in: refused in words, nothing stored, nothing sent.
            conn.send_interval = 0.02
            await conn._start_sender(writer)
            store.set_joined(chan.id, False)
            hub.frames.clear()
            sent_before = len(writer.sent())
            try:
                await session.say(chan.id, "anyone?")
                refused = None
            except ValueError as exc:
                refused = str(exc)
            check("say to a channel we left is refused", refused,
                  "You're not in #c. Rejoin to send.")
            check("and nothing was stored", hub.of("event"), [])
            await asyncio.sleep(0.05)
            check("and nothing was sent", len(writer.sent()), sent_before)

            # By name, to a channel with no buffer: refused without making one.
            try:
                await session.say(target="#nowhere", text="hi")
                refused = False
            except ValueError:
                refused = True
            check("say to an unknown channel by name is refused", refused, True)
            check("without leaving an empty buffer behind",
                  store.find_buffer(session.network_id, "#nowhere"), None)
            session_module.SAY_ECHO_WAIT = 0.5
            await conn._stop_sender()
            store.close()

    asyncio.run(run())


def test_membership_frames():
    """Our own part, kick and disconnect are TOLD to the clients (G07)."""
    print("membership frames (G07)")
    from relay.ircproto import parse_line

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            session.conn.nick = "me"
            await session.join("#c")          # not registered: only wanted

            def shape(frames):
                out = []
                for f in frames:
                    if f["type"] == "buffer":
                        out.append(("buffer", f["buffer"]["name"], f["buffer"]["joined"]))
                    elif f["type"] == "members":
                        out.append(("members", len(f["members"])))
                    elif f["type"] == "event":
                        out.append(("event", f["event"]["kind"]))
                return out

            await session._on_message(parse_line(":me!u@h JOIN #c"))
            check("our join announces joined:true",
                  shape(hub.frames)[:1], [("buffer", "#c", True)])
            await session._on_message(parse_line(":s 353 me = #c :me @alice"))
            await session._on_message(parse_line(":s 366 me #c :End"))
            bid = store.find_buffer(session.network_id, "#c").id

            hub.frames.clear()
            await session._on_message(parse_line(":alice!a@h KICK #c me :being loud"))
            check("a kick of us: buffer joined:false, empty members, then the kick",
                  shape(hub.frames),
                  [("buffer", "#c", False), ("members", 0), ("event", "kick")])
            kick = hub.of("event")[-1]["event"]
            check("the kicker is the sender", kick["from"], "alice")
            check("extra carries who was kicked and why", kick["extra"],
                  {"target": "me", "reason": "being loud"})
            check("the text is the reason, as before", kick["text"], "being loud")
            check("a kick does not remove the channel from the wanted list",
                  "#c" in session._wanted_channels, True)
            check("nor from the saved one", "#c" in store.networks()[0]["channels"], True)

            await session._on_message(parse_line(":me!u@h JOIN #c"))
            hub.frames.clear()
            await session._on_message(parse_line(":me!u@h PART #c :bye"))
            check("our part: buffer joined:false, empty members, then the part",
                  shape(hub.frames),
                  [("buffer", "#c", False), ("members", 0), ("event", "part")])

            # Someone else's kick changes the member list and nothing else.
            await session._on_message(parse_line(":me!u@h JOIN #c"))
            await session._on_message(parse_line(":bob!b@h JOIN #c"))
            hub.frames.clear()
            await session._on_message(parse_line(":alice!a@h KICK #c bob :spam"))
            check("someone else's kick keeps us joined",
                  [s for s in shape(hub.frames) if s[0] == "buffer"], [])

            # The upstream link drops: every channel we were in says so.
            other = store.get_or_create_buffer(session.network_id, "#d", "channel")
            store.set_joined(other.id, True)
            hub.frames.clear()
            await session._on_disconnected("connection lost")
            left = sorted((s[1], s[2]) for s in shape(hub.frames) if s[0] == "buffer")
            check("a disconnect sends joined:false for each joined channel",
                  left, [("#c", False), ("#d", False)])
            check("and an empty member list for each",
                  sorted(f["buffer"] for f in hub.of("members") if not f["members"]),
                  sorted([bid, other.id]))

            # Closing a channel parts it; the server's PART coming back must not
            # un-close it.
            store.set_joined(bid, True)
            session.conn.registered = True
            await session.close_buffer(bid)
            await session._on_message(parse_line(":me!u@h PART #c :closing"))
            check("the PART that closing sent does not reopen the channel",
                  store.buffer(bid).archived, True)
            check("closing a channel forgets it", "#c" in session._wanted_channels, False)

            # Closing one we were kicked from (nothing to part) forgets it too,
            # or the next reconnect would join it and reopen it.
            await session.join("#kicked")
            kicked = store.get_or_create_buffer(session.network_id, "#kicked", "channel")
            await session.close_buffer(kicked.id)
            check("closing a channel we were kicked from forgets it",
                  "#kicked" in session._wanted_channels, False)

            # Before the post-registration join burst (it waits for Q and the
            # cloak), a Rejoin only joins the list. Sending it at once would
            # carry the real host into the channel.
            sent = []
            session.conn.send_command = lambda *a, **k: sent.append(a)
            session._joined_once = False
            await session.join("#early")
            check("a join before the join burst is held for it", sent, [])
            check("and goes out with the burst", "#early" in session._wanted_channels, True)
            session._joined_once = True
            await session.join("#later")
            check("after the burst a join goes straight out", sent, [("JOIN", "#later")])
            store.close()

    asyncio.run(run())


def test_mode_parsing():
    print("mode parsing (G56)")
    from relay.ircproto import parse_chanmodes, parse_mode_changes
    check("groups", parse_chanmodes("b,k,l,imnpstrDducCNMT"),
          ("b", "k", "l", "imnpstrDducCNMT"))
    check("short spec is padded", parse_chanmodes("b"), ("b", "", "", ""))
    check("prefix and list modes take a parameter",
          parse_mode_changes("+ov-b", ["alice", "bob", "*!*@x"], "ov"),
          [("+", "o", "alice"), ("+", "v", "bob"), ("-", "b", "*!*@x")])
    # THE TRAP: +l takes a parameter only when set. Miscounting it shifts
    # every parameter after it, and the limit gets opped.
    check("a limit takes one only when set",
          parse_mode_changes("+l-l+o", ["10", "carol"], "ov"),
          [("+", "l", "10"), ("-", "l", None), ("+", "o", "carol")])
    check("a key takes one both ways",
          parse_mode_changes("+k-k", ["s3cret", "s3cret"], "ov"),
          [("+", "k", "s3cret"), ("-", "k", "s3cret")])
    check("flags take none", parse_mode_changes("+nt-m", [], "ov"),
          [("+", "n", None), ("+", "t", None), ("-", "m", None)])
    check("missing parameters are None, not an exception",
          parse_mode_changes("+oo", ["one"], "ov"), [("+", "o", "one"), ("+", "o", None)])


def test_member_deltas():
    """Joins, parts, kicks, quits, renames and prefix changes are one small
    frame each. A full list only after NAMES, and a mode storm queues no NAMES
    at all unless a change cannot be worked out locally (G56)."""
    print("member deltas (G56)")
    from relay.ircproto import parse_line

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            session.conn.nick = "me"
            session.conn.registered = True
            sent = []
            session.conn.send_command = lambda *a, **k: (sent.append(a), True)[1]

            async def say(line):
                await session._on_message(parse_line(line))

            await say(":s 005 me PREFIX=(ohv)@%+ CHANMODES=b,k,l,imnpst :are supported")
            await say(":me!u@h JOIN #c")
            await say(":s 353 me = #c :me @alice +bob carol")
            await say(":s 366 me #c :End")
            bid = store.find_buffer(session.network_id, "#c").id
            check("NAMES ends in one full list",
                  [len(f["members"]) for f in hub.of("members")], [4])

            hub.frames.clear()
            await say(":dave!d@h JOIN #c")
            await say(":carol!c@h PART #c :bye")
            await say(":alice!a@h KICK #c bob :spam")
            await say(":dave!d@h NICK :dan")
            await say(":alice!a@h QUIT :gone")
            deltas = [{k: v for k, v in f.items() if k != "buffer"} for f in hub.frames
                      if f["type"].startswith("member_")]
            check("each change is one delta", deltas, [
                {"type": "member_add", "member": {"nick": "dave", "prefix": "", "away": False}},
                {"type": "member_remove", "nick": "carol"},
                {"type": "member_remove", "nick": "bob"},
                {"type": "member_update", "nick": "dave", "new_nick": "dan"},
                {"type": "member_remove", "nick": "alice"},
            ])
            check("every delta names the buffer",
                  {f["buffer"] for f in hub.frames if f["type"].startswith("member_")}, {bid})
            check("and no full list was sent for any of them", hub.of("members"), [])
            check("the store agrees", sorted(m["nick"] for m in store.members(bid)), ["dan", "me"])
            # A delta precedes the event it explains, as the full list did.
            order = [f["type"] for f in hub.frames]
            check("the delta comes before its event",
                  order.index("member_add") < order.index("event"), True)

            # A mode storm: sixty people opped in sixty MODE lines, the shape of
            # Q auto-opping everyone after a netjoin.
            for i in range(60):
                await say(f":p{i}!u@h JOIN #c")
            hub.frames.clear()
            sent.clear()
            for i in range(60):
                await say(f":Q!TheQBot@CServe.quakenet.org MODE #c +o p{i}")
            check("a mode storm sends sixty deltas",
                  len([f for f in hub.of("member_update") if f.get("prefix") == "@"]), 60)
            check("and not one full list", hub.of("members"), [])
            check("and queues no NAMES", [a for a in sent if a[0] == "NAMES"], [])
            check("sixty mode events are still recorded", len(hub.of("event")), 60)
            check("everyone is an op in the store",
                  {m["prefix"] for m in store.members(bid) if m["nick"].startswith("p")}, {"@"})

            # A mixed line with a limit in front: the parameter must not shift.
            await say(":q!u@h JOIN #c")
            hub.frames.clear()
            await say(":alice!a@h MODE #c +lo 10 q")
            check("+lo 10 q ops q, not '10'",
                  [(f["nick"], f["prefix"]) for f in hub.of("member_update")], [("q", "@")])

            # A lower prefix given to an op shows nothing new; taking away the
            # one that shows is a guess, so it is sent AND NAMES is asked once.
            hub.frames.clear()
            sent.clear()
            await say(":alice!a@h MODE #c +v p1")
            check("voicing an op changes nothing visible", hub.of("member_update"), [])
            session.names_settle = 0.05
            await say(":alice!a@h MODE #c -o p1")
            await say(":alice!a@h MODE #c -o p2")
            check("deopping shows no prefix for now",
                  [(f["nick"], f["prefix"]) for f in hub.of("member_update")],
                  [("p1", ""), ("p2", "")])
            check("the NAMES waits for the burst to settle",
                  [a for a in sent if a[0] == "NAMES"], [])
            await asyncio.sleep(0.1)
            check("and asks NAMES once for the channel, not once per line",
                  [a for a in sent if a[0] == "NAMES"], [("NAMES", "#c")])
            hub.frames.clear()
            await say(":alice!a@h MODE #c +v p3")
            check("voicing an op is not a change", hub.of("member_update"), [])
            await say(":alice!a@h MODE #c +h p2")
            check("a halfop outranks nothing",
                  [(f["nick"], f["prefix"]) for f in hub.of("member_update")], [("p2", "%")])
            hub.frames.clear()
            await say(":alice!a@h MODE #c +b *!*@spam")
            await say(":alice!a@h MODE #c +o nobody")
            check("a ban or an unknown nick is no delta", hub.of("member_update"), [])

            # When the NAMES reply lands, the full list settles it.
            await say(":s 353 me = #c :me +p1 p2")
            await say(":s 366 me #c :End")
            check("NAMES still ends in a full list",
                  [len(f["members"]) for f in hub.of("members")], [3])
            store.close()

    asyncio.run(run())


def test_failure_words():
    print("connection failures in words (G19)")
    import socket
    import ssl
    from relay.ircconn import PingTimeout, describe_failure
    check("refused", describe_failure(ConnectionRefusedError(61, "Connect call failed")),
          "connection refused")
    check("dns", describe_failure(socket.gaierror(8, "nodename nor servname provided")),
          "DNS lookup failed")
    check("tls verify", describe_failure(ssl.SSLCertVerificationError(1, "certificate verify failed")),
          "TLS certificate did not verify")
    check("ping timeout", describe_failure(PingTimeout("no response to PING")), "ping timeout")
    check("connect timeout", describe_failure(asyncio.TimeoutError()), "connection timed out")
    check("a sentence stays a sentence",
          describe_failure(ConnectionError("server closed the connection")),
          "server closed the connection")
    # A name with an IPv6 and an IPv4 address (localhost, most networks):
    # asyncio's one OSError with every address's failure in its text.
    import errno
    refused = errno.ECONNREFUSED
    check("every address refused is still 'connection refused'",
          describe_failure(OSError(f"Multiple exceptions: [Errno {refused}] Connect call failed "
                                   f"('::1', 6750, 0, 0), [Errno {refused}] Connect call failed "
                                   "('127.0.0.1', 6750)")), "connection refused")
    check("mixed failures are said once",
          describe_failure(OSError(f"Multiple exceptions: [Errno {refused}] a, "
                                   f"[Errno {errno.EHOSTUNREACH}] b")),
          "could not reach any of the server's addresses")

    async def run():
        # The real reconnect loop against a port nobody is listening on: the
        # failure used to be logged and nothing else.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "s.db"))
            hub = RecordingHub()
            session = NetworkSession(NetworkConfig(slug="t", name="T", host="127.0.0.1",
                                                   port=port, nick="me"), store, hub)
            session.conn._backoff = lambda attempt: 0.05
            session.start()
            await asyncio.sleep(0.4)
            await session.stop()
            status = [e.text for e in store.backlog(session.status_buffer.id, limit=50)]
            check("a refused connection is said in the status buffer",
                  [t for t in status if "could not connect" in t],
                  [f"could not connect to 127.0.0.1:{port}: connection refused"])
            waiting = [f["network"] for f in hub.of("network") if f["network"]["next_retry_at"]]
            check("the network frame names the reason while waiting",
                  {n["last_error"] for n in waiting}, {"connection refused"})
            check("and when the next attempt is", all(n["next_retry_at"] > time.time() - 5
                                                        for n in waiting) and bool(waiting), True)
            check("several attempts, one line", len(waiting) > 2, True)
            store.close()

    asyncio.run(run())


def test_outage_lines():
    """Disconnected and Reconnected, once each per outage, in every channel we
    were in -- and a restart still owes the second (G19)."""
    print("outage lines (G19)")
    from relay.ircproto import parse_line

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            session.conn.nick = "me"
            for name in ("#a", "#b", "#left"):
                await session._on_message(parse_line(f":me!u@h JOIN {name}"))
            await session._on_message(parse_line(":me!u@h PART #left :bye"))
            a = store.find_buffer(session.network_id, "#a").id
            b = store.find_buffer(session.network_id, "#b").id
            left = store.find_buffer(session.network_id, "#left").id

            def lines(bid):
                return [(e.text, e.extra) for e in store.backlog(bid, limit=50)
                        if e.kind == "server"]

            reason = "Closing Link: me[127.0.0.1] (Excess Flood)"
            await session._on_disconnected(reason)
            check("each channel we were in says so, with the reason",
                  lines(a), [(f"Disconnected: {reason}",
                              {"connection": "lost", "reason": reason})])
            check("the same in the other", len(lines(b)), 1)
            check("a channel we had left says nothing", lines(left), [])
            # A retry that connected and dropped again before rejoining: no
            # channel is joined, so nothing more is written.
            await session._on_disconnected("connection refused")
            check("one line per outage, not one per retry", len(lines(a)), 1)

            await session._on_message(parse_line(":me!u@h JOIN #a"))
            check("the first rejoin says Reconnected",
                  lines(a)[-1], ("Reconnected", {"connection": "restored"}))
            await session._on_message(parse_line(":me!u@h PART #a"))
            await session._on_message(parse_line(":me!u@h JOIN #a"))
            check("and only the first", len(lines(a)), 2)

            # A restart: the stop wrote "Disconnected" last in #b, so the next
            # process still owes it its "Reconnected".
            from relay.session import NetworkSession
            again = NetworkSession(session.config, store, RecordingHub())
            again.conn.nick = "me"
            await again._on_message(parse_line(":me!u@h JOIN #b"))
            check("a restarted bouncer still closes the outage",
                  lines(b)[-1], ("Reconnected", {"connection": "restored"}))
            tail = store.backlog(b, limit=3)
            check("lost, restored, then our join tagged as the rejoin",
                  [(e.kind, (e.extra or {}).get("connection"), (e.extra or {}).get("rejoin"))
                   for e in tail[-3:]],
                  [("server", "lost", None), ("server", "restored", None), ("join", None, True)])
            check("a join that ends no outage is not tagged",
                  [e.extra for e in store.backlog(a, limit=50) if e.kind == "join"][-1], {})
            store.close()

    asyncio.run(run())


def test_error_routing():
    """Error numerics land in the conversation they are about (G18)."""
    print("error routing (G18)")
    from relay.ircproto import parse_line
    import relay.session as session_module

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            session.conn.nick = "me"
            session.conn.registered = True
            session._joined_once = True
            session.conn.send_command = lambda *a, **k: True
            await session._on_message(parse_line(":me!u@h JOIN #c"))
            chan = store.find_buffer(session.network_id, "#c")
            typo = store.get_or_create_buffer(session.network_id, "typo", "query")
            status = session.status_buffer.id

            def last(bid):
                e = store.backlog(bid, limit=1)[-1]
                return (e.kind, e.text, e.extra)

            await session.set_topic(chan.id, "new topic")
            await session._on_message(parse_line(":s 482 me #c :You're not channel operator"))
            check("482 lands in the channel, not the status buffer",
                  last(chan.id), ("server", "You're not channel operator", {"numeric": "482"}))

            await session._on_message(parse_line(":s 401 me typo :No such nick/channel"))
            check("401 for a nick lands in its query",
                  last(typo.id), ("server", "No such nick/channel", {"numeric": "401"}))

            await session.set_nick("alice", origin=chan.id)
            await session._on_message(parse_line(":s 433 me alice :Nickname is already in use."))
            check("433 goes back to where /nick was typed",
                  last(chan.id), ("server", "alice: Nickname is already in use.",
                                  {"numeric": "433"}))

            await session.join("#secret", origin=typo.id)
            await session._on_message(parse_line(":s 473 me #secret :Cannot join channel (+i)"))
            check("a join refused for a channel with no buffer goes back to the asker",
                  last(typo.id), ("server", "#secret: Cannot join channel (+i)",
                                  {"numeric": "473"}))
            check("and makes no buffer for it",
                  store.find_buffer(session.network_id, "#secret"), None)

            # Past the memory, or with nothing asked: the status buffer, and
            # nothing is dropped -- 477 used to vanish entirely.
            session._recent_requests = {k: (v[0], v[1] - 60) for k, v in
                                        session._recent_requests.items()}
            await session._on_message(parse_line(":s 433 me bob :Nickname is already in use."))
            check("an old request no longer claims the reply",
                  last(status), ("server", "bob: Nickname is already in use.", {"numeric": "433"}))
            await session._on_message(parse_line(":s 477 me #elsewhere :You need a registered nick"))
            check("every 4xx is kept", last(status)[2], {"numeric": "477"})

            # 301 repeats after every line sent to someone away; once is enough.
            before = len(store.backlog(typo.id, limit=50))
            for _ in range(3):
                await session._on_message(parse_line(":s 301 me typo :gone fishing"))
            check("an away reply lands in the query once",
                  len(store.backlog(typo.id, limit=50)) - before, 1)
            check("saying who and why", last(typo.id)[1], "gone fishing")
            store.close()

    asyncio.run(run())


def test_notify_levels():
    """What pushes is the buffer's notify level; a mention no longer un-mutes
    a detached buffer; push_preview off keeps the text off the lock screen
    (G35)."""
    print("notify levels and push preview (G35)")
    from relay.ircproto import parse_line

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            session.conn.nick = "me"
            await session._on_message(parse_line(":me!u@h JOIN #c"))
            chan = store.find_buffer(session.network_id, "#c")
            check("a channel defaults to mentions", chan.notify, "mentions")

            async def line(text, target="#c", sender="bob"):
                hub.pushed.clear()
                await session._on_message(parse_line(f":{sender}!b@h PRIVMSG {target} :{text}"))
                return [(n.title, n.body) for n in hub.pushed]

            check("mentions: chatter does not push", await line("just chatting"), [])
            check("mentions: a mention does", await line("me: look"), [("#c", "bob: me: look")])
            query_push = await line("hello there", target="me")
            check("a query defaults to all, and pushes", query_push, [("bob", "hello there")])
            check("a query's notify says so",
                  store.find_buffer(session.network_id, "bob").notify, "all")

            await session.set_buffer_settings(chan.id, notify="all")
            check("all: chatter pushes", await line("just chatting"), [("#c", "bob: just chatting")])
            hub.pushed.clear()
            await session._on_message(parse_line(":carol!c@h JOIN #c"))
            check("all: a join does not", hub.pushed, [])

            await session.set_buffer_settings(chan.id, notify="none")
            check("none: not even a mention", await line("me: hello?"), [])
            await session.set_buffer_settings(chan.id, notify="mentions", pinned=True)
            check("pinned is kept", store.buffer(chan.id).pinned, True)
            check("and on the wire", store.buffer(chan.id).to_wire("t")["pinned"], True)

            # Muted: the mention still notifies, and it stays muted.
            await session.set_detached(chan.id, True)
            hub.frames.clear()
            check("a detached channel's mention still pushes", len(await line("me: ping")), 1)
            check("and it stays detached", store.buffer(chan.id).detached, True)
            check("no buffer frame un-mutes it",
                  [f["buffer"]["detached"] for f in hub.of("buffer")], [])

            store.set_setting("push_preview", False)
            check("no preview: a channel says where, not what",
                  await line("me: secret plans"), [("#c", "New message in #c")])
            check("no preview: a query says who, not what",
                  await line("the password is hunter2", target="me"),
                  [("bob", "Message from bob")])

            try:
                store.set_buffer_settings(chan.id, notify="loud")
                refused = False
            except ValueError:
                refused = True
            check("an unknown level is refused", refused, True)
            store.close()

    asyncio.run(run())


def test_topic_on_join():
    """332 then 333 is one buffer frame with who and when; a rejoin with the
    same topic sends only the JOIN's buffer frame (G39, the wave 1 leftover)."""
    print("topic on join (G39)")
    from relay.ircproto import parse_line

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            session.conn.nick = "me"

            async def join_burst():
                for raw in (":me!u@h JOIN #c",
                            ":s 332 me #c :frag on",
                            ":s 333 me #c morgan!~s@host 1758000000",
                            ":s 353 me = #c :me @morgan",
                            ":s 366 me #c :End"):
                    await session._on_message(parse_line(raw))

            await join_burst()
            frames = hub.of("buffer")
            check("first join: the JOIN, then one frame for the topic",
                  [(f["buffer"]["topic"], f["buffer"]["topic_by"], f["buffer"]["topic_at"])
                   for f in frames],
                  [(None, None, None), ("frag on", "morgan", 1758000000.0)])

            await session._on_message(parse_line(":me!u@h PART #c"))
            hub.frames.clear()
            await join_burst()
            check("a rejoin with the same topic sends the buffer frame once",
                  len(hub.of("buffer")), 1)

            await session._on_message(parse_line(":me!u@h PART #c"))
            hub.frames.clear()
            for raw in (":me!u@h JOIN #c", ":s 331 me #c :No topic is set",
                        ":s 353 me = #c :me", ":s 366 me #c :End"):
                await session._on_message(parse_line(raw))
            check("no topic now: the JOIN shows the old one, the end of the names clears it",
                  [f["buffer"]["topic"] for f in hub.of("buffer")], ["frag on", None])

            hub.frames.clear()
            before = time.time()
            await session._on_message(parse_line(":alice!a@h TOPIC #c :new one"))
            live = hub.of("buffer")[-1]["buffer"]
            check("a live change names who", (live["topic"], live["topic_by"]), ("new one", "alice"))
            check("and when", live["topic_at"] >= before, True)
            store.close()

    asyncio.run(run())


def test_highlight_words_owned():
    """config.json seeds the words; after that the database owns them."""
    print("highlight words in SQLite (G35)")
    from relay.ircproto import parse_line

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "s.db"))
            config = NetworkConfig(slug="t", name="T", host="h", nick="me",
                                   highlight_words=["pizza"])
            session = NetworkSession(config, store, RecordingHub())
            check("seeded from config", store.highlight_words(session.network_id), ["pizza"])
            session.set_highlight_words(["quake", "rail gun"])
            check("matched like the nick",
                  (session.highlighter.matches("anyone for QUAKE?"),
                   session.highlighter.matches("quakes are scary"),
                   session.highlighter.matches("\x02rail gun\x02 time")),
                  (True, False, True))
            # A restart with the same config.json: the database wins.
            again = NetworkSession(config, store, RecordingHub())
            check("the database's words survive a restart",
                  again.highlighter.words, ["quake", "rail gun"])
            check("pizza is no longer a mention", again.highlighter.matches("pizza time"), False)
            store.close()

    asyncio.run(run())


def test_mark_all_read():
    print("mark all read (G37)")
    with tempfile.TemporaryDirectory() as tmp:
        s = Store(os.path.join(tmp, "m.db"))
        a = s.upsert_network("a", "A", "h", 6667, False, "me")
        b = s.upsert_network("b", "B", "h", 6667, False, "me")
        ca = s.get_or_create_buffer(a, "#a", "channel")
        cb = s.get_or_create_buffer(b, "#b", "channel")
        closed = s.get_or_create_buffer(a, "#closed", "channel")
        for buf, net in ((ca, a), (cb, b), (closed, a)):
            for i in range(3):
                s.append_event(buffer_id=buf.id, network_id=net, kind="message",
                               sender="x", text=f"{i}")
        s.set_archived(closed.id, True)
        marks = s.mark_all_read(a)
        check("one network: its open buffers, to their newest",
              marks, [(ca.id, s.newest_eid(ca.id))])
        check("the other network is untouched", s.unread_counts()[cb.id]["unread"], 3)
        s.mark_all_read()
        check("all networks", s.unread_counts()[cb.id]["unread"], 0)
        s.close()


def test_away_persisted():
    """Away is saved, re-sent on every registration and survives a restart;
    auto-away marks you away when nobody is attached and never touches your
    own (G25)."""
    print("away, persisted and automatic (G25)")
    from relay.hub import Hub

    class NoPush:
        async def send(self, n, d): pass

    class FakeClient:
        presence, focused_buffer = "unknown", None

        def enqueue(self, data): pass

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "a.db"))
            hub = Hub(store, NoPush())
            config = NetworkConfig(slug="t", name="T", host="h", nick="me")
            session = NetworkSession(config, store, hub)
            hub.sessions["t"] = session
            sent = []
            session.conn.send_command = lambda *a, **k: (sent.append(a), True)[1]

            # Set while disconnected: kept, and sent once registered.
            await session.set_away("gone fishing")
            check("set while disconnected is kept", session.to_wire()["away"], "gone fishing")
            check("and nothing is sent yet", sent, [])
            session.conn.registered = True
            session.conn.nick = "me"
            await session._on_registered("me")
            check("registration re-sends it", sent[:1], [("AWAY", "gone fishing")])

            # A restart: a new session on the same database.
            again = NetworkSession(config, store, Hub(store, NoPush()))
            check("it survives a restart", again.to_wire()["away"], "gone fishing")
            await session.set_away("")
            check("clearing is saved too", store.network_away(session.network_id), None)
            check("with a bare AWAY", sent[-1], ("AWAY",))

            # Auto-away: off by default, so nothing happens.
            hub.auto_away_after = 0.05
            sent.clear()
            hub.start_idle_timer()
            await asyncio.sleep(0.1)
            check("auto_away off: nobody attached changes nothing", sent, [])

            store.set_setting("auto_away", True)
            hub.start_idle_timer()
            await asyncio.sleep(0.1)
            check("auto_away on: nobody attached marks away",
                  (sent, session.to_wire()["away"]), ([("AWAY", "Away")], "Away"))
            client = FakeClient()
            hub.add(client)
            check("a client attaching takes it back",
                  (sent[-1], session.to_wire()["away"]), (("AWAY",), None))

            # The user's own away is never replaced or cleared by it.
            await session.set_away("at lunch")
            sent.clear()
            hub.discard(client)
            await asyncio.sleep(0.1)
            check("an away you set is not replaced", (sent, session.to_wire()["away"]),
                  ([], "at lunch"))
            hub.add(client)
            check("nor cleared when you come back", (sent, session.to_wire()["away"]),
                  ([], "at lunch"))
            hub.discard(client)
            store.close()

    asyncio.run(run())


def test_raw_lines():
    """raw goes as typed, except what would hurt: more than one line, the
    registration commands, QUIT, a Q password in clear (G41)."""
    print("raw lines (G41)")

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            session.conn.nick = "me"
            session.conn.registered = True
            sent = []
            session.conn.send = lambda line, **k: (sent.append(line), True)[1]
            session.conn.send_command = lambda *a, **k: (sent.append(" ".join(a)), True)[1]

            async def refused(line):
                try:
                    await session.raw(line)
                except ValueError as exc:
                    return str(exc)
                return None

            for line in ("QUIT", "quit :bye", "PASS hunter2", "USER a 0 * :b", "CAP LS 302",
                         "AUTHENTICATE PLAIN",
                         "PRIVMSG #c :one\r\nQUIT", "PRIVMSG #c :a\x00b", "", "   ",
                         "PRIVMSG #c :" + "x" * 500):
                check(f"refused: {line[:40]!r}", (await refused(line)) is not None, True)
            check("QUIT says why", await refused("QUIT"),
                  "QUIT would disconnect the bouncer itself. Use the app to disconnect.")
            check("nothing refused was sent", sent, [])

            # A password typed to a service is no longer refused (G61): one
            # rule for every service, and it is the line's KEPT copy that is
            # cut down, never what is sent. A raw line keeps nothing at all.
            events_before = store.max_eid()
            for line in ("MODE #c +i", "PRIVMSG Q :HELLO", "PRIVMSG bob :\x01PING 123\x01",
                         ":me PRIVMSG #c :with a prefix", "WHO #c",
                         "PRIVMSG Q :AUTH quinn hunter2", "privmsg q@CServe.quakenet.org :auth quinn x",
                         "NOTICE Q :NEWPASS old new new", "PRIVMSG NickServ :IDENTIFY hunter2"):
                check(f"sent as is: {line!r}", (await refused(line), sent[-1] if sent else None),
                      (None, line))
            check("and nothing of a raw line is stored", store.max_eid(), events_before)

            # Commands that change what the bouncer keeps are kept in step.
            session._joined_once = False
            check("a JOIN before the join burst waits", await refused("JOIN #new"),
                  "Still connecting; try again in a moment.")
            session._joined_once = True
            await session.raw("JOIN #new,#other")
            check("a raw JOIN is wanted, so it comes back after a reconnect",
                  [c for c in session._wanted_channels if c in ("#new", "#other")], ["#new", "#other"])
            await session.raw("PART #new :bye")
            check("a raw PART is not", "#new" in session._wanted_channels, False)
            await session.raw("AWAY :brb")
            check("a raw AWAY is the away frame", (session.to_wire()["away"], sent[-1]),
                  ("brb", "AWAY brb"))
            session.conn.registered = False
            check("not connected is refused", await refused("MODE #c +i"),
                  "not connected to the network")
            store.close()

    asyncio.run(run())


def test_channel_list():
    print("channel list (G41)")
    from relay.ircproto import parse_line
    import relay.session as session_module

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            session.conn.nick = "me"
            session.conn.registered = True
            sent = []
            session.conn.send_command = lambda *a, **k: (sent.append(a), True)[1]

            async def feed(*lines):
                for line in lines:
                    await session._on_message(parse_line(line))

            future = session.list_channels("#quake*")
            check("LIST goes out with the mask", sent[-1], ("LIST", "#quake*"))
            try:
                session.list_channels()
                second = None
            except ValueError as exc:
                second = str(exc)
            check("one at a time", second, "A channel list is already on its way. Wait for it.")
            await feed(":s 321 me Channel :Users  Name",
                       ":s 322 me #small 3 :a small one",
                       ":s 322 me #big 250 :\x02the\x02 big one",
                       ":s 322 me #mid 40 :",
                       ":s 323 me :End of /LIST")
            channels, complete = await future
            check("most populated first, topics as sent",
                  channels, [{"name": "#big", "users": 250, "topic": "\x02the\x02 big one"},
                             {"name": "#mid", "users": 40, "topic": ""},
                             {"name": "#small", "users": 3, "topic": "a small one"}])
            check("complete", complete, True)
            status = [e.text for e in store.backlog(session.status_buffer.id, limit=20)]
            check("none of it lands in the status buffer", status, [])

            saved = session_module.LIST_MAX
            session_module.LIST_MAX = 2
            future = session.list_channels()
            await feed(*[f":s 322 me #c{i} {i} :t" for i in range(5)], ":s 323 me :End")
            channels, complete = await future
            check("capped to the biggest", [c["name"] for c in channels], ["#c4", "#c3"])
            check("and not complete", complete, False)
            session_module.LIST_MAX = saved

            future = session.list_channels()
            await feed(":s 263 me LIST :Server load is temporarily too heavy.")
            try:
                await future
                failed = None
            except ValueError as exc:
                failed = str(exc)
            check("a try-again is an error in words", failed, "Server load is temporarily too heavy.")

            session.list_timeout = 0.05
            future = session.list_channels()
            await feed(":s 322 me #partial 9 :t")
            channels, complete = await future
            check("a server that never ends it: what came, not complete",
                  ([c["name"] for c in channels], complete), (["#partial"], False))
            store.close()

    asyncio.run(run())


def test_invite_and_wallops():
    print("invites and wallops (G42)")
    from relay.ircproto import parse_line

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            session.conn.nick = "me"
            status = session.status_buffer.id

            await session._on_message(parse_line(":dave!d@host INVITE me :#secret"))
            e = store.backlog(status, limit=1)[-1]
            check("an invite is stored in the status buffer",
                  (e.kind, e.sender, e.text, e.extra, e.highlight),
                  ("invite", "dave", "invited you to #secret", {"channel": "#secret"}, True))
            check("it pushes like a mention",
                  [(n.title, n.body) for n in hub.pushed], [("T", "dave invited you to #secret")])
            check("it counts as unread there", store.unread_counts()[status],
                  {"unread": 1, "highlights": 1})
            check("and is in the mentions inbox", store.highlights(limit=1)[0].kind, "invite")
            events = [i for i, f in enumerate(hub.frames) if f["type"] == "event"]
            unread = [i for i, f in enumerate(hub.frames) if f["type"] == "unread"]
            check("the new counts go to every client right after it",
                  (bool(unread) and unread[-1] > events[-1],
                   unread and hub.frames[unread[-1]]["counts"][status]),
                  (True, {"unread": 1, "highlights": 1}))

            before = len(store.backlog(status, limit=50))
            await session._on_message(parse_line(":dave!d@host INVITE bob #secret"))
            check("someone else's invite is not ours", len(store.backlog(status, limit=50)), before)
            await session.set_ignored("dave", True)
            await session._on_message(parse_line(":dave!d@host INVITE me :#spam"))
            check("a blocked nick's invite is dropped", len(store.backlog(status, limit=50)), before)

            await session._on_message(parse_line(":oper!o@staff WALLOPS :maintenance at noon"))
            w = store.backlog(status, limit=1)[-1]
            check("a wallops is a notice in the status buffer",
                  (w.kind, w.sender, w.text, w.extra),
                  ("notice", "oper", "maintenance at noon", {"wallops": True}))

            # A CTCP reply: into the query with them if there is one.
            pal = store.get_or_create_buffer(session.network_id, "pal", "query")
            await session._on_message(parse_line(":pal!p@h NOTICE me :\x01PING 1758000000\x01"))
            r = store.backlog(pal.id, limit=1)[-1]
            check("a CTCP reply is a notice from them, in the query",
                  (r.kind, r.sender, r.text, r.extra),
                  ("notice", "pal", "CTCP PING reply: 1758000000",
                   {"ctcp": "PING", "reply": "1758000000"}))
            await session._on_message(parse_line(
                ":stranger!s@h NOTICE me :\x01VERSION irssi 1.4\x01"))
            r = store.backlog(status, limit=1)[-1]
            check("with no query, in the status buffer",
                  (r.kind, r.sender, r.extra), ("notice", "stranger",
                                                {"ctcp": "VERSION", "reply": "irssi 1.4"}))
            sent = []
            session.conn.send_command = lambda *a, **k: (sent.append(a), True)[1]
            await session._on_message(parse_line(":pal!p@h NOTICE me :\x01PING 1\x01"))
            check("and a CTCP reply is never answered", sent, [])
            check("nor pushed", [n for n in hub.pushed if "CTCP" in n.body], [])
            store.close()

    asyncio.run(run())


def test_wanted_channels():
    """/join and /part survive a restart; the file's own changes still apply (G10)."""
    print("wanted channels (G10)")
    from relay.app import merge_wanted_channels as merge

    check("first start is the file", merge([], [], ["#a", "#b"]), ["#a", "#b"])
    check("a client join survives a restart",
          merge(["#a", "#b", "#joined"], ["#a", "#b"], ["#a", "#b"]), ["#a", "#b", "#joined"])
    # THE BUG: a file channel you parted came back on every deploy.
    check("a file channel you parted stays parted",
          merge(["#a"], ["#a", "#b"], ["#a", "#b"]), ["#a"])
    check("a channel added to the file is joined",
          merge(["#a"], ["#a"], ["#a", "#new"]), ["#a", "#new"])
    check("a channel removed from the file is left",
          merge(["#a", "#b"], ["#a", "#b"], ["#a"]), ["#a"])
    check("names compare as IRC compares them",
          merge(["#Quake[3]"], ["#quake{3}"], ["#QUAKE[3]"]), ["#Quake[3]"])
    check("an upgrade from before this was saved changes nothing",
          merge(["#a", "#b"], [], ["#a", "#b"]), ["#a", "#b"])

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            await session.join("#fromphone")
            await session.part("#config")
            saved = store.networks()[0]["channels"]
            check("join and part are written through", saved, ["#fromphone"])
            store.close()

    asyncio.run(run())


def test_unread_rules():
    print("unread counts (G16)")

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            nid = session.network_id
            chan = store.get_or_create_buffer(nid, "#c", "channel")
            store.append_event(buffer_id=chan.id, network_id=nid, kind="message",
                               sender="me", text="mine", self_=True)
            check("our own lines are not unread", store.unread_counts()[chan.id],
                  {"unread": 0, "highlights": 0})
            store.append_event(buffer_id=chan.id, network_id=nid, kind="message",
                               sender="alice", text="theirs")
            check("theirs are", store.unread_counts()[chan.id]["unread"], 1)

            zed = store.get_or_create_buffer(nid, "zed", "query")
            store.append_event(buffer_id=zed.id, network_id=nid, kind="message",
                               sender="zed", text="me: question", highlight=True)
            check("a mention counts", store.unread_counts()[zed.id],
                  {"unread": 1, "highlights": 1})
            store.set_archived(zed.id, True)
            # Listed at zero rather than omitted, so a client merging counts
            # clears the badge it already has.
            check("an archived buffer counts nothing", store.unread_counts()[zed.id],
                  {"unread": 0, "highlights": 0})
            store.set_archived(zed.id, False)

            await session.close_buffer(zed.id)
            check("closing marks it read", store.buffer(zed.id).last_seen_eid,
                  store.newest_eid(zed.id))
            check("and tells every client", [f["eid"] for f in hub.of("read_marker")],
                  [store.newest_eid(zed.id)])
            # Reopened by someone speaking: only the new line counts.
            store.get_or_create_buffer(nid, "zed", "query")
            store.append_event(buffer_id=zed.id, network_id=nid, kind="message",
                               sender="zed", text="again")
            check("reopened, only what is new counts", store.unread_counts()[zed.id],
                  {"unread": 1, "highlights": 0})
            store.close()

    asyncio.run(run())


def test_typing():
    """IRCv3 +typing: a client's `typing` becomes a debounced TAGMSG, and
    someone else's TAGMSG becomes a `typing` frame that nothing stores."""
    print("typing notifications (+typing over TAGMSG)")

    m = parse_line("@+typing=active :bob!u@h TAGMSG #c")
    check("a client-only tag keeps its plus", m.tags, {"+typing": "active"})
    check("TAGMSG is the command", m.command, "TAGMSG")
    check("with its target and no text", (m.params, m.prefix.nick), (["#c"], "bob"))
    m = parse_line("@time=2026-09-23T10:00:00.000Z;+typing=paused :bob!u@h TAGMSG me")
    check("beside a server tag", (m.tags.get("+typing"), m.tags.get("time")),
          ("paused", "2026-09-23T10:00:00.000Z"))

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            nid = session.network_id
            conn = session.conn
            writer = FakeWriter()
            conn._writer, conn.registered, conn.connected = writer, True, True
            # A bucket that refills at once, so `spare` is about the queue.
            conn.send_interval = 0.001
            await conn._start_sender(writer)
            chan = store.get_or_create_buffer(nid, "#c", "channel")
            store.set_joined(chan.id, True)

            async def typed(state, buffer_id=chan.id):
                queued = session.send_typing(buffer_id, state)
                await asyncio.sleep(0.03)
                return queued

            # --- out: the debounce -------------------------------------------
            check("nothing without message-tags", await typed("active"), False)
            check("  and nothing written", writer.sent(), [])
            conn.caps.add("message-tags")
            check("the first active goes", await typed("active"), True)
            check("  as a TAGMSG with the tag", writer.sent()[-1], "@+typing=active TAGMSG #c")
            check("a second within three seconds does not", await typed("active"), False)
            session._typing_sent[fold("#c")] -= 3.1
            check("one after three seconds does", await typed("active"), True)
            check("done goes once", await typed("done"), True)
            check("  as done", writer.sent()[-1], "@+typing=done TAGMSG #c")
            check("and not twice", await typed("done"), False)
            check("paused with nothing owed is nothing", await typed("paused"), False)
            await typed("active")
            check("paused after an active goes as paused",
                  (await typed("paused"), writer.sent()[-1]),
                  (True, "@+typing=paused TAGMSG #c"))
            check("  and owes no done after it", await typed("done"), False)
            check("an unknown state is nothing", await typed("thinking"), False)
            check("the Server buffer is nothing", await typed("active", session.status_buffer.id),
                  False)
            store.set_joined(chan.id, False)
            check("a channel we left is nothing", await typed("active"), False)
            store.set_joined(chan.id, True)

            # A line said is the end of the typing: nothing is owed after it.
            await typed("active")
            await session.say(chan.id, "hello")
            await asyncio.sleep(0.03)
            check("the message went", writer.sent()[-1], "PRIVMSG #c hello")
            check("no done after a message", await typed("done"), False)

            # No room to spare: never ahead of somebody's line.
            before = len(writer.sent())
            conn._tokens, conn.send_interval = 0.0, 100.0
            check("with the bucket spent, nothing", await typed("active"), False)
            check("  and nothing written", len(writer.sent()), before)
            conn.send_interval = 0.001

            # --- in: relayed, never stored -----------------------------------
            unread_before = store.unread_counts()
            newest_before = store.newest_eid(chan.id)
            hub.frames.clear()
            await session._on_message(parse_line("@+typing=active :bob!u@h TAGMSG #c"))
            await session._on_message(parse_line("@+typing=paused :bob!u@h TAGMSG #c"))
            await session._on_message(parse_line("@+typing=done :bob!u@h TAGMSG #c"))
            check("active, and paused and done both as done",
                  hub.of("typing"),
                  [{"type": "typing", "buffer": chan.id, "nick": "bob", "state": "active"},
                   {"type": "typing", "buffer": chan.id, "nick": "bob", "state": "done"},
                   {"type": "typing", "buffer": chan.id, "nick": "bob", "state": "done"}])
            check("nothing else was sent", {f["type"] for f in hub.frames}, {"typing"})
            check("nothing stored", store.newest_eid(chan.id), newest_before)
            check("nothing unread", store.unread_counts(), unread_before)

            hub.frames.clear()
            await session._on_message(parse_line(f"@+typing=active :{session.nick}!u@h TAGMSG #c"))
            await session._on_message(parse_line("@+draft/react=x :bob!u@h TAGMSG #c"))
            await session._on_message(parse_line("@+typing=active :bob!u@h TAGMSG #elsewhere"))
            await session._on_message(parse_line(f"@+typing=active :carol!u@h TAGMSG {session.nick}"))
            check("not ourselves, not another tag, not a channel we are not in, "
                  "and typing opens no query", hub.frames, [])
            check("  no buffer made for carol", store.find_buffer(nid, "carol"), None)

            carol = store.get_or_create_buffer(nid, "carol", "query")
            await session._on_message(parse_line(f"@+typing=active :carol!u@h TAGMSG {session.nick}"))
            check("in an open query it is relayed", hub.of("typing"),
                  [{"type": "typing", "buffer": carol.id, "nick": "carol", "state": "active"}])

            await conn._stop_sender()
            store.close()

    asyncio.run(run())


def test_client_queue():
    """A client that stops reading stops only itself (G02)."""
    print("per-client outbound queue (G02)")
    import relay.gateway as gw
    from relay.hub import Hub

    class FakeWS:
        def __init__(self, stall=False):
            self.stall = stall
            self.sent = []
            self.closed_with = None
            self._never = asyncio.Event()

        async def send_str(self, data):
            if self.stall:
                await self._never.wait()
            self.sent.append(data)

        async def close(self, code, message=b""):
            self.closed_with = (code, message)
            if self.stall:
                await self._never.wait()      # never answers the close either

    class FakeTransport:
        aborted = False

        def abort(self):
            self.aborted = True

    class NoPush:
        async def send(self, n, d): pass

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "q.db"))
            hub = Hub(store, NoPush())
            saved = (gw.CLIENT_SEND_TIMEOUT, gw.CLIENT_CLOSE_GRACE, gw.CLIENT_QUEUE_MAX,
                     gw.CLIENT_QUEUE_SOFT)
            gw.CLIENT_SEND_TIMEOUT, gw.CLIENT_CLOSE_GRACE = 0.2, 0.1

            live_ws, stuck_ws, transport = FakeWS(), FakeWS(stall=True), FakeTransport()
            live = gw.Client(live_ws, 1, hub)
            stuck = gw.Client(stuck_ws, 1, hub, transport=transport)
            for c in (live, stuck):
                c.start()
                hub.add(c)

            # THE BUG: broadcast awaited every client's socket, so this loop sat
            # on the stalled one and the IRC read loop that calls it stopped.
            started = time.monotonic()
            for i in range(2000):
                await hub.broadcast({"type": "event", "n": i, "pad": "z" * 400})
            check("broadcasting past a stalled client never waits on it",
                  time.monotonic() - started < 0.5, True)
            for _ in range(100):
                if len(live_ws.sent) == 2000:
                    break
                await asyncio.sleep(0.02)
            numbers = [int(s.split('"n":')[1].split(",")[0]) for s in live_ws.sent]
            check("the live client got everything, in order", numbers, list(range(2000)))

            await asyncio.sleep(0.5)
            check("the stalled client was closed as falling behind",
                  (stuck_ws.closed_with or (None,))[0], gw.CLOSE_FELL_BEHIND)
            check("and, since it would not take the close either, dropped",
                  transport.aborted, True)
            check("and detached from the hub", stuck in hub.clients, False)
            check("the live client is still attached", live in hub.clients, True)

            # A client that reads, but too slowly, overflows its queue instead.
            gw.CLIENT_QUEUE_MAX, gw.CLIENT_QUEUE_SOFT = 20_000, 10_000
            slow_ws = FakeWS(stall=True)
            slow = gw.Client(slow_ws, 1, hub, transport=FakeTransport())
            slow.start()
            hub.add(slow)
            for i in range(100):
                hub.publish({"type": "event", "n": i, "pad": "z" * 400})
            await asyncio.sleep(0.05)
            check("overflowing the queue closes the client",
                  (slow_ws.closed_with or (None,))[0], gw.CLOSE_FELL_BEHIND)
            check("and frees what it held", slow.queued_bytes, 0)

            (gw.CLIENT_SEND_TIMEOUT, gw.CLIENT_CLOSE_GRACE, gw.CLIENT_QUEUE_MAX,
             gw.CLIENT_QUEUE_SOFT) = saved
            for c in (live, stuck, slow):
                await c.finish()
            store.close()

    asyncio.run(run())


def test_token_revocation():
    """A revoked token loses its devices and its live sockets (G06)."""
    print("token revocation (G06)")
    import relay.gateway as gw
    from relay.config import Config
    from relay.hub import Hub

    class NoPush:
        async def send(self, n, d): pass

    class FakeClient:
        def __init__(self, token_id):
            self.token_id = token_id
            self.id = token_id
            self.presence, self.focused_buffer = "unknown", None
            self.closed_with = None

        def enqueue(self, data): pass

        async def close(self, code, reason):
            self.closed_with = (code, reason)

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "t.db"))
            keep = store.verify_token(store.create_token("phone"))
            lost = store.verify_token(store.create_token("lost phone"))
            store.register_device(keep, "aa" * 32, "ios", "sandbox")
            store.register_device(lost, "bb" * 32, "ios", "production")
            check("both devices get pushes while both tokens are good",
                  sorted(d["apns_token"] for d in store.devices()), ["aa" * 32, "bb" * 32])

            # Revoked in another process: only the database changes.
            other = Store(store.path)
            other.revoke_token(lost)
            other.close()
            check("a revoked token's device gets no push",
                  [d["apns_token"] for d in store.devices()], ["aa" * 32])
            check("and its row is gone, not just hidden",
                  store.db.execute("SELECT COUNT(*) AS c FROM devices WHERE token_id=?",
                                   (lost,)).fetchone()["c"], 0)
            check("token_active sees the revoke", store.token_active(lost), False)
            check("and not the other one", store.token_active(keep), True)

            # A device row left over from before (revoked some other way) is
            # still never pushed to.
            store.db.execute("INSERT INTO devices (token_id, apns_token, platform,"
                             " environment, updated_at) VALUES (?,?,?,?,0)",
                             (lost, "cc" * 32, "ios", "sandbox"))
            check("a leftover row under a revoked token is filtered out",
                  [d["apns_token"] for d in store.devices()], ["aa" * 32])

            hub = Hub(store, NoPush())
            gateway = gw.Gateway(Config(db_path=store.path), store, hub)
            good, bad = FakeClient(keep), FakeClient(lost)
            hub.add(good)
            hub.add(bad)
            closed = await gateway.close_revoked_clients()
            check("the sweep closes the revoked socket", bad.closed_with,
                  (gw.CLOSE_REVOKED, "token revoked"))
            check("with 1008", gw.CLOSE_REVOKED, 1008)
            check("and only that one", (closed, good.closed_with), (1, None))

            # Sign-out removes only the signing-out token's own row.
            check("unregister removes our own device",
                  store.unregister_device(keep, "aa" * 32), True)
            store.register_device(keep, "dd" * 32, "ios", "sandbox")
            check("unregister cannot remove another token's device",
                  store.unregister_device(lost, "dd" * 32), False)
            store.close()

    asyncio.run(run())


# --- wave 4: networks, CAP/SASL, redaction, hardening (G58-G62, G77, G78) ------

class ScriptedServer:
    """A real TCP server on an ephemeral port that answers each line it reads
    with whatever `respond(line)` returns. For IRCConnection's registration
    paths, which need a socket but not a whole IRC server."""

    def __init__(self, respond):
        self.respond = respond
        self.lines: list[str] = []
        self.writer = None

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def _handle(self, reader, writer):
        self.writer = writer
        while True:
            raw = await reader.readline()
            if not raw:
                break
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            self.lines.append(line)
            for out in self.respond(line) or []:
                writer.write((out + "\r\n").encode())
            await writer.drain()

    def said(self, prefix):
        return [l for l in self.lines if l.startswith(prefix)]

    async def stop(self):
        self.server.close()
        if self.writer is not None:
            self.writer.close()


def plain_server(nick_refusals=None, cap_reply=None):
    """A server that registers on NICK+USER. `nick_refusals` maps a nick to
    the numeric refusing it; `cap_reply` is what it says to CAP (None: nothing
    at all, the way many ircu servers treat an unknown command before
    registration)."""
    state = {"nick": None}
    refusals = nick_refusals or {}

    def respond(line):
        words = line.split()
        if words[0] == "CAP":
            return [cap_reply] if cap_reply else []
        if words[0] == "NICK":
            nick = words[1]
            if nick in refusals:
                return [f":s {refusals[nick]} * {nick} :Nickname refused"]
            state["nick"] = nick
        if words[0] == "USER" or (words[0] == "NICK" and state.get("user")):
            state["user"] = True
            if state["nick"]:
                return [f":s 001 {state['nick']} :Welcome"]
        return []
    return respond


def cap_server(accounts=None, offered="server-time multi-prefix sasl=PLAIN,EXTERNAL echo-message"):
    """A server that holds registration until CAP END, the IRCv3 way, and
    checks SASL PLAIN against `accounts`."""
    import base64 as b64
    state = {"nick": None, "user": False, "held": False, "mech": None}
    accounts = accounts or {}

    def respond(line):
        words = line.split(" ")
        out = []
        if words[0] == "CAP" and words[1] == "LS":
            state["held"] = True
            out.append(f":s CAP * LS :{offered}")
        elif words[0] == "CAP" and words[1] == "REQ":
            want = line.split(" ", 2)[2].lstrip(":")
            out.append(f":s CAP * ACK :{want}")
        elif words[0] == "CAP" and words[1] == "END":
            state["held"] = False
        elif words[0] == "AUTHENTICATE" and words[1] in ("PLAIN", "EXTERNAL"):
            state["mech"] = words[1]
            out.append("AUTHENTICATE +")
        elif words[0] == "AUTHENTICATE":
            try:
                _, user, pw = b64.b64decode(words[1]).decode().split("\0")
            except Exception:
                user, pw = "", None
            if accounts.get(user) == pw:
                out += [f":s 900 * * {user} :You are now logged in as {user}",
                        ":s 903 * :SASL authentication successful"]
            else:
                out.append(":s 904 * :SASL authentication failed")
        elif words[0] == "NICK":
            state["nick"] = words[1]
        elif words[0] == "USER":
            state["user"] = True
        if state["nick"] and state["user"] and not state["held"] and not state.get("done"):
            state["done"] = True
            out.append(f":s 001 {state['nick']} :Welcome")
        return out
    return respond


async def register_against(respond, wait=5.0, **kwargs):
    """Connect an IRCConnection to a scripted server and wait up to `wait`
    for it to register. Returns (conn, server, registered). The backoff is
    made long, so a failed attempt is not retried inside the test."""
    from relay.ircconn import IRCConnection
    server = await ScriptedServer(respond).start()
    got = []

    async def on_message(msg):
        got.append(msg)
    options = {k: kwargs.pop(k) for k in list(kwargs) if k in (
        "register_timeout", "cap_timeout", "idle_ping_after", "pong_timeout")}
    conn = IRCConnection(host="127.0.0.1", port=server.port, tls=False,
                         nicks=kwargs.pop("nicks", ["me"]), username="u", realname="r",
                         on_message=on_message, **kwargs)
    for key, value in options.items():
        setattr(conn, key, value)
    conn._backoff = lambda attempt: 60.0
    conn.received = got
    conn.start()
    registered = await conn.wait_registered(timeout=wait)
    return conn, server, registered


def test_registration_paths():
    """CAP LS 302 first and nothing waits on it; SASL; PASS; nick walking;
    the registration deadline (G59, G61, G77)."""
    print("registration: CAP, SASL, PASS, nick walking (G59, G61, G77)")
    from relay.ircconn import NOT_ACCEPTED

    async def run():
        # A server that ignores CAP entirely: registration is exactly as fast
        # as before (no pause for a CAP reply that never comes).
        started = time.monotonic()
        conn, server, ok = await register_against(plain_server())
        check("no CAP reply: registers", ok, True)
        check("  with no wait for CAP", time.monotonic() - started < 1.0, True)
        check("  CAP LS 302 went first, then NICK and USER",
              [l.split()[0] for l in server.lines[:3]], ["CAP", "NICK", "USER"])
        check("  and no CAP END to a server that never spoke CAP", server.said("CAP END"), [])
        await conn.stop(); await server.stop()

        # snircd: 421 to CAP. Registers as before, and the 421 is not passed
        # on to become a line in the status buffer.
        conn, server, ok = await register_against(
            plain_server(cap_reply=":s 421 * CAP :Unknown command"))
        check("snircd's 421: registers", ok, True)
        check("  and the 421 is swallowed",
              [m.command for m in conn.received if m.command == "421"], [])
        await conn.stop(); await server.stop()

        # A CAP server, SASL PLAIN that works.
        conn, server, ok = await register_against(
            cap_server({"riley": "hunter2"}), sasl_mechanism="PLAIN",
            sasl_username="riley", sasl_password="hunter2")
        check("CAP + SASL: registers", ok, True)
        req = server.said("CAP REQ")
        check("  asks for what it wants and nothing else",
              req, ["CAP REQ :server-time multi-prefix sasl"])
        check("  AUTHENTICATE PLAIN then the payload",
              server.said("AUTHENTICATE")[:1], ["AUTHENTICATE PLAIN"])
        import base64 as b64
        payload = server.said("AUTHENTICATE ")[1].split()[1]
        check("  the payload is authcid NUL authcid NUL password",
              b64.b64decode(payload).decode(), "riley\0riley\0hunter2")
        check("  CAP END after 903", server.said("CAP END"), ["CAP END"])
        check("  caps recorded", conn.caps, {"server-time", "multi-prefix", "sasl"})
        check("  no error", conn.last_error, None)
        await conn.stop(); await server.stop()

        # SASL refused: registration carries on, last_error says so.
        conn, server, ok = await register_against(
            cap_server({"riley": "right"}), sasl_mechanism="PLAIN",
            sasl_username="riley", sasl_password="wrong")
        check("SASL refused: still registers", ok, True)
        check("  last_error says the login failed", conn.last_error, "SASL login failed")
        check("  the 904 reaches the session for the status buffer",
              [m.command for m in conn.received if m.command == "904"], ["904"])
        await conn.stop(); await server.stop()

        # SASL configured but the server does not speak CAP at all.
        conn, server, ok = await register_against(
            plain_server(), sasl_mechanism="PLAIN", sasl_username="riley", sasl_password="x")
        check("SASL with no CAP server: registers, and says the login did not happen",
              (ok, conn.last_error), (True, "SASL login failed"))
        await conn.stop(); await server.stop()

        # A server password goes before NICK, and is never logged.
        conn, server, ok = await register_against(plain_server(), password="secret pass")
        check("PASS before NICK", [l.split()[0] for l in server.lines[:4]],
              ["CAP", "PASS", "NICK", "USER"])
        check("  a password with a space is one parameter", server.said("PASS"),
              ["PASS :secret pass"])
        await conn.stop(); await server.stop()

        # 433 walks the alternatives, then nick_ (not random digits first).
        conn, server, ok = await register_against(
            plain_server({"me": "433", "me2": "433"}), nicks=["me", "me2"])
        check("433 twice: registers on the next nick", (ok, conn.nick), (True, "me_"))
        await conn.stop(); await server.stop()

        # 432 for every nick: gives up in the server's words, rather than
        # walking suffixes for ever (the hang).
        def all_refused(line):
            if line.startswith("NICK "):
                return [f":s 432 * {line.split()[1]} :Erroneous Nickname"]
            return []
        conn, server, ok = await register_against(all_refused, wait=1.0, nicks=["9lives"])
        check("432 for every nick: never registers", ok, False)
        check("  last_error is the server's refusal", conn.last_error,
              "9lives: Erroneous Nickname")
        check("  and it backs off to retry", conn.next_retry_at is not None, True)
        check("  after a bounded number of tries", len(server.said("NICK")) <= 7, True)
        await conn.stop(); await server.stop()

        # A server that accepts the connection and says nothing at all.
        conn, server, ok = await register_against(lambda line: [], wait=1.0,
                                                  register_timeout=0.5)
        check("silence: the registration deadline ends it", ok, False)
        check("  in words", conn.last_error, NOT_ACCEPTED)
        await conn.stop(); await server.stop()

        # A CAP server that never answers the REQ: CAP END goes anyway.
        responder = cap_server()

        def stalls(line):
            return [] if line.startswith("CAP REQ") else responder(line)
        conn, server, ok = await register_against(stalls, cap_timeout=0.3)
        check("a stalled CAP REQ: CAP END after the timeout, and it registers",
              (server.said("CAP END"), ok), (["CAP END"], True))
        await conn.stop(); await server.stop()

    asyncio.run(run())


def test_dead_link():
    """Ping after a quiet minute, drop after 30s with no answer (G78)."""
    print("dead link detection (G78)")
    from relay.ircconn import IDLE_PING_AFTER, PONG_TIMEOUT
    check("ping after 60s idle", IDLE_PING_AFTER, 60.0)
    check("drop 30s after an unanswered ping", PONG_TIMEOUT, 30.0)

    async def run():
        responder = plain_server()

        def no_pong(line):
            return [] if line.startswith("PING") else responder(line)
        conn, server, ok = await register_against(no_pong)
        conn.idle_ping_after, conn.pong_timeout = 0.2, 0.2
        # The read loop picks the new clocks up on its next wait.
        server.writer.write(b":s NOTICE me :wake up\r\n")
        await asyncio.sleep(1.2)
        check("pinged when idle", len(server.said("PING")) >= 1, True)
        check("and dropped when nothing came back", conn.last_error, "ping timeout")
        await conn.stop(); await server.stop()

    asyncio.run(run())


def test_wire_hygiene():
    """Nothing from IRC can end a line we write, and a server cannot grow the
    read buffer without limit (security pass, 2026-09-22)."""
    print("wire hygiene: no CR/LF/NUL out, bounded line in")
    from relay.ircconn import MAX_LINE_IN
    from relay.ircproto import encode_line

    check("a CR ends the line", encode_line("NOTICE bob :\x01PING 1\rQUIT :bye\x01"),
          b"NOTICE bob :\x01PING 1")
    check("so does a LF", encode_line("PONG :a\nJOIN #x"), b"PONG :a")
    check("and a NUL", encode_line("PRIVMSG #c :a\0b"), b"PRIVMSG #c :a")
    check("a clean line is untouched", encode_line("PRIVMSG #c :hi there"),
          b"PRIVMSG #c :hi there")

    async def run():
        conn, server, ok = await register_against(plain_server())
        check("registered", ok, True)
        # A CTCP PING whose argument hides a second command behind a bare CR,
        # and a server PING doing the same: both are echoed, neither may carry
        # the CR back out.
        server.writer.write(b":evil!e@h PRIVMSG me :\x01PING 7\rQUIT :owned\x01\r\n"
                            b"PING :tok\rJOIN #owned\r\n")
        # Two ordinary lines in one read still arrive as two.
        server.writer.write(b":s NOTICE me :one\r\n:s NOTICE me :two\r\n")
        await asyncio.sleep(0.5)
        check("no line we wrote has a CR in it",
              [l for l in server.lines if "\r" in l], [])
        check("the PONG went, cut at the CR", server.said("PONG"), ["PONG :tok"])
        check("two lines in one chunk are two messages",
              [m.params[-1] for m in conn.received if m.command == "NOTICE"][-2:],
              ["one", "two"])
        # A line with no end: the link is dropped once it passes the limit,
        # instead of the buffer growing until the process runs out of memory.
        server.writer.write(b"A" * (MAX_LINE_IN * 4))
        await asyncio.sleep(0.5)
        check("an endless line drops the link", "longer than" in (conn.last_error or ""), True)
        await conn.stop(); await server.stop()

    asyncio.run(run())


def test_input_bounds():
    """One frame cannot hold the event loop: a `say` too long to ever send and
    a search of thousands of words are refused before any work is done
    (security pass, 2026-09-22)."""
    print("input bounds: say and search")
    from relay.ircproto import MAX_SAY_TEXT
    from relay.store import MAX_SEARCH_CHARS, MAX_SEARCH_TERMS

    budget = say_budget("#c")
    started = time.monotonic()
    try:
        split_message("\U0001F600" * 1_000_000, budget)
        refused = False
    except ValueError:
        refused = True
    check("a 4 MB say is refused", refused, True)
    check("  at once", time.monotonic() - started < 0.5, True)
    check("the longest say that could ever be sent still splits",
          len(split_message("x " * (MAX_SAY_TEXT // 2), budget)) > 200, True)

    with tempfile.TemporaryDirectory() as tmp:
        s = Store(os.path.join(tmp, "b.db"))
        nid = s.upsert_network("n", "N", "h", 6667, False, "me")
        buf = s.get_or_create_buffer(nid, "#c", "channel")
        for i in range(50):
            s.append_event(buffer_id=buf.id, network_id=nid, kind="message",
                           sender="bob", text=f"c++ is a word {i}")

        def refused_search(query):
            started = time.monotonic()
            try:
                s.search(query)
                return False, time.monotonic() - started
            except ValueError:
                return True, time.monotonic() - started

        ok, took = refused_search(" ".join(["w"] * 20000))
        check("20000 words are refused", ok, True)
        check("  at once", took < 0.5, True)
        check(f"past {MAX_SEARCH_CHARS} characters is refused",
              refused_search("a" * (MAX_SEARCH_CHARS + 1))[0], True)
        check(f"more than {MAX_SEARCH_TERMS} words is refused",
              refused_search(" ".join(f"w{i}" for i in range(MAX_SEARCH_TERMS + 1)))[0], True)
        check("the same word many times is one word",
              len(s.search(" ".join(["c++"] * 30))), 50)
        check("an ordinary search is untouched", len(s.search("c++ word")), 50)
        s.close()


def test_auth_throttle():
    """The failed-token throttle: constant time per failure however many
    addresses fail, IPv6 counted by /64, and a ceiling for everyone together
    (security pass, 2026-09-22)."""
    print("auth throttle")
    from relay import gateway as gw
    from relay.config import Config
    from relay.hub import Hub

    class NoPush:
        async def send(self, notification, devices):
            pass

    check("IPv4 is its own bucket", gw._throttle_key("198.51.100.7"), "198.51.100.7")
    check("IPv6 counts by its /64",
          gw._throttle_key("2001:db8:1:2:aaaa::1"), gw._throttle_key("2001:db8:1:2:ffff::9"))
    check("  and a different /64 is a different bucket",
          gw._throttle_key("2001:db8:1:2::1") == gw._throttle_key("2001:db8:1:3::1"), False)
    check("a mapped IPv4 is the IPv4", gw._throttle_key("::ffff:198.51.100.7"), "198.51.100.7")

    with tempfile.TemporaryDirectory() as tmp:
        store = Store(os.path.join(tmp, "t.db"))
        gateway = gw.Gateway(Config(db_path=store.path), store, Hub(store, NoPush()))

        for _ in range(gw.AUTH_MAX_FAILURES):
            gateway._record_failure("198.51.100.7")
        check("ten failures throttle that address", gateway._rate_limited("198.51.100.7"), True)
        check("  and not its neighbour", gateway._rate_limited("198.51.100.8"), False)
        for i in range(gw.AUTH_MAX_FAILURES):
            gateway._record_failure(f"2001:db8:9:9::{i + 1:x}")
        check("ten failures across one /64 throttle all of it",
              gateway._rate_limited("2001:db8:9:9::beef"), True)

        # Thirty thousand addresses: the table stays bounded and a failure
        # costs the same at the end as at the start. It used to rebuild the
        # whole table on every failure past 4096.
        gateway._auth_failures.clear()

        def cost(start, n):
            t0 = time.perf_counter()
            for i in range(start, start + n):
                gateway._record_failure(f"2001:db8:{i >> 16:x}:{i & 0xffff:x}::1")
            return (time.perf_counter() - t0) / n

        early = cost(0, 2000)
        cost(2000, 26000)
        late = cost(28000, 2000)
        check("the table is bounded", len(gateway._auth_failures) <= gw.AUTH_TRACKED_MAX, True)
        check("a failure costs the same with 30000 addresses seen", late < early * 5 + 20e-6, True)
        check("past the global ceiling everyone without a token waits",
              gateway._rate_limited("192.0.2.200"), True)
        store.close()


def test_preview_requests_bounded():
    """One client can have at most MAX_PREVIEWS_PER_CLIENT link previews
    waiting; the count comes back down as they are answered (security pass,
    2026-09-22)."""
    print("link previews per client are bounded")
    from relay import gateway as gw
    from relay.config import Config
    from relay.hub import Hub

    class NoPush:
        async def send(self, notification, devices):
            pass

    class SlowPreviews:
        def __init__(self):
            self.release = asyncio.Event()

        async def preview(self, url):
            await self.release.wait()
            return {"title": "t"}

        async def close(self):
            pass

    class Client:
        closing = False
        previews_pending = 0

        def __init__(self):
            self.errors, self.sent = [], []

        async def error(self, req, message):
            self.errors.append(message)

        async def send(self, frame):
            self.sent.append(frame)

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "p.db"))
            gateway = gw.Gateway(Config(db_path=store.path, link_previews=False), store,
                                 Hub(store, NoPush()))
            gateway.previews = SlowPreviews()
            client = Client()
            extra = 7
            for i in range(gw.MAX_PREVIEWS_PER_CLIENT + extra):
                await gateway._dispatch(client, {"type": "link_preview", "req": f"r{i}",
                                                 "url": f"https://example.com/{i}"})
            await asyncio.sleep(0)
            check("the ones past the cap are refused", len(client.errors), extra)
            check("  and the rest wait", client.previews_pending, gw.MAX_PREVIEWS_PER_CLIENT)
            gateway.previews.release.set()
            await asyncio.sleep(0.1)
            check("answered, the count is back to nothing", client.previews_pending, 0)
            check("  and every one that waited was answered",
                  len([f for f in client.sent if f.get("type") == "link_preview"]),
                  gw.MAX_PREVIEWS_PER_CLIENT)
            store.close()

    asyncio.run(run())


def test_db_private():
    """The database and its -wal and -shm are the owner's alone, fresh or
    left behind at 0644 by an older bouncer (security pass, 2026-09-22)."""
    print("database file modes")
    import stat
    old_umask = os.umask(0o022)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            for name, before in (("fresh.db", None), ("old.db", 0o644)):
                path = os.path.join(tmp, name)
                if before is not None:
                    open(path, "w").close()
                    os.chmod(path, before)
                    open(path + "-wal", "w").close()
                    os.chmod(path + "-wal", before)
                s = Store(path)
                s.meta_set("probe", "x")
                modes = {suffix: stat.S_IMODE(os.stat(path + suffix).st_mode)
                         for suffix in ("", "-wal", "-shm") if os.path.exists(path + suffix)}
                s.close()
                check(f"{name}: owner only", {k: oct(v) for k, v in modes.items()},
                      {k: oct(0o600) for k in modes})
    finally:
        os.umask(old_umask)


def test_network_connect_controls():
    """connect_now cuts a backoff wait short; stop says why (G60)."""
    print("network on/off and reconnect now (G60)")
    from relay.ircconn import IRCConnection

    async def run():
        conn = IRCConnection(host="h", port=1, tls=False, nicks=["me"], username="u",
                             realname="r", on_message=None)
        attempts = []

        async def refused():
            attempts.append(time.monotonic())
            raise ConnectionRefusedError()
        conn._connect_once = refused
        conn._backoff = lambda attempt: 30.0          # a long wait
        conn.start()
        await asyncio.sleep(0.1)
        check("waiting out a backoff", (len(attempts), conn.next_retry_at is not None), (1, True))
        conn.connect_now()
        await asyncio.sleep(0.1)
        check("reconnect now does not wait", len(attempts), 2)
        await conn.stop("bye", reason="you turned this network off")
        check("stopped: not running, no countdown", (conn.running, conn.next_retry_at),
              (False, None))
        conn.connect_now()
        await asyncio.sleep(0.1)
        check("turned on again: it starts", (conn.running, len(attempts)), (True, 3))
        await conn.stop()

    asyncio.run(run())


def test_secret_redaction():
    """A password typed to a service is sent as typed and kept only as its
    verb: in the echo, in backlog, never in search (G61)."""
    print("secrets to services (G61)")
    from relay.ircproto import is_service, redact_line, redact_secret

    check("NickServ IDENTIFY", redact_secret("NickServ", "IDENTIFY hunter2"), "IDENTIFY ********")
    check("any case", redact_secret("nickserv", "identify acct hunter2"), "identify ********")
    check("Q AUTH", redact_secret("Q@CServe.quakenet.org", "AUTH quinn hunter2"), "AUTH ********")
    check("Q by its short name", redact_secret("Q", "auth quinn x"), "auth ********")
    check("SET PASSWORD keeps both words",
          redact_secret("NickServ", "SET PASSWORD newpw"), "SET PASSWORD ********")
    check("GHOST", redact_secret("NickServ", "GHOST me pw"), "GHOST ********")
    check("any *Serv", redact_secret("AuthServ", "AUTH me pw"), "AUTH ********")
    check("NickServ@services", redact_secret("NickServ@services.libera.chat", "IDENTIFY x"),
          "IDENTIFY ********")
    check("REGISTER, RECOVER, SETPASS, NEWPASS",
          [redact_secret("NickServ", f"{v} x y") for v in ("REGISTER", "RECOVER", "SETPASS")]
          + [redact_secret("Q", "NEWPASS a b b")],
          ["REGISTER ********", "RECOVER ********", "SETPASS ********", "NEWPASS ********"])
    check("not a secret verb", redact_secret("NickServ", "INFO quinn"), None)
    check("not a service", redact_secret("morgan", "IDENTIFY hunter2"), None)
    check("a channel is not a service", is_service("#hangout"), False)
    check("SET without PASSWORD is not a secret", redact_secret("NickServ", "SET EMAIL x"), None)
    check("the log line is cut too",
          redact_line("PRIVMSG NickServ :IDENTIFY hunter2"), "PRIVMSG NickServ :IDENTIFY ********")
    check("PASS is never logged", redact_line("PASS :my secret"), "PASS ********")
    check("nor a SASL payload", redact_line("AUTHENTICATE aHVnaABodWdoAHg="), "AUTHENTICATE ********")
    check("but AUTHENTICATE + is", redact_line("AUTHENTICATE +"), "AUTHENTICATE +")
    check("Anope's ID, LOGIN, RELEASE, REGAIN, GROUP, PASSWD, SAREGISTER",
          [redact_secret("NickServ", f"{v} a b") for v in
           ("ID", "id", "LOGIN", "RELEASE", "REGAIN", "GROUP", "PASSWD", "SAREGISTER")],
          ["ID ********", "id ********", "LOGIN ********", "RELEASE ********",
           "REGAIN ********", "GROUP ********", "PASSWD ********", "SAREGISTER ********"])
    check("Q's HELLO and CHALLENGEAUTH",
          [redact_secret("Q", "HELLO a@b.c a@b.c"), redact_secret("Q", "CHALLENGEAUTH quinn 0af3 x")],
          ["HELLO ********", "CHALLENGEAUTH ********"])
    check("SASET nick PASSWORD keeps three words",
          redact_secret("NickServ", "SASET bob PASSWORD x"), "SASET bob PASSWORD ********")
    check("old Anope SET #chan PASSWORD",
          redact_secret("ChanServ", "SET #c PASSWORD x"), "SET #c PASSWORD ********")
    check("IDLE is not ID", redact_secret("NickServ", "IDLE x"), None)
    check("NS alias in the wire log", redact_line("NS ID hunter2"), "NS ID ********")
    check("NICKSERV alias", redact_line("NICKSERV IDENTIFY acct pw"), "NICKSERV IDENTIFY ********")
    check("a bare IDENTIFY command", redact_line("IDENTIFY pw"), "IDENTIFY ********")
    check("OPER's password", redact_line("OPER riley pw"), "OPER riley ********")
    check("an ordinary NS line", redact_line("NS INFO quinn"), "NS INFO quinn")

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            conn = session.conn
            writer = FakeWriter()
            conn._writer, conn.registered, conn.connected = writer, True, True
            await conn._start_sender(writer)
            event = await session.say(target="NickServ", text="IDENTIFY hunter2")
            check("sent as typed", writer.sent()[-1], "PRIVMSG NickServ :IDENTIFY hunter2")
            check("echoed redacted", (event or {}).get("text"), "IDENTIFY ********")
            check("  and marked", (event or {}).get("extra"), {"redacted": True})
            buf = store.find_buffer(session.network_id, "NickServ")
            check("stored redacted", [e.text for e in store.backlog(buf.id)], ["IDENTIFY ********"])
            check("never found by search", store.search("hunter2") + store.search("IDENTIFY"), [])
            check("nor by a from: search",
                  [e.text for e in store.search("", sender=session.nick)], [])
            check("nothing anywhere holds the password",
                  store.db.execute("SELECT COUNT(*) FROM events WHERE text LIKE '%hunter2%'"
                                   " OR extra LIKE '%hunter2%'").fetchone()[0], 0)
            store.db.execute("INSERT INTO events_search(events_search) VALUES ('integrity-check')")
            check("the search index is intact", True, True)
            # nick@server: sent as typed, kept in the Server buffer, no query.
            event = await session.say(target="Q@CServe.quakenet.org", text="AUTH quinn pw")
            check("nick@server goes out as addressed",
                  writer.sent()[-1], "PRIVMSG Q@CServe.quakenet.org :AUTH quinn pw")
            check("  echoed into the Server buffer, saying where it went, redacted",
                  ((event or {}).get("buffer"), (event or {}).get("text"), (event or {}).get("extra")),
                  (session.status_buffer.id, "AUTH ********",
                   {"to": "Q@CServe.quakenet.org", "redacted": True}))
            check("  and no query was made for it",
                  store.find_buffer(session.network_id, "Q@CServe.quakenet.org"), None)
            # An ordinary line to the same service is kept as it is.
            event = await session.say(target="NickServ", text="INFO quinn")
            check("an ordinary line is untouched", (event or {}).get("text"), "INFO quinn")
            # Deleting a redacted row does not corrupt the index.
            store.db.execute("DELETE FROM events WHERE buffer_id=?", (buf.id,))
            store.db.execute("INSERT INTO events_search(events_search) VALUES ('integrity-check')")
            check("deleting it leaves the index intact", True, True)
            # Not sent: the secret is not kept for a retry either.
            import relay.session as session_module
            session_module.SAY_ECHO_WAIT = 0.05
            conn._tokens, conn.send_interval = 0.0, 100.0
            hub.frames.clear()
            await session.say(target="NickServ", text="IDENTIFY hunter3")
            await conn._stop_sender()
            conn._drop_queued("connection lost")
            dropped = [f["event"] for f in hub.of("event")]
            check("a secret that was not sent is not kept to be retried",
                  [(e["text"], e.get("extra")) for e in dropped],
                  [("Not sent (connection lost): IDENTIFY ********", {"redacted": True})])
            session_module.SAY_ECHO_WAIT = 0.5
            store.close()

    asyncio.run(run())


def test_secret_scrub_migration():
    """Lines stored before a verb was on the list are redacted once, and the
    search index stays intact."""
    print("stored secrets scrubbed once")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "s.db")
        store = Store(path)
        nid = store.upsert_network("t", "T", "h", 6667, False, "me")
        ns = store.get_or_create_buffer(nid, "NickServ", "query")
        q = store.get_or_create_buffer(nid, "Q@CServe.quakenet.org", "query")
        friend = store.get_or_create_buffer(nid, "friend", "query")
        add = functools.partial(store.append_event, network_id=nid, sender="me", self_=True)
        add(buffer_id=ns.id, kind="message", text="ID hunter2")
        add(buffer_id=ns.id, kind="message", text="INFO quinn")
        add(buffer_id=ns.id, kind="message", text="IDENTIFY ********", extra={"redacted": True})
        add(buffer_id=q.id, kind="message", text="HELLO a@b.c a@b.c")
        add(buffer_id=friend.id, kind="message", text="ID hunter2 is my password lol")
        store.append_event(buffer_id=ns.id, network_id=nid, kind="server",
                           text="Not sent (connection lost): LOGIN acct hunter3",
                           extra={"not_sent": "LOGIN acct hunter3"})
        store.append_event(buffer_id=ns.id, network_id=nid, kind="message", sender="NickServ",
                           text="Password accepted")
        store.db.execute("DELETE FROM meta WHERE key='secret_scrub'")
        store.close()
        store = Store(path)
        texts = [(r["text"], r["extra"]) for r in store.db.execute(
            "SELECT text, extra FROM events ORDER BY eid")]
        check("scrubbed, the rest untouched", texts, [
            ("ID ********", '{"redacted": true}'), ("INFO quinn", None),
            ("IDENTIFY ********", '{"redacted": true}'), ("HELLO ********", '{"redacted": true}'),
            ("ID hunter2 is my password lol", None),
            ("Not sent (connection lost): LOGIN ********", '{"redacted": true}'),
            ("Password accepted", None)])
        check("gone from search", [e.text for e in store.search("hunter2")],
              ["ID hunter2 is my password lol"])
        check("nor a.b.c", [e.text for e in store.search("a@b.c")], [])
        store.db.execute("INSERT INTO events_search(events_search) VALUES ('integrity-check')")
        store.db.execute("DELETE FROM events")
        store.db.execute("INSERT INTO events_search(events_search) VALUES ('integrity-check')")
        check("the index survives the scrub and a delete after it", True, True)
        store.close()


def test_unread_cache():
    """unread_counts keeps its counts between calls; they must always equal a
    count from scratch, whatever happened in between."""
    print("unread counts kept between calls")
    import random
    rng = random.Random(7)

    def from_scratch(store):
        rows = store.db.execute(
            "SELECT b.id AS bid, b.detached AS detached, b.archived AS archived,"
            " COUNT(e.eid) AS total, COALESCE(SUM(e.highlight), 0) AS highlights"
            " FROM buffers b LEFT JOIN events e ON e.buffer_id = b.id"
            " AND e.eid > b.last_seen_eid AND e.kind IN ('message', 'action', 'notice', 'invite')"
            " AND e.self = 0 GROUP BY b.id")
        return {r["bid"]: {"unread": 0 if (r["detached"] or r["archived"]) else r["total"],
                           "highlights": 0 if r["archived"] else r["highlights"]} for r in rows}

    with tempfile.TemporaryDirectory() as tmp:
        store = Store(os.path.join(tmp, "u.db"))
        nid = store.upsert_network("t", "T", "h", 6667, False, "me")
        bufs = [store.get_or_create_buffer(nid, f"#c{i}", "channel") for i in range(4)]
        bufs.append(store.get_or_create_buffer(nid, "friend", "query"))
        wrong = 0
        for step in range(600):
            op = rng.random()
            buf = rng.choice(bufs)
            if op < 0.6:
                store.append_event(buffer_id=buf.id, network_id=nid,
                                   kind=rng.choice(["message", "join", "notice", "invite"]),
                                   sender="x", text="hi", self_=rng.random() < 0.1,
                                   highlight=rng.random() < 0.2)
            elif op < 0.75:
                newest = store.newest_eid(buf.id)
                store.mark_read(buf.id, rng.randint(0, newest) if newest else 0)
            elif op < 0.82:
                store.set_detached(buf.id, rng.random() < 0.5)
            elif op < 0.88:
                store.set_archived(buf.id, rng.random() < 0.5)
            elif op < 0.92:
                store.clear_events(buf.id, chunk=rng.randint(1, 5))
            elif op < 0.94 and len(bufs) > 2:
                src = bufs.pop()
                store.merge_buffers(src.id, bufs[0].id)
            if rng.random() < 0.5 and store.unread_counts() != from_scratch(store):
                wrong += 1
        check("kept counts equal a count from scratch, 600 random steps", wrong, 0)
        check("and at the end", store.unread_counts(), from_scratch(store))
        store.close()


def test_background_queue_bounded():
    """On a link too busy to send background lines, a newer presence poll
    replaces the older one's ISONs instead of adding to them."""
    print("background queue bounded")
    with tempfile.TemporaryDirectory() as tmp:
        store, hub, session = make_session(tmp)
        session.conn.registered = True           # and never spare: nothing drains
        sizes = []
        for i in range(120):
            store.get_or_create_buffer(session.network_id, f"friend{i}", "query")
            session._poll_presence()
            sizes.append(len(session._background))
        names = sorted((f"friend{i}" for i in range(120)), key=str.lower)
        queued = [n for _, command, params, _ in session._background for n in params[0].split()]
        check("the queue holds only the newest poll", max(sizes) <= 4, True)
        check("  and it asks about everyone, once", queued, names)
        store.close()


def test_server_time():
    """server-time's @time is when the stored event happened (G77)."""
    print("server-time (G77)")
    from relay.ircproto import parse_server_time
    check("parsed", parse_server_time("2020-01-02T03:04:05.250Z"), 1577934245.25)
    check("no fraction", parse_server_time("2020-01-02T03:04:05Z"), 1577934245.0)
    check("garbage", parse_server_time("yesterday"), None)
    check("absent", parse_server_time(None), None)

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            session.conn.nick = "me"
            await session._on_message(parse_line(
                "@time=2020-01-02T03:04:05.000Z :bob!b@h PRIVMSG #c :from the past"))
            await session._on_message(parse_line(":bob!b@h PRIVMSG #c :untagged"))
            await session._on_message(parse_line(
                "@time=2999-01-01T00:00:00.000Z :bob!b@h PRIVMSG #c :from the future"))
            events = {e["event"]["text"]: e["event"]["ts"] for e in hub.of("event")}
            check("a tagged line keeps the server's time", events["from the past"], 1577934245.0)
            check("an untagged one is stamped now",
                  abs(events["untagged"] - time.time()) < 5, True)
            check("the future is clamped to now",
                  abs(events["from the future"] - time.time()) < 5, True)
            store.close()

    asyncio.run(run())


def test_network_frame_and_isupport():
    """The network frame carries the settings and the raw ISUPPORT (G58)."""
    print("network frame fields (G58)")

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            wire = session.to_wire()
            check("isupport starts unknown", wire["isupport"],
                  {"network": None, "prefix": None, "chanmodes": None, "statusmsg": None,
                   "casemapping": None, "chantypes": None})
            await session._on_message(parse_line(
                ":s 005 me NETWORK=QuakeNet PREFIX=(ov)@+ CHANMODES=b,k,l,imnpstrDducCNMT "
                "CASEMAPPING=rfc1459 :are supported by this server"))
            await asyncio.sleep(0.7)
            check("the raw values, as the server sent them",
                  {k: v for k, v in session.to_wire()["isupport"].items() if v},
                  {"network": "QuakeNet", "prefix": "(ov)@+",
                   "chanmodes": "b,k,l,imnpstrDducCNMT", "casemapping": "rfc1459"})
            check("a network frame follows the 005s", len(hub.of("network")) >= 1, True)
            # A new connection (any server, any edit or none) starts unknown
            # again, raw and parsed, before its own 005 arrives.
            await session._on_message(parse_line(
                ":s 005 me PREFIX=(qaohv)~&@%+ STATUSMSG=~&@%+ CHANTYPES=# TARGMAX=JOIN:3 "
                "CASEMAPPING=ascii MONITOR=100 :are supported"))
            await session._on_connected()
            check("a new connection forgets the old server's ISUPPORT",
                  (session.to_wire()["isupport"], session.prefix_map, session.statusmsg,
                   session.chantypes, session.casemapping, session.join_targets,
                   session.monitor_limit, session._statusmsg_chars()),
                  ({"network": None, "prefix": None, "chanmodes": None, "statusmsg": None,
                    "casemapping": None, "chantypes": None}, {"@": "o", "+": "v"}, None,
                   "#&", "rfc1459", None, None, "@+"))
            check("no secret is ever in it", "password" in json_keys(session.to_wire()), False)
            check("sasl without a password",
                  NetworkSession(dataclasses_replace(session.config, slug="s2",
                                                     sasl_mechanism="PLAIN",
                                                     sasl_username="u", sasl_password="p"),
                                 store, hub).to_wire()["sasl"],
                  {"mechanism": "PLAIN", "username": "u"})
            store.close()

    asyncio.run(run())


def json_keys(obj) -> set:
    import json
    return set(json.dumps(obj).replace('"', " ").split())


def dataclasses_replace(obj, **kw):
    import dataclasses
    return dataclasses.replace(obj, **kw)


def test_network_fields():
    """add_network / edit_network validation (G59, G62)."""
    print("network field checks (G59, G62)")
    from relay.netguard import address_is_public as is_public_ip
    from relay.netfields import clean_channels, clean_nick, network_fields

    for address, want in (("8.8.8.8", True), ("2606:4700::1111", True), ("127.0.0.1", False),
                          ("10.0.0.1", False), ("192.168.1.1", False), ("172.16.0.1", False),
                          ("169.254.169.254", False), ("100.64.0.1", False), ("224.0.0.1", False),
                          ("0.0.0.0", False), ("::1", False), ("fe80::1", False),
                          ("::ffff:127.0.0.1", False), ("fd00::1", False)):
        check(f"public? {address}", is_public_ip(address), want)
    for nick in ("9lives", "a,b", "x" * 200, "-dash", "two words", "a\r\nQUIT", ""):
        check(f"nick refused: {nick[:12]!r}", refuses(clean_nick, nick), True)
    for nick in ("quinn", "quinn2", "[m]x", "a_b-c", "Riley`", "{|}^"):
        check(f"nick accepted: {nick!r}", clean_nick(nick), nick)
    check("channels get their #", clean_channels(["hangout", "#defrag", "&local"]),
          ["#hangout", "#defrag", "&local"])
    check("duplicate channels once", clean_channels(["#a", "#A", "a"]), ["#a"])
    # "#a b" is no longer refused: it is the channel #a and its key (see
    # test_channel_keys). Two spaces' worth is still not a channel.
    for bad in (["#a b c"], ["#a,b"], ["#a\x07"], ["#" + "x" * 60], "#a"):
        check(f"channels refused: {bad!r}"[:40], refuses(clean_channels, bad), True)

    async def run():
        async def fields(frame, **kw):
            return await network_fields(frame, allow_private_hosts=True, **kw)

        got = await fields({"host": "irc.example.net", "nick": "quinn", "tls": True,
                            "sasl": {"mechanism": "plain", "username": "quinn", "password": "x y"},
                            "password": "pw", "alt_nicks": ["quinn_", "QUINN", ""]},
                           adding=True)
        check("an add, with defaults and secrets",
              {k: got[k] for k in ("host", "port", "name", "sasl_mechanism", "sasl_password",
                                   "password", "alt_nicks")},
              {"host": "irc.example.net", "port": 6697, "name": "irc.example.net",
               "sasl_mechanism": "PLAIN", "sasl_password": "x y", "password": "pw",
               "alt_nicks": ["quinn_"]})
        current = NetworkConfig(slug="q", name="Q", host="irc.example.net", nick="quinn",
                                tls=True, sasl_mechanism="PLAIN", sasl_username="quinn",
                                sasl_password="kept")
        got = await fields({"nick": "quinn2", "sasl": {"mechanism": "PLAIN", "username": "quinn"}},
                           adding=False, current=current)
        check("an edit is only what it names; a SASL password left out is kept",
              got, {"nick": "quinn2", "sasl_mechanism": "PLAIN", "sasl_username": "quinn",
                    "sasl_password": "kept"})
        got = await fields({"sasl": None, "password": "", "q_username": None},
                           adding=False, current=current)
        check("null and empty clear the secrets",
              got, {"sasl_mechanism": "", "sasl_username": "", "sasl_password": "",
                    "password": "", "q_username": ""})
        got = await fields({"password": None, "q_password": None, "nick": "quinn3"},
                           adding=False, current=current)
        check("a null password or Q password is left alone", got, {"nick": "quinn3"})
        got = await fields({"q_password": ""}, adding=False, current=current)
        check("an empty Q password clears it", got, {"stored_q_password": ""})
        try:
            await network_fields({"host": "127.0.0.1", "nick": "x"}, adding=True,
                                 allow_private_hosts=False)
            refused = None
        except ValueError as exc:
            refused = str(exc)
        check("a private host is refused in words", refused,
              "That address is on a private network.")
        for bad in ({"port": "abc"}, {"port": True}, {"tls": "yes"}, {"name": "a\nb"},
                    {"realname": "x\r\n"}, {"password": "a\nb"},
                    {"sasl": {"mechanism": "SCRAM", "username": "u", "password": "p"}}):
            try:
                await fields(bad, adding=False, current=current)
                ok = False
            except ValueError:
                ok = True
            check(f"edit refused: {bad!r}"[:48], ok, True)

        # A password is never sent over a plain connection: PASS and SASL
        # PLAIN carry it as it is, on every reconnect.
        async def refusal(frame, **kw):
            try:
                await fields(frame, **kw)
                return None
            except ValueError as exc:
                return str(exc)
        plain = {"host": "irc.example.net", "nick": "quinn", "tls": False}
        check("an add with SASL PLAIN and no TLS is refused",
              await refusal({**plain, "sasl": {"mechanism": "PLAIN", "username": "quinn",
                                               "password": "pw"}}, adding=True),
              "That SASL login would be sent unencrypted. Turn on TLS first.")
        check("an add with a server password and no TLS is refused",
              await refusal({**plain, "password": "pw"}, adding=True),
              "That server password would be sent unencrypted. Turn on TLS first.")
        check("  and so is one that leaves tls out, which means off",
              await refusal({"host": "irc.example.net", "nick": "quinn", "password": "pw"},
                            adding=True) is not None, True)
        check("SASL EXTERNAL without TLS is refused: it can only fail",
              "needs TLS" in (await refusal({**plain, "sasl": {"mechanism": "EXTERNAL"}},
                                            adding=True) or ""), True)
        got = await fields({**plain, "password": ""}, adding=True)
        check("no TLS and no password is fine", (got["tls"], got["password"]), (False, ""))
        check("turning TLS off under a stored SASL login is refused",
              await refusal({"tls": False}, adding=False, current=current),
              "That SASL login would be sent unencrypted. Turn on TLS first.")
        got = await fields({"tls": False, "sasl": None}, adding=False, current=current)
        check("  unless the same edit drops the login",
              (got["tls"], got["sasl_mechanism"]), (False, ""))
        stored = NetworkConfig(slug="p", name="P", host="irc.example.net", nick="quinn",
                               tls=False, password="old")
        check("a password on a network without TLS is refused on an edit too",
              await refusal({"password": "new"}, adding=False, current=stored) is not None, True)
        check("  but a rename of one stored before the rule is let through",
              await fields({"name": "Renamed"}, adding=False, current=stored),
              {"name": "Renamed"})
        check("  and clearing the password fixes it",
              await fields({"password": ""}, adding=False, current=stored), {"password": ""})

    asyncio.run(run())


def test_config_network_edits():
    """A client's edit to a config.json network wins for the fields it
    edited; the rest keep following the file (G60)."""
    print("editing a config.json network (G60)")
    from relay.app import network_from_file, network_from_record

    with tempfile.TemporaryDirectory() as tmp:
        store = Store(os.path.join(tmp, "e.db"))
        nid = store.save_network(slug="quakenet", name="QuakeNet", host="irc.quakenet.org",
                                 port=6667, tls=False, nick="quinn2", username="quinn",
                                 realname="quinn", channels=["#hangout"], source="config",
                                 config_channels=["#hangout"])
        store.set_network_fields(nid, {"nick": "quinn3", "alt_nicks": ["quinn3_"],
                                       "sasl_mechanism": "PLAIN", "sasl_username": "u",
                                       "sasl_password": "p"},
                                 edited=["nick", "alt_nicks"])
        record = store.network_by_slug("quakenet")
        # The file changed its realname and port since; nobody edited those.
        from_file = NetworkConfig(slug="quakenet", name="QuakeNet", host="irc.quakenet.org",
                                  port=6668, nick="quinn2", username="quinn", realname="new name",
                                  channels=["#hangout"], q_username="quinn")
        net = network_from_file(from_file, record)
        check("the edited nick wins over the file", net.nick, "quinn3")
        check("so does the edited alt list", net.alt_nicks, ["quinn3_"])
        check("an untouched field follows the file", (net.port, net.realname), (6668, "new name"))
        check("the secrets come from the database", (net.sasl_mechanism, net.sasl_password),
              ("PLAIN", "p"))
        check("it is still a config network", (net.source, net.edited),
              ("config", ["nick", "alt_nicks"]))
        check("Q login still from the file", net.q_username, "quinn")
        os.environ["GEYEM_Q_PASSWORD"] = "from-env"
        try:
            check("a config network's Q password is the environment's", net.q_password,
                  "from-env")
            client = network_from_record(dict(record, slug="other", q_username="x",
                                              q_password="stored"))
            check("a client network never reads the environment", client.q_password, "stored")
        finally:
            del os.environ["GEYEM_Q_PASSWORD"]
        # A fallback nick is where it is in use, not the nick asked for.
        store.set_network_nick(nid, "quinn3_")
        check("a fallback is not written over the nick asked for",
              store.network_by_slug("quakenet")["nick"], "quinn3")
        store.close()


def test_buffer_ids_never_reused():
    """AUTOINCREMENT buffer ids, including for a database made before it (G78)."""
    print("buffer ids never reused (G78)")
    import sqlite3
    with tempfile.TemporaryDirectory() as tmp:
        s = Store(os.path.join(tmp, "n.db"))
        a = s.upsert_network("a", "A", "h", 6667, False, "me")
        b = s.upsert_network("b", "B", "h", 6667, False, "me")
        s.get_or_create_buffer(a, "#keep", "channel")
        gone = s.get_or_create_buffer(b, "#gone", "channel").id
        s.delete_network(b)
        fresh = s.get_or_create_buffer(a, "#new", "channel").id
        check("a deleted buffer's id is not handed out again", fresh > gone, True)
        s.close()

        # A database from before: plain INTEGER PRIMARY KEY, and a gap.
        path = os.path.join(tmp, "old.db")
        make_v6_db(path, events=20)
        db = sqlite3.connect(path)
        before = db.execute("SELECT id, name FROM buffers ORDER BY id").fetchall()
        db.close()
        s = Store(path)
        sql = s.db.execute("SELECT sql FROM sqlite_master WHERE name='buffers'").fetchone()[0]
        check("migrated to AUTOINCREMENT", "AUTOINCREMENT" in sql.upper(), True)
        check("every buffer kept its id",
              [tuple(r) for r in s.db.execute("SELECT id, name FROM buffers ORDER BY id")],
              [tuple(r) for r in before])
        check("events still find their buffers",
              s.db.execute("SELECT COUNT(*) FROM events e LEFT JOIN buffers b"
                           " ON b.id = e.buffer_id WHERE b.id IS NULL").fetchone()[0], 0)
        top = max(r[0] for r in before)
        new_id = s.get_or_create_buffer(1, "#after", "channel").id
        check("new ids start above the old ones", new_id > top, True)
        s.close()
        s = Store(path)
        check("and the migration runs once", s.buffer(new_id).name, "#after")
        s.close()


def test_edge_cases():
    """Paging clamps, around's complete, UTF-8 safe truncation, the member
    order and the CSP script hashes (G62, G78)."""
    print("edge cases (G62, G78)")
    from relay.ircproto import encode_line
    from relay.gateway import _origin_host, inline_script_hashes

    with tempfile.TemporaryDirectory() as tmp:
        s = Store(os.path.join(tmp, "p.db"))
        nid = s.upsert_network("n", "N", "h", 6667, False, "me")
        other = s.get_or_create_buffer(nid, "#other", "channel")
        s.append_event(buffer_id=other.id, network_id=nid, kind="message", text="first ever")
        buf = s.get_or_create_buffer(nid, "#c", "channel")
        eids = [s.append_event(buffer_id=buf.id, network_id=nid, kind="message",
                               text=f"m{i}").eid for i in range(10)]
        check("negative limit is one row, not every row", len(s.backlog(buf.id, limit=-1)), 1)
        check("a huge limit is capped", len(s.backlog(buf.id, limit=10**9)), 10)
        check("around the first line: nothing older in THIS buffer",
              s.has_older(buf.id, eids[0]), False)
        check("around a later line: something older", s.has_older(buf.id, eids[5]), True)
        s.add_member(buf.id, "zed", "")
        s.add_member(buf.id, "owner", "~")
        s.add_member(buf.id, "admin", "&")
        s.add_member(buf.id, "op", "@")
        s.add_member(buf.id, "voice", "+")
        check("~ and & sort first, not last", [m["nick"] for m in s.members(buf.id)],
              ["owner", "admin", "op", "voice", "zed"])
        s.close()

    line = "TOPIC #c :" + "é" * 300
    data = encode_line(line)
    check("cut to 510 bytes at most", len(data) <= 510, True)
    check("on a character boundary", data.decode("utf-8").endswith("é"), True)
    check("short lines untouched", encode_line("PING x"), b"PING x")

    html = "<p>x</p><script>\nlet a = 1;\n</script><script src=x.js></script><SCRIPT>b()</SCRIPT>"
    import base64 as b64
    import hashlib
    want = [b64.b64encode(hashlib.sha256(t.encode()).digest()).decode()
            for t in ("\nlet a = 1;\n", "b()")]
    check("one hash per inline script, none for src=", inline_script_hashes(html), want)
    # What the browser hashes is what its HTML parser read: CRLF is LF, and a
    # NUL is U+FFFD. index.html has literal NULs in one script.
    parsed = "a\n�b\n"
    check("hashed as the parser reads it",
          inline_script_hashes("<script>a\r\n\0b\r</script>"),
          [b64.b64encode(hashlib.sha256(parsed.encode()).digest()).decode()])
    check("origin host", _origin_host("https://irc.example.com"), "irc.example.com")
    check("origin with a port", _origin_host("http://127.0.0.1:8850"), "127.0.0.1:8850")
    check("the default port drops", _origin_host("https://x.com:443"), "x.com")
    check("a file:// page's null origin is nobody's", _origin_host("null"), None)
    from relay.gateway import _safe_filename
    check("export names: one dash where the channel's # was",
          [_safe_filename("local-#two-2026-09-22"), _safe_filename("quakenet-#hangout-2026-09-22"),
           _safe_filename("q-Bob[m]-2026-09-22"), _safe_filename("q-a--b-x")],
          ["local-two-2026-09-22", "quakenet-hangout-2026-09-22", "q-Bob-m-2026-09-22", "q-a-b-x"])

    # The upload endpoint's port survives into connect-src.
    from types import SimpleNamespace
    from relay.gateway import Gateway
    from relay.uploads import UploadConfig

    def upload_origin(endpoint):
        fake = SimpleNamespace(uploader=SimpleNamespace(config=UploadConfig(
            endpoint=endpoint, bucket="Pics", access_key="a", secret_key="s",
            public_base="https://img.example")))
        return Gateway._upload_origin(fake)
    check("an endpoint's port is kept, both styles",
          upload_origin("https://s3.example:9900"),
          " https://s3.example:9900 https://pics.s3.example:9900")
    check("443 is left implicit", upload_origin("https://s3.example:443/"),
          " https://s3.example https://pics.s3.example")
    check("no port, none added", upload_origin("https://x.r2.cloudflarestorage.com"),
          " https://x.r2.cloudflarestorage.com https://pics.x.r2.cloudflarestorage.com")

    # X-Forwarded-Host names the page's own host only when cloudflared (on
    # loopback) says it. From anywhere else it is whatever the caller typed.
    from unittest import mock
    from aiohttp.test_utils import make_mocked_request

    def origin_allowed(peer, origin, forwarded):
        transport = mock.Mock()
        transport.get_extra_info.return_value = (peer, 50000)
        request = make_mocked_request(
            "GET", "/ws", transport=transport,
            headers={"Host": "127.0.0.1:8770", "Origin": origin, "X-Forwarded-Host": forwarded})
        return Gateway._origin_allowed(SimpleNamespace(config=SimpleNamespace(allowed_origins=[])),
                                       request)
    check("X-Forwarded-Host from loopback names the own host",
          origin_allowed("127.0.0.1", "https://geeyem.example", "geeyem.example"), True)
    check("X-Forwarded-Host from anywhere else is not believed",
          origin_allowed("203.0.113.5", "https://evil.example", "evil.example"), False)
    check("  and the request's own Host still is",
          origin_allowed("203.0.113.5", "http://127.0.0.1:8770", "evil.example"), True)


def test_asset_versions():
    """Icons are addressed by their own content hash (2026-09-23), so a new icon
    is a new URL no browser, service worker or Cloudflare edge has cached."""
    import asyncio
    from aiohttp.test_utils import make_mocked_request
    from relay import gateway as gw
    from relay.config import Config
    from relay.hub import Hub

    import json

    class NoPush:
        async def send(self, notification, devices):
            pass
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(os.path.join(tmp, "t.db"))
        gateway = gw.Gateway(Config(db_path=store.path), store, Hub(store, NoPush()))
        v = gateway.asset_version("icon-192.png")
        check("an icon has a version", len(v), 12)
        check("  and it is stable", gateway.asset_version("icon-192.png"), v)
        check("a missing file has none", gateway.asset_version("nope.png"), "")
        manifest = json.loads(asyncio.run(
            gateway.handle_manifest(make_mocked_request("GET", "/manifest.webmanifest"))).body)
        srcs = [i["src"] for i in manifest["icons"]]
        check("the manifest names versioned icons",
              all("?v=" in s and len(s.split("?v=")[1]) == 12 for s in srcs), True)
        body = gateway._read_index(gateway._web_root / "index.html")[0]
        check("the page's home-screen icon is versioned",
              f'href="icon-192.png?v={v}"' in body, True)
        check("  and the bare link is gone", 'href="icon-192.png"' in body, False)
        versioned = asyncio.run(gateway.handle_asset(
            make_mocked_request("GET", f"/icon-192.png?v={v}")))
        check("a versioned icon is cached for good",
              versioned.headers["Cache-Control"], "public, max-age=31536000, immutable")
        bare = asyncio.run(gateway.handle_asset(make_mocked_request("GET", "/icon-192.png")))
        check("a bare icon is revalidated", bare.headers["Cache-Control"], "no-cache")


def test_remove_network_with_ignores():
    """Removing a network with a block on it (audit 2026-09-26, item 1): the
    delete used to fail its foreign key after the session had been stopped,
    so the network vanished live and came back on restart."""
    print("remove a network that has blocks (2026-09-26)")
    with tempfile.TemporaryDirectory() as tmp:
        s = Store(os.path.join(tmp, "rm.db"))
        a = s.upsert_network("a", "A", "h", 6667, False, "me")
        b = s.upsert_network("b", "B", "h", 6667, False, "me")
        s.add_ignore(b, "spammer")
        s.add_ignore(a, "keepme")
        buf = s.get_or_create_buffer(b, "#gone", "channel")
        s.append_event(buffer_id=buf.id, network_id=b, kind="message", text="hi")
        try:
            s.delete_network(b)
            ok = True
        except Exception as exc:
            ok = f"raised {type(exc).__name__}: {exc}"
        check("a network with an ignore deletes", ok, True)
        check("its ignores went with it", s.ignores(b), [])
        check("another network's are untouched", s.ignores(a), ["keepme"])
        check("and so did the network", s.network_by_slug("b"), None)
        s.close()

    # The app: a delete that fails puts the session back rather than leaving
    # it gone from memory and present in the database.
    from relay.app import Relay
    from relay.config import Config

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            relay = Relay(Config(db_path=os.path.join(tmp, "app.db")))
            nid = relay.store.save_network(
                slug="c", name="C", host="h", port=6667, tls=False, nick="me",
                username="me", realname="me", channels=[], source="client",
                enabled=True, alt_nicks=[], q_username=None)
            session = relay._attach(NetworkConfig(slug="c", name="C", host="h", nick="me",
                                                  source="client"))
            started = []
            session.start = lambda: started.append(True)

            real_delete = relay.store.delete_network

            def failing(_nid):
                raise RuntimeError("disk full")
            relay.store.delete_network = failing
            try:
                await relay.remove_network("c")
                outcome = "no error"
            except ValueError:
                outcome = "ValueError"
            check("a failed delete is reported to the client", outcome, "ValueError")
            check("and the network stays, live and in the database",
                  ("c" in relay.hub.sessions, session in relay.sessions,
                   relay.store.network_by_slug("c") is not None), (True, True, True))
            check("its session is started again", started, [True])

            relay.store.delete_network = real_delete
            relay.store.add_ignore(nid, "spammer")
            await relay.remove_network("c")
            check("with a block on it, removal now succeeds everywhere",
                  ("c" in relay.hub.sessions, relay.store.network_by_slug("c")), (False, None))
            relay.store.close()

    asyncio.run(run())


def test_highlight_on_fallback_nick():
    """On the fallback (quinn_) the configured nick and the alts still highlight
    (audit 2026-09-26, item 2)."""
    print("highlights on a fallback nick (2026-09-26)")
    m = HighlightMatcher("quinn_", [], own_nicks=["quinn", "quinn2"])
    check("the configured nick highlights on the fallback", m.matches("quinn: you there?"), True)
    check("so does an alt", m.matches("quinn2 ping"), True)
    check("and the current nick", m.matches("quinn_ hi"), True)
    check("a word containing it does not", m.matches("quinnx is a thing"), False)
    m.set_own_nicks(["riley"])
    check("set_own_nicks replaces them", (m.matches("quinn: hi"), m.matches("riley: hi")),
          (False, True))

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "hl.db"))
            hub = RecordingHub()
            session = NetworkSession(
                NetworkConfig(slug="t", name="T", host="h", port=6667, nick="quinn",
                              alt_nicks=["quinn2"], channels=["#c"]), store, hub)
            session.conn.nick = "quinn_"
            session.conn.registered = True
            session.highlighter.set_nick("quinn_")
            from relay.ircproto import parse_line
            await session._on_message(parse_line(":quinn_!u@h JOIN #c"))
            await session._on_message(parse_line(":alice!a@h PRIVMSG #c :quinn: you there?"))
            ev = [f["event"] for f in hub.of("event") if f["event"].get("from") == "alice"]
            check("a line naming quinn while we are quinn_ is a highlight",
                  [e["highlight"] for e in ev], [True])
            check("and it pushes", len(hub.pushed), 1)
            await session.edit({"alt_nicks": ["riley"]})
            check("an edit of the alts follows through",
                  session.highlighter.matches("riley: hi"), True)
            store.close()

    asyncio.run(run())


def test_join_task_bound_to_connection():
    """The JOINs held for Q belong to one connection (audit 2026-09-26, item 3)."""
    print("held joins die with their connection (2026-09-26)")

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "j.db"))
            hub = RecordingHub()
            session = NetworkSession(
                NetworkConfig(slug="t", name="T", host="h", port=6667, nick="me",
                              channels=["#c"], q_username="me", stored_q_password="pw",
                              source="client"),
                store, hub)
            lines = []
            session.conn.send = lambda line, **k: lines.append(line) or True
            session.conn.send_command = lambda *a, **k: True
            session.conn.nick = "me"
            session.conn.registered = True
            await session._on_registered("me")
            task = session._join_task
            check("registration holds the joins in a task it keeps", task is not None, True)
            check("waiting on Q", session.qauth.awaiting, True)
            session.conn.registered = False
            await session._on_disconnected("ping timeout")
            await asyncio.sleep(0)
            check("a disconnect cancels it", (task.done(), session._join_task), (True, None))
            check("no JOIN went out", [l for l in lines if l.startswith("JOIN")], [])

            # And one the cancel could not reach checks its generation.
            session.conn.registered = True
            session.qauth.start()
            stray = asyncio.create_task(session._join_after_auth(timeout=0.3))
            await asyncio.sleep(0.05)
            session._conn_generation += 1           # a newer connection
            session.qauth.state = "authed"
            await asyncio.sleep(0.5)
            check("a task from an old connection joins nothing",
                  (stray.done(), [l for l in lines if l.startswith("JOIN")]), (True, []))

            # The current connection's task still joins.
            session.qauth.start()
            live = asyncio.create_task(session._join_after_auth(timeout=0.3))
            await asyncio.sleep(0.9)
            check("the current connection's task joins",
                  (live.done(), [l for l in lines if l.startswith("JOIN")]), (True, ["JOIN #c"]))
            store.close()

    asyncio.run(run())


def test_names_topic_unjoined():
    """/quote NAMES and TOPIC for channels we are not in make no buffers
    (audit 2026-09-26, item 4)."""
    print("NAMES / TOPIC replies for channels we are not in (2026-09-26)")
    from relay.ircproto import parse_line

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            session.conn.nick = "me"
            session.conn.registered = True
            session._joined_once = True
            session.conn.send = lambda *a, **k: True
            session.conn.send_command = lambda *a, **k: True
            await session._on_message(parse_line(":me!u@h JOIN #mine"))
            mine = store.find_buffer(session.network_id, "#mine")
            query = store.get_or_create_buffer(session.network_id, "pal", "query")
            before = {b.name for b in store.buffers(include_archived=True)}

            def texts(bid):
                return [e.text for e in store.backlog(bid, limit=50) if e.kind == "server"]

            # A bare NAMES typed in the query: every channel's list, then "*".
            await session.raw("NAMES", origin=query.id)
            for raw in (":s 353 me = #mine :me @op",
                        ":s 353 me = #other :x +y",
                        ":s 353 me * * :loner",
                        ":s 366 me * :End of /NAMES list."):
                await session._on_message(parse_line(raw))
            await session.raw("TOPIC #elsewhere", origin=query.id)
            for raw in (":s 332 me #elsewhere :their topic",
                        ":s 333 me #elsewhere bob!b@h 1758000000"):
                await session._on_message(parse_line(raw))
            session._recent_requests.clear()      # nothing asked recently
            await session._on_message(parse_line(":s 331 me #quiet :No topic is set."))
            after = {b.name for b in store.buffers(include_archived=True)}
            check("no buffer is made for *, #other, #elsewhere or #quiet", after - before, set())
            check("the joined channel's members are applied",
                  sorted(m["nick"] for m in session.members_to_wire(mine.id)), ["me", "op"])
            shown = texts(query.id)
            check("the other channel's names are a line where NAMES was typed",
                  "#other: x +y" in shown, True)
            check("so are the people in no channel", "*: loner" in shown, True)
            check("and the topic, and who set it",
                  ("#elsewhere: their topic" in shown,
                   any(t.startswith("#elsewhere: topic set by bob") for t in shown)), (True, True))
            check("a 331 with nothing asked lands in the status buffer",
                  "#quiet: No topic is set." in texts(session.status_buffer.id), True)
            check("nothing is left half-accumulated", session._names_accum, {})
            # The joined channel still takes its own topic as before.
            await session._on_message(parse_line(":s 332 me #mine :ours"))
            await session._on_message(parse_line(":s 333 me #mine op 1758000000"))
            check("a joined channel's topic is still stored",
                  store.find_buffer(session.network_id, "#mine").topic, "ours")
            store.close()

    asyncio.run(run())


def test_hello_first_with_auto_away():
    """Hub.add(ready=False) leaves the auto-away until client_ready()
    (audit 2026-09-26, item 5; the end-to-end half is in test_endtoend)."""
    print("hello before the auto-away network frame (2026-09-26)")
    from relay.hub import Hub

    class NoPush:
        async def send(self, n, d): pass

    class Seen:
        presence, focused_buffer = "unknown", None
        def __init__(self): self.frames = []
        def enqueue(self, data): self.frames.append(data)

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "aa.db"))
            hub = Hub(store, NoPush())
            session = NetworkSession(NetworkConfig(slug="t", name="T", host="h", nick="me"),
                                     store, hub)
            hub.sessions["t"] = session
            store.set_setting("auto_away", True)
            hub.auto_away_active = True
            session.set_auto_away(True)
            client = Seen()
            hub.add(client, ready=False)
            check("attached but not ready: nothing published yet", client.frames, [])
            check("the away still stands", session.to_wire()["away"] is not None, True)
            hub.client_ready()
            check("ready: taken back", (hub.auto_away_active, session.to_wire()["away"]),
                  (False, None))
            store.close()

    asyncio.run(run())


def test_tag_unescape_and_spaces():
    """IRCv3 tag unescaping in one pass; parameters split on spaces only
    (audit 2026-09-26, item 6)."""
    print("tag unescaping and space-only splitting (2026-09-26)")
    from relay.ircproto import unescape_tag_value
    for raw, want in ((r"a\:b", "a;b"), (r"a\sb", "a b"), (r"a\\b", "a\\b"),
                      (r"a\rb\nc", "a\rb\nc"),
                      (r"\\s", "\\s"),            # an escaped backslash, then s
                      (r"\\:", "\\:"),
                      (r"a\bc", "abc"),           # unknown escape: drop the backslash
                      ("end\\", "end"),           # trailing lone backslash dropped
                      (r"\\\s", "\\ "),
                      ("plain", "plain"), ("", "")):
        check(f"unescape {raw!r}", unescape_tag_value(raw), want)
    m = parse_line(r"@k=one\stwo\\s;x=\: :n!u@h PRIVMSG #c :hi")
    check("tags through parse_line", (m.tags["k"], m.tags["x"]), ("one two\\s", ";"))
    m = parse_line(":n!u@h PRIVMSG #a b :hi there")
    check("a non-breaking space inside a parameter is not a separator",
          m.params, ["#a b", "hi there"])
    m = parse_line(":n!u@h MODE #c\t+o x")
    check("nor is a tab", m.params, ["#c\t+o", "x"])
    m = parse_line(":n!u@h PRIVMSG   #c   :a  b")
    check("runs of spaces still separate", m.params, ["#c", "a  b"])
    check("trailing may be empty", parse_line("PART #c :").params, ["#c", ""])
    check("a bare trailing line", parse_line(":s :just text").params, [])


def test_presence_expires():
    """A foreground client not heard from in PRESENCE_TTL no longer holds
    back a push (audit 2026-09-26, item 7)."""
    print("stale foreground presence expires (2026-09-26)")
    from relay.hub import Hub, PRESENCE_TTL

    class NoPush:
        async def send(self, n, d): pass

    class Phone:
        presence, focused_buffer = "foreground", 7
        def __init__(self, heard): self.last_heard = heard
        def enqueue(self, data): pass

    with tempfile.TemporaryDirectory() as tmp:
        store = Store(os.path.join(tmp, "p.db"))
        hub = Hub(store, NoPush())
        fresh = Phone(time.monotonic())
        hub.clients.add(fresh)
        check("a client heard from just now is watching", hub.has_active_viewer(7), True)
        hub.clients.discard(fresh)
        stale = Phone(time.monotonic() - PRESENCE_TTL - 1)
        hub.clients.add(stale)
        check("one silent past the TTL is not", hub.has_active_viewer(7), False)
        stale.last_heard = time.monotonic()
        check("until it is heard from again", hub.has_active_viewer(7), True)
        store.close()


def test_instant_reclaim():
    """A QUIT or NICK that frees our configured nick takes it at once
    (audit 2026-09-26, item 8)."""
    print("instant nick reclaim (2026-09-26)")
    from relay.ircproto import parse_line
    import relay.session as session_module

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp, nick="quinn")
            sent = []
            session.conn.send_command = lambda *a, **k: sent.append(a)
            session.conn.send = lambda *a, **k: True
            session.conn.registered = True
            session.conn.nick = "quinn_"
            session._joined_once = True
            session.reclaim_interval = 3600         # only the instant path acts
            session._start_reclaim()
            await session._on_message(parse_line(":quinn_!u@h JOIN #c"))
            await session._on_message(parse_line(":quinn!old@ghost JOIN #c"))

            await session._on_message(parse_line(":someone!s@h QUIT :bye"))
            check("someone else quitting asks for nothing", ("NICK", "quinn") in sent, False)
            await session._on_message(parse_line(":QUINN!old@ghost QUIT :Ping timeout"))
            check("our ghost quitting takes the nick at once", sent.count(("NICK", "quinn")), 1)

            # Within the gap a second trigger is ignored.
            await session._on_message(parse_line(":quinn!x@h NICK quinn_away"))
            check("but not twice inside the gap", sent.count(("NICK", "quinn")), 1)
            session._instant_reclaim_at -= session_module.INSTANT_RECLAIM_GAP + 1
            await session._on_message(parse_line(":quinn!x@h NICK QUINN"))
            check("a case change frees nothing", sent.count(("NICK", "quinn")), 1)
            await session._on_message(parse_line(":quinn!x@h NICK other"))
            check("a rename away from it does", sent.count(("NICK", "quinn")), 2)

            # A nick chosen by hand stops the reclaim, and with it this.
            session._cancel_reclaim()
            session._instant_reclaim_at = float("-inf")
            await session._on_message(parse_line(":quinn!x@h QUIT :bye"))
            check("no reclaim running, no instant reclaim", sent.count(("NICK", "quinn")), 2)
            store.close()

    asyncio.run(run())


def test_health_irc_flag():
    """The anonymous /health says whether any network is registered, and
    nothing more (audit 2026-09-26, item 9)."""
    print("/health irc flag (2026-09-26)")
    import json as _json
    from aiohttp.test_utils import make_mocked_request
    from relay import gateway as gw
    from relay.config import Config
    from relay.hub import Hub

    class NoPush:
        async def send(self, n, d): pass

    with tempfile.TemporaryDirectory() as tmp:
        store = Store(os.path.join(tmp, "h.db"))
        hub = Hub(store, NoPush())
        gateway = gw.Gateway(Config(db_path=store.path), store, hub)

        def body():
            resp = asyncio.run(gateway.handle_health(make_mocked_request("GET", "/health")))
            return _json.loads(resp.text)

        check("no networks: not on IRC", body(), {"ok": True, "protocol": body()["protocol"],
                                                  "irc": False})
        session = NetworkSession(NetworkConfig(slug="t", name="T", host="h", nick="me"),
                                 store, hub)
        hub.sessions["t"] = session
        check("a network not registered: still false", body()["irc"], False)
        session.conn.registered = True
        check("registered: true", body()["irc"], True)
        check("and the anonymous body is still three keys", sorted(body()),
              ["irc", "ok", "protocol"])
        store.close()


def test_log_hygiene():
    """httpx and httpcore quiet below WARNING (audit 2026-09-26, item 10)."""
    print("log hygiene (2026-09-26)")
    import logging
    from relay.__main__ import _setup_logging
    _setup_logging(False)
    check("httpx is WARNING", logging.getLogger("httpx").level, logging.WARNING)
    check("httpcore is WARNING", logging.getLogger("httpcore").level, logging.WARNING)


def test_backup_every_instance():
    """tools/backup.py backs up every instance, each under its own prefix,
    encrypted, and prunes per instance (audit 2026-09-26, item 13)."""
    print("backups of every instance (2026-09-26)")
    import importlib.util
    import io
    import json as _json
    import tarfile
    from datetime import datetime, timedelta, timezone
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        print("  (cryptography not installed; skipped)")
        return
    spec = importlib.util.spec_from_file_location(
        "geyem_backup", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "tools", "backup.py"))
    backup = importlib.util.module_from_spec(spec)
    sys.modules["geyem_backup"] = backup        # dataclasses looks itself up there
    spec.loader.exec_module(backup)

    class FakeS3:
        def __init__(self): self.objects = {}
        def upload_file(self, path, bucket, key):
            self.objects[key] = {"Key": key, "Body": open(path, "rb").read(),
                                 "LastModified": datetime.now(timezone.utc)}
        def list_objects_v2(self, Bucket, Prefix, **kw):
            return {"Contents": [dict(o, Size=len(o["Body"])) for k, o in self.objects.items()
                                 if k.startswith(Prefix)]}
        def delete_object(self, Bucket, Key): self.objects.pop(Key, None)

    with tempfile.TemporaryDirectory() as tmp:
        main_dir, rowan, stray = (os.path.join(tmp, d) for d in
                                 ("geyem", "geyem-rowan", "geyem-new"))
        other = os.path.join(tmp, "unrelated")
        for d in (main_dir, rowan, stray, other):
            os.makedirs(d)
        with open(os.path.join(main_dir, "config.json"), "w") as f:
            _json.dump({"db_path": "geyem.db"}, f)
        with open(os.path.join(rowan, "config.json"), "w") as f:
            _json.dump({"db_path": "rowan.db", "listen_port": 8772}, f)
        with open(os.path.join(stray, "config.json"), "w") as f:
            _json.dump({}, f)                   # an instance with no database yet
        for path, text in ((os.path.join(main_dir, "geyem.db"), "riley"),
                           (os.path.join(rowan, "rowan.db"), "rowan")):
            s = Store(path)
            nid = s.upsert_network("n", "N", "h", 6667, False, "me")
            b = s.get_or_create_buffer(nid, "#c", "channel")
            s.append_event(buffer_id=b.id, network_id=nid, kind="message", text=text)
            s.close()

        found = backup.discover_instances(main_dir, {})
        check("instances: this one, then its -* siblings with a config",
              [(i.label, os.path.basename(i.db)) for i in found],
              [("main", "geyem.db"), ("new", "relay.db"), ("rowan", "rowan.db")])
        check("prefixes never nest",
              [i.prefix for i in found],
              ["geyem-backups/", "geyem-backups-new/", "geyem-backups-rowan/"])

        s3 = FakeS3()
        # An old backup of main's that retention must keep (the oldest of its
        # month), and one of rowan's under rowan's own prefix.
        old = datetime.now(timezone.utc) - timedelta(days=90)
        s3.objects["geyem-backups/x/geyem-old.tar.gz.enc"] = {
            "Key": "geyem-backups/x/geyem-old.tar.gz.enc", "Body": b"", "LastModified": old}
        key = Fernet.generate_key().decode()
        failed = backup.backup(main_dir, {"GEYEM_BACKUP_KEY": key}, s3=s3, bucket="b")
        check("the instance without a database fails, the others do not", failed, 1)
        uploaded = sorted(k for k in s3.objects if "old" not in k)
        check("one upload each for main and rowan, under their own prefixes",
              sorted(k.split("/")[0] for k in uploaded), ["geyem-backups", "geyem-backups-rowan"])
        rowan_key = next(k for k in uploaded if k.startswith("geyem-backups-rowan/"))
        plain = Fernet(key.encode()).decrypt(s3.objects[rowan_key]["Body"])
        with tarfile.open(fileobj=io.BytesIO(plain)) as tar:
            names = sorted(tar.getnames())
            tar.extractall(tmp + "/restored")
        check("rowan's archive is encrypted and holds his db and config",
              names, ["config.json", "rowan.db"])
        r = Store(os.path.join(tmp, "restored", "rowan.db"))
        check("and it is his", [e.text for e in r.backlog(1, limit=5)], ["rowan"])
        r.close()
        check("main's old backup survived the pruning",
              "geyem-backups/x/geyem-old.tar.gz.enc" in s3.objects, True)

        # GEYEM_BACKUP_DIRS names them exactly.
        only = backup.discover_instances(main_dir, {"GEYEM_BACKUP_DIRS": f"{main_dir},{rowan}"})
        check("GEYEM_BACKUP_DIRS lists them exactly", [i.label for i in only], ["main", "rowan"])
        # No key: refuses before touching anything.
        try:
            backup.backup(main_dir, {}, s3=FakeS3(), bucket="b")
            refused = False
        except SystemExit:
            refused = True
        check("no key, no upload", refused, True)


# --- October 2026: the polish contract (docs/PROTOCOL.md) -----------------------


def make_v8_db(path, events=600):
    """A database in the shape the live bouncer has before the October 2026
    work: polish-oct's schema (tests/fixtures/schema_v8.sql) with a network
    from config.json and one a client added (with secrets), channels left
    marked joined, tokens (one revoked), a device, a browser subscription,
    settings, the meta rows that code leaves, and lines written through its
    own search triggers, one of them redacted."""
    import sqlite3
    here = os.path.dirname(os.path.abspath(__file__))
    db = sqlite3.connect(path)
    db.executescript(open(os.path.join(here, "fixtures", "schema_v8.sql")).read())
    db.executescript("""
        INSERT INTO meta VALUES ('secret:previews', 'aa55');
        INSERT INTO networks (id, slug, name, host, port, tls, nick, created_at, username,
                              realname, channels, source, config_channels, highlight_words,
                              away, alt_nicks, q_username, edited, current_nick)
            VALUES (1, 'quakenet', 'QuakeNet', 'irc.quakenet.org', 6667, 0, 'quinn', 0,
                    'quinn', 'quinn', '["#hangout","#defrag"]', 'config',
                    '["#hangout","#defrag"]', '["riley"]', 'gone fishing', '["quinn_"]',
                    'quinn', '["nick"]', 'quinn_');
        INSERT INTO networks (id, slug, name, host, port, tls, nick, created_at, username,
                              realname, channels, source, sasl_mechanism, sasl_username,
                              sasl_password, server_password)
            VALUES (2, 'libera', 'Libera', 'irc.libera.chat', 6697, 1, 'riley', 0,
                    'riley', 'riley', '["#python"]', 'client', 'PLAIN', 'riley', 's3cret', 'pw');
        INSERT INTO settings VALUES ('push_preview', 'false'), ('auto_away', 'true');
        INSERT INTO buffers (id, network_id, name, name_lower, kind, created_at)
            VALUES (1, 1, '*status*', '*status*', 'status', 0);
        INSERT INTO buffers (id, network_id, name, name_lower, kind, topic, joined, created_at,
                             last_seen_eid, notify, pinned)
            VALUES (2, 1, '#hangout', '#hangout', 'channel', 'frag on', 1, 0, 100,
                    'all', 1);
        INSERT INTO buffers (id, network_id, name, name_lower, kind, joined, detached, created_at)
            VALUES (3, 1, '#defrag', '#defrag', 'channel', 1, 1, 0);
        INSERT INTO buffers (id, network_id, name, name_lower, kind, created_at)
            VALUES (4, 1, 'morgan', 'morgan', 'query', 0);
        INSERT INTO buffers (id, network_id, name, name_lower, kind, created_at)
            VALUES (5, 2, '*status*', '*status*', 'status', 0);
        INSERT INTO members VALUES (2, 'morgan', 'morgan', '@');
        INSERT INTO tokens (id, token_hash, label, created_at, last_used_at)
            VALUES (1, 'ab', 'Riley''s iPhone', 1790000000.5, 1791240000.25);
        INSERT INTO tokens (id, token_hash, label, created_at, revoked)
            VALUES (2, 'cd', 'lost phone', 1780000000, 1);
        INSERT INTO tokens (id, token_hash, label, created_at) VALUES (3, 'ef', 'web', 1790000001);
        INSERT INTO devices (token_id, apns_token, platform, environment, updated_at)
            VALUES (1, 'aabb', 'ios', 'production', 0);
        INSERT INTO webpush_subscriptions (token_id, endpoint, p256dh, auth, subject, updated_at)
            VALUES (3, 'https://push.example/x', 'k', 'a', 'https://b.example', 0);
        INSERT INTO ignores VALUES (1, 'spambot', 'spambot', 0);
    """)
    rows = []
    for i in range(events):
        buffer_id = (2, 2, 3, 4, 1)[i % 5]
        rows.append((buffer_id, 1, 1758000000 + i, "message" if buffer_id != 1 else "server",
                     ("morgan", "PuFF", "quinn")[i % 3], f"line {i} about railguns",
                     int(i % 3 == 2), int(i % 50 == 0 and buffer_id != 1),
                     '{"statusmsg": "@"}' if i % 97 == 0 else None))
    db.executemany("INSERT INTO events (buffer_id, network_id, ts, kind, sender, text, self,"
                   " highlight, extra) VALUES (?,?,?,?,?,?,?,?,?)", rows)
    db.execute("INSERT INTO events (buffer_id, network_id, ts, kind, sender, text, self, extra)"
               " VALUES (4, 1, 1759000000, 'message', 'quinn', 'IDENTIFY ********', 1, ?)",
               ('{"redacted": true}',))
    db.commit()
    db.close()


def test_migration_from_v8():
    """THE DEPLOY. The live database (polish-oct's schema, version 8) opens
    under this code, keeps every row of everything, and gains exactly two
    things: a `channel_keys` column on networks and an `epoch` row in meta."""
    print("migration from the deployed schema (v8)")
    import sqlite3
    from relay.store import SCHEMA_VERSION
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "live.db")
        make_v8_db(path)
        before = sqlite3.connect(path)
        tables = ("events", "buffers", "networks", "tokens", "devices", "webpush_subscriptions",
                  "settings", "members", "ignores", "meta")
        snapshot = {t: before.execute(f"SELECT * FROM {t} ORDER BY 1, 2").fetchall()
                    for t in tables}
        columns = {t: [r[1] for r in before.execute(f"PRAGMA table_info({t})")] for t in tables}
        objects_before = {r[0] for r in before.execute("SELECT name FROM sqlite_master")}
        before.close()

        s = Store(path)
        for t in tables:
            listed = ", ".join(columns[t])
            now = [tuple(r) for r in s.db.execute(f"SELECT {listed} FROM {t} ORDER BY 1, 2")]
            if t == "meta":
                # The version moves on and the epoch arrives; every other row
                # (the search index's, the scrub's, the secrets) is as it was.
                now = [r for r in now if r[0] not in ("schema_version", "epoch")]
                was = [r for r in snapshot[t] if r[0] != "schema_version"]
            else:
                was = snapshot[t]
            check(f"every row of {t} survives, byte for byte", now == was, True)
        check("the schema version is recorded", s.meta_get("schema_version"), str(SCHEMA_VERSION))
        check("  and it is 10", SCHEMA_VERSION, 10)
        added = {t: [r["name"] for r in s.db.execute(f"PRAGMA table_info({t})")
                     if r["name"] not in columns[t]] for t in tables}
        # buffers.muted_until arrived with timed mutes; an older release reads
        # rows by name and never names it, so a rollback is safe.
        check("exactly two columns are added: channel keys, and a timed mute's end",
              {t: c for t, c in added.items() if c},
              {"networks": ["channel_keys"], "buffers": ["muted_until"]})
        # Schema 10 adds the uploads table and its two indexes, and nothing
        # else; the previous release never names them, so a rollback is safe.
        check("only the uploads table and its indexes are added, nothing dropped",
              {r[0] for r in s.db.execute("SELECT name FROM sqlite_master")}
              == objects_before | {"uploads", "uploads_due", "uploads_list",
                                "sqlite_autoindex_uploads_1"},
              True)
        check("existing networks have no keys",
              [r["channel_keys"] for r in s.db.execute("SELECT channel_keys FROM networks")],
              ["{}", "{}"])
        check("  which read as none", [n["channel_keys"] for n in s.networks()], [{}, {}])
        epoch = s.epoch
        check("the database is given an epoch", (len(epoch), all(c in "0123456789abcdef"
                                                              for c in epoch)), (16, True))
        check("old lines are still searchable, without a rebuild",
              len(s.search("railguns", limit=200)), 200)
        check("the redacted line is still out of the index", s.search("IDENTIFY"), [])
        check("the device and the browser are still pushed to",
              (len(s.devices()), len(s.webpush_subscriptions())), (1, 1))
        check("settings are as they were, and a sound that was never chosen is the default", s.settings(),
              {"push_preview": False, "auto_away": True, "push_sound": "default",
               "nick_colors": {}, "nick_palette": "default"})
        check("the tokens frame reads the old rows",
              [(t["id"], t["label"], t["push"]) for t in s.active_tokens()],
              [(1, "Riley's iPhone", True), (3, "web", True)])
        # A ROLLBACK must work too: deploy.sh puts the previous release back
        # over this database if the new one does not come up. That code names
        # its columns, so a column it has never heard of has to fill itself in.
        s.db.execute(
            "INSERT INTO networks (slug, name, host, port, tls, nick, created_at,"
            " username, realname, channels, enabled, source, config_channels,"
            " alt_nicks, q_username)"
            " VALUES ('old', 'Old', 'h', 6667, 0, 'n', 0, 'n', 'n', '[]', 1, 'client', '[]',"
            " '[]', NULL)")
        check("the previous release's INSERT still works on the migrated database",
              s.network_by_slug("old")["channel_keys"], {})
        s.db.execute("DELETE FROM networks WHERE slug='old'")
        s.close()

        again = Store(path)
        check("the epoch is the same the next time it is opened", again.epoch, epoch)
        check("and nothing is migrated twice",
              [r["name"] for r in again.db.execute("PRAGMA table_info(networks)")].count(
                  "channel_keys"), 1)
        # A session over it: the frame the clients get is the new shape.
        session = NetworkSession(NetworkConfig(slug="quakenet", name="QuakeNet",
                                               host="irc.quakenet.org", nick="quinn",
                                               channels=["#hangout", "#defrag"]),
                                 again, RecordingHub())
        wire = session.to_wire()
        check("the network frame lists names, and nothing keyed",
              (wire["channels"], wire["keyed"]), (["#hangout", "#defrag"], []))
        again.close()

    # The older fixture too: a database that somehow skipped the releases
    # between still ends up in the same place.
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "older.db")
        make_v6_db(path, events=50)
        s = Store(path)
        check("a v6 database gains the column and an epoch as well",
              ("channel_keys" in {r["name"] for r in s.db.execute("PRAGMA table_info(networks)")},
               len(s.epoch)), (True, 16))
        s.close()


def test_epoch():
    """hello.epoch: made once per database, kept, and new after a restore
    (B-R9)."""
    print("database epoch (B-R9)")
    import importlib.util
    import sqlite3
    import subprocess
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "e.db")
        s = Store(path)
        epoch = s.epoch
        nid = s.upsert_network("n", "N", "h", 6667, False, "me")
        buf = s.get_or_create_buffer(nid, "#c", "channel")
        s.append_event(buffer_id=buf.id, network_id=nid, kind="message", sender="a", text="one")
        s.close()
        s = Store(path)
        check("a new database has an epoch, and keeps it", s.epoch, epoch)
        other = Store(os.path.join(tmp, "other.db"))
        check("another database has another", other.epoch == epoch, False)
        other.close()

        # A backup taken by tools/backup.py carries no epoch, so the database
        # restored from it is given a new one the first time it is opened --
        # with nothing for whoever restores it to remember.
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        spec = importlib.util.spec_from_file_location(
            "geyem_backup_epoch", os.path.join(here, "tools", "backup.py"))
        backup = importlib.util.module_from_spec(spec)
        sys.modules["geyem_backup_epoch"] = backup
        spec.loader.exec_module(backup)
        snap = os.path.join(tmp, "restored", "e.db")
        os.makedirs(os.path.dirname(snap))
        backup.snapshot(snap, path)
        check("the snapshot is one file, with nothing left beside it",
              sorted(os.listdir(os.path.dirname(snap))), ["e.db"])
        raw = sqlite3.connect(snap)
        check("the snapshot has no epoch",
              raw.execute("SELECT COUNT(*) FROM meta WHERE key='epoch'").fetchone()[0], 0)
        check("  and is otherwise whole",
              (raw.execute("PRAGMA integrity_check").fetchone()[0],
               raw.execute("SELECT text FROM events").fetchall()), ("ok", [("one",)]))
        raw.close()
        check("the live database still has its own", s.epoch, epoch)
        restored = Store(snap)
        check("a restored database gets a new epoch", restored.epoch == epoch, False)
        check("  and keeps its history", [e.text for e in restored.backlog(buf.id)], ["one"])
        restored.close()

        # Restored some other way (a disk snapshot, a copied file): by hand.
        fresh = s.new_epoch()
        check("new_epoch changes it", (fresh == epoch, s.epoch), (False, fresh))
        s.close()
        config = os.path.join(tmp, "config.json")
        with open(config, "w") as f:
            f.write('{"db_path": "e.db"}')
        env = {k: v for k, v in os.environ.items() if not k.startswith("RELAY_")}

        def cli(*args):
            return subprocess.run([sys.executable, "-m", "relay", "-c", config, "epoch", *args],
                                  cwd=here, env=env, capture_output=True, text=True)

        shown = cli("show")
        check("`relay epoch show` prints it", (shown.returncode, shown.stdout.strip()), (0, fresh))
        made = cli("new")
        again = cli("show")
        check("`relay epoch new` makes a new one and says what it is",
              (made.returncode, made.stdout.strip() == again.stdout.strip(),
               again.stdout.strip() == fresh), (0, True, False))


def test_say_nonce():
    """A `say` nonce comes back on every event that send produces: each line's
    echo and each "Not sent" line (contract 1)."""
    print("say nonce on every echo and every not-sent line")
    import relay.session as session_module
    from relay.gateway import clean_nonce

    for good in ("k3J9x", "a", "A-b_9", "x" * 64):
        check(f"a nonce: {good[:12]!r}", clean_nonce(good), good)
    for bad in ("", "x" * 65, "has space", "quo\"te", "ünï", 7, None, ["a"], "a\nb"):
        check(f"not a nonce, so ignored: {str(bad)[:12]!r}", clean_nonce(bad), None)

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            conn = session.conn
            writer = FakeWriter()
            conn._writer, conn.registered, conn.connected = writer, True, True
            # The flood limiter's pace is tested elsewhere; here it only has
            # to keep order.
            conn.send_interval = 0.005
            await conn._start_sender(writer)
            chan = store.get_or_create_buffer(session.network_id, "#c", "channel")
            store.set_joined(chan.id, True)

            event = await session.say(chan.id, "one\ntwo\nthree", nonce="n1")
            await asyncio.sleep(0.05)
            echoes = [f["event"] for f in hub.of("event") if f["event"]["self"]]
            check("the ok's event carries the nonce", (event or {}).get("extra"), {"nonce": "n1"})
            check("every line of a multi-line send carries it, not only the first",
                  [(e["text"], e["extra"]) for e in echoes],
                  [("one", {"nonce": "n1"}), ("two", {"nonce": "n1"}), ("three", {"nonce": "n1"})])
            check("history keeps it, for a client that reconnects",
                  [e.extra.get("nonce") for e in store.backlog(chan.id, limit=10)],
                  ["n1", "n1", "n1"])

            hub.frames.clear()
            await session.say(chan.id, "plain")
            await asyncio.sleep(0.05)
            check("a send with no nonce has none",
                  [f["event"].get("extra") for f in hub.of("event")], [None])
            hub.frames.clear()
            await session.say(chan.id, "to the ops", statusmsg="@", nonce="n2")
            await asyncio.sleep(0.05)
            check("it sits beside what the echo already carried",
                  hub.of("event")[0]["event"]["extra"], {"statusmsg": "@", "nonce": "n2"})

            # Still queued when the link drops: each line that never went is
            # said so, with the same nonce, so the client can fail the right one.
            session_module.SAY_ECHO_WAIT = 0.05
            conn._tokens, conn.send_interval = 0.0, 100.0
            hub.frames.clear()
            event = await session.say(chan.id, "four\nfive", nonce="n3")
            check("queued: no event with the ok", event, None)
            await conn._stop_sender()
            conn._drop_queued("connection lost")
            check("each dropped line carries the nonce beside the text",
                  [f["event"]["extra"] for f in hub.of("event")],
                  [{"not_sent": "four", "nonce": "n3"}, {"not_sent": "five", "nonce": "n3"}])

            # A password to a service: redacted either way, nonce all the same.
            conn._tokens, conn.send_interval = 5.0, 0.005
            await conn._start_sender(writer)
            hub.frames.clear()
            await session.say(target="NickServ", text="IDENTIFY hunter2", nonce="n4")
            await asyncio.sleep(0.05)
            check("a redacted echo keeps its mark and gains the nonce",
                  hub.of("event")[0]["event"]["extra"], {"redacted": True, "nonce": "n4"})
            check("  and is still kept out of search", store.search("IDENTIFY"), [])
            session_module.SAY_ECHO_WAIT = 0.5
            await conn._stop_sender()
            store.close()

    asyncio.run(run())


def test_channel_keys():
    """Keyed channels: the key rides with the channel on every JOIN, survives
    a restart, and is never said back (B-R5, contract 5)."""
    print("channel keys (B-R5)")
    import json as _json
    from relay.app import network_from_file, network_from_record
    from relay.ircproto import check_channel_key, join_lines, redact_line
    from relay.netfields import clean_channel_entries, network_fields, split_channel_keys

    check("an entry may be a channel, a space and its key",
          clean_channel_entries(["#secret hunter2", "open", "#Open"]),
          (["#secret", "#open"], {"#secret": "hunter2"}))
    check("a bare name gets its # before the key is read",
          clean_channel_entries(["secret hunter2"]), (["#secret"], {"#secret": "hunter2"}))
    for bad in (["#a b c"], ["#a b,c"], ["#a " + "k" * 65], ["#a :k"]):
        check(f"refused: {bad[0][:14]!r}", refuses(clean_channel_entries, bad), True)
    try:
        clean_channel_entries(["#vault open,sesame"])
        said = ""
    except ValueError as exc:
        said = str(exc)
    check("a refusal names the channel and never repeats the key",
          ("#vault" in said, "sesame" in said), (True, False))
    for bad in ("two words", "a,b", "", ":x", "k" * 65, "a\nb"):
        check(f"key refused: {bad[:8]!r}", refuses(check_channel_key, bad), True)
    check("keyed channels go first in a JOIN, keys after",
          join_lines(["#a", "#k", "#b"], {"#k": "sesame"}), ["JOIN #k,#a,#b sesame"])
    check("a JOIN's keys are not logged", redact_line("JOIN #k,#a sesame"), "JOIN #k,#a ********")
    check("  and a JOIN without one is logged as it is", redact_line("JOIN #a,#b"), "JOIN #a,#b")
    check("config.json's own entries are taken apart the same way",
          split_channel_keys(["#a", "#locked filekey", ""]), (["#a", "#locked"],
                                                             {"#locked": "filekey"}))

    async def run():
        got = await network_fields({"channels": ["#secret hunter2", "#open"]}, adding=False,
                                   allow_private_hosts=True)
        check("edit_network: names in channels, keys beside them", got,
              {"channels": ["#secret", "#open"], "channel_keys": {"#secret": "hunter2"}})

        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            sent = []
            session.conn.send = lambda line, **k: (sent.append(line), True)[1]
            session.conn.registered, session._joined_once = True, True

            await session.join("#secret", key="hunter2")
            check("join sends the key", sent[-1], "JOIN #secret hunter2")
            record = store.networks()[0]
            check("the key is kept with the wanted list, by folded name",
                  (record["channels"], record["channel_keys"]),
                  (["#config", "#secret"], {"#secret": "hunter2"}))
            wire = session.to_wire()
            check("the network frame lists names only, and says which are keyed",
                  (wire["channels"], wire["keyed"]), (["#config", "#secret"], ["#secret"]))
            check("  never the key", "hunter2" in _json.dumps(wire), False)

            await session.join("#SECRET")
            check("a rejoin by name alone brings the remembered key", sent[-1],
                  "JOIN #SECRET hunter2")
            await session.join("#secret", key="newkey")
            check("a new key replaces the old one",
                  (sent[-1], store.networks()[0]["channel_keys"]),
                  ("JOIN #secret newkey", {"#secret": "newkey"}))
            for bad in ("two words", "a,b"):
                try:
                    await session.join("#x", key=bad)
                    refused = False
                except ValueError:
                    refused = True
                check(f"join refuses a key IRC cannot carry: {bad!r}", refused, True)
            check("  and wants nothing because of it", "#x" in session._wanted_channels, False)

            # THE BUG: the reconnect's JOIN held names only, so a +k channel
            # answered 475 after every netsplit and every deploy.
            sent.clear()
            session._joined_once = False
            await session._do_joins()
            check("the join burst after a reconnect carries the key",
                  sent, ["JOIN #secret,#config newkey"])

            # A restart: what was saved is what the next process starts from.
            reborn = network_from_record(store.networks()[0])
            again = NetworkSession(reborn, store, RecordingHub())
            lines = []
            again.conn.send = lambda line, **k: (lines.append(line), True)[1]
            again.conn.registered = True
            await again._do_joins()
            check("and so does the first join after a restart",
                  lines, ["JOIN #secret,#config newkey"])
            check("  with the frame still saying which", again.to_wire()["keyed"], ["#secret"])

            # A network in config.json: the saved keys follow their channels,
            # and a key written in the file itself is taken out of the name.
            names, keys = split_channel_keys(["#config", "#filelocked filekey"])
            file_net = network_from_file(
                NetworkConfig(slug="t", name="T", host="h", nick="me", channels=names,
                              channel_keys=keys),
                dict(store.networks()[0], config_channels=["#config"]))
            check("a config.json network keeps a client's key and takes the file's",
                  (file_net.channels, file_net.channel_keys),
                  (["#config", "#secret", "#filelocked"],
                   {"#secret": "newkey", "#filelocked": "filekey"}))

            # edit_network: the frame shows names only, so an edit screen
            # sends names only back -- which must not forget the key.
            session._joined_once = True
            await session.edit({"channels": ["#config", "#secret"]})
            check("an edit that lists a keyed channel by name keeps its key",
                  store.networks()[0]["channel_keys"], {"#secret": "newkey"})
            sent.clear()
            await session.edit({"channels": ["#config", "#other"],
                                "channel_keys": {"#other": "k2"}})
            check("an edit can add a keyed channel and drop another",
                  (sorted(sent), store.networks()[0]["channel_keys"]),
                  (["JOIN #other k2", "PART #secret leaving"], {"#other": "k2"}))
            await session.part("#other")
            check("leaving a channel forgets its key",
                  (store.networks()[0]["channel_keys"], session.to_wire()["keyed"]), ({}, []))

            # A raw "/quote JOIN #a,#b k1,k2" is kept in step the same way.
            await session.raw("JOIN #r1,#r2 rawkey")
            check("a raw JOIN's keys are remembered by position",
                  store.networks()[0]["channel_keys"], {"#r1": "rawkey"})

            everything = _json.dumps(hub.frames) + " ".join(
                (e.text or "") + _json.dumps(e.extra)
                for b in store.buffers(include_archived=True)
                for e in store.backlog(b.id, limit=500))
            check("no frame and no stored event ever holds a key",
                  [k for k in ("hunter2", "newkey", "k2", "rawkey") if k in everything], [])
            store.close()

    asyncio.run(run())


def test_raw_answers():
    """What the server says back to a `raw` line is shown, for ten seconds
    (B-R4): the numerics nothing else has a use for, in the Server buffer."""
    print("answers to raw lines (B-R4)")
    from relay.ircproto import parse_line
    import relay.session as session_module

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            session.conn.nick = "me"
            session.conn.registered, session._joined_once = True, True

            def send(line, **k):
                if k.get("on_sent"):
                    k["on_sent"]()
                return True
            session.conn.send = send
            status = session.status_buffer.id

            def shown():
                return [(e.text, e.extra.get("numeric")) for e in store.backlog(status, limit=500)
                        if e.kind == "server"]

            async def feed(*lines):
                for line in lines:
                    await session._on_message(parse_line(line))

            ban = ":s 367 me #c *!*@bad.example op 1758000000"
            await feed(ban)
            check("unasked, a ban list line is dropped as before", shown(), [])

            # THE BUG: /quote MODE #c +b was typed into silence.
            await session.raw("MODE #c +b")
            await feed(ban, ":s 368 me #c :End of channel ban list")
            check("after a raw line, its answer lands in the Server buffer",
                  shown(), [("#c *!*@bad.example op 1758000000", "367"),
                            ("#c End of channel ban list", "368")])
            check("  and reaches the clients as events",
                  [f["event"]["buffer"] for f in hub.of("event")], [status, status])

            # The window closes.
            session._raw_sent = {k: at - session_module.RAW_ANSWER_WINDOW - 1
                                 for k, at in session._raw_sent.items()}
            await feed(ban)
            check("ten seconds on, numerics are the bouncer's own business again",
                  len(shown()), 2)

            # A WHOIS typed by hand has no card waiting, so it is shown; one
            # the app asked for is collected into its card and is not.
            await session.raw("WHOIS alice")
            await session.whois("bob", "r1")
            await feed(":s 311 me alice ~a host.example * :Alice A",
                       ":s 311 me bob ~b host.example * :Bob B",
                       ":s 318 me alice :End of /WHOIS list.")
            check("a hand-typed WHOIS is shown; the app's own lookup is not",
                  shown()[2:], [("alice ~a host.example * Alice A", "311"),
                                ("alice End of /WHOIS list.", "318")])
            check("  and the app's lookup is still collected for its card",
                  session._whois_pending["bob"].data.get("realname"), "Bob B")
            for pending in session._whois_pending.values():
                pending.cancel()

            # A WHO typed by hand, once; the away poll's own replies are not.
            before = len(shown())
            await session.raw("WHO #c")
            await feed(":s 352 me #c ~a host.example s alice H :0 Alice",
                       ":s 315 me #c :End of /WHO list.")
            await feed(":s 352 me #c ~a host.example s alice H :0 Alice",
                       ":s 315 me #c :End of /WHO list.")
            check("a hand-typed WHO is shown, and only the one answer",
                  [n for _, n in shown()[before:]], ["352", "315"])

            # The channel's modes carry its KEY, which is a password: the 324
            # is never shown, whoever asked.
            await session.raw("MODE #c")
            await feed(":s 324 me #c +ntk sesame")
            check("a 324 is never echoed (it holds the channel key)",
                  [t for t, _ in shown() if "sesame" in t], [])

            # Errors go where they always went, not here.
            before = len(shown())
            await feed(":me!u@h JOIN #c")
            await feed(":s 482 me #c :You're not channel operator")
            check("an error numeric is routed to its channel, not the Server buffer",
                  len(shown()), before)

            # A LINKS or a LIST is thousands of lines. The answer is capped.
            await session.raw("LINKS")
            before = len(shown())
            for i in range(session_module.RAW_ANSWER_MAX + 50):
                await feed(f":s 364 me hub{i}.example leaf.example :1 a server")
            tail = shown()[before:]
            check("one raw line shows at most RAW_ANSWER_MAX lines, then says so",
                  (len(tail), tail[-1][0]),
                  (session_module.RAW_ANSWER_MAX + 1,
                   f"(more than {session_module.RAW_ANSWER_MAX} lines of reply; "
                   "the rest are not shown)"))
            store.close()

    asyncio.run(run())


def test_unclean_stop_marker():
    """After a crash, the channels that were joined get the outage line a
    clean stop would have written (B-R3)."""
    print("gap marker after an unclean stop (B-R3)")
    from relay.ircproto import parse_line

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store, hub, session = make_session(tmp)
            session.conn.nick = "me"
            for name in ("#a", "#b", "#closed"):
                await session._on_message(parse_line(f":me!u@h JOIN {name}"))
            a = store.find_buffer(session.network_id, "#a").id
            b = store.find_buffer(session.network_id, "#b").id
            closed = store.find_buffer(session.network_id, "#closed").id
            store.set_archived(closed, True)
            # The last thing anyone said before the lights went out.
            store.append_event(buffer_id=a, network_id=session.network_id, kind="message",
                               sender="alice", text="last words", ts=1790000000.0)

            def lines(bid):
                return [(e.text, e.extra, e.ts) for e in store.backlog(bid, limit=50)
                        if e.kind == "server"]

            # SIGKILL: no _on_disconnected, the database still says joined.
            again = NetworkSession(session.config, store, RecordingHub())
            why = "the bouncer stopped unexpectedly"
            want = (f"Disconnected: {why}", {"connection": "lost", "reason": why}, 1790000000.0)
            check("a channel left joined by a crash gets the outage line",
                  lines(a), [want])
            check("  the same line a clean stop writes, in every such channel", lines(b), [want])
            check("  stamped when the bouncer was last known alive, not at the restart",
                  lines(a)[0][2] < time.time() - 1000, True)
            check("a closed channel is left alone", lines(closed), [])
            check("nothing is joined in the new process",
                  [x.joined for x in store.buffers() if x.kind == "channel"], [False, False])

            again.conn.nick = "me"
            await again._on_message(parse_line(":me!u@h JOIN #a"))
            check("the rejoin closes the gap as after any outage",
                  [(t, e) for t, e, _ in lines(a)][-1],
                  ("Reconnected", {"connection": "restored"}))

            # A clean stop wrote its own line; the next start adds nothing.
            await again._on_disconnected("relay restarting")
            count = len(lines(a))
            NetworkSession(session.config, store, RecordingHub())
            check("a clean stop is not marked twice", len(lines(a)), count)
            check("  and #b, never rejoined, still has just the one", len(lines(b)), 1)
            store.close()

    asyncio.run(run())


def test_burst_holds_live_frames():
    """A client never sees a live event for a buffer before that buffer's
    burst backlog, and never sees one line twice (B-R2)."""
    print("live frames wait for the initial burst (B-R2)")
    import json as _json
    import relay.gateway as gw
    from relay.config import Config
    from relay.hub import Hub

    class NoPush:
        async def send(self, n, d): pass

    class RecordingWS:
        def __init__(self):
            self.sent = []

        async def send_str(self, data):
            self.sent.append(_json.loads(data))

        async def close(self, code, message=b""):
            pass

    class Interrupted(gw.Client):
        """A client whose burst is interrupted where a real one can be: in
        `send`, which waits whenever the queue is over CLIENT_QUEUE_SOFT, and
        the IRC loop runs in that wait. `hooks` says what happens on IRC just
        before a given frame of the burst is queued."""

        hooks: dict = {}

        async def send(self, frame):
            hook = self.hooks.pop((frame["type"], frame.get("buffer")), None)
            if hook:
                hook()
                await asyncio.sleep(0)
            await super().send(frame)

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "burst.db"))
            hub = Hub(store, NoPush())
            session = NetworkSession(NetworkConfig(slug="t", name="T", host="h", nick="me"),
                                     store, hub)
            hub.sessions["t"] = session
            gateway = gw.Gateway(Config(db_path=store.path), store, hub)
            nid = session.network_id
            a = store.get_or_create_buffer(nid, "#a", "channel").id
            z = store.get_or_create_buffer(nid, "#z", "channel").id
            for buf in (a, z):
                for i in range(3):
                    store.append_event(buffer_id=buf, network_id=nid, kind="message",
                                       sender="x", text=f"old {i}")
            token_id = store.verify_token(store.create_token("burst"))

            ws = RecordingWS()
            client = Interrupted(ws, token_id, hub)
            said = []

            def say(buffer_id, text):
                said.append(session._record(buffer_id, "message", sender="y", text=text).eid)

            client.hooks = {
                # While the buffer list is going out -- before either backlog
                # has been read -- someone speaks in both channels.
                ("buffers", None): lambda: (say(a, "early in a"), say(z, "early in z")),
                # And again once #a's backlog has been read and is on its way
                # out: in #a (too late for its backlog) and in #z (in time
                # for its backlog, which has not been read yet).
                ("backlog", a): lambda: (say(a, "late in a"), say(z, "mid in z")),
            }

            # Exactly what handle_ws does around the burst.
            client.start()
            client.hold()
            hub.add(client, ready=False)
            sent_upto = await gateway._send_initial_state(client)
            client.release(sent_upto)
            say(a, "after the burst")
            for _ in range(100):
                if not client.queued_bytes and not client._writing:
                    break
                await asyncio.sleep(0.01)
            check("the burst was interrupted where the test meant it to be", client.hooks, {})

            order = ws.sent
            first_backlog = {f["buffer"]: i for i, f in enumerate(order) if f["type"] == "backlog"}
            live = [(i, f["event"]) for i, f in enumerate(order) if f["type"] == "event"]
            in_backlog = [e["eid"] for f in order if f["type"] == "backlog" for e in f["events"]]
            check("the burst reached both channels", sorted(first_backlog), [a, z])
            check("THE BUG: no live event for a buffer before that buffer's backlog",
                  [e["text"] for i, e in live if i < first_backlog[e["buffer"]]], [])
            check("  nor before the burst is over at all",
                  [e["text"] for i, e in live if i < max(first_backlog.values())], [])
            delivered = in_backlog + [e["eid"] for _, e in live]
            check("no line is delivered twice", len(delivered), len(set(delivered)))
            check("every line said during the burst is delivered",
                  [eid for eid in said if eid not in delivered], [])
            check("a line the backlog already carried is not repeated live",
                  [e["text"] for _, e in live], ["late in a", "after the burst"])
            check("what was held comes out in the order it happened",
                  [e["eid"] for _, e in live], sorted(e["eid"] for _, e in live))
            check("hello is still the first frame", order[0]["type"], "hello")

            # Held frames are bounded like queued ones: a burst that takes so
            # long that megabytes pile up behind it ends the same way.
            gw.CLIENT_QUEUE_MAX, saved_max = 2000, gw.CLIENT_QUEUE_MAX
            slow = gw.Client(RecordingWS(), token_id, hub)
            slow.hold()
            for i in range(20):
                slow.enqueue('{"type":"event","pad":"' + "z" * 400 + '"}')
            await asyncio.sleep(0.05)
            check("too much held during a burst closes the client", slow.closing, True)
            gw.CLIENT_QUEUE_MAX = saved_max
            await client.finish()
            await slow.finish()
            store.close()

    asyncio.run(run())


def test_hello_additions():
    """hello says whether APNs is configured, which page build and database
    this is, and which token attached (contract 2)."""
    print("hello: apns, build, epoch, token, can_pair")
    import json as _json
    import relay.gateway as gw
    from relay.config import Config
    from relay.hub import Hub
    from relay.push import NullPushProvider

    class RealEnough:
        async def send(self, n, d): pass

    class Seen:
        def __init__(self, token_id):
            self.token_id, self.frames = token_id, []
        async def send(self, frame): self.frames.append(frame)

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "h.db"))
            hub = Hub(store, NullPushProvider())
            gateway = gw.Gateway(Config(db_path=store.path), store, hub)
            token_id = store.verify_token(store.create_token("Riley's iPhone"))
            client = Seen(token_id)
            await gateway._send_initial_state(client)
            hello = client.frames[0]
            check("apns is false with only the logging provider", hello["apns"], False)
            check("epoch is the database's", hello["epoch"], store.epoch)
            check("token names the one this socket attached with",
                  hello["token"], {"id": token_id, "label": "Riley's iPhone"})
            check("can_pair", hello["can_pair"], True)
            etag = gateway._read_index(gateway._web_root / "index.html")[2]
            check("build is the page's ETag, without its quotes",
                  (hello["build"], '"' in hello["build"]), (etag.strip('"'), False))
            check("what was there before is still there",
                  [k for k in ("protocol", "server", "max_eid", "resumed", "initial_backlog",
                               "can_upload", "link_previews", "webpush_key", "media_host",
                               "has_networks", "can_add_networks") if k not in hello], [])

            hub.push_provider = RealEnough()
            client = Seen(token_id)
            await gateway._send_initial_state(client)
            check("apns is true with a real provider", client.frames[0]["apns"], True)

            # No web/ beside the bouncer: no page, so no build to compare.
            gateway._web_root = gateway._web_root / "nowhere"
            client = Seen(token_id)
            await gateway._send_initial_state(client)
            check("build is left out when no page is served", "build" in client.frames[0], False)
            store.close()

    asyncio.run(run())


def test_read_elsewhere():
    """A read on one device is pushed, quietly and once, to the others
    (contract 4)."""
    print("read elsewhere: background push to the other devices")
    from relay.hub import Hub, READ_PUSH_DEBOUNCE
    from relay.push import Notification, ReadReceipt

    check("the payload is exactly the contract's",
          ReadReceipt(3, 912, 3).to_apns_payload(),
          {"aps": {"content-available": 1, "badge": 3},
           "relay": {"read": {"buffer": 3, "eid": 912}}})
    check("  and `all` for everything at once",
          ReadReceipt(None, None, 0).to_apns_payload(),
          {"aps": {"content-available": 1, "badge": 0}, "relay": {"read": {"all": True}}})
    check("the debounce is two seconds", READ_PUSH_DEBOUNCE, 2.0)

    class Recorder:
        def __init__(self): self.alerts, self.reads = [], []
        async def send(self, n, devices): self.alerts.append((n, devices))
        async def send_read(self, r, devices):
            self.reads.append((r.to_apns_payload(), sorted(d["apns_token"] for d in devices)))

    class Web:
        def __init__(self): self.sent = []
        async def send(self, n, browsers): self.sent.append(n)

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "r.db"))
            provider = Recorder()
            hub = Hub(store, provider)
            hub.webpush = Web()
            hub.read_push_debounce = 0.05
            nid = store.upsert_network("n", "N", "h", 6667, False, "me")
            buf = store.get_or_create_buffer(nid, "#c", "channel").id
            other = store.get_or_create_buffer(nid, "#d", "channel").id
            phone = store.verify_token(store.create_token("phone"))
            ipad = store.verify_token(store.create_token("ipad"))
            web = store.verify_token(store.create_token("web"))
            store.register_device(phone, "aa11", "ios", "production")
            store.register_device(ipad, "bb22", "ios", "production")
            store.register_webpush(web, "https://push.example/x", "k", "a")
            for i in range(3):
                store.append_event(buffer_id=buf, network_id=nid, kind="message", sender="x",
                                   text="me: hi", highlight=True)
            last = store.newest_eid(buf)

            async def settle():
                await asyncio.sleep(0.15)

            # Reading is a run of mark_reads: one push, with the newest eid.
            hub.read_elsewhere(web, buf, last - 2)
            hub.read_elsewhere(web, buf, last - 1)
            store.mark_read(buf, last - 1)
            await asyncio.sleep(0.01)
            check("nothing is sent before the debounce", provider.reads, [])
            await settle()
            check("one push for a run of reads, to every device not the reader's",
                  provider.reads,
                  [({"aps": {"content-available": 1, "badge": 1},
                     "relay": {"read": {"buffer": buf, "eid": last - 1}}}, ["aa11", "bb22"])])
            check("the badge is the number an alert would carry now",
                  provider.reads[0][0]["aps"]["badge"], store.badge_count())
            check("no web push for a read", hub.webpush.sent, [])

            # The reader's own device is left out.
            provider.reads.clear()
            store.mark_read(buf, last)
            hub.read_elsewhere(phone, buf, last)
            await settle()
            check("the device that read is not pushed to",
                  [devices for _, devices in provider.reads], [["bb22"]])
            check("  and the badge came down with the read",
                  provider.reads[0][0]["aps"]["badge"], 0)

            # Following a channel as it scrolls: nothing to take down, so no
            # push at all -- one a line would be a stream at a phone in a pocket.
            provider.reads.clear()
            for _ in range(3):
                hub.read_elsewhere(web, buf, last)
                await settle()
            check("a read that changes nothing for the other devices is not pushed",
                  provider.reads, [])

            # Until an alert for that buffer has gone out again.
            event = store.append_event(buffer_id=buf, network_id=nid, kind="message",
                                       sender="x", text="me: again", highlight=True)
            await hub.push(Notification(title="#c", body="x: me: again", buffer_id=buf,
                                        eid=event.eid, network="n", badge=store.badge_count()))
            store.mark_read(buf, event.eid)
            hub.read_elsewhere(web, buf, event.eid)
            await settle()
            check("after an alert, the next read of that buffer is pushed",
                  [(p["relay"]["read"], p["aps"]["badge"]) for p, _ in provider.reads],
                  [({"buffer": buf, "eid": event.eid}, 0)])

            # mark_all_read: one push that says so, at once, and in place of
            # whatever single buffers were still waiting their two seconds.
            provider.reads.clear()
            hub.read_elsewhere(ipad, other, 5)
            hub.read_elsewhere(ipad, None)
            await asyncio.sleep(0.01)
            check("mark_all_read is one push, `all`, sent without the wait",
                  provider.reads, [({"aps": {"content-available": 1, "badge": 0},
                                     "relay": {"read": {"all": True}}}, ["aa11"])])
            await settle()
            check("  and it stands for the reads that were waiting", len(provider.reads), 1)

            # Nobody else to tell, and a provider from before read receipts.
            provider.reads.clear()
            store.unregister_device(ipad, "bb22")
            hub.read_elsewhere(phone, None)
            await settle()
            check("with no other device there is nothing to send", provider.reads, [])

            class Old:
                async def send(self, n, d): pass
            hub.push_provider = Old()
            hub.read_elsewhere(web, None)
            await settle()
            check("a provider without send_read is simply not told", True, True)

            hub.cancel_read_pushes()
            hub.read_elsewhere(web, buf, 1)
            check("after shutdown nothing more is scheduled", hub._read_timers, {})
            store.close()

    asyncio.run(run())


def test_presence_ttl():
    """PRESENCE_TTL rides out one late ping (B-R8)."""
    print("presence outlives one late ping (B-R8)")
    from relay.hub import Hub, PRESENCE_TTL

    class NoPush:
        async def send(self, n, d): pass

    class Tab:
        presence, focused_buffer = "foreground", 7
        def __init__(self, heard): self.last_heard = heard
        def enqueue(self, data): pass

    check("the TTL is 70 seconds: two 30-second pings and a margin", PRESENCE_TTL, 70.0)
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(os.path.join(tmp, "p.db"))
        hub = Hub(store, NoPush())
        check("the hub uses it", hub.presence_ttl, PRESENCE_TTL)
        # THE BUG: at 40 seconds, a ping 15 seconds late made someone looking
        # straight at the conversation count as away, and their phone buzzed.
        hub.clients.add(Tab(time.monotonic() - 45))
        check("a ping that is 15 seconds late does not end the watching",
              hub.has_active_viewer(7), True)
        hub.clients.clear()
        hub.clients.add(Tab(time.monotonic() - 75))
        check("two missed pings do", hub.has_active_viewer(7), False)
        store.close()


def test_loop_lag_probe():
    """The loop-lag probe says when the event loop was held, and cannot flood
    the journal doing it (B-R6, the cheap half)."""
    print("loop lag probe (B-R6)")
    import logging
    from relay.app import LAG_WARN_AFTER, watch_loop_lag

    check("it warns past about a quarter of a second", LAG_WARN_AFTER, 0.25)

    class Catch(logging.Handler):
        def __init__(self):
            super().__init__(logging.WARNING)
            self.lines = []

        def emit(self, record):
            self.lines.append(record.getMessage())

    async def run():
        catch = Catch()
        logger = logging.getLogger("relay")
        logger.addHandler(catch)
        propagate, logger.propagate = logger.propagate, False
        # Generous margins: this runs in the deploy gate, on a machine that
        # may be busy, and a stall of its own must not read as a failure.
        probe = asyncio.create_task(watch_loop_lag(interval=0.02, threshold=0.1,
                                                   report_every=1.5))
        try:
            await asyncio.sleep(0.15)
            check("a loop that is running freely says nothing", catch.lines, [])
            for _ in range(4):
                time.sleep(0.2)                # something holding the loop
                await asyncio.sleep(0.04)
            check("the first stall is reported, and only the first",
                  (len(catch.lines), "the event loop was blocked for" in "".join(catch.lines)),
                  (1, True))
            await asyncio.sleep(1.5)
            time.sleep(0.2)
            await asyncio.sleep(0.06)
            check("the next report counts the ones it did not report",
                  (len(catch.lines), "and 3 more since the last report" in catch.lines[-1]),
                  (2, True))
        finally:
            probe.cancel()
            logger.removeHandler(catch)
            logger.propagate = propagate

    asyncio.run(run())


def test_page_gzip():
    """The page is served gzipped to anyone who can take it, compressed once
    per version of the page (W-R2)."""
    print("gzip for the web page (W-R2)")
    import gzip
    from aiohttp.test_utils import make_mocked_request
    from relay import gateway as gw
    from relay.config import Config
    from relay.hub import Hub

    class NoPush:
        async def send(self, n, d): pass

    def accepts(value):
        headers = {"Accept-Encoding": value} if value is not None else {}
        return gw._accepts_gzip(make_mocked_request("GET", "/", headers=headers))

    for value, want in (("gzip", True), ("gzip, deflate, br", True), ("br;q=1.0, gzip;q=0.5", True),
                        ("*", True), ("GZIP", True), (None, False), ("", False),
                        ("identity", False), ("br", False), ("gzip;q=0", False),
                        ("gzip;q=0, *", False), ("*;q=0", False)):
        check(f"Accept-Encoding {value!r}", accepts(value), want)

    with tempfile.TemporaryDirectory() as tmp:
        store = Store(os.path.join(tmp, "g.db"))
        gateway = gw.Gateway(Config(db_path=store.path), store, Hub(store, NoPush()))
        index = gateway._web_root / "index.html"
        page = gateway._read_index(index)[0]

        def get(**headers):
            return asyncio.run(gateway.handle_web(
                make_mocked_request("GET", "/", headers={"Host": "b.example", **headers})))

        plain = get()
        packed = get(**{"Accept-Encoding": "gzip, deflate, br"})
        check("without Accept-Encoding the page is as it is",
              (plain.headers.get("Content-Encoding"), plain.text == page), (None, True))
        check("with it, gzip", packed.headers.get("Content-Encoding"), "gzip")
        check("  which unpacks to the same page",
              gzip.decompress(packed.body).decode("utf-8") == page, True)
        check("  and is a great deal smaller", len(packed.body) < len(page.encode()) / 2, True)
        check("both say the answer depends on Accept-Encoding",
              (plain.headers.get("Vary"), packed.headers.get("Vary")),
              ("Accept-Encoding", "Accept-Encoding"))
        check("the ETag is the page's either way, and still a strong one",
              (packed.headers["ETag"], plain.headers["ETag"].startswith('"')),
              (plain.headers["ETag"], True))
        check("the policy is the same either way",
              packed.headers["Content-Security-Policy"], plain.headers["Content-Security-Policy"])
        check("  and its hashes are of the scripts in the unpacked page",
              all(f"'sha256-{h}'" in packed.headers["Content-Security-Policy"]
                  for h in gw.inline_script_hashes(gzip.decompress(packed.body).decode())), True)
        check("still text/html in utf-8",
              (packed.content_type, packed.charset), ("text/html", "utf-8"))

        fresh = get(**{"Accept-Encoding": "gzip", "If-None-Match": packed.headers["ETag"]})
        check("a browser that has it still gets a 304 with no body",
              (fresh.status, fresh.body, fresh.headers.get("Vary"),
               fresh.headers.get("Content-Encoding")), (304, None, "Accept-Encoding", None))

        check("compressed once per version of the page, not once per request",
              gateway._read_index(index)[3] is gateway._read_index(index)[3], True)
        check("  and byte for byte the same on any bouncer (no timestamp in it)",
              gateway._read_index(index)[3], gzip.compress(page.encode("utf-8"), 9, mtime=0))
        store.close()


def test_pairing_codes():
    """Pairing codes: unambiguous, single use, five minutes, five at once,
    and gone with the token that made them (contract 3)."""
    print("pairing codes")
    import relay.gateway as gw
    from relay.config import Config
    from relay.hub import Hub

    class NoPush:
        async def send(self, n, d): pass

    class FakeWS:
        async def send_str(self, data): pass
        async def close(self, code, message=b""): pass

    check("the alphabet has nothing that reads as something else",
          [c for c in "0O1IL" if c in gw.PAIR_ALPHABET], [])
    check("  and is upper case and digits only",
          all(c.isupper() or c.isdigit() for c in gw.PAIR_ALPHABET), True)
    check("a code is typed however it comes: case, spaces, a dash",
          gw.clean_pair_code(" abcd-efgh "), "ABCDEFGH")
    for bad in ("", "ABC", "ABCDEFGHJ", None, 12345678, "A" * 500):
        check(f"not a code: {str(bad)[:10]!r}", gw.clean_pair_code(bad), "")
    check("a label is trimmed", gw.clean_label("  Riley's  iPad "), "Riley's iPad")
    for bad in ("", "   ", "x" * 65, "bell\x07", None, 7):
        check(f"not a label: {str(bad)[:10]!r}", gw.clean_label(bad), None)

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "pair.db"))
            hub = Hub(store, NoPush())
            gateway = gw.Gateway(Config(db_path=store.path), store, hub)
            maker = store.verify_token(store.create_token("mac"))
            client = gw.Client(FakeWS(), maker, hub)
            client.host = "bouncer.example"

            ticket = gateway._new_pairing(client, "iPad")
            check("a code is eight characters of the alphabet",
                  (len(ticket.code), all(c in gw.PAIR_ALPHABET for c in ticket.code)), (8, True))
            check("a wrong code redeems nothing",
                  gateway._redeem_pairing("ZZZZZZZZ" if ticket.code != "ZZZZZZZZ" else "YYYYYYYY"),
                  None)
            got = gateway._redeem_pairing(ticket.code)
            check("the right one does, with its label and host",
                  (got.label, got.host, got.token_id), ("iPad", "bouncer.example", maker))
            check("once", gateway._redeem_pairing(ticket.code), None)

            codes = [gateway._new_pairing(client, f"d{i}").code for i in range(gw.MAX_PAIRINGS + 2)]
            check("at most five wait at once", len(gateway._pairings), gw.MAX_PAIRINGS)
            check("  the oldest gave way, the newest all work",
                  ([gateway._redeem_pairing(c) is not None for c in codes]),
                  [False, False, True, True, True, True, True])

            old = gateway._new_pairing(client, "slow")
            old.created -= gw.PAIR_TTL + 1
            check("a code is gone after five minutes", gateway._redeem_pairing(old.code), None)

            orphan = gateway._new_pairing(client, "after sign-out")
            store.revoke_token(maker)
            check("a code dies with the token that made it",
                  gateway._redeem_pairing(orphan.code), None)
            store.close()

    asyncio.run(run())


def test_deploy_script():
    """deploy.sh installs requirements into the remote venv before anything
    is swapped, and gates on every test script. Read, never run: it sshes."""
    print("deploy.sh: pip before the swap, all five test scripts")
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if not os.path.exists(os.path.join(here, "deploy.sh")):
        print("  (no deploy.sh in this checkout; skipped)")
        return
    script = open(os.path.join(here, "deploy.sh")).read()
    remote = script[script.index("<<'REMOTE_SCRIPT'"):script.index("\nREMOTE_SCRIPT\n")]
    unpack = remote.index('tar -xzf "/tmp/$BASENAME" -C "$STAGE"')
    pip = remote.index('-m pip install')
    parse = remote.index("ast.parse")
    swap = remote.index('mv "$STAGE/relay" "$REMOTE/relay"')
    check("requirements are installed after unpacking and before the parse check and the swap",
          unpack < pip < parse < swap, True)
    install = remote[pip - 200:pip + 300]
    check("with the remote venv's own interpreter, from the staged file, quietly",
          ('"$PY" -m pip install' in install, '"$STAGE/requirements.txt"' in install,
           " -q " in install or "--quiet" in install), (True, True, True))
    check("and a failure stops the deploy there", "exit 1" in install, True)
    check("nothing has been moved by then",
          [w for w in ('mv "$REMOTE/relay"', "install_web", "systemctl restart")
           if w in remote[:pip]], [])
    tests = sorted(f for f in os.listdir(os.path.join(here, "tests")) if f.startswith("test_"))
    check("there are five test scripts", len(tests), 5)
    check("the deploy is gated on every one of them",
          [t for t in tests if t[:-3] not in script], [])


def test_upload_keys_and_delete():
    print("uploads: random names, and deleting")
    from relay.uploads import (DELETE_DENIED, NOT_OURS, UploadConfig, Uploader, _KEY_RE)

    class FakeS3:
        def __init__(self):
            self.deleted = []
            self.fail = None

        def generate_presigned_url(self, op, Params, ExpiresIn):
            return f"https://acct.r2.example/{Params['Bucket']}/{Params['Key']}?sig=1"

        def delete_object(self, Bucket, Key):
            if self.fail:
                raise self.fail
            self.deleted.append((Bucket, Key))

    up = Uploader(UploadConfig(endpoint="https://acct.r2.example", bucket="b",
                               access_key="a", secret_key="s",
                               public_base="https://img.example"))
    up.available = True            # boto3 may not be installed where this runs
    up._client = fake = FakeS3()

    # --- the key carries nothing of the filename -----------------------------
    names = ["tax return 2026.pdf", "IMG_4021.HEIC", "../../etc/passwd", "mom's passport.jpg", ""]
    types = ["application/pdf", "image/heic", "image/png", "image/jpeg", "text/plain"]
    keys = []
    for name, ctype in zip(names, types):
        r = up.presign(filename=name, content_type=ctype, size=10)
        key = r["public_url"].removeprefix("https://img.example/")
        keys.append(key)
        check(f"random key for {name!r}", bool(_KEY_RE.fullmatch(key)), True)
        low = key.lower()
        check(f"nothing of {name!r} survives in the key",
              not any(w in low for w in ("tax", "return", "img_4021", "passwd", "passport", "mom")),
              True)
        check(f"extension comes from the content type ({ctype})",
              key.rsplit(".", 1)[-1], {"application/pdf": "pdf", "image/heic": "heic",
                                       "image/png": "png", "image/jpeg": "jpg",
                                       "text/plain": "txt"}[ctype])
    check("keys are all different", len(set(keys)), len(keys))
    r = up.presign(filename="x.jpg", content_type="image/jpeg", size=10)
    check("the signed URL is for the same key as the public one",
          r["upload_url"].split("/b/")[1].split("?")[0],
          r["public_url"].removeprefix("https://img.example/"))

    # --- which links name one of ours ----------------------------------------
    own = "2026/10/" + "A" * 22 + ".png"
    legacy = "2026/09/" + "b-_9" * 5 + "Zz" + "-photo.jpg"        # token + name (before 2026-10-11)
    check("a new-style link", up.key_for_url("https://img.example/" + own), own)
    check("a legacy link", up.key_for_url("https://img.example/" + legacy), legacy)
    check("a query on a shared link is ignored",
          up.key_for_url("https://img.example/" + own + "?x=1#y"), own)
    check("host case is not a difference",
          up.key_for_url("https://IMG.example/" + own), own)
    for label, bad in [
            ("another host", "https://evil.example/" + own),
            ("a look-alike host", "https://img.example.evil.example/" + own),
            ("plain http", "http://img.example/" + own),
            ("another port", "https://img.example:8443/" + own),
            ("credentials in the address", "https://user@img.example/" + own),
            ("the bucket root", "https://img.example/"),
            ("a key that is not ours (the otherbot's pictures)", "https://img.example/ab12cd3.png"),
            ("a backup", "https://img.example/state-backups/0123456789abcdef/otherbot-20261010.tar.gz"),
            ("a short token", "https://img.example/2026/10/short.png"),
            ("an extension we never write", "https://img.example/2026/10/" + "A" * 22 + ".html"),
            ("a path that climbs", "https://img.example/2026/10/../" + own),
            ("a percent-escape", "https://img.example/2026/10/%41" + "A" * 21 + ".png"),
            ("not a string", None),
            ("empty", ""),
            ("not a URL", "banana")]:
        check(f"refused: {label}", up.key_for_url(bad), None)

    # --- deleting --------------------------------------------------------------
    check("delete returns the key", up.delete("https://img.example/" + own), own)
    check("and asks storage to remove exactly that", fake.deleted, [("b", own)])
    for label, bad in [("a file that is not ours", "https://img.example/ab12cd3.png"),
                       ("another host", "https://evil.example/" + own)]:
        try:
            up.delete(bad)
            got = "deleted"
        except ValueError as exc:
            got = str(exc)
        check(f"delete refuses {label}", got, NOT_OURS)
    check("and nothing else was removed", fake.deleted, [("b", own)])

    class Denied(Exception):
        response = {"Error": {"Code": "AccessDenied"}}
    fake.fail = Denied("denied")
    try:
        up.delete("https://img.example/" + own)
        got = "deleted"
    except ValueError as exc:
        got = str(exc)
    check("a storage key without delete permission says so", got, DELETE_DENIED)
    fake.fail = RuntimeError("storage fell over")
    try:
        up.delete("https://img.example/" + own)
        got = "deleted"
    except RuntimeError:
        got = "raised"          # the gateway turns this into NOT_DELETED
    check("any other storage failure is the gateway's to report", got, "raised")
    up.available = False
    try:
        up.delete("https://img.example/" + own)
        got = "deleted"
    except ValueError as exc:
        got = str(exc)
    check("with no S3 library it is the same sentence as upload", got,
          "Uploads aren't set up on this bouncer.")

    # --- the frame, through the gateway's own dispatcher --------------------
    from types import SimpleNamespace
    from relay.gateway import Gateway

    class Client:
        def __init__(self):
            self.replies = []

        async def ok(self, req, **fields):
            self.replies.append(("ok", req, fields))

        async def error(self, req, message):
            self.replies.append(("error", req, message))

    def call(uploader, frame):
        client = Client()
        noop_store = SimpleNamespace(record_upload=lambda *a, **k: None,
                                     mark_upload_deleted=lambda *a, **k: None,
                                     list_uploads=lambda **k: [])
        asyncio.run(Gateway._dispatch(SimpleNamespace(uploader=uploader, store=noop_store),
                                      client, frame))
        return client.replies

    up.available = True
    fake.fail = None
    fake.deleted.clear()
    url = "https://img.example/" + own
    check("delete_upload: ok, and says which link",
          call(up, {"type": "delete_upload", "req": "c1", "url": url}),
          [("ok", "c1", {"deleted": url})])
    check("  and it went to storage", fake.deleted, [("b", own)])
    check("delete_upload: somebody else's file is a sentence, not a crash",
          call(up, {"type": "delete_upload", "req": "c2", "url": "https://img.example/ab12cd3.png"}),
          [("error", "c2", NOT_OURS)])
    check("delete_upload: no url",
          call(up, {"type": "delete_upload", "req": "c3"})[0][0], "error")
    check("delete_upload: a url that is not text",
          call(up, {"type": "delete_upload", "req": "c4", "url": {"x": 1}})[0][0], "error")
    check("delete_upload: no bucket configured",
          call(None, {"type": "delete_upload", "req": "c5", "url": url}),
          [("error", "c5", "Uploads aren't set up on this bouncer.")])
    fake.fail = RuntimeError("storage fell over: secret-detail-for-the-journal")
    got = call(up, {"type": "delete_upload", "req": "c6", "url": url})
    check("delete_upload: a storage failure is a sentence, with no detail in it",
          got, [("error", "c6", "The file could not be deleted. Try again in a moment.")])
    fake.fail = Denied("denied")
    check("delete_upload: a key that cannot delete says so",
          call(up, {"type": "delete_upload", "req": "c7", "url": url}),
          [("error", "c7", DELETE_DENIED)])


def test_upload_expiry_and_list():
    print("uploads: a timer, a list, and a sweeper")
    import asyncio
    import tempfile
    import types
    from relay.gateway import Gateway
    from relay.store import Store
    from relay.uploads import MAX_TTL, MIN_TTL, UploadConfig, Uploader

    with tempfile.TemporaryDirectory() as tmp:
        store = Store(os.path.join(tmp, "u.db"))
        now = 1_000_000.0
        keys = [f"2026/10/{c * 22}.png" for c in "ABCD"]
        store.record_upload(keys[0], "image/png", 10, now, None)          # stays
        store.record_upload(keys[1], "image/png", 11, now + 1, now + 60)  # due soon
        store.record_upload(keys[2], "image/png", 12, now + 2, now + 9999)
        store.record_upload(keys[3], "image/png", 13, now + 3, now + 30)  # never sent
        store.mark_uploads_sent(keys[:3])
        listed = [r["key"] for r in store.list_uploads(before=None, limit=10)]
        check("the list is newest first and leaves out what was never sent",
              listed, [keys[2], keys[1], keys[0]])
        check("it pages by created",
              [r["key"] for r in store.list_uploads(before=now + 2, limit=10)], [keys[1], keys[0]])
        check("a file not yet due is not due", [r["key"] for r in store.due_uploads(now + 10)], [])
        check("due files come out soonest first, sent or not",
              [r["key"] for r in store.due_uploads(now + 100)], [keys[3], keys[1]])

        class FakeUploader:
            available = True
            config = types.SimpleNamespace(public_base="https://img.example")

            def __init__(self):
                self.deleted, self.fail = [], set()

            def delete(self, url):
                key = url.removeprefix("https://img.example/")
                if key in self.fail:
                    raise ValueError("denied")
                self.deleted.append(key)
                return key

        fake = FakeUploader()
        fake.fail.add(keys[3])
        gw = types.SimpleNamespace(uploader=fake, store=store, _upload_sweep_failed=set())
        import time as _time
        real_time = _time.time
        _time.time = lambda: now + 100
        try:
            done = asyncio.run(Gateway.sweep_uploads(gw))
            check("the sweep deletes what is due and counts it", (done, fake.deleted), (1, [keys[1]]))
            check("a refusal is remembered, once", gw._upload_sweep_failed, {keys[3]})
            fake.fail.clear()
            done = asyncio.run(Gateway.sweep_uploads(gw))
            check("a retry succeeds and clears it", (done, gw._upload_sweep_failed), (1, set()))
        finally:
            _time.time = real_time
        check("a deleted file leaves the list",
              [r["key"] for r in store.list_uploads(before=None, limit=10)], [keys[2], keys[0]])
        check("nothing is left due", store.due_uploads(now + 100), [])

    up = Uploader(UploadConfig(endpoint="https://e", bucket="b", access_key="a",
                               secret_key="s", public_base="https://img.example"))
    up.available = True
    up._client = types.SimpleNamespace(
        generate_presigned_url=lambda op, Params, ExpiresIn: "https://e/" + Params["Key"])
    check("no ttl: the file stays",
          up.presign(filename="", content_type="image/png", size=1)["expires_at"], None)
    r = up.presign(filename="", content_type="image/png", size=1, ttl=3600)
    check("a ttl is counted from now", 3590 < r["expires_at"] - __import__("time").time() <= 3600, True)
    for bad in (MIN_TTL - 1, MAX_TTL + 1, -5):
        try:
            up.presign(filename="", content_type="image/png", size=1, ttl=bad)
            check(f"ttl {bad} is refused", True, False)
        except ValueError:
            check(f"ttl {bad} is refused", True, True)


def test_upload_cache_protection():
    """A deleted file must stop loading. Cloudflare caches an object with no
    Cache-Control for four hours, so every upload is marked no-store before its
    link goes out (measured against the live bucket 2026-10-11: HIT after
    delete without it, BYPASS then 404 with it)."""
    print("uploads: a folder per person")
    from relay.uploads import UploadConfig, Uploader, _KEY_RE, key_pattern

    def folder_uploader(prefix):
        u = Uploader(UploadConfig(endpoint="https://acct.r2.example", bucket="b",
                                  access_key="a", secret_key="s",
                                  public_base="https://img.example", prefix=prefix))
        u.available = True

        class _S3:
            deleted = []

            def generate_presigned_url(self, op, Params, ExpiresIn):
                return f"https://acct.r2.example/{Params['Bucket']}/{Params['Key']}?sig=1"

            def delete_object(self, Bucket, Key):
                self.deleted.append(Key)
        u._client = _S3()
        return u

    morgan = folder_uploader("morgan")
    r = morgan.presign(filename="x.png", content_type="image/png", size=10)
    pub = r["public_url"].removeprefix("https://img.example/")
    check("a prefixed key starts with the folder, then year/month", pub.split("/")[0], "morgan")
    check("the folder is followed by YYYY/MM/<name>.<ext>",
          bool(key_pattern("morgan").fullmatch(pub)), True)
    check("the signed URL is for that same key",
          r["upload_url"].split("/b/")[1].split("?")[0], pub)
    check("its own link is recognised", morgan.key_for_url("https://img.example/" + pub), pub)
    check("it can delete its own file", morgan.delete("https://img.example/" + pub), pub)
    plain = "2026/10/" + "A" * 22 + ".png"
    check("an older, unprefixed upload of its own still counts",
          morgan.key_for_url("https://img.example/" + plain), plain)
    other = "rowan/2026/10/" + "A" * 22 + ".png"
    check("another folder's file is not this bouncer's to touch",
          morgan.key_for_url("https://img.example/" + other), None)
    check("a folder that merely looks like one is refused",
          morgan.key_for_url("https://img.example/morgan/../2026/10/" + "A" * 22 + ".png"), None)
    check("with no prefix a key is the plain shape",
          bool(_KEY_RE.fullmatch(folder_uploader("").presign(
              filename="", content_type="image/png", size=10)["public_url"]
              .removeprefix("https://img.example/"))), True)
    renamed = Uploader(UploadConfig(endpoint="https://acct.r2.example", bucket="b",
                                    access_key="a", secret_key="s",
                                    public_base="https://img.example", prefix="quinn",
                                    old_prefixes=("riley",)))
    oldkey = "riley/2026/10/" + "A" * 22 + ".png"
    check("a renamed folder's old files are still its own",
          renamed.key_for_url("https://img.example/" + oldkey), oldkey)
    check("and the new folder works", renamed.key_for_url(
        "https://img.example/quinn/2026/10/" + "A" * 22 + ".png") is not None, True)
    check("another person's folder is still not", renamed.key_for_url(
        "https://img.example/" + other), None)
    check("an unprefixed bouncer does not accept a folder it was not given",
          folder_uploader("").key_for_url("https://img.example/" + other), None)
    import os
    os.environ.update(GEYEM_S3_ENDPOINT="https://e", GEYEM_S3_BUCKET="b",
                      GEYEM_S3_ACCESS_KEY="a", GEYEM_S3_SECRET_KEY="s",
                      GEYEM_S3_PUBLIC_BASE="https://img.example")
    for raw, want in (("morgan", "morgan"), (" Rowan/ ", ""), ("../x", ""), ("a b", ""), ("", "")):
        os.environ["GEYEM_UPLOAD_PREFIX"] = raw
        check(f"GEYEM_UPLOAD_PREFIX {raw!r}", UploadConfig.from_env().prefix, want)
    os.environ["GEYEM_UPLOAD_PREFIX"] = "quinn"
    os.environ["GEYEM_UPLOAD_PREFIX_ALSO"] = "riley, bad name,quinn,rowan"
    check("old folders are read, junk and the current one dropped",
          UploadConfig.from_env().old_prefixes, ("riley", "rowan"))
    del os.environ["GEYEM_UPLOAD_PREFIX_ALSO"]
    del os.environ["GEYEM_UPLOAD_PREFIX"]

    print("uploads: uncacheable before the link goes out")
    import inspect
    from types import SimpleNamespace
    from relay.gateway import Gateway
    from relay.uploads import CACHE_CONTROL, UploadConfig, Uploader

    class FakeS3:
        def __init__(self):
            self.heads = {}
            self.copies = []
            self.fail = None

        def head_object(self, Bucket, Key):
            if self.fail:
                raise self.fail
            return dict(self.heads.get(Key, {"ContentType": "image/png"}))

        def copy_object(self, **kw):
            self.copies.append(kw)

    up = Uploader(UploadConfig(endpoint="https://acct.r2.example", bucket="b",
                               access_key="a", secret_key="s",
                               public_base="https://img.example"))
    up.available = True
    up._client = fake = FakeS3()
    k1 = "2026/10/" + "A" * 22 + ".png"
    k2 = "2026/10/" + "B" * 22 + ".jpg"
    legacy = "2026/09/" + "C" * 22 + "-photo.jpg"

    check("CACHE_CONTROL is no-store", CACHE_CONTROL, "no-store")

    # --- finding the links in a line ----------------------------------------
    check("a link in a sentence", up.keys_in(f"oops https://img.example/{k1} sorry"), [k1])
    check("trailing punctuation is not part of the link",
          up.keys_in(f"see https://img.example/{k1}."), [k1])
    check("two, in order, once each",
          up.keys_in(f"https://img.example/{k2} and https://img.example/{k1} https://img.example/{k2}"),
          [k2, k1])
    check("a legacy name", up.keys_in(f"https://img.example/{legacy}"), [legacy])
    check("somebody else's link is not ours",
          up.keys_in("https://img.example/ab12cd3.png https://elsewhere.example/" + k1), [])
    check("a line with no link", up.keys_in("hello"), [])
    check("not text", up.keys_in(None), [])
    check("at most three",
          len(up.keys_in(" ".join(f"https://img.example/2026/10/{chr(65 + i) * 22}.png"
                                  for i in range(6)))), 3)

    # --- marking one ----------------------------------------------------------
    check("an unmarked object is changed", up.protect(k1), True)
    check("with its content type kept, and replaced not merged",
          fake.copies,
          [{"Bucket": "b", "Key": k1, "CopySource": {"Bucket": "b", "Key": k1},
            "MetadataDirective": "REPLACE", "ContentType": "image/png",
            "CacheControl": "no-store"}])
    fake.heads[k2] = {"ContentType": "image/jpeg", "CacheControl": "no-store"}
    check("one already marked is left alone", up.protect(k2), False)
    check("  and nothing was copied for it", len(fake.copies), 1)
    fake.heads[legacy] = {"ContentType": "image/jpeg", "CacheControl": "max-age=14400"}
    check("one with some other Cache-Control is replaced", up.protect(legacy), True)
    check("  keeping its image/jpeg", fake.copies[-1]["ContentType"], "image/jpeg")
    try:
        up.protect("ab12cd3.png")
        got = "marked"
    except ValueError:
        got = "refused"
    check("a key that is not ours is never touched", got, "refused")

    # --- the gateway step -----------------------------------------------------
    def run(text, uploader=up):
        fake_self = SimpleNamespace(uploader=uploader)
        asyncio.run(Gateway._protect_upload_links(fake_self, text))

    fake.copies.clear()
    fake.heads.clear()
    run(f"here https://img.example/{k1}")
    check("a say that links an upload marks it", [c["Key"] for c in fake.copies], [k1])
    fake.copies.clear()
    run("no links here")
    run("https://example.com/x.png")
    check("other lines cost storage nothing", fake.copies, [])
    fake.fail = RuntimeError("storage fell over")
    run(f"here https://img.example/{k1}")      # must not raise: the line still goes out
    check("a storage failure does not stop the line", True, True)
    run(f"here https://img.example/{k1}", uploader=None)
    check("with no bucket it is a no-op", True, True)

    # And the say branch actually calls it, before the line is queued.
    source = inspect.getsource(Gateway._dispatch)
    branch = source[source.index("if type_ == P.C_SAY:"):]
    branch = branch[:branch.index("if type_ == P.C_TYPING:")]
    check("C_SAY protects links before queueing the line",
          0 <= branch.find("self._protect_upload_links(text)") < branch.find("queue_say"), True)


def main():
    for fn in (test_parser, test_format, test_line_safety, test_message_splitting,
               test_ctcp_limits, test_nick_reclaim, test_quit_hosts, test_casemapping, test_isupport,
               test_highlight, test_strip, test_netsplit, test_paging,
               test_detached, test_push_sound, test_migration, test_migration_from_v6, test_qauth,
               test_store, test_search,
               test_whois_timeout, test_decode_fallback, test_flood_bucket, test_join_batching,
               test_reconnect_loop, test_say_echo_on_write, test_membership_frames,
               test_mode_parsing, test_member_deltas, test_failure_words,
               test_outage_lines, test_error_routing, test_notify_levels,
               test_topic_on_join, test_highlight_words_owned, test_mark_all_read,
               test_away_persisted, test_raw_lines, test_channel_list,
               test_invite_and_wallops,
               test_wanted_channels,
               test_unread_rules, test_typing, test_client_queue, test_token_revocation,
               test_registration_paths, test_dead_link, test_wire_hygiene, test_input_bounds,
               test_auth_throttle, test_preview_requests_bounded, test_db_private,
               test_network_connect_controls,
               test_secret_redaction, test_secret_scrub_migration, test_unread_cache, test_background_queue_bounded, test_server_time, test_network_frame_and_isupport,
               test_network_fields, test_config_network_edits, test_buffer_ids_never_reused,
               test_edge_cases, test_asset_versions,
               # audit 2026-09-26
               test_remove_network_with_ignores, test_highlight_on_fallback_nick,
               test_join_task_bound_to_connection, test_names_topic_unjoined,
               test_hello_first_with_auto_away, test_tag_unescape_and_spaces,
               test_presence_expires, test_instant_reclaim, test_health_irc_flag,
               test_log_hygiene, test_backup_every_instance,
               # the polish contract, 2026-10
               test_migration_from_v8, test_epoch, test_say_nonce, test_channel_keys,
               test_raw_answers, test_unclean_stop_marker, test_burst_holds_live_frames,
               test_hello_additions, test_read_elsewhere, test_presence_ttl,
               test_loop_lag_probe, test_page_gzip, test_pairing_codes, test_deploy_script,
               test_upload_keys_and_delete, test_upload_cache_protection,
               test_upload_expiry_and_list):
        fn()
    print()
    if FAILED:
        print(f"{len(FAILED)} FAILURE(S):")
        for f in FAILED:
            print(f"  - {f}")
        return 1
    print("all unit tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
