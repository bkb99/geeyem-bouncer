"""SQLite-backed state: buffers, backlog, member lists, tokens, devices.

Why SQLite and not Postgres: the working set is one person's IRC history. A
decade of a busy channel is a few hundred megabytes, every query is "the last N
rows of one buffer", and the box already has enough running on it. SQLite in WAL
mode does that with no daemon, no port, no password, and a backup that is a file
copy. If this ever grows past one user, see docs/ARCHITECTURE.md -- the schema
is already keyed to survive the move.

THE EID. Every stored event gets an `eid` from a single AUTOINCREMENT sequence
shared by every buffer on every network. That gives three things at once:
  - a total order that matches arrival order, across buffers;
  - a cursor for paging backlog that can never repeat or be reused (AUTOINCREMENT,
    not rowid reuse), so "everything after 1234" is exactly right after a delete;
  - a read marker that is one integer per buffer.
Clients never invent an eid. They echo one back.

Threading: every call here runs on the event loop thread. The writes are single
small INSERTs and the reads are indexed range scans, both far below the point
where blocking the loop matters. If that stops being true the fix is a writer
thread behind an asyncio.Queue, not a different database.
"""

from __future__ import annotations

import copy
import functools
import json
import logging
import os
import re
import secrets
import sqlite3
import time
import unicodedata
from dataclasses import dataclass
from typing import Any, Iterable

from .ircproto import fold, strip_formatting

log = logging.getLogger("relay.store")


SCHEMA_VERSION = 10


# --- search terms --------------------------------------------------------------

@dataclass(frozen=True)
class SearchTerm:
    """One word or "quoted phrase" of a search, as the store will use it.

    `fts` is the term quoted for FTS5 and marked as a prefix, or None when it
    has no letters or digits for FTS5 to index ("((", ":)"). `literal` is the
    term itself when it holds punctuation FTS5 would throw away, so the line
    must also contain it as typed ("c++", "quinn:", "img.example.com").
    """

    text: str
    fts: str | None
    literal: str | None


# A "quoted phrase", or a run of anything but spaces and quotes. A quote with
# no partner matches neither and is skipped, so '"unterminated' is a search
# for the word, not an error.
_TERM = re.compile(r'"([^"]*)"|([^\s"]+)')

# How much one search may ask for. Every term is a prefix match joined to the
# rest with AND, and the query runs on the event loop: a search of 20000
# one-letter words over 30000 lines held the whole bouncer -- the IRC link,
# every client -- for 68 seconds, most of the way to a ping timeout. Nobody
# types more than a handful of words into a search box.
MAX_SEARCH_CHARS = 300
MAX_SEARCH_TERMS = 12


def search_terms(query: str) -> list[SearchTerm]:
    """Split a plain-text search into terms. Never raises, whatever is typed."""
    out: list[SearchTerm] = []
    for match in _TERM.finditer(query):
        phrase, word = match.group(1), match.group(2)
        if phrase is not None:
            text = " ".join(phrase.split())
        else:
            # A trailing * was FTS5's prefix syntax, which older clients let
            # people type. Every term is a prefix now, so it means nothing.
            text = word.rstrip("*")
        if not text:
            continue
        has_word = any(ch.isalnum() for ch in text)
        punctuated = any(not (ch.isalnum() or ch.isspace()) for ch in text)
        fts = '"' + text.replace('"', '""') + '"*' if has_word else None
        out.append(SearchTerm(text=text, fts=fts, literal=text if punctuated else None))
    return out


@functools.lru_cache(maxsize=64)
def _fold_needle(text: str) -> str:
    return _fold_text(text)


def _fold_text(text: str) -> str:
    """Text as search compares it: formatting codes out, accents off, curly
    apostrophes straightened, whitespace runs single, case folded."""
    text = unicodedata.normalize("NFKD", strip_formatting(text))
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = text.replace("’", "'").replace("‘", "'")
    return " ".join(text.split()).casefold()


def _has_literal(text: str | None, needle: str) -> int:
    """SQL geeyem_has(text, needle): does the line contain the term as typed?"""
    if not text:
        return 0
    return 1 if _fold_needle(needle) in _fold_text(text) else 0


# SQL: is the column all ASCII? One character per byte. (GLOB '*[^ -~]*' says
# the same and is seven times slower.)
_ASCII = "length({col}) = length(CAST({col} AS BLOB))"


def _fold_or_none(nick: str | None) -> str | None:
    """SQL geeyem_fold(sender): a nick as IRC compares it (rfc1459)."""
    return fold(nick) if nick else None


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- A network is configurable at runtime, not only from config.json. The app asks
-- the user for a nick and a server on first launch, the way a client should,
-- rather than making them edit a file on a server they may not have open.
CREATE TABLE IF NOT EXISTS networks (
    id         INTEGER PRIMARY KEY,
    slug       TEXT UNIQUE NOT NULL,
    name       TEXT NOT NULL,
    host       TEXT NOT NULL,
    port       INTEGER NOT NULL,
    tls        INTEGER NOT NULL DEFAULT 0,
    nick       TEXT NOT NULL,
    created_at REAL NOT NULL,
    username   TEXT NOT NULL DEFAULT '',
    realname   TEXT NOT NULL DEFAULT '',
    -- JSON list: the wanted-channel set, i.e. what is joined on every connect.
    -- Written on every client join and part, so a restart does not undo them.
    channels   TEXT NOT NULL DEFAULT '[]',
    enabled    INTEGER NOT NULL DEFAULT 1,
    -- Where the network came from. A network defined in config.json is not
    -- deletable from a client: the file would recreate it on the next restart
    -- and the deletion would look like it silently failed.
    source     TEXT NOT NULL DEFAULT 'client',
    -- JSON list: config.json's channels for this network as of the last start.
    -- Kept so the next start can tell a channel newly added to the file (join
    -- it) from one the user has since parted (leave it parted). See
    -- app.merge_wanted_channels.
    config_channels TEXT NOT NULL DEFAULT '[]',
    -- JSON list: words besides the nick that count as a mention. NULL until
    -- first seeded from config.json; from then on this is the copy that
    -- counts, and a client changes it with `set_settings`.
    highlight_words TEXT,
    -- The away message the user set, or NULL. Persisted so it survives a
    -- reconnect and a restart; see session.set_away.
    away            TEXT,
    -- JSON list: nicks to fall back on when `nick` is taken, in order.
    alt_nicks       TEXT NOT NULL DEFAULT '[]',
    q_username      TEXT,
    -- Secrets a client set with `edit_network`. Never sent back to a client
    -- (the network frame says only whether one is set), never logged. This
    -- file is mode 600 on the VPS and its backups are encrypted. The Q
    -- password of a network in config.json is not here: it stays in .env.
    server_password TEXT,
    sasl_mechanism  TEXT,
    sasl_username   TEXT,
    sasl_password   TEXT,
    q_password      TEXT,
    -- JSON list of the fields a client has edited on a network defined in
    -- config.json. Those fields are read from this row from then on; every
    -- other field keeps following the file. See app.Relay.run.
    edited          TEXT NOT NULL DEFAULT '[]',
    -- The nick the network is actually using right now, which on a fallback
    -- (quinn_) is not `nick`. `nick` is the one asked for. They used to be the
    -- same column, so a fallback taken once became the nick asked for on
    -- every later start.
    current_nick    TEXT,
    -- JSON object: the key of each wanted channel that has one (+k), by the
    -- channel's rfc1459-folded name. Beside `channels` rather than inside it,
    -- so that list stays a list of names: it is what the network frame shows,
    -- and a key is a password. Never sent to a client, never logged.
    channel_keys    TEXT NOT NULL DEFAULT '{}'
);

-- Settings that belong to the user rather than to a network or a buffer, one
-- JSON value per key: push_preview, auto_away.
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- A buffer is anything a client can display a list of lines for: a channel, a
-- private query, or the per-network status window that connection notices and
-- server numerics land in. Storing all three in one table is what lets the
-- client treat them identically.
--
-- AUTOINCREMENT, so an id is never handed out twice. Without it SQLite reuses
-- the highest id after that row is deleted, and a removed network's buffers
-- came back as some new conversation's ids -- under a permalink, a client's
-- stored scroll position, or a collapsed-rows key that still named the old one.
CREATE TABLE IF NOT EXISTS buffers (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id    INTEGER NOT NULL REFERENCES networks(id),
    name          TEXT NOT NULL,
    name_lower    TEXT NOT NULL,          -- rfc1459-folded; the uniqueness key
    kind          TEXT NOT NULL,          -- channel | query | status
    topic         TEXT,
    topic_by      TEXT,
    topic_at      REAL,
    joined        INTEGER NOT NULL DEFAULT 0,
    -- Detached: still joined upstream and still recording, but muted. Ordinary
    -- traffic stops counting as unread; a mention still does.
    detached      INTEGER NOT NULL DEFAULT 0,
    created_at    REAL NOT NULL,
    last_seen_eid INTEGER NOT NULL DEFAULT 0,
    archived      INTEGER NOT NULL DEFAULT 0,
    -- What pushes: 'all' | 'mentions' | 'none'. NULL is the default for the
    -- kind ('all' for a query, 'mentions' otherwise), so a default that
    -- changes later changes for every buffer nobody has set.
    notify        TEXT,
    pinned        INTEGER NOT NULL DEFAULT 0,
    -- A mute that ends by itself: unix seconds, NULL for "until I say". Only
    -- meaningful while detached; the gateway's sweep clears both together.
    muted_until   REAL,
    UNIQUE (network_id, name_lower)
);

CREATE TABLE IF NOT EXISTS events (
    eid        INTEGER PRIMARY KEY AUTOINCREMENT,
    buffer_id  INTEGER NOT NULL REFERENCES buffers(id),
    network_id INTEGER NOT NULL,
    ts         REAL NOT NULL,
    kind       TEXT NOT NULL,
    sender     TEXT,
    sender_host TEXT,
    text       TEXT,
    self       INTEGER NOT NULL DEFAULT 0,
    highlight  INTEGER NOT NULL DEFAULT 0,
    extra      TEXT                       -- JSON, kind-specific fields
);

-- The one index that matters: "the newest N events of this buffer, before eid X".
CREATE INDEX IF NOT EXISTS events_buffer_eid ON events (buffer_id, eid DESC);
-- Partial index for the mentions view; highlights are a tiny fraction of rows.
CREATE INDEX IF NOT EXISTS events_highlights ON events (eid DESC) WHERE highlight = 1;

-- Live membership, not history. Rebuilt wholesale from the NAMES reply on every
-- join, because a member list reconstructed from join/part events drifts the
-- moment one netsplit is missed.
CREATE TABLE IF NOT EXISTS members (
    buffer_id  INTEGER NOT NULL REFERENCES buffers(id),
    nick       TEXT NOT NULL,
    nick_lower TEXT NOT NULL,
    prefix     TEXT NOT NULL DEFAULT '',  -- '@', '+', '' ...
    PRIMARY KEY (buffer_id, nick_lower)
);

-- Client credentials. The token itself is never stored -- only its SHA-256 --
-- so a stolen database does not hand over a working login.
CREATE TABLE IF NOT EXISTS tokens (
    id           INTEGER PRIMARY KEY,
    token_hash   TEXT UNIQUE NOT NULL,
    label        TEXT NOT NULL,
    created_at   REAL NOT NULL,
    last_used_at REAL,
    revoked      INTEGER NOT NULL DEFAULT 0
);

-- Full-text search over every message ever received.
--
-- An external-content FTS5 table: the text is NOT duplicated, it points back at
-- events.rowid. The triggers below keep it in step. This is the feature a
-- bouncer uniquely enables -- nobody else has your whole history -- and it is
-- why the backlog is worth keeping forever.
--
-- The text only, and no stemming. The first index (events_fts, replaced by
-- _migrate) indexed the sender too, so "bob" found everything bob ever said,
-- and stemmed with porter, so "railing" matched "rail" while typing "runn"
-- found nothing: the index held "run". Search now matches each word as a
-- prefix of a word, which is what a person typing expects. `unicode61` with
-- remove_diacritics still makes "cafe" find "café".
CREATE VIRTUAL TABLE IF NOT EXISTS events_search USING fts5(
    text,
    content='events',
    content_rowid='eid',
    tokenize="unicode61 remove_diacritics 2"
);

-- The triggers that keep it in step are SEARCH_TRIGGERS, below.

-- People the user has blocked. Server-side rather than per-device, because a
-- block that only applies to the phone is not a block -- the same message would
-- still arrive on the Mac, and would still have produced a push notification.
CREATE TABLE IF NOT EXISTS ignores (
    network_id INTEGER NOT NULL REFERENCES networks(id),
    nick_lower TEXT NOT NULL,
    nick       TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (network_id, nick_lower)
);

CREATE TABLE IF NOT EXISTS devices (
    id          INTEGER PRIMARY KEY,
    token_id    INTEGER REFERENCES tokens(id),
    apns_token  TEXT UNIQUE NOT NULL,
    platform    TEXT NOT NULL,             -- ios | macos
    environment TEXT NOT NULL,             -- sandbox | production
    updated_at  REAL NOT NULL
);
"""


# How an event's `extra` says it was redacted (see ircproto.redact_secret), as
# json.dumps writes it. Matched as text so the condition needs nothing SQLite
# might have been built without.
REDACTED_MARK = '"redacted": true'
_NOT_REDACTED = "instr(COALESCE({row}.extra, ''), '" + REDACTED_MARK + "') = 0"

# The search index's triggers. A line marked redacted (a password typed to a
# service, cut to its verb) is never indexed at all -- there is nothing in it
# worth finding, and "never indexed" is a simpler promise than "indexed but
# harmless". The delete trigger carries the same condition, because an FTS5
# 'delete' for a row that was never indexed corrupts the index.
SEARCH_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS events_search_insert AFTER INSERT ON events
WHEN %(new)s BEGIN
    INSERT INTO events_search(rowid, text) VALUES (new.eid, new.text);
END;

CREATE TRIGGER IF NOT EXISTS events_search_delete AFTER DELETE ON events
WHEN %(old)s BEGIN
    INSERT INTO events_search(events_search, rowid, text)
    VALUES ('delete', old.eid, old.text);
END;
""" % {"new": _NOT_REDACTED.format(row="new"), "old": _NOT_REDACTED.format(row="old")}

# The most rows any page query returns, whatever it is asked for. The gateway
# clamps to smaller numbers first; this is the floor under all of them, so a
# negative or enormous `limit` can never become SQLite's "no limit".
MAX_PAGE = 5000


def _clamp(limit: Any, cap: int = MAX_PAGE) -> int:
    try:
        value = int(limit)
    except (TypeError, ValueError):
        value = 50
    return max(1, min(value, cap))


NOTIFY_LEVELS = ("all", "mentions", "none")
# The notification sounds a person can choose (setting `push_sound`): the
# system's own, silence, and four that ship inside the iOS app as <name>.caf.
PUSH_SOUNDS = ("default", "none", "chime", "pop", "bell", "drop")


def default_notify(kind: str) -> str:
    """Every line of a private conversation is addressed to you; a channel's
    are mostly not."""
    return "all" if kind == "query" else "mentions"


@dataclass
class Buffer:
    id: int
    network_id: int
    name: str
    kind: str
    topic: str | None = None
    joined: bool = False
    last_seen_eid: int = 0
    archived: bool = False
    detached: bool = False
    muted_until: float | None = None
    topic_by: str | None = None
    topic_at: float | None = None
    notify: str = "mentions"
    pinned: bool = False

    def to_wire(self, network_slug: str) -> dict[str, Any]:
        return {
            "id": self.id,
            "network": network_slug,
            "name": self.name,
            "kind": self.kind,
            "topic": self.topic,
            "joined": self.joined,
            "last_seen_eid": self.last_seen_eid,
            "archived": self.archived,
            "detached": self.detached,
            # When a timed mute ends (unix seconds), or null for "until I say".
            "muted_until": self.muted_until if self.detached else None,
            # Who set the topic and when (from 333 on join, and from a TOPIC
            # change), or null when the server never said.
            "topic_by": self.topic_by,
            "topic_at": self.topic_at,
            "notify": self.notify,
            "pinned": self.pinned,
        }


@dataclass
class Event:
    eid: int
    buffer_id: int
    network_id: int
    ts: float
    kind: str
    sender: str | None
    text: str | None
    self_: bool
    highlight: bool
    extra: dict[str, Any]
    sender_host: str | None = None

    def to_wire(self) -> dict[str, Any]:
        out = {
            "eid": self.eid,
            "buffer": self.buffer_id,
            "ts": self.ts,
            "kind": self.kind,
            "from": self.sender,
            "text": self.text,
            "self": self.self_,
            "highlight": self.highlight,
        }
        # The hostmask. Public information on IRC -- it is in every join and
        # every WHOIS -- but not shown by default, because a wall of
        # user@host in a busy channel is noise. The client reveals it on
        # demand. Omitted when absent rather than sent as null, since most
        # events have no sender at all.
        if self.sender_host:
            out["host"] = self.sender_host
        if self.extra:
            out["extra"] = self.extra
        return out


def _row_to_event(row: sqlite3.Row) -> Event:
    return Event(
        eid=row["eid"],
        buffer_id=row["buffer_id"],
        network_id=row["network_id"],
        ts=row["ts"],
        kind=row["kind"],
        sender=row["sender"],
        text=row["text"],
        self_=bool(row["self"]),
        highlight=bool(row["highlight"]),
        extra=json.loads(row["extra"]) if row["extra"] else {},
        sender_host=row["sender_host"],
    )


def _owner_only(path: str) -> None:
    """The database, and its -wal and -shm, readable by their owner only.

    It is every message and private message, the passwords a client stored
    (server, SASL, Q), the VAPID private key and the link-preview secret. It
    used to be created with whatever the umask gave -- 0644 under the usual
    022, readable by every account on the machine. SQLite gives the -wal and
    -shm the database file's own mode when it makes them, so creating the
    database 0600 covers those; ones left over from before are fixed here too.
    """
    if not path or path == ":memory:" or path.startswith("file:"):
        return
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        os.close(fd)
    except OSError:
        return                      # sqlite3 will say what is wrong, better
    for candidate in (path, path + "-wal", path + "-shm", path + "-journal"):
        try:
            if os.stat(candidate).st_mode & 0o077:
                os.chmod(candidate, 0o600)
        except OSError:
            pass


class Store:
    def __init__(self, path: str):
        self.path = path
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        _owner_only(path)
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        # unread_counts' kept counts: buffer id -> [marker, unread, highlights]
        # as of eid _unread_upto.
        self._unread_cache: dict[int, list[int]] = {}
        self._unread_upto = 0
        # WAL so a reader (a backup, a `sqlite3` shell, a future stats script)
        # never blocks the bouncer's writes, and vice versa.
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        # Search helpers, in Python because SQLite's own lower() and LIKE only
        # fold ASCII. See search().
        self.db.create_function("geeyem_has", 2, _has_literal, deterministic=True)
        self.db.create_function("geeyem_fold", 1, _fold_or_none, deterministic=True)
        self.db.executescript(SCHEMA)
        self.db.executescript(WAVE4B_SCHEMA)
        self._migrate()
        self.db.executescript(SEARCH_TRIGGERS)
        self.db.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        # The epoch: made once, when a database has none -- a new database, or
        # one from before there were epochs, on its first start under this
        # code -- and never changed by anything but new_epoch(). INSERT OR
        # IGNORE, so two processes opening the same new database (the bouncer
        # and a `token new`) cannot each write their own.
        self.db.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('epoch', ?)",
                        (secrets.token_hex(8),))

    def _migrate(self) -> None:
        """Bring an existing database up to the current schema.

        CREATE TABLE IF NOT EXISTS does nothing to a table that already exists,
        so a column added later never appears in a database made before it. This
        adds the missing ones. It is deliberately additive: a migration that
        drops or rewrites is a migration that can lose backlog.
        """
        have = {row["name"] for row in self.db.execute("PRAGMA table_info(buffers)")}
        for column, definition in (
            ("detached", "INTEGER NOT NULL DEFAULT 0"),
            ("notify", "TEXT"),
            ("pinned", "INTEGER NOT NULL DEFAULT 0"),
            ("muted_until", "REAL"),
        ):
            if column not in have:
                self.db.execute(f"ALTER TABLE buffers ADD COLUMN {column} {definition}")
        # The search index. Built from `events` once, here, rather than lazily,
        # so the first search on a large history is fast rather than
        # mysteriously slow. Recorded in meta only after the build finishes: a
        # count of rows cannot tell a built index from an empty one, because a
        # count on an external-content table reads the content table.
        built = self.db.execute(
            "SELECT value FROM meta WHERE key='search_index'").fetchone()
        if built is None or built["value"] != "events_search":
            self.db.execute("INSERT INTO events_search(events_search) VALUES ('rebuild')")
            self.db.execute("INSERT OR REPLACE INTO meta (key, value)"
                            " VALUES ('search_index', 'events_search')")
        # The first index is replaced, not kept beside it. It holds nothing
        # that is not in `events` -- it is an index -- and keeping it would
        # have every stored line written into two of them forever.
        self.db.execute("DROP TRIGGER IF EXISTS events_fts_insert")
        self.db.execute("DROP TRIGGER IF EXISTS events_fts_delete")
        self.db.execute("DROP TABLE IF EXISTS events_fts")

        have = {row["name"] for row in self.db.execute("PRAGMA table_info(networks)")}
        for column, definition in (
            ("username", "TEXT NOT NULL DEFAULT ''"),
            ("realname", "TEXT NOT NULL DEFAULT ''"),
            ("channels", "TEXT NOT NULL DEFAULT '[]'"),
            ("enabled", "INTEGER NOT NULL DEFAULT 1"),
            ("source", "TEXT NOT NULL DEFAULT 'client'"),
            ("config_channels", "TEXT NOT NULL DEFAULT '[]'"),
            ("highlight_words", "TEXT"),
            ("away", "TEXT"),
            ("alt_nicks", "TEXT NOT NULL DEFAULT '[]'"),
            ("q_username", "TEXT"),
            ("server_password", "TEXT"),
            ("sasl_mechanism", "TEXT"),
            ("sasl_username", "TEXT"),
            ("sasl_password", "TEXT"),
            ("q_password", "TEXT"),
            ("edited", "TEXT NOT NULL DEFAULT '[]'"),
            ("current_nick", "TEXT"),
            ("channel_keys", "TEXT NOT NULL DEFAULT '{}'"),
        ):
            if column not in have:
                self.db.execute(f"ALTER TABLE networks ADD COLUMN {column} {definition}")
        self._buffers_autoincrement()
        # The search triggers gained a condition (redacted lines are never
        # indexed). CREATE TRIGGER IF NOT EXISTS leaves an old one in place, so
        # the old pair goes once, and SEARCH_TRIGGERS puts the new pair back
        # right after this. Nothing is re-indexed: no line before this was
        # marked redacted, so the old triggers indexed exactly what the new
        # ones would have.
        done = self.db.execute("SELECT value FROM meta WHERE key='search_triggers'").fetchone()
        if done is None or done["value"] != "2":
            self.db.execute("DROP TRIGGER IF EXISTS events_search_insert")
            self.db.execute("DROP TRIGGER IF EXISTS events_search_delete")
            self.db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('search_triggers', '2')")
        # Quits were stored without the quitter's host until 2026-09-21. Fill
        # them in once from that person's latest earlier line in the same
        # channel (their join, usually), so an old "left" line can show who
        # left. Only ever writes into an empty host, and runs once.
        done = self.db.execute("SELECT value FROM meta WHERE key='quit_hosts'").fetchone()
        if done is None:
            self.db.execute(
                "UPDATE events SET sender_host = ("
                "  SELECT e2.sender_host FROM events e2"
                "   WHERE e2.buffer_id = events.buffer_id"
                "     AND lower(e2.sender) = lower(events.sender)"
                "     AND e2.eid < events.eid"
                "     AND e2.sender_host IS NOT NULL AND e2.sender_host != ''"
                "   ORDER BY e2.eid DESC LIMIT 1)"
                " WHERE kind = 'quit' AND (sender_host IS NULL OR sender_host = '')")
            self.db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('quit_hosts', '1')")
        # Until 2026-09-22 only some services verbs were redacted: "ID hunter2"
        # (Anope's IDENTIFY), LOGIN, RELEASE, REGAIN, GROUP and Q's HELLO were
        # stored, indexed and backed up as typed. Scrubbed once, by the same
        # rule `say` now applies; a later widening of the rule bumps the value
        # so it runs again.
        done = self.db.execute("SELECT value FROM meta WHERE key='secret_scrub'").fetchone()
        if done is None or done["value"] != "1":
            # One transaction: a row out of the index but still unredacted
            # would be 'deleted' from it a second time later, corrupting it.
            self.db.execute("BEGIN")
            try:
                self._scrub_secrets()
                self.db.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES ('secret_scrub', '1')")
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
        self.db.execute(
            "UPDATE meta SET value=? WHERE key='schema_version'", (str(SCHEMA_VERSION),)
        )

    def _scrub_secrets(self) -> int:
        """Redact every stored line that `say` would redact today.

        Our own lines to a service, and the "Not sent" line a dropped one left
        behind, in any conversation whose name is a service. Each one leaves
        the search index first (with the text it was indexed under, which is
        what an external-content FTS5 'delete' needs), then gets the text and
        the `redacted` mark `say` gives it. Returns how many were scrubbed.
        """
        from .ircproto import is_service, redact_secret

        names = {row["id"]: row["name"] for row in self.db.execute(
            "SELECT id, name FROM buffers WHERE kind != 'channel'") if is_service(row["name"])}
        scrubbed = 0
        for buffer_id in names:
            rows = self.db.execute(
                "SELECT eid, kind, text, extra FROM events WHERE buffer_id=?"
                " AND ((self=1 AND kind IN ('message', 'notice')) OR kind='server')",
                (buffer_id,)).fetchall()
            for row in rows:
                extra = json.loads(row["extra"]) if row["extra"] else {}
                if extra.get("redacted"):
                    continue
                if row["kind"] == "server":
                    line = extra.get("not_sent")
                    kept = redact_secret(names[buffer_id], line) if line else None
                    if kept is None:
                        continue
                    text = row["text"][:len(row["text"]) - len(line)] + kept
                    extra.pop("not_sent", None)
                else:
                    kept = redact_secret(names[buffer_id], row["text"] or "")
                    if kept is None:
                        continue
                    text = kept
                extra["redacted"] = True
                self.db.execute(
                    "INSERT INTO events_search(events_search, rowid, text) VALUES ('delete', ?, ?)",
                    (row["eid"], row["text"]))
                self.db.execute("UPDATE events SET text=?, extra=? WHERE eid=?",
                                (text, json.dumps(extra), row["eid"]))
                scrubbed += 1
        if scrubbed:
            log.info("redacted %d stored line(s) typed to services", scrubbed)
        return scrubbed

    def _buffers_autoincrement(self) -> None:
        """Rebuild `buffers` with AUTOINCREMENT ids, keeping every id it has.

        SQLite cannot add AUTOINCREMENT to an existing column, so this is the
        one migration that copies a table: a new table with the new definition,
        every row copied with its id, the old one dropped and the new one
        renamed into its place. It is the procedure SQLite's own documentation
        gives for this (foreign keys off for the swap, then checked). The ids
        are copied as they are, so every event, member, read marker and client
        that names a buffer by id still names the same one.

        The sequence starts at the highest id there is. An id deleted before
        this ran (a removed network's buffers, at the top of the range) could
        still come back once; there is no record of it to say otherwise.
        """
        row = self.db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='buffers'").fetchone()
        if row is None or "AUTOINCREMENT" in (row["sql"] or "").upper():
            return
        start = SCHEMA.index("CREATE TABLE IF NOT EXISTS buffers")
        definition = SCHEMA[start:SCHEMA.index(");", start) + 2]
        definition = definition.replace("CREATE TABLE IF NOT EXISTS buffers",
                                        "CREATE TABLE buffers_autoinc")
        self.db.execute("PRAGMA foreign_keys=OFF")
        try:
            self.db.execute("BEGIN")
            try:
                self.db.execute(definition)
                old = [r["name"] for r in self.db.execute("PRAGMA table_info(buffers)")]
                new = {r["name"] for r in self.db.execute("PRAGMA table_info(buffers_autoinc)")}
                columns = ", ".join(c for c in old if c in new)
                self.db.execute(f"INSERT INTO buffers_autoinc ({columns})"
                                f" SELECT {columns} FROM buffers")
                self.db.execute("DROP TABLE buffers")
                self.db.execute("ALTER TABLE buffers_autoinc RENAME TO buffers")
                self.db.execute("DELETE FROM sqlite_sequence"
                                " WHERE name IN ('buffers', 'buffers_autoinc')")
                self.db.execute("INSERT INTO sqlite_sequence (name, seq)"
                                " SELECT 'buffers', COALESCE(MAX(id), 0) FROM buffers")
                # Every id was copied as it was, so nothing that pointed at a
                # buffer can point at nothing now. Checked anyway, and said in
                # the journal rather than refusing to start: a bouncer that will
                # not open its database over a stray row is worse than the row.
                for table in ("events", "members"):
                    broken = self.db.execute(f"PRAGMA foreign_key_check({table})").fetchall()
                    if broken:
                        log.warning("%d row(s) in %s name a buffer that does not exist",
                                    len(broken), table)
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
        finally:
            self.db.execute("PRAGMA foreign_keys=ON")
        log.info("buffers table rebuilt with AUTOINCREMENT ids")

    def close(self) -> None:
        self.db.close()

    # --- networks ----------------------------------------------------------

    def upsert_network(self, slug: str, name: str, host: str, port: int, tls: bool, nick: str) -> int:
        row = self.db.execute("SELECT id FROM networks WHERE slug = ?", (slug,)).fetchone()
        if row:
            self.db.execute(
                "UPDATE networks SET name=?, host=?, port=?, tls=?, nick=? WHERE id=?",
                (name, host, port, int(tls), nick, row["id"]),
            )
            return row["id"]
        cur = self.db.execute(
            "INSERT INTO networks (slug, name, host, port, tls, nick, created_at) VALUES (?,?,?,?,?,?,?)",
            (slug, name, host, port, int(tls), nick, time.time()),
        )
        return int(cur.lastrowid)

    def save_network(self, *, slug: str, name: str, host: str, port: int, tls: bool,
                     nick: str, username: str = "", realname: str = "",
                     channels: list[str] | None = None, source: str = "client",
                     enabled: bool | None = None, config_channels: list[str] | None = None,
                     alt_nicks: list[str] | None = None,
                     q_username: str | None = None,
                     channel_keys: dict[str, str] | None = None) -> int:
        """Create or update a network's definition.

        `enabled` is left as it is on an update unless given: it is the on/off
        switch a client flips with `network_connect`, and a restart that read
        config.json must not quietly turn a network back on. The secrets are
        not here at all; set_network_fields writes those. `channel_keys` is
        left as it is on an update unless given, like `enabled`.
        """
        channels_json = json.dumps(channels or [])
        config_json = json.dumps(config_channels or [])
        row = self.db.execute("SELECT id FROM networks WHERE slug=?", (slug,)).fetchone()
        if row:
            self.db.execute(
                "UPDATE networks SET name=?, host=?, port=?, tls=?, nick=?, username=?,"
                " realname=?, channels=?, source=?, config_channels=? WHERE id=?",
                (name, host, port, int(tls), nick, username or nick, realname or nick,
                 channels_json, source, config_json, row["id"]),
            )
            if channel_keys is not None:
                self.db.execute("UPDATE networks SET channel_keys=? WHERE id=?",
                                (json.dumps(dict(channel_keys)), row["id"]))
            if enabled is not None:
                self.set_network_enabled(row["id"], enabled)
            if alt_nicks is not None:
                self.db.execute("UPDATE networks SET alt_nicks=? WHERE id=?",
                                (json.dumps(list(alt_nicks)), row["id"]))
            if q_username is not None:
                self.db.execute("UPDATE networks SET q_username=? WHERE id=?",
                                (q_username or None, row["id"]))
            return row["id"]
        cur = self.db.execute(
            "INSERT INTO networks (slug, name, host, port, tls, nick, created_at,"
            " username, realname, channels, enabled, source, config_channels,"
            " alt_nicks, q_username, channel_keys)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (slug, name, host, port, int(tls), nick, time.time(),
             username or nick, realname or nick, channels_json,
             int(True if enabled is None else enabled), source, config_json,
             json.dumps(list(alt_nicks or [])), q_username or None,
             json.dumps(dict(channel_keys or {}))),
        )
        return int(cur.lastrowid)

    # The columns a client may change with edit_network, and how each is kept.
    # Lists are JSON; the rest are stored as given, "" and None both meaning
    # "not set" for the secrets.
    EDITABLE_COLUMNS = {
        "name": "text", "host": "text", "port": "int", "tls": "bool", "nick": "text",
        "alt_nicks": "json", "username": "text", "realname": "text",
        "q_username": "optional", "server_password": "optional",
        "sasl_mechanism": "optional", "sasl_username": "optional",
        "sasl_password": "optional", "q_password": "optional",
    }

    def set_network_fields(self, network_id: int, fields: dict[str, Any], *,
                           edited: Iterable[str] = ()) -> None:
        """Write the fields a client edited, and remember their names in
        `edited` (for a network in config.json, the edited fields win over the
        file from then on). One statement per field; all or nothing."""
        self.db.execute("BEGIN")
        try:
            for column, value in fields.items():
                how = self.EDITABLE_COLUMNS.get(column)
                if how is None:
                    raise ValueError(f"not an editable network field: {column}")
                if how == "json":
                    value = json.dumps(list(value or []))
                elif how == "bool":
                    value = int(bool(value))
                elif how == "optional":
                    value = value or None
                self.db.execute(f"UPDATE networks SET {column}=? WHERE id=?", (value, network_id))
            names = list(edited)
            if names:
                row = self.db.execute("SELECT edited FROM networks WHERE id=?",
                                      (network_id,)).fetchone()
                try:
                    have = json.loads(row["edited"] or "[]") if row else []
                except ValueError:
                    have = []
                merged = have + [n for n in names if n not in have]
                self.db.execute("UPDATE networks SET edited=? WHERE id=?",
                                (json.dumps(merged), network_id))
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def set_network_enabled(self, network_id: int, enabled: bool) -> None:
        self.db.execute("UPDATE networks SET enabled=? WHERE id=?", (int(enabled), network_id))

    def network_enabled(self, network_id: int) -> bool:
        row = self.db.execute("SELECT enabled FROM networks WHERE id=?", (network_id,)).fetchone()
        return bool(row["enabled"]) if row else True

    def networks(self) -> list[dict[str, Any]]:
        out = []
        for row in self.db.execute("SELECT * FROM networks ORDER BY id"):
            record = dict(row)
            for key in ("channels", "config_channels", "alt_nicks", "edited"):
                try:
                    value = json.loads(record.get(key) or "[]")
                except ValueError:
                    value = []
                record[key] = value if isinstance(value, list) else []
            # {folded channel name: key}. Anything else in the column (it is
            # '{}' for every network that existed before keys were kept) reads
            # as no keys, never as an error at startup.
            try:
                keys = json.loads(record.get("channel_keys") or "{}")
            except ValueError:
                keys = {}
            record["channel_keys"] = {
                name: key for name, key in (keys.items() if isinstance(keys, dict) else ())
                if isinstance(name, str) and isinstance(key, str) and key}
            out.append(record)
        return out

    def network_by_slug(self, slug: str) -> dict[str, Any] | None:
        return next((n for n in self.networks() if n["slug"] == slug), None)

    def set_network_channels(self, network_id: int, channels: list[str],
                             keys: dict[str, str] | None = None) -> None:
        """The wanted list, and with `keys` the keys that go with it
        ({folded name: key}), in one statement so the two never disagree.
        Without `keys` they are left as they are."""
        if keys is None:
            self.db.execute("UPDATE networks SET channels=? WHERE id=?",
                            (json.dumps(channels), network_id))
        else:
            self.db.execute("UPDATE networks SET channels=?, channel_keys=? WHERE id=?",
                            (json.dumps(channels), json.dumps(dict(keys)), network_id))

    def delete_network(self, network_id: int) -> None:
        """Remove a network and everything under it.

        Buffers and events go too. This is the one genuinely destructive
        operation in the store, which is why the gateway only allows it for
        networks a client created -- one defined in config.json would come back
        on the next restart and the deletion would look like it failed.
        """
        self.db.execute("BEGIN")
        try:
            buffers = [r["id"] for r in self.db.execute(
                "SELECT id FROM buffers WHERE network_id=?", (network_id,))]
            for bid in buffers:
                self.db.execute("DELETE FROM members WHERE buffer_id=?", (bid,))
                self.db.execute("DELETE FROM events WHERE buffer_id=?", (bid,))
            # Every row that REFERENCES networks(id) goes in the same
            # transaction. `ignores` was missed until 2026-09-26: with one block
            # on the network the final DELETE failed its foreign key and rolled
            # back, after the session had already been stopped -- the network
            # vanished live and came back on the next restart. Events carry a
            # network_id too (no FK), so stragglers are caught by that as well.
            self.db.execute("DELETE FROM ignores WHERE network_id=?", (network_id,))
            self.db.execute("DELETE FROM events WHERE network_id=?", (network_id,))
            self.db.execute("DELETE FROM buffers WHERE network_id=?", (network_id,))
            self.db.execute("DELETE FROM networks WHERE id=?", (network_id,))
            self.db.execute("COMMIT")
            self._forget_unread()
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    # --- blocking ----------------------------------------------------------

    def add_ignore(self, network_id: int, nick: str) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO ignores (network_id, nick_lower, nick, created_at)"
            " VALUES (?,?,?,?)",
            (network_id, fold(nick), nick, time.time()),
        )

    def remove_ignore(self, network_id: int, nick: str) -> None:
        self.db.execute("DELETE FROM ignores WHERE network_id=? AND nick_lower=?",
                        (network_id, fold(nick)))

    def ignored_nicks(self, network_id: int) -> set[str]:
        return {r["nick_lower"] for r in self.db.execute(
            "SELECT nick_lower FROM ignores WHERE network_id=?", (network_id,))}

    def ignores(self, network_id: int) -> list[str]:
        return [r["nick"] for r in self.db.execute(
            "SELECT nick FROM ignores WHERE network_id=? ORDER BY nick_lower", (network_id,))]

    def set_network_nick(self, network_id: int, nick: str) -> None:
        """The nick in use right now. Not `nick`, which is the one asked for:
        writing a fallback (quinn_) there made it the nick asked for on the next
        start. See the `current_nick` column."""
        self.db.execute("UPDATE networks SET current_nick=? WHERE id=?", (nick, network_id))

    def network_away(self, network_id: int) -> str | None:
        row = self.db.execute("SELECT away FROM networks WHERE id=?", (network_id,)).fetchone()
        return (row["away"] or None) if row else None

    def set_network_away(self, network_id: int, message: str | None) -> None:
        self.db.execute("UPDATE networks SET away=? WHERE id=?", (message or None, network_id))

    # --- buffers -----------------------------------------------------------

    def get_or_create_buffer(self, network_id: int, name: str, kind: str, *,
                             unarchive: bool = True) -> Buffer:
        lower = fold(name)
        row = self.db.execute(
            "SELECT * FROM buffers WHERE network_id=? AND name_lower=?", (network_id, lower)
        ).fetchone()
        if row is None:
            cur = self.db.execute(
                "INSERT INTO buffers (network_id, name, name_lower, kind, created_at)"
                " VALUES (?,?,?,?,?)",
                (network_id, name, lower, kind, time.time()),
            )
            row = self.db.execute("SELECT * FROM buffers WHERE id=?", (cur.lastrowid,)).fetchone()
        elif row["archived"] and unarchive:
            # Talking in an archived buffer un-archives it; that is what a client
            # expects when someone messages them out of the blue. Membership
            # bookkeeping passes unarchive=False: the server confirming the PART
            # that closing a channel sent is not anyone talking, and used to
            # bring the channel straight back.
            self.db.execute("UPDATE buffers SET archived=0 WHERE id=?", (row["id"],))
            row = self.db.execute("SELECT * FROM buffers WHERE id=?", (row["id"],)).fetchone()
        return self._buffer(row)

    def find_buffer(self, network_id: int, name: str) -> Buffer | None:
        """A buffer by name, or None. Never creates one and never un-archives."""
        row = self.db.execute(
            "SELECT * FROM buffers WHERE network_id=? AND name_lower=?", (network_id, fold(name))
        ).fetchone()
        return self._buffer(row) if row else None

    @staticmethod
    def _buffer(row: sqlite3.Row) -> Buffer:
        return Buffer(
            id=row["id"],
            network_id=row["network_id"],
            name=row["name"],
            kind=row["kind"],
            topic=row["topic"],
            joined=bool(row["joined"]),
            last_seen_eid=row["last_seen_eid"],
            archived=bool(row["archived"]),
            detached=bool(row["detached"]),
            muted_until=row["muted_until"],
            topic_by=row["topic_by"],
            topic_at=row["topic_at"],
            notify=row["notify"] if row["notify"] in NOTIFY_LEVELS else default_notify(row["kind"]),
            pinned=bool(row["pinned"]),
        )

    def buffers(self, include_archived: bool = False) -> list[Buffer]:
        sql = "SELECT * FROM buffers"
        if not include_archived:
            sql += " WHERE archived = 0"
        sql += " ORDER BY kind, name"
        return [self._buffer(r) for r in self.db.execute(sql)]

    def buffer(self, buffer_id: int) -> Buffer | None:
        row = self.db.execute("SELECT * FROM buffers WHERE id=?", (buffer_id,)).fetchone()
        return self._buffer(row) if row else None

    def set_archived(self, buffer_id: int, archived: bool) -> None:
        """Hide a buffer without destroying its history.

        Closing a conversation must never delete it. The backlog stays exactly
        where it was, and the buffer reappears -- un-archived by
        get_or_create_buffer -- the moment anyone speaks in it again.
        """
        self.db.execute("UPDATE buffers SET archived=? WHERE id=?", (int(archived), buffer_id))

    def set_detached(self, buffer_id: int, detached: bool, until: float | None = None) -> None:
        self.db.execute("UPDATE buffers SET detached=?, muted_until=? WHERE id=?",
                        (int(detached), until if detached else None, buffer_id))

    def expired_mutes(self, now: float) -> list[int]:
        """Buffers whose timed mute has run out."""
        return [r["id"] for r in self.db.execute(
            "SELECT id FROM buffers WHERE detached=1 AND muted_until IS NOT NULL"
            " AND muted_until <= ?", (now,))]

    def set_joined(self, buffer_id: int, joined: bool) -> None:
        self.db.execute("UPDATE buffers SET joined=? WHERE id=?", (int(joined), buffer_id))

    def clear_joined(self, network_id: int) -> None:
        """Mark every channel of a network not joined and empty its member list.

        For a fresh process: whatever the database says, a connection that has
        not been made yet is not in any channel. A crash skips the clean
        disconnect that would otherwise have said so.
        """
        self.db.execute(
            "DELETE FROM members WHERE buffer_id IN"
            " (SELECT id FROM buffers WHERE network_id=? AND kind='channel')", (network_id,))
        self.db.execute(
            "UPDATE buffers SET joined=0 WHERE network_id=? AND kind='channel'", (network_id,))

    def set_topic(self, buffer_id: int, topic: str | None, by: str | None = None,
                  at: float | None = None) -> None:
        """The topic and who set it when. `by`/`at` are None when not known:
        a 332 on join says what the topic is and nothing about who, and it
        used to be stamped with the time of the join, so every topic read as
        set a minute ago. 333 fills them in (set_topic_meta)."""
        self.db.execute(
            "UPDATE buffers SET topic=?, topic_by=?, topic_at=? WHERE id=?",
            (topic, by, at, buffer_id),
        )

    def set_topic_meta(self, buffer_id: int, by: str | None, at: float | None) -> None:
        self.db.execute("UPDATE buffers SET topic_by=?, topic_at=? WHERE id=?",
                        (by, at, buffer_id))

    def set_buffer_settings(self, buffer_id: int, *, notify: str | None = None,
                            pinned: bool | None = None) -> None:
        if notify is not None:
            if notify not in NOTIFY_LEVELS:
                raise ValueError(f"notify must be one of {', '.join(NOTIFY_LEVELS)}")
            self.db.execute("UPDATE buffers SET notify=? WHERE id=?", (notify, buffer_id))
        if pinned is not None:
            self.db.execute("UPDATE buffers SET pinned=? WHERE id=?", (int(pinned), buffer_id))

    def mark_all_read(self, network_id: int | None = None) -> list[tuple[int, int]]:
        """Every open buffer (of one network, or all) read up to its newest
        event, in one statement. Returns (buffer id, marker) for each."""
        where = "archived = 0" + (" AND network_id = ?" if network_id is not None else "")
        params: tuple = (network_id,) if network_id is not None else ()
        self.db.execute(
            "UPDATE buffers SET last_seen_eid = MAX(last_seen_eid,"
            " (SELECT COALESCE(MAX(eid), 0) FROM events WHERE buffer_id = buffers.id))"
            f" WHERE {where}", params)
        return [(r["id"], r["last_seen_eid"]) for r in self.db.execute(
            f"SELECT id, last_seen_eid FROM buffers WHERE {where} ORDER BY id", params)]

    # --- settings ----------------------------------------------------------

    SETTING_DEFAULTS: dict[str, Any] = {"push_preview": True, "auto_away": False,
                                        "push_sound": "default",
                                        "nick_colors": {}, "nick_palette": "default"}

    def get_setting(self, key: str) -> Any:
        row = self.db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        if row is None:
            return self.SETTING_DEFAULTS.get(key)
        try:
            return json.loads(row["value"])
        except ValueError:
            return self.SETTING_DEFAULTS.get(key)

    def set_setting(self, key: str, value: Any) -> None:
        self.db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                        (key, json.dumps(value)))

    def settings(self) -> dict[str, Any]:
        # A copy of any mutable default, so a caller cannot edit the shared one.
        return {key: copy.deepcopy(self.get_setting(key)) for key in self.SETTING_DEFAULTS}

    def highlight_words(self, network_id: int) -> list[str] | None:
        """This network's extra mention words, or None if never set here."""
        row = self.db.execute("SELECT highlight_words FROM networks WHERE id=?",
                              (network_id,)).fetchone()
        if row is None or row["highlight_words"] is None:
            return None
        try:
            words = json.loads(row["highlight_words"])
        except ValueError:
            return None
        return [w for w in words if isinstance(w, str)] if isinstance(words, list) else None

    def set_highlight_words(self, network_id: int, words: list[str]) -> None:
        self.db.execute("UPDATE networks SET highlight_words=? WHERE id=?",
                        (json.dumps(list(words)), network_id))

    def mark_read(self, buffer_id: int, eid: int) -> int:
        """Advance the read marker. Never moves backwards -- two clients racing
        would otherwise hand each other an unread badge that keeps reappearing.

        Also never moves past the buffer's newest stored eid. The eid is a
        number the client echoes back, not one it can be trusted to have gotten
        right -- a stale cursor, a bug, or a buffer whose history got shorter
        somehow would otherwise let a client silence a buffer's unread badge
        forever: nothing arriving before that phantom eid would ever again be
        greater than last_seen_eid. Clamping to what has actually happened
        means the worst a bad eid can do is mark everything that exists as
        read, which is recoverable the moment the next message arrives.
        """
        newest = self.db.execute(
            "SELECT COALESCE(MAX(eid), 0) AS m FROM events WHERE buffer_id=?", (buffer_id,)
        ).fetchone()["m"]
        eid = min(eid, newest)
        self.db.execute(
            "UPDATE buffers SET last_seen_eid = MAX(last_seen_eid, ?) WHERE id = ?",
            (eid, buffer_id),
        )
        row = self.db.execute("SELECT last_seen_eid FROM buffers WHERE id=?", (buffer_id,)).fetchone()
        return row["last_seen_eid"] if row else eid

    def unread_counts(self) -> dict[int, dict[str, int]]:
        """Per buffer: how many events and how many highlights since the marker.

        Two things never count. Your own lines: a /msg sent from the phone gave
        that query an unread badge on every other device, for words you wrote.
        And archived buffers: a closed conversation is hidden, so a count on it
        is a badge nothing on screen can clear -- the app icon stayed at 1 for
        good after closing a query that held a mention. Archived buffers are
        still listed, at zero, so a client that merges counts clears its own.
        """
        # This runs on every push and after every mark_read, and counting every
        # unread row each time cost 46 ms with 200k of them. So the counts are
        # kept: each buffer's (marker, unread, highlights) as of `upto`, the
        # newest eid counted. A call counts only the rows that arrived since,
        # and recounts a buffer from scratch only when its marker moved. Rows
        # deleted or moved between buffers (the only other changes) drop the
        # whole cache; see _forget_unread.
        newest = self.max_eid()
        buffers = self.db.execute(
            "SELECT id, detached, archived, last_seen_eid FROM buffers").fetchall()
        cache = self._unread_cache
        upto = self._unread_upto
        fresh: dict[int, list[int]] = {}
        for b in buffers:
            held = cache.get(b["id"])
            if held is not None and held[0] == b["last_seen_eid"]:
                fresh[b["id"]] = held
        recount = [b for b in buffers if b["id"] not in fresh]
        for b in recount:
            row = self.db.execute(
                "SELECT COUNT(*) AS total, COALESCE(SUM(highlight), 0) AS highlights"
                "  FROM events WHERE buffer_id = ? AND eid > ? AND eid <= ?"
                "   AND kind IN ('message', 'action', 'notice', 'invite') AND self = 0",
                (b["id"], b["last_seen_eid"], newest)).fetchone()
            fresh[b["id"]] = [b["last_seen_eid"], row["total"], row["highlights"]]
        if newest > upto:
            recounted = {b["id"] for b in recount}
            for row in self.db.execute(
                    "SELECT e.buffer_id AS bid, COUNT(*) AS total,"
                    "       COALESCE(SUM(e.highlight), 0) AS highlights"
                    "  FROM events e JOIN buffers b ON b.id = e.buffer_id"
                    " WHERE e.eid > ? AND e.eid <= ? AND e.eid > b.last_seen_eid"
                    "   AND e.kind IN ('message', 'action', 'notice', 'invite') AND e.self = 0"
                    " GROUP BY e.buffer_id", (upto, newest)):
                held = fresh.get(row["bid"])
                if held is not None and row["bid"] not in recounted:
                    held[1] += row["total"]
                    held[2] += row["highlights"]
        self._unread_cache, self._unread_upto = fresh, newest
        by_id = {b["id"]: b for b in buffers}
        return {
            bid: {
                # A detached buffer is muted: ordinary traffic stops counting, so
                # it cannot keep a badge lit. A mention still counts -- that is
                # what makes muting safe to use on a busy channel.
                "unread": 0 if (by_id[bid]["detached"] or by_id[bid]["archived"]) else total,
                "highlights": 0 if by_id[bid]["archived"] else highlights,
            }
            for bid, (_, total, highlights) in fresh.items()
        }

    def _forget_unread(self) -> None:
        """Rows were deleted or moved: the kept unread counts are recounted."""
        self._unread_cache, self._unread_upto = {}, 0

    def badge_count(self) -> int:
        """The number on the app icon: unread mentions, across every buffer.

        One place, because two things send it and they must agree: an alert
        push carries it, and so does the background push that follows a read
        on another device (see Hub.read_elsewhere). A badge that an alert set
        to 3 and a read then set by some other sum is a badge nobody trusts.
        """
        return sum(c["highlights"] for c in self.unread_counts().values())

    def connection_lost_last(self, buffer_id: int) -> bool:
        """Is the newest event in this buffer a "Disconnected" line?

        How a restarted bouncer knows a channel is still owed its
        "Reconnected" line: stopping wrote the first as the last thing in each
        channel, and nothing can be said in a channel we are not in. One
        indexed row per buffer, not a search.
        """
        row = self.db.execute(
            "SELECT kind, extra FROM events WHERE buffer_id=? ORDER BY eid DESC LIMIT 1",
            (buffer_id,),
        ).fetchone()
        if row is None or row["kind"] != "server" or not row["extra"]:
            return False
        try:
            return json.loads(row["extra"]).get("connection") == "lost"
        except ValueError:
            return False

    def newest_eid(self, buffer_id: int) -> int:
        return self.db.execute(
            "SELECT COALESCE(MAX(eid), 0) AS m FROM events WHERE buffer_id=?", (buffer_id,)
        ).fetchone()["m"]

    def newest_event_time(self) -> float | None:
        """When the newest stored event, in any buffer, says it happened, or
        None with no events at all. The last moment this database is known to
        have had a bouncer writing to it; see session._mark_unclean_stop."""
        row = self.db.execute("SELECT ts FROM events ORDER BY eid DESC LIMIT 1").fetchone()
        return row["ts"] if row else None

    # --- events ------------------------------------------------------------

    def append_event(
        self,
        *,
        buffer_id: int,
        network_id: int,
        kind: str,
        sender: str | None = None,
        sender_host: str | None = None,
        text: str | None = None,
        self_: bool = False,
        highlight: bool = False,
        extra: dict[str, Any] | None = None,
        ts: float | None = None,
    ) -> Event:
        ts = ts if ts is not None else time.time()
        extra_json = json.dumps(extra) if extra else None
        cur = self.db.execute(
            "INSERT INTO events (buffer_id, network_id, ts, kind, sender, sender_host, text, self, highlight, extra)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (buffer_id, network_id, ts, kind, sender, sender_host, text,
             int(self_), int(highlight), extra_json),
        )
        return Event(
            eid=int(cur.lastrowid),
            buffer_id=buffer_id,
            network_id=network_id,
            ts=ts,
            kind=kind,
            sender=sender,
            text=text,
            self_=self_,
            highlight=highlight,
            extra=extra or {},
            sender_host=sender_host,
        )

    def backlog(self, buffer_id: int, *, before_eid: int | None = None, limit: int = 50) -> list[Event]:
        """The `limit` events ending just before `before_eid`, oldest first.

        Returned oldest-first even though it is selected newest-first, because
        every caller wants to append them in display order and reversing in the
        client is a bug waiting to be written twice.
        """
        limit = _clamp(limit)
        if before_eid:
            rows = self.db.execute(
                "SELECT * FROM events WHERE buffer_id=? AND eid < ? ORDER BY eid DESC LIMIT ?",
                (buffer_id, before_eid, limit),
            ).fetchall()
        else:
            rows = self.db.execute(
                "SELECT * FROM events WHERE buffer_id=? ORDER BY eid DESC LIMIT ?",
                (buffer_id, limit),
            ).fetchall()
        return [_row_to_event(r) for r in reversed(rows)]

    def backlog_after(self, buffer_id: int, after_eid: int, limit: int = 50) -> list[Event]:
        """The `limit` events immediately following `after_eid`, oldest first."""
        limit = _clamp(limit)
        rows = self.db.execute(
            "SELECT * FROM events WHERE buffer_id=? AND eid > ? ORDER BY eid ASC LIMIT ?",
            (buffer_id, after_eid, limit),
        ).fetchall()
        return [_row_to_event(r) for r in rows]

    def events_since(self, buffer_id: int, since_eid: int, limit: int) -> tuple[list[Event], bool]:
        """What a reattaching client missed in one buffer: the events after
        `since_eid`, oldest first, and whether that is all of them.

        Capped at the NEWEST `limit`, not the oldest. A client that was away
        for a thousand lines wants to land on what is being said now; the
        hole it is left with sits just after the lines it already held, where
        it can page into it (and draw a gap row until it does). Taking the
        oldest instead would leave the hole at the live end, under a composer.
        """
        limit = _clamp(limit)
        rows = self.db.execute(
            "SELECT * FROM events WHERE buffer_id=? AND eid > ? ORDER BY eid DESC LIMIT ?",
            (buffer_id, since_eid, limit + 1),
        ).fetchall()
        complete = len(rows) <= limit
        return [_row_to_event(r) for r in reversed(rows[:limit])], complete

    def backlog_around(self, buffer_id: int, eid: int, limit: int = 50) -> list[Event]:
        """History on BOTH sides of an eid, oldest first, including it.

        This is what a push notification needs: tapping "quinn mentioned you"
        should land you in the conversation surrounding that line, not at the
        end of the channel with the message somewhere above. Paging backwards
        only cannot answer it -- you do not know how far back to go.
        """
        limit = _clamp(limit)
        half = max(1, limit // 2)
        before = self.db.execute(
            "SELECT * FROM events WHERE buffer_id=? AND eid < ? ORDER BY eid DESC LIMIT ?",
            (buffer_id, eid, half),
        ).fetchall()
        onward = self.db.execute(
            "SELECT * FROM events WHERE buffer_id=? AND eid >= ? ORDER BY eid ASC LIMIT ?",
            (buffer_id, eid, limit - half),
        ).fetchall()
        return [_row_to_event(r) for r in reversed(before)] + [_row_to_event(r) for r in onward]

    def has_older(self, buffer_id: int, eid: int) -> bool:
        """Is there anything in this buffer before `eid`? What `around` asks to
        say whether its page reached the start of the buffer. It used to
        compare with eid 1, the first line on the whole bouncer, so an
        `around` page never said it had reached the start of any other."""
        return self.db.execute(
            "SELECT 1 FROM events WHERE buffer_id=? AND eid < ? LIMIT 1", (buffer_id, eid)
        ).fetchone() is not None

    def highlights(self, limit: int = 100, before_eid: int | None = None) -> list[Event]:
        """Every mention, across every buffer and network, NEWEST first --
        the mentions inbox reads down from the latest. Served by the partial
        index on highlight=1, so it stays a short scan however long the
        history."""
        limit = _clamp(limit)
        if before_eid:
            rows = self.db.execute(
                "SELECT * FROM events WHERE highlight=1 AND eid < ? ORDER BY eid DESC LIMIT ?",
                (before_eid, limit),
            ).fetchall()
        else:
            rows = self.db.execute(
                "SELECT * FROM events WHERE highlight=1 ORDER BY eid DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_row_to_event(r) for r in rows]

    def search(self, query: str, *, buffer_id: int | None = None,
               sender: str | None = None, since: float | None = None,
               until: float | None = None, limit: int = 50,
               before_eid: int | None = None) -> list[Event]:
        """Find messages. Newest first, because recent is usually what is wanted.

        `query` is PLAIN TEXT, not FTS5 syntax. It used to go into MATCH as
        typed, so a link, a domain, "what's", "c++", "#hangout" and "quinn:"
        were all syntax errors -- the things people most want to find again.
        Now each word (or "quoted phrase") is quoted for FTS5 and matched as
        the start of a word, and a word with punctuation in it must also appear
        literally, because FTS5 throws the punctuation away: "c++" would
        otherwise find every line with a word starting with c.

        `sender` is an exact nick (IRC case folding), a filter rather than a
        search term; `since` and `until` bound `ts`; `before_eid` pages.
        """
        if len(query or "") > MAX_SEARCH_CHARS:
            raise ValueError(f"A search can be at most {MAX_SEARCH_CHARS} characters.")
        # A term twice finds nothing more, and each punctuated one is a Python
        # call per matching row, so the same word typed twelve times cost
        # twelve times the one.
        terms = list({t.text.casefold(): t for t in search_terms(query or "")}.values())
        if len(terms) > MAX_SEARCH_TERMS:
            raise ValueError(f"Search for at most {MAX_SEARCH_TERMS} words at once.")
        if not terms and not sender:
            return []
        limit = _clamp(limit)

        fts = " ".join(t.fts for t in terms if t.fts)
        if fts:
            sql = ["SELECT e.* FROM events_search s JOIN events e ON e.eid = s.rowid",
                   "WHERE events_search MATCH ?"]
            params: list[Any] = [fts]
        else:
            # Nothing FTS5 can use ("((", ":)"), or a sender alone: a scan in
            # eid order, which stops as soon as the page is full.
            sql = ["SELECT e.* FROM events e WHERE 1"]
            params = []
        for term in terms:
            if term.literal:
                # geeyem_has is a Python call per row, and ":)" or "c++" used
                # to make one for every line there is: 400 ms over 200k lines,
                # on the event loop. Most lines are ASCII, and folding ASCII
                # only removes characters (formatting codes), lowers letters
                # and collapses spaces: every other character of the folded
                # term must be in the line as it is. SQLite checks that in C
                # (lower() only for letters), and only lines that pass, or are
                # not ASCII (accents, emoji, fullwidth forms), go on to the
                # exact test.
                needed = sorted(set(_fold_needle(term.literal)) - {" "})
                if all(char.isascii() for char in needed):
                    present = " AND ".join(
                        "instr(lower(e.text), ?) > 0" if char.isalpha() else "instr(e.text, ?) > 0"
                        for char in needed) or "1"
                    params.extend(needed)
                else:
                    present = "0"          # an ASCII line cannot hold it at all
                sql.append(f"AND (NOT {_ASCII.format(col='e.text')} OR ({present}))"
                           " AND geeyem_has(e.text, ?)")
                params.append(term.literal)
        if buffer_id is not None:
            sql.append("AND e.buffer_id = ?")
            params.append(buffer_id)
        if sender:
            # LIKE is ASCII case-insensitive and in C, and "_" stands in for
            # the four characters rfc1459 folds ({}|^ are []\~), so it passes
            # every nick that folds to this one and very little else; only
            # those go on to the Python call. A nick with no lines at all used
            # to cost one call per row, 45 ms over 200k lines.
            folded = fold(sender)
            pattern = "".join("_" if ch in "{}|^" else ("!" + ch if ch in "%_!" else ch)
                              for ch in folded)
            sql.append("AND e.sender LIKE ? ESCAPE '!' AND geeyem_fold(e.sender) = ?")
            params.extend([pattern, folded])
        if since is not None:
            sql.append("AND e.ts >= ?")
            params.append(since)
        if until is not None:
            sql.append("AND e.ts <= ?")
            params.append(until)
        if before_eid:
            sql.append("AND e.eid < ?")
            params.append(before_eid)
        # Only things people said. A search that returns joins and mode changes
        # is a search you have to filter by eye.
        sql.append("AND e.kind IN ('message', 'action', 'notice')")
        # A password typed to a service is kept only as its verb, and even that
        # is never offered back by search (it is not in the index either; this
        # covers the scans that do not use the index).
        sql.append("AND " + _NOT_REDACTED.format(row="e"))
        sql.append("ORDER BY e.eid DESC LIMIT ?")
        params.append(limit)

        try:
            rows = self.db.execute(" ".join(sql), params).fetchall()
        except sqlite3.OperationalError as exc:
            # Should not happen any more -- every term is quoted -- but if it
            # does, the person searching gets a sentence, not "fts5: syntax
            # error near ...", and the detail goes to the journal.
            # Not the query itself: it is what someone was looking for in
            # their own conversations, and the journal is not the place.
            log.warning("a search of %d term(s) failed: %s", len(terms), exc)
            raise ValueError("That search could not be run. Try different words.") from exc
        return [_row_to_event(r) for r in rows]

    def max_eid(self) -> int:
        row = self.db.execute("SELECT COALESCE(MAX(eid), 0) AS m FROM events").fetchone()
        return row["m"]

    # --- members -----------------------------------------------------------

    def replace_members(self, buffer_id: int, members: Iterable[tuple[str, str]]) -> None:
        """Wholesale replacement of a channel's member list. See the schema note."""
        self.db.execute("BEGIN")
        try:
            self.db.execute("DELETE FROM members WHERE buffer_id=?", (buffer_id,))
            self.db.executemany(
                "INSERT OR REPLACE INTO members (buffer_id, nick, nick_lower, prefix) VALUES (?,?,?,?)",
                [(buffer_id, nick, fold(nick), prefix) for nick, prefix in members],
            )
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def add_member(self, buffer_id: int, nick: str, prefix: str = "") -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO members (buffer_id, nick, nick_lower, prefix) VALUES (?,?,?,?)",
            (buffer_id, nick, fold(nick), prefix),
        )

    def remove_member(self, buffer_id: int, nick: str) -> None:
        self.db.execute(
            "DELETE FROM members WHERE buffer_id=? AND nick_lower=?", (buffer_id, fold(nick))
        )

    def member(self, buffer_id: int, nick: str) -> dict[str, str] | None:
        """One member of a channel, as stored, or None."""
        row = self.db.execute(
            "SELECT nick, prefix FROM members WHERE buffer_id=? AND nick_lower=?",
            (buffer_id, fold(nick)),
        ).fetchone()
        return {"nick": row["nick"], "prefix": row["prefix"]} if row else None

    def set_member_prefix(self, buffer_id: int, nick: str, prefix: str) -> None:
        self.db.execute(
            "UPDATE members SET prefix=? WHERE buffer_id=? AND nick_lower=?",
            (prefix, buffer_id, fold(nick)),
        )

    def rename_member(self, old: str, new: str, network_id: int | None = None) -> list[int]:
        """Rename a nick everywhere it appears. Returns the buffers that changed,
        so the gateway can push exactly those member lists and no others.

        `network_id` keeps a rename on one network out of another's channels:
        the same nick on two networks is two different people."""
        if network_id is None:
            rows = self.db.execute(
                "SELECT buffer_id FROM members WHERE nick_lower=?", (fold(old),)
            ).fetchall()
        else:
            rows = self.db.execute(
                "SELECT m.buffer_id FROM members m JOIN buffers b ON b.id = m.buffer_id"
                " WHERE m.nick_lower=? AND b.network_id=?", (fold(old), network_id)
            ).fetchall()
        ids = [r["buffer_id"] for r in rows]
        for bid in ids:
            row = self.db.execute(
                "SELECT prefix FROM members WHERE buffer_id=? AND nick_lower=?", (bid, fold(old))
            ).fetchone()
            prefix = row["prefix"] if row else ""
            self.db.execute("DELETE FROM members WHERE buffer_id=? AND nick_lower=?", (bid, fold(old)))
            self.add_member(bid, new, prefix)
        return ids

    def members(self, buffer_id: int) -> list[dict[str, str]]:
        rows = self.db.execute(
            "SELECT nick, prefix FROM members WHERE buffer_id=? ORDER BY"
            # Owners and admins, ops, half-ops, voiced, then everyone else --
            # the order a client would have to re-derive anyway. ~ and & used to
            # fall through to the end, below people with no prefix at all.
            "  CASE prefix WHEN '~' THEN 0 WHEN '&' THEN 1 WHEN '@' THEN 2"
            "   WHEN '%' THEN 3 WHEN '+' THEN 4 ELSE 5 END,"
            "  nick_lower",
            (buffer_id,),
        )
        return [{"nick": r["nick"], "prefix": r["prefix"]} for r in rows]

    def last_known_host(self, buffer_id: int, nick: str) -> str | None:
        """The most recent hostmask seen for someone in this channel.

        Needed to build a ban mask. IRC's NAMES reply carries no hosts, so the
        only source is an event we have actually seen from them — a join, a
        message, a part. Falls back to None, and the caller then bans the nick
        alone, which is weaker but honest about what it knows.
        """
        row = self.db.execute(
            "SELECT sender_host FROM events"
            " WHERE buffer_id=? AND lower(sender)=? AND sender_host IS NOT NULL"
            " AND sender_host != ''"
            " ORDER BY eid DESC LIMIT 1",
            (buffer_id, nick.lower()),
        ).fetchone()
        return row["sender_host"] if row else None

    def member_nicks(self, buffer_id: int) -> set[str]:
        return {
            r["nick_lower"]
            for r in self.db.execute("SELECT nick_lower FROM members WHERE buffer_id=?", (buffer_id,))
        }

    def clear_members(self, buffer_id: int) -> None:
        self.db.execute("DELETE FROM members WHERE buffer_id=?", (buffer_id,))

    # --- tokens ------------------------------------------------------------

    @staticmethod
    def hash_token(token: str) -> str:
        import hashlib

        return hashlib.sha256(token.encode()).hexdigest()

    def create_token(self, label: str) -> str:
        """Mint a client token. The plaintext is returned once and never stored."""
        token = "relay_" + secrets.token_urlsafe(32)
        self.db.execute(
            "INSERT INTO tokens (token_hash, label, created_at) VALUES (?,?,?)",
            (self.hash_token(token), label, time.time()),
        )
        return token

    def token_id(self, token: str) -> int | None:
        """The id of an active token, without counting it as used: for the
        bouncer itself, which has just made it (first run)."""
        row = self.db.execute(
            "SELECT id FROM tokens WHERE token_hash=? AND revoked=0", (self.hash_token(token),)
        ).fetchone()
        return row["id"] if row else None

    def verify_token(self, token: str) -> int | None:
        row = self.db.execute(
            "SELECT id FROM tokens WHERE token_hash=? AND revoked=0", (self.hash_token(token),)
        ).fetchone()
        if not row:
            return None
        self.db.execute("UPDATE tokens SET last_used_at=? WHERE id=?", (time.time(), row["id"]))
        return row["id"]

    def list_tokens(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.db.execute(
            "SELECT id, label, created_at, last_used_at, revoked FROM tokens ORDER BY id"
        )]

    def token(self, token_id: int) -> dict[str, Any] | None:
        """One token's id and label, revoked or not, or None. Never the hash."""
        row = self.db.execute("SELECT id, label, revoked FROM tokens WHERE id=?",
                              (token_id,)).fetchone()
        return dict(row) if row else None

    def active_tokens(self) -> list[dict[str, Any]]:
        """The tokens that still work, for the `tokens` frame: id, label,
        when each was made and last used, and whether anything is registered
        for notifications under it (an APNs device or a browser subscription).
        Never the hash, and never a revoked one: a revoked token is gone as far
        as any client is concerned."""
        return [
            {"id": r["id"], "label": r["label"], "created_at": r["created_at"],
             "last_used_at": r["last_used_at"], "push": bool(r["push"])}
            for r in self.db.execute(
                "SELECT t.id, t.label, t.created_at, t.last_used_at,"
                "       (EXISTS (SELECT 1 FROM devices d WHERE d.token_id = t.id)"
                "        OR EXISTS (SELECT 1 FROM webpush_subscriptions w"
                "                    WHERE w.token_id = t.id)) AS push"
                "  FROM tokens t WHERE t.revoked = 0 ORDER BY t.id")]

    def revoke_token(self, token_id: int) -> bool:
        """Revoke a client token and forget the devices registered under it.

        Usually called from the CLI, in another process from the running
        bouncer. The devices go here, at the source, because a revoked phone
        must stop getting message text on its lock screen whether or not the
        bouncer notices the revocation first. The bouncer closes the phone's
        live socket on its own next check (see Gateway._token_sweep).
        """
        cur = self.db.execute("UPDATE tokens SET revoked=1 WHERE id=?", (token_id,))
        self.db.execute("DELETE FROM devices WHERE token_id=?", (token_id,))
        self.db.execute("DELETE FROM webpush_subscriptions WHERE token_id=?", (token_id,))
        return cur.rowcount > 0

    def token_active(self, token_id: int) -> bool:
        """Is this token still good? Missing counts as revoked.

        A token is checked at the handshake and again after that, because a
        socket outlives the moment it was opened: revoking a lost phone's token
        has to cut off the connection it already has, not only its next one.
        """
        row = self.db.execute("SELECT revoked FROM tokens WHERE id=?", (token_id,)).fetchone()
        return bool(row) and not row["revoked"]

    # --- uploads (schema 10) -------------------------------------------------

    def record_upload(self, key: str, content_type: str, size: int,
                      created: float, expires: float | None) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO uploads (key, content_type, size, created, expires) "
            "VALUES (?, ?, ?, ?, ?)", (key, content_type, size, created, expires))

    def mark_uploads_sent(self, keys: list[str]) -> None:
        for key in keys:
            self.db.execute("UPDATE uploads SET sent = 1 WHERE key = ? AND deleted IS NULL",
                            (key,))

    def mark_upload_deleted(self, key: str, when: float) -> None:
        """Also records a file that was deleted by link which the table never
        saw (one uploaded before schema 10), so a later list does not need it."""
        self.db.execute("UPDATE uploads SET deleted = ? WHERE key = ?", (when, key))

    def list_uploads(self, *, before: float | None, limit: int) -> list[sqlite3.Row]:
        """Live uploads that went out in a line, newest first. `before` is the
        `created` of the last row of the page before."""
        if before is None:
            cur = self.db.execute(
                "SELECT * FROM uploads WHERE deleted IS NULL AND sent = 1 "
                "ORDER BY created DESC LIMIT ?", (limit,))
        else:
            cur = self.db.execute(
                "SELECT * FROM uploads WHERE deleted IS NULL AND sent = 1 AND created < ? "
                "ORDER BY created DESC LIMIT ?", (before, limit))
        return cur.fetchall()

    def due_uploads(self, now: float, limit: int = 20) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM uploads WHERE deleted IS NULL AND expires IS NOT NULL "
            "AND expires <= ? ORDER BY expires LIMIT ?", (now, limit)).fetchall()

    def active_token_ids(self) -> set[int]:
        return {r["id"] for r in self.db.execute("SELECT id FROM tokens WHERE revoked=0")}

    # --- devices -----------------------------------------------------------

    def register_device(self, token_id: int, apns_token: str, platform: str, environment: str) -> None:
        self.db.execute(
            "INSERT INTO devices (token_id, apns_token, platform, environment, updated_at)"
            " VALUES (?,?,?,?,?)"
            " ON CONFLICT(apns_token) DO UPDATE SET"
            "   token_id=excluded.token_id, platform=excluded.platform,"
            "   environment=excluded.environment, updated_at=excluded.updated_at",
            (token_id, apns_token, platform, environment, time.time()),
        )

    def devices(self) -> list[dict[str, Any]]:
        """Devices to push to: only those registered under a token still active.

        Filtered here rather than trusted to have been cleaned up, because the
        revoke happens in another process and a row could outlive it for any
        number of reasons (an older bouncer revoked it, a crash between the two
        statements). A revoked token's device must never get a push.
        """
        return [dict(r) for r in self.db.execute(
            "SELECT d.* FROM devices d JOIN tokens t ON t.id = d.token_id"
            " WHERE t.revoked = 0")]

    def unregister_device(self, token_id: int, apns_token: str) -> bool:
        """A client signing out. Only its own row: a device registered under a
        different token is that token's business."""
        cur = self.db.execute("DELETE FROM devices WHERE apns_token=? AND token_id=?",
                              (apns_token, token_id))
        return cur.rowcount > 0

    def forget_devices_for_token(self, token_id: int) -> int:
        cur = self.db.execute("DELETE FROM devices WHERE token_id=?", (token_id,))
        self.db.execute("DELETE FROM webpush_subscriptions WHERE token_id=?", (token_id,))
        return cur.rowcount

    def forget_device(self, apns_token: str) -> None:
        """Called when APNs reports a token as gone. Keeping it means retrying a
        dead device forever and eventually getting rate-limited for it."""
        self.db.execute("DELETE FROM devices WHERE apns_token=?", (apns_token,))

    # --- people (G84) --------------------------------------------------------

    def member_buffers(self, network_id: int, nick: str) -> list[tuple[int, str]]:
        """Every channel of a network this person is in, with the spelling of
        their nick stored there: (buffer id, nick)."""
        return [(r["buffer_id"], r["nick"]) for r in self.db.execute(
            "SELECT m.buffer_id, m.nick FROM members m JOIN buffers b ON b.id = m.buffer_id"
            " WHERE m.nick_lower=? AND b.network_id=?", (fold(nick), network_id))]

    def open_queries(self, network_id: int) -> dict[str, str]:
        """{folded nick: nick} for every open (not closed) query of a network."""
        return {r["name_lower"]: r["name"] for r in self.db.execute(
            "SELECT name, name_lower FROM buffers"
            " WHERE network_id=? AND kind='query' AND archived=0", (network_id,))}

    def member_count(self, buffer_id: int) -> int:
        return self.db.execute("SELECT COUNT(*) AS n FROM members WHERE buffer_id=?",
                               (buffer_id,)).fetchone()["n"]

    # --- query rename and merge (G65) --------------------------------------

    def rename_buffer(self, buffer_id: int, name: str) -> None:
        """A query follows its person to a new nick. Only for a name no other
        buffer of the network holds -- merge_buffers is for when one does."""
        self.db.execute("UPDATE buffers SET name=?, name_lower=? WHERE id=?",
                        (name, fold(name), buffer_id))

    def merge_buffers(self, src: int, dst: int) -> None:
        """Fold one query into another: every line of `src` moves to `dst`
        (eids unchanged, so the two histories interleave in the order they
        happened), and `src` is gone.

        One read marker has to stand for two. It is the later of the two, pulled
        back to just before the first line that was unread in either, so nothing
        that was unread before the merge reads as read after it -- at the cost
        of a few already-read lines of the other one counting again.
        """
        a, b = self.buffer(src), self.buffer(dst)
        if a is None or b is None or src == dst:
            return
        first_unread = self.db.execute(
            "SELECT MIN(eid) AS m FROM events WHERE self = 0"
            " AND kind IN ('message', 'action', 'notice', 'invite')"
            " AND ((buffer_id = ? AND eid > ?) OR (buffer_id = ? AND eid > ?))",
            (src, a.last_seen_eid, dst, b.last_seen_eid)).fetchone()["m"]
        marker = max(a.last_seen_eid, b.last_seen_eid)
        if first_unread is not None and first_unread <= marker:
            marker = first_unread - 1
        self.db.execute("BEGIN")
        try:
            self.db.execute("UPDATE events SET buffer_id=? WHERE buffer_id=?", (dst, src))
            self.db.execute(
                "UPDATE buffers SET last_seen_eid=?, pinned=?, archived=? WHERE id=?",
                (marker, int(a.pinned or b.pinned), int(a.archived and b.archived), dst))
            self.db.execute("DELETE FROM members WHERE buffer_id=?", (src,))
            self.db.execute("DELETE FROM buffers WHERE id=?", (src,))
            self.db.execute("COMMIT")
            self._forget_unread()
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    # --- clearing and export (G76) -----------------------------------------

    def clear_events(self, buffer_id: int, chunk: int = 5000) -> int:
        """Delete up to `chunk` of a buffer's events; returns how many went.

        In chunks so the caller can yield to the event loop between them: a
        busy channel's years are hundreds of thousands of rows, each taking its
        search-index entry with it (the delete trigger), and one statement for
        all of them would hold the IRC read loop for seconds. The search rows go
        with the events because the index is external-content: the trigger
        removes each one as its event is deleted.
        """
        cur = self.db.execute(
            "DELETE FROM events WHERE eid IN"
            " (SELECT eid FROM events WHERE buffer_id=? ORDER BY eid LIMIT ?)",
            (buffer_id, chunk))
        self._forget_unread()
        return cur.rowcount

    def count_events(self, buffer_id: int) -> int:
        return self.db.execute("SELECT COUNT(*) AS n FROM events WHERE buffer_id=?",
                               (buffer_id,)).fetchone()["n"]

    # --- small secrets and facts in `meta` ----------------------------------

    def meta_get(self, key: str) -> str | None:
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def meta_set(self, key: str, value: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))

    @property
    def epoch(self) -> str:
        """An opaque id of this database, constant for its life.

        What `hello` carries so a client can tell that the database behind the
        bouncer is not the one its cached lines came from. An eid is only
        unique within one database: after a restore from last night's backup
        the bouncer hands out again the eids it used since, for different
        lines, and a client that kept the old ones would merge the two
        histories by number. A restored database must therefore carry a new
        epoch -- tools/backup.py leaves the epoch out of every snapshot it
        takes, so a restored one is given a new one here the first time it is
        opened, and `python -m relay epoch new` does it by hand for a database
        brought back any other way (a disk snapshot, a copied file).
        """
        value = self.meta_get("epoch")
        if value is None:                 # deleted under a running bouncer
            return self.new_epoch()
        return value

    def new_epoch(self) -> str:
        value = secrets.token_hex(8)
        self.meta_set("epoch", value)
        return value

    def secret(self, name: str, nbytes: int = 32) -> bytes:
        """A random key made once and kept: the HMAC key behind link-preview
        image URLs. In the database rather than the environment because nobody
        should have to set it up, and losing it only breaks old image links."""
        key = f"secret:{name}"
        value = self.meta_get(key)
        if value is None:
            value = secrets.token_hex(nbytes)
            self.meta_set(key, value)
        return bytes.fromhex(value)

    # --- web push subscriptions (G74) ---------------------------------------

    def register_webpush(self, token_id: int, endpoint: str, p256dh: str, auth: str,
                         subject: str | None = None) -> None:
        self.db.execute(
            "INSERT INTO webpush_subscriptions"
            " (token_id, endpoint, p256dh, auth, subject, updated_at) VALUES (?,?,?,?,?,?)"
            " ON CONFLICT(endpoint) DO UPDATE SET token_id=excluded.token_id,"
            "   p256dh=excluded.p256dh, auth=excluded.auth, subject=excluded.subject,"
            "   updated_at=excluded.updated_at",
            (token_id, endpoint, p256dh, auth, subject, time.time()))

    def unregister_webpush(self, token_id: int, endpoint: str) -> bool:
        """Only this token's own subscription, as with unregister_device."""
        cur = self.db.execute(
            "DELETE FROM webpush_subscriptions WHERE endpoint=? AND token_id=?",
            (endpoint, token_id))
        return cur.rowcount > 0

    def webpush_subscriptions(self) -> list[dict[str, Any]]:
        """Browsers to push to: only under a token still active, like devices()."""
        return [dict(r) for r in self.db.execute(
            "SELECT w.* FROM webpush_subscriptions w JOIN tokens t ON t.id = w.token_id"
            " WHERE t.revoked = 0")]

    def forget_webpush(self, endpoint: str) -> None:
        """The push service said this subscription is gone (404/410)."""
        self.db.execute("DELETE FROM webpush_subscriptions WHERE endpoint=?", (endpoint,))

    # --- link preview cache (G71) --------------------------------------------

    def cached_preview(self, url: str, max_age: float, error_age: float
                       ) -> tuple[dict | None, str | None] | None:
        """(card, None) or (None, error) when fetched recently enough, else None.
        Failures are kept for less time than successes: a page that was down
        should not stay without a card for a day."""
        row = self.db.execute(
            "SELECT fetched_at, data, error FROM link_previews WHERE url=?", (url,)).fetchone()
        if row is None:
            return None
        age = time.time() - row["fetched_at"]
        if row["error"] is not None:
            return (None, row["error"]) if age < error_age else None
        if age >= max_age:
            return None
        try:
            return json.loads(row["data"]), None
        except ValueError:
            return None

    def save_preview(self, url: str, card: dict | None, error: str | None) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO link_previews (url, fetched_at, data, error)"
            " VALUES (?,?,?,?)",
            (url, time.time(), json.dumps(card) if card is not None else None, error))

    def prune_previews(self, max_age: float) -> None:
        cutoff = time.time() - max_age
        self.db.execute("DELETE FROM link_previews WHERE fetched_at < ?", (cutoff,))
        self.db.execute("DELETE FROM preview_images WHERE created_at < ?", (cutoff,))

    def preview_image_url(self, digest: str) -> str | None:
        row = self.db.execute("SELECT url FROM preview_images WHERE hash=?",
                              (digest,)).fetchone()
        return row["url"] if row else None

    def save_preview_image(self, digest: str, url: str) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO preview_images (hash, url, created_at) VALUES (?,?,?)",
            (digest, url, time.time()))


# Tables added in wave 4 (link previews, web push). Created with IF NOT EXISTS
# on every start, like SCHEMA, so an older database simply gains them; nothing
# in them is history, and losing any of it costs a refetch or a re-subscribe.
WAVE4B_SCHEMA = """
-- A browser's Web Push subscription (the PWA's notifications). The endpoint is
-- the push service's URL for that one browser; p256dh and auth are the keys the
-- payload is encrypted to (RFC 8291). Tied to the token it was registered
-- under, so revoking the token stops the notifications, like `devices`.
CREATE TABLE IF NOT EXISTS webpush_subscriptions (
    id         INTEGER PRIMARY KEY,
    token_id   INTEGER REFERENCES tokens(id),
    endpoint   TEXT UNIQUE NOT NULL,
    p256dh     TEXT NOT NULL,
    auth       TEXT NOT NULL,
    -- The VAPID `sub` claim to send with it: the web client's own origin, which
    -- is a real https URL (Apple refuses a push whose subject is not).
    subject    TEXT,
    updated_at REAL NOT NULL
);

-- Link cards, one per URL, kept a day. `data` is the card as JSON; `error` the
-- sentence a failed fetch answered with, kept for less time.
CREATE TABLE IF NOT EXISTS link_previews (
    url        TEXT PRIMARY KEY,
    fetched_at REAL NOT NULL,
    data       TEXT,
    error      TEXT
);

-- The remote image behind each /p/<mac>/<hash> URL a card handed out. The hash
-- is what the URL names; the bouncer fetches `url` itself, so the phone never
-- contacts the site.
CREATE TABLE IF NOT EXISTS preview_images (
    hash       TEXT PRIMARY KEY,
    url        TEXT NOT NULL,
    created_at REAL NOT NULL
);

-- What this bouncer has handed out an upload URL for (schema 10). The storage
-- bucket is not listed anywhere else: the bouncer used to forget a file the
-- moment it had signed for it, so there was no "my uploads" and nothing to
-- expire. `sent` is set when a line carrying the link goes out, which is how a
-- file that was signed for and never picked is kept out of the list. `expires`
-- is NULL for a file that stays. `deleted` is when it went (by hand or by the
-- timer); the row is kept so a link in an old line can still say what it was.
CREATE TABLE IF NOT EXISTS uploads (
    key          TEXT PRIMARY KEY,
    content_type TEXT NOT NULL,
    size         INTEGER NOT NULL,
    created      REAL NOT NULL,
    expires      REAL,
    sent         INTEGER NOT NULL DEFAULT 0,
    deleted      REAL
);
CREATE INDEX IF NOT EXISTS uploads_due ON uploads (expires) WHERE deleted IS NULL AND expires IS NOT NULL;
CREATE INDEX IF NOT EXISTS uploads_list ON uploads (created) WHERE deleted IS NULL AND sent = 1;
"""
