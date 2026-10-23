"""A NetworkSession: one IRC network's worth of state, backlog and rejoin logic.

This is where an IRC line becomes a stored event and a frame for the clients. It
owns the IRCConnection but is not owned by any client -- it runs whether or not
anyone is attached, which is the whole point.

Sequence of a received channel line:
    IRCConnection -> on_message -> _handle_privmsg
      -> resolve/create the buffer
      -> decide highlight
      -> Store.append_event   (assigns the eid; this is the moment it is durable)
      -> hub.broadcast        (live clients)
      -> push, if it was a highlight and nothing is watching
The store write happens BEFORE the broadcast, deliberately: a client must never
see an eid that would not be there after a crash.
"""

from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from . import protocol as P
from . import APP_NAME
from .config import NetworkConfig
from .highlight import HighlightMatcher
from .ircconn import IRCConnection
from .ircproto import (
    DEFAULT_CHANMODES,
    IgnoreMatcher,
    Message,
    Prefix,
    check_channel,
    check_channel_key,
    check_param,
    fold,
    format_line,
    is_mask,
    join_lines,
    make_ctcp,
    mask_matches_everyone,
    netsplit_servers,
    normalize_mask,
    parse_chanmodes,
    parse_ctcp,
    parse_isupport,
    parse_line,
    parse_mode_changes,
    parse_prefix_map,
    parse_server_time,
    redact_secret,
    say_budget,
    split_message,
    strip_formatting,
    targmax,
)
from .push import Notification
from .qauth import Q_BOT, QAuth
from .store import Buffer, Store

if TYPE_CHECKING:
    from .hub import Hub

log = logging.getLogger("relay.session")

STATUS_BUFFER_NAME = "*status*"

# Lines already waiting upstream before a `say` is refused outright. The queue
# drains at one line every two seconds once the burst is spent (see
# ircconn.FLOOD_INTERVAL), so 15 is half a minute of waiting -- past that,
# accepting the message would be accepting a line that arrives long after the
# conversation moved on.
MAX_QUEUED_BEFORE_REFUSING = 15

# How long `say` waits for its first line to reach the socket before answering.
# The echo is stored when a line is WRITTEN, not when it is queued (see say),
# and the `ok` carries that echo when it exists. With the queue empty the write
# happens within the same tick, so the ok looks exactly as it always has; behind
# a queue the ok goes without it rather than holding the client's other frames.
SAY_ECHO_WAIT = 0.5

# CTCP replies are answered on someone else's schedule, which is the problem:
# anyone can send a hundred CTCP PINGs, and answering all of them puts a hundred
# NOTICEs in front of the user's own next message. One reply per sender per verb
# per ten seconds, five in ten seconds overall, and the rest are dropped without
# a word -- and without a line in the status buffer either, or a CTCP flood
# would become a status-buffer flood. Per verb: a client that asks VERSION and
# then PING in the same second (irssi's /ctcp nick VERSION then /ping, which is
# what people do) used to get the PING dropped.
CTCP_WINDOW = 10.0
CTCP_PER_SENDER = 10.0
CTCP_BURST = 5

# The CTCPs that are answered, and what with. CLIENTINFO lists the verbs this
# client understands, ACTION included (it is how /me arrives).
CTCP_CLIENTINFO = "ACTION CLIENTINFO PING VERSION"

# Wave 4 presence: how often to ask who is away (WHO, only where the server
# has no away-notify) and who is online (ISON, only where it has no MONITOR),
# and the largest channel a WHO is sent for. A WHO of a 300-person channel is
# 300 lines back; past that the answer costs more than it is worth, and a big
# channel's away marks are the least interesting ones.
WHO_INTERVAL = 300.0
WHO_MAX_MEMBERS = 300
ISON_INTERVAL = 60.0
# The first poll waits this long after registering, so the join burst and the
# MOTD are over and the server's 005 (does it have MONITOR?) is known.
FIRST_POLL_DELAY = 10.0
# A query opened or renamed asks again sooner than the minute, but no more
# often than this.
PRESENCE_MIN_GAP = 5.0
# How long an ISON may go unanswered before its place in line is given up. An
# ISON the server refuses (421) is never answered, and the replies carry
# nothing to say which question they answer, so the line of questions is
# matched up in order; one left in it forever would shift every answer after it.
ISON_STALE = 30.0
# One ISON or MONITOR line's worth of nicks, in bytes: comfortably inside the
# 512-byte line once the command and the server's own additions are counted.
PRESENCE_LINE_BYTES = 400

# Private messages from these are services talking, not people: into the status
# buffer (or an open query with them), never highlighted, never pushed. Q is
# QuakeNet's; NickServ, ChanServ and the rest end in "Serv" everywhere else.
SERVICE_NICKS = {"q"}


def _batches(names: list[str], *, sep: str = " ",
             limit: int = PRESENCE_LINE_BYTES) -> list[list[str]]:
    """Nicks grouped so each group, joined by `sep`, fits in one line."""
    out: list[list[str]] = []
    current: list[str] = []
    size = 0
    for name in names:
        cost = len(name.encode("utf-8")) + len(sep)
        if current and size + cost > limit:
            out.append(current)
            current, size = [], 0
        current.append(name)
        size += cost
    if current:
        out.append(current)
    return out

# Numerics worth writing into the status buffer. Everything else from the server
# is either handled structurally (names, topic, isupport) or is MOTD-grade noise
# that would bury the interesting lines.
INTERESTING_NUMERICS = {
    "004",  # server version
    "251", "255",  # user counts
    # The WHOIS numerics are deliberately not here. They are collected into one
    # `whois` frame instead (see NetworkSession.whois), because nine lines of
    # server text in a buffer nobody is looking at is not an answer to "who is
    # this". Two of them are not only whois replies: 301 is also what the
    # server says when you message someone who is away, and 401 when you
    # message someone who has gone. With no lookup waiting on them they are
    # routed like the errors below (see _route_numeric), into the query.
    "375", "372", "376",  # motd; kept because people do read the QuakeNet motd
    # 396 is handled structurally by _h_396, not echoed here. Errors (4xx and
    # 5xx) are not listed: every one is routed, see ERROR_SOURCES.
}

# Every 4xx and 5xx numeric is routed to the buffer it concerns (see
# NetworkSession._route_numeric) rather than filtered through the list above;
# that filter used to drop 482, 477, 432, 437, 441 and the rest, so a refused
# /topic, /op or /kick said nothing anywhere. When a numeric names no channel
# and no query buffer, it goes back to the conversation that sent the command
# most likely to have caused it, if that was in the last REQUEST_MEMORY seconds.
REQUEST_MEMORY = 10.0
# A 301 ("alice is away: lunch") repeats after every line sent to alice; the
# same message is shown again only after this long.
AWAY_REPLY_QUIET = 3600.0
# After a client's `raw` line goes out, the server's answer is shown for this
# long: any numeric nothing else has a use for becomes a line in the Server
# buffer (see NetworkSession._raw_answer). Outside the window those numerics
# are dropped as before -- they are the server talking to the bouncer (the
# LUSERS block at connect, the replies to its own WHO and MODE), not to anyone.
# Until 2026-10 they were dropped inside it too, so /quote MODE #chan +b,
# WHOWAS and a hand-typed WHO were typed into silence.
RAW_ANSWER_WINDOW = 10.0
# The most lines one `raw` may put there. A LIST on QuakeNet is tens of
# thousands of rows and a LINKS or a STATS hundreds; past this the rest are
# dropped and one line says so.
RAW_ANSWER_MAX = 200
# The numerics that make up a WHOIS reply, a WHO reply and a LIST reply. Each
# has a handler that keeps it for something the bouncer asked (a whois card,
# the away poll, a channel browser) and has nothing to do with one a person
# typed by hand; see _raw_claims.
WHOIS_NUMERICS = {"311", "312", "313", "317", "318", "319", "330", "338", "671"}
WHO_NUMERICS = {"352", "315"}
LIST_NUMERICS = {"321", "322", "323"}
ERROR_SOURCES: dict[str, tuple[str, ...]] = {
    "401": ("PRIVMSG", "NOTICE", "CTCP", "WHOIS", "INVITE", "MODE", "KICK"),
    "403": ("JOIN", "PART", "TOPIC", "MODE", "KICK", "NAMES", "LIST"),
    "404": ("PRIVMSG", "NOTICE"),
    "405": ("JOIN",),
    "407": ("PRIVMSG", "NOTICE", "JOIN"),
    "411": ("PRIVMSG", "NOTICE"),
    "412": ("PRIVMSG", "NOTICE"),
    "431": ("NICK",), "432": ("NICK",), "433": ("NICK",), "436": ("NICK",),
    "437": ("NICK", "JOIN"), "438": ("NICK",),
    "441": ("KICK", "MODE"),
    "442": ("PART", "TOPIC", "KICK", "MODE", "INVITE", "NAMES"),
    "443": ("INVITE",),
    "467": ("MODE",),
    "471": ("JOIN",), "473": ("JOIN",), "474": ("JOIN",), "475": ("JOIN",),
    "476": ("JOIN", "MODE"), "477": ("JOIN", "PRIVMSG", "NOTICE"), "478": ("MODE",),
    "482": ("TOPIC", "MODE", "KICK", "INVITE"),
    "501": ("MODE",), "502": ("MODE",),
}

# How long a WHOIS waits for the 318 that ends it. A server that is going to
# answer answers in well under a second, so this is not a guess at a slow
# reply -- it is the backstop for a nick the server neither confirms nor
# denies, which otherwise leaves the client waiting forever.
WHOIS_TIMEOUT = 10.0

# Every field of a successful whois frame, filled in with what "not known"
# looks like. The server sends whichever numerics it feels like and QuakeNet
# sends a different set from the rest, so without this the card would have a
# dozen optional keys and the client would need a branch for each.
WHOIS_FIELDS: dict = {
    "user": "",
    "host": "",
    "realname": "",
    "server": "",
    "server_info": "",
    "channels": [],
    "idle_seconds": None,
    "signon_at": None,
    "account": None,
    "away": None,
    "secure": False,
    "operator": False,
    "actual_host": None,
}


@dataclass
class PendingWhois:
    """One WHOIS in flight.

    Its reply is a run of numerics that arrive as separate lines and name only
    the nick, so the folded nick is the only thing there is to key on and the
    only thing tying the reply back to the client that asked. The partial is
    filled in as the lines arrive and goes out as one frame when 318 closes it.
    """

    nick: str
    req: str | None
    data: dict = field(default_factory=dict)
    timeout: asyncio.Task | None = None

    def cancel(self) -> None:
        if self.timeout is not None:
            self.timeout.cancel()
            self.timeout = None


@dataclass
class PendingList:
    """One LIST in flight: the rows so far, and who is waiting for them."""

    future: asyncio.Future
    rows: list = field(default_factory=list)
    timeout: asyncio.Task | None = None


# How often a bouncer sitting on a fallback nick asks whether its own is free.
RECLAIM_INTERVAL = 60.0
# The least time between two instant reclaims (a QUIT or NICK that frees our
# configured nick; see NetworkSession._reclaim_now_if_freed).
INSTANT_RECLAIM_GAP = 10.0

# What auto-away says. See NetworkSession.set_auto_away and hub.Hub.
AUTO_AWAY_MESSAGE = "Away"

# Typing notifications (IRCv3 +typing, a client-only tag on TAGMSG). At most
# one "active" per this many seconds per target, which is the rate the spec
# asks for: a receiver keeps someone "typing" for six seconds after the last
# one, so every three keeps the line up without a TAGMSG per keystroke.
TYPING_ACTIVE_EVERY = 3.0
# What a client may say, and what goes upstream for each. "paused" is sent on
# as it is; a receiver of ours reads it as "done" (see _h_tagmsg).
TYPING_STATES = ("active", "paused", "done")

# A channel list (LIST) keeps the most populated this many channels, and gives
# up waiting for the server's 323 after this long. QuakeNet lists tens of
# thousands of channels; a phone wants the ones people are in.
LIST_MAX = 5000
LIST_TIMEOUT = 90.0

# Commands a `raw` line may not carry. PASS, USER, CAP and AUTHENTICATE belong
# to registration, which the bouncer does itself; QUIT would end the bouncer's
# own connection, which is what "disconnect" in the app is for.
#
# A password typed to a service (IDENTIFY to NickServ, AUTH to Q) is NOT
# refused here any more. It used to be, for Q only; now one rule covers every
# service and every way of typing it: the line goes to the service as typed,
# and what the bouncer keeps of it stops at the verb. `raw` keeps nothing of
# what it sends in the first place, and `say` redacts its echo (see say).
_REGISTRATION_ONLY = "PASS, USER, CAP and AUTHENTICATE are the bouncer's to send."
RAW_REFUSED = {
    "PASS": _REGISTRATION_ONLY,
    "USER": _REGISTRATION_ONLY,
    "CAP": _REGISTRATION_ONLY,
    "AUTHENTICATE": _REGISTRATION_ONLY,
    "QUIT": "QUIT would disconnect the bouncer itself. Use the app to disconnect.",
}

# The time a stored event says it happened, while one line from the server is
# being handled: its IRCv3 `@time=` when the server sends server-time, else
# unset and the store uses "now". A context variable rather than a parameter
# threaded through every handler, and scoped to the task handling that one
# line -- the flood queue's callbacks (our own echoes) run in their own task
# and never see it.
_EVENT_TS: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "geeyem_event_ts", default=None)

# The lines whose `@time=` is when something happened in a conversation, and
# so the stored event's time. Numerics are answers to what we just asked and
# are stamped when they arrive.
TIMED_COMMANDS = {"PRIVMSG", "NOTICE", "JOIN", "PART", "KICK", "QUIT", "NICK", "TOPIC",
                  "MODE", "INVITE", "WALLOPS", "AWAY", "ACCOUNT", "CHGHOST", "SETNAME"}

# The ISUPPORT (005) tokens every client is shown, as the server sent them, in
# the network frame's `isupport`. The clients build operator menus from PREFIX
# and CHANMODES, and route @#chan with STATUSMSG.
ISUPPORT_WIRE = ("network", "prefix", "chanmodes", "statusmsg", "casemapping", "chantypes")

# What edit_network can change that only a new connection can apply.
RECONNECT_FIELDS = ("host", "port", "tls", "username", "realname", "password",
                    "sasl_mechanism", "sasl_username", "sasl_password")

# How long an uncertain member-list change waits before asking for NAMES, so a
# burst of them is one question. See NetworkSession._queue_names.
NAMES_SETTLE = 1.5


class NetworkSession:
    def __init__(self, config: NetworkConfig, store: Store, hub: "Hub", *,
                 allow_private_hosts: bool = False):
        self.config = config
        self.store = store
        self.hub = hub
        # A test rig's fake server lives on 127.0.0.1; see relay/netguard.py.
        self.allow_private_hosts = allow_private_hosts

        self.network_id = store.upsert_network(
            config.slug, config.name, config.host, config.port, config.tls, config.nick
        )
        # On or off, as `network_connect` last left it. Off means no
        # connection and no reconnecting until turned on again; it survives a
        # restart. Separate from config.json's `enabled`, which leaves a
        # network out altogether.
        self.enabled = store.network_enabled(self.network_id)
        # The raw ISUPPORT values clients are shown (ISUPPORT_WIRE), null until
        # the server has said. The parsed forms the bouncer itself uses are
        # casemapping, prefix_map, chantypes and chanmodes below.
        self.isupport: dict[str, str | None] = {key: None for key in ISUPPORT_WIRE}
        self._isupport_flush: asyncio.TimerHandle | None = None
        # Nothing is joined before the connection exists. A crash skips the
        # clean disconnect that would have said so, and a channel left marked
        # joined is one `say` would happily send to. It also skipped the
        # "Disconnected" line that disconnect writes, so that goes in first,
        # while the database still says which channels we were in.
        self._mark_unclean_stop()
        store.clear_joined(self.network_id)
        self.status_buffer = store.get_or_create_buffer(self.network_id, STATUS_BUFFER_NAME, "status")
        # Extra mention words: config.json's seed the database the first time,
        # and from then on the database's are the ones that count, so a word
        # added from a phone survives a restart and a redeploy.
        words = store.highlight_words(self.network_id)
        if words is None:
            words = list(config.highlight_words)
            store.set_highlight_words(self.network_id, words)
        self.highlighter = HighlightMatcher(config.nick, words, own_nicks=config.all_nicks)
        self.qauth = QAuth(config.q_username, config.q_password,
                           hide_host=config.q_hide_host) if config.q_username else None
        self._awaiting_cloak = False
        self._joined_once = False
        # None means not away. Kept here rather than asked of the server
        # because IRC has no query for "am I away right now" -- the client set
        # it -- and saved, so a reconnect or a restart puts it back.
        self._away: str | None = store.network_away(self.network_id)
        # True while the bouncer itself has marked us away because nobody has
        # been attached for a while (the `auto_away` setting). Never set while
        # the user has an away of their own.
        self._auto_away = False
        # When an "active" typing TAGMSG last went to each target, folded.
        # Present means a "done" is still owed; see send_typing.
        self._typing_sent: dict[str, float] = {}
        # Compiled once so a blocked user does not cost a query per line.
        # Reloaded whenever the list changes. Nicks and masks both: a bare nick
        # is the mask nick!*@*. See ircproto.IgnoreMatcher.
        self._ignores = IgnoreMatcher(self.store.ignores(self.network_id))
        # New nicks of ignored people, followed for as long as they keep them.
        # A mask on the host survives a nick change by itself; this is what
        # lets a plain nick ignore survive one too, for the life of the
        # connection. Folded nicks.
        self._ignore_followed: set[str] = set()

        # ISUPPORT-derived server facts. The defaults are what to assume before
        # the server has told us -- QuakeNet's actual values, as it happens.
        self.casemapping = "rfc1459"
        self.prefix_map: dict[str, str] = {"@": "o", "+": "v"}
        self.chantypes = "#&"
        self.chanmodes = DEFAULT_CHANMODES
        # STATUSMSG: the prefixes a message can put in front of a channel to
        # reach only its ops ("@#chan") or its voiced people. None until the
        # server says; ircu (QuakeNet) never does, but still delivers "@#chan"
        # notices, so the fallback is the PREFIX symbols. See _statusmsg_chars.
        self.statusmsg: str | None = None
        # How many channels one JOIN may name (ISUPPORT TARGMAX=JOIN:n); None
        # is no stated limit, and join_lines still keeps each line to 510 bytes.
        self.join_targets: int | None = None
        # MONITOR's list size, when the server has MONITOR (never on QuakeNet):
        # online/offline pushed to us instead of an ISON every minute.
        self.monitor_limit: int | None = None

        # Channel modes, "+ntk" (parameters left out), per channel buffer id.
        # From the 324 that answers the MODE sent after each join, kept up to
        # date from MODE lines. In memory: after a restart the join asks again.
        self._modes: dict[int, str] = {}
        # Who is away, by folded nick: from away-notify where the server has it,
        # otherwise from a WHO of each channel every five minutes. A person's
        # away is theirs, not a channel's, so one set serves every member list.
        self._away_people: set[str] = set()
        # Online or not, for the people we have an open query with (folded
        # nick -> bool): from ISON (or MONITOR), and from anything they are
        # seen doing. Absent is "not known yet".
        self._online: dict[str, bool] = {}
        # WHO replies (352) collected until the 315 that ends them.
        self._who_accum: list[tuple[str, bool]] = []
        # Channels joined since the last NAMES, so their first WHO goes out as
        # soon as the member list is known rather than at the next poll.
        self._fresh_joins: set[str] = set()
        # The ISONs written and not yet answered, in the order written: the 303
        # replies name no question, so they are matched up in order. Each is
        # (purpose, folded nicks asked, when written). See _h_303.
        self._ison_pending: deque[tuple[str, list[str], float]] = deque()
        # The nicks on our MONITOR list, folded, when the server has MONITOR.
        self._monitored: set[str] = set()
        # Lines the bouncer wants to send for itself (MODE after a join, WHO,
        # ISON, MONITOR), sent one at a time and only when the send queue is
        # idle -- never ahead of anything the user typed. Keyed so the same
        # question is never waiting twice. See _send_background.
        self._background: deque[tuple[str, str, tuple, object]] = deque()
        self._background_keys: set[str] = set()
        self._poll_task: asyncio.Task | None = None
        self._presence_dirty = False
        self.poll_tick = 1.0
        self.who_interval = WHO_INTERVAL
        self.who_max_members = WHO_MAX_MEMBERS
        self.ison_interval = ISON_INTERVAL
        self.first_poll_delay = FIRST_POLL_DELAY
        self.presence_min_gap = PRESENCE_MIN_GAP

        self.conn = IRCConnection(
            host=config.host,
            port=config.port,
            tls=config.tls,
            nicks=config.all_nicks,
            username=config.username,
            realname=config.realname,
            on_message=self._on_message,
            on_connected=self._on_connected,
            on_disconnected=self._on_disconnected,
            on_registered=self._on_registered,
            on_connect_failed=self._on_connect_failed,
            on_state_change=self._on_state_change,
            **self._connection_settings(config),
        )
        # Channels that were given a "Disconnected" line and are waiting for
        # the "Reconnected" one. Seeded from the store, so a bouncer restart
        # (whose stop wrote the first line) still gets the second.
        self._lost_channels: set[int] = {
            b.id for b in store.buffers(include_archived=True)
            if b.network_id == self.network_id and b.kind == "channel"
            and store.connection_lost_last(b.id)
        }
        # The last connect failure written to the status buffer, so a server
        # that refuses us every few minutes for an hour is one line, not
        # twenty. Cleared whenever a connection opens.
        self._last_failure_logged: str | None = None
        # Which buffer the user typed each kind of command in, and when. An
        # error numeric that names no channel and no query buffer ("433 alice
        # :Nickname is already in use") goes back to where it was asked.
        self._recent_requests: dict[str, tuple[int, float]] = {}
        # (folded nick, away message) -> when that 301 was last shown.
        self._away_replies: dict[tuple[str, str], float] = {}
        # The channel list being collected, if one was asked for. One at a
        # time per network: the replies carry nothing to tell two apart.
        self._list: PendingList | None = None
        self.list_timeout = LIST_TIMEOUT
        # Channels we intend to be in. Seeded from config (which app.py has
        # already merged with what was saved last time), grown by a client's
        # /join, shrunk by its /part, saved on every change, and replayed on
        # every reconnect -- that replay is what makes a netsplit invisible to
        # the phone, and the saving is what makes a deploy invisible too.
        self._wanted_channels: list[str] = list(config.channels)
        # The key of each wanted channel that needs one (+k), by folded name.
        # Kept with the list and sent with every JOIN, the reconnect's
        # included: the list used to hold names only, so a keyed channel
        # answered 475 after every netsplit and every deploy until someone
        # typed the key again. A key is a password. It goes to the server in
        # the JOIN and to the database; it is never in an event, a frame or
        # the journal (to_wire says only which channels have one).
        self._channel_keys: dict[str, str] = {
            fold(name): key for name, key in config.channel_keys.items() if key}
        # When a client's `raw` line last went out, by command, and how many
        # lines of answer have been shown for it. See _raw_answer.
        self._raw_sent: dict[str, float] = {}
        self._raw_shown = 0
        # Channels whose topic changed in a join burst and has not been
        # announced yet. See _h_332.
        self._topic_dirty: set[int] = set()
        # Channels with a NAMES waiting to be sent. See _queue_names.
        self._names_queued: set[str] = set()
        self.names_settle = NAMES_SETTLE
        # NAMES arrives over several 353 lines and is only complete at 366, so it
        # is accumulated here rather than written per-line.
        self._names_accum: dict[str, list[tuple[str, str]]] = {}
        self._names_shown: dict[str, str] = {}
        # When each sender was last answered with a CTCP reply, and when the
        # last few replies went out at all. See _ctcp_allowed.
        self._ctcp_last: dict[str, float] = {}
        self._ctcp_recent: list[float] = []
        # WHOIS lookups waiting for their numerics, keyed by folded nick. The
        # timeout is an attribute rather than the constant so a test can make
        # the deadline something it can wait for.
        self._whois_pending: dict[str, PendingWhois] = {}
        self.whois_timeout = WHOIS_TIMEOUT
        # Set while we hold a fallback nick (quinn_) because the configured one
        # (quinn) was taken at registration. See _reclaim_loop.
        self._reclaim_task: asyncio.Task | None = None
        self.reclaim_interval = RECLAIM_INTERVAL
        # The JOINs held for Q and the cloak (see _join_after_auth), and which
        # connection they belong to: bumped on every registration and every
        # disconnect, so a task from an old link can tell it is one.
        self._join_task: asyncio.Task | None = None
        self._conn_generation = 0
        # When an instant reclaim last went out; see _reclaim_now_if_freed.
        self._instant_reclaim_at = float("-inf")

    # --- lifecycle ---------------------------------------------------------

    def _mark_unclean_stop(self) -> None:
        """Write the outage line a stop that never happened did not.

        A clean stop disconnects, and disconnecting writes "Disconnected" into
        every channel we were in and marks it not joined. A channel still
        marked joined when a process starts is therefore one whose last
        process died first -- SIGKILL, the OOM killer, the box losing power --
        and its history used to read straight across the hole, the last line
        before the crash sitting right above the first after the restart with
        nothing to say anyone was missing in between. Now it gets the same
        line, with the same `extra.connection`, so clients draw the same gap;
        the rejoin then writes "Reconnected" as it does after any outage.

        Stamped with the time of the newest line the database holds, which is
        the last moment the bouncer is known to have been running: "now"
        would put the start of the gap at the end of it. Stored without a
        broadcast, since no client can be attached to a session that is still
        being built.
        """
        crashed = [b for b in self.store.buffers()
                   if b.network_id == self.network_id and b.kind == "channel"
                   and b.joined and not self.store.connection_lost_last(b.id)]
        if not crashed:
            return
        reason = "the bouncer stopped unexpectedly"
        when = min(self.store.newest_event_time() or time.time(), time.time())
        for buf in crashed:
            self.store.append_event(
                buffer_id=buf.id, network_id=self.network_id, kind=P.KIND_SERVER,
                text=f"Disconnected: {reason}", ts=when,
                extra={"connection": "lost", "reason": reason})
        log.warning("%s: the last run did not stop cleanly; marked the gap in %d channel(s)",
                    self.config.slug, len(crashed))

    def start(self) -> None:
        # A network turned off from a client stays off across a restart.
        if self.enabled:
            self.conn.start()

    async def stop(self) -> None:
        self._cancel_reclaim()
        self._conn_generation += 1
        self._cancel_join_task()
        self._stop_polls()
        for pending in self._whois_pending.values():
            pending.cancel()
        self._whois_pending.clear()
        if self._isupport_flush is not None:
            self._isupport_flush.cancel()
        await self.conn.stop()

    @property
    def nick(self) -> str:
        return self.conn.nick

    def is_me(self, nick: str) -> bool:
        return fold(nick, self.casemapping) == fold(self.nick, self.casemapping)

    def to_wire(self) -> dict:
        cfg = self.config
        return {
            "slug": cfg.slug,
            "name": cfg.name,
            "host": cfg.host,
            "nick": self.nick,
            "connected": self.conn.connected,
            "registered": self.conn.registered,
            "status_buffer": self.status_buffer.id,
            "away": self.away_message,
            # Why the link last ended or failed ("connection refused", the
            # server's "Closing Link: ... (Excess Flood)", "ping timeout");
            # null once it registers again. After registering it can still say
            # "SASL login failed": connected, but not logged in.
            "last_error": self.conn.last_error,
            # When the next attempt starts, in unix seconds, while waiting to
            # reconnect; null while connected or connecting.
            "next_retry_at": self.conn.next_retry_at,
            # --- the network's settings, what an edit screen shows (G60) ---
            "port": cfg.port,
            "tls": cfg.tls,
            "username": cfg.username,
            "realname": cfg.realname,
            # The nick asked for. `nick` above is the one in use, which on a
            # fallback (quinn_) is not it -- and an edit screen that showed the
            # fallback would save it as the nick asked for.
            "configured_nick": cfg.nick,
            "alt_nicks": list(cfg.alt_nicks),
            # The channels joined on every connect: the wanted list, which
            # join, part and close keep up to date. Names only. Which of them
            # have a key is said beside it, the way `has_password` says there
            # is a server password: never the key.
            "channels": list(self._wanted_channels),
            "keyed": [c for c in self._wanted_channels if fold(c) in self._channel_keys],
            "enabled": self.enabled,
            "source": cfg.source,
            # Whether a secret is set, never the secret.
            "has_password": bool(cfg.password),
            "sasl": cfg.sasl,
            "q_username": cfg.q_username or None,
            "isupport": dict(self.isupport),
        }

    # --- settings a client changes ------------------------------------------

    def _connection_settings(self, cfg: NetworkConfig) -> dict:
        """What IRCConnection needs from a NetworkConfig beyond the basics."""
        return {
            "password": cfg.password,
            "sasl_mechanism": cfg.sasl_mechanism,
            "sasl_username": cfg.sasl_username,
            "sasl_password": cfg.sasl_password,
            "tls_cert": cfg.tls_cert,
            # A host that came from a client is dialled only while it is a
            # public address. config.json's own hosts are the file's business.
            "guard_address": (not self.allow_private_hosts
                              and (cfg.source == "client" or "host" in cfg.edited)),
        }

    async def edit(self, changes: dict) -> None:
        """Apply an `edit_network`. `changes` maps NetworkConfig fields to
        values that relay/netfields.py has already checked.

        Stored first (see Store.set_network_fields), then applied: the name at
        once; the nick as a NICK on the live link, and the nick asked for from
        then on; the channels as joins and parts; a new Q login at once if the
        link is up. Anything only a new connection can carry (RECONNECT_FIELDS)
        drops the link and dials again straight away.
        """
        old = self.config
        changes = dict(changes)
        if "stored_q_password" in changes and old.q_password_from_env:
            raise ValueError("This network's Q password is set on the bouncer itself. "
                             "Change it there.")
        channels = changes.pop("channels", None)
        # The keys that came with the list ("#secret hunter2" entries), by
        # channel name. Applied with the list below, never stored as a field.
        channel_keys = changes.pop("channel_keys", None) or {}
        new = dataclasses.replace(old, **changes)
        changed = [f for f in changes if getattr(old, f) != getattr(new, f)]
        columns = {"password": "server_password", "stored_q_password": "q_password"}
        secrets = {"password", "sasl_mechanism", "sasl_username", "sasl_password",
                   "stored_q_password"}
        self.store.set_network_fields(
            self.network_id,
            {columns.get(f, f): getattr(new, f) for f in changed},
            # For a network in config.json, these now win over the file. The
            # secrets are only ever the database's, so they need no marking.
            edited=[f for f in changed if f not in secrets],
        )
        if changed:
            new = dataclasses.replace(
                new, edited=list(dict.fromkeys([*old.edited, *(f for f in changed
                                                               if f not in secrets)])))
        self.config = new
        self.highlighter.set_own_nicks(new.all_nicks)
        self.conn.configure(host=new.host, port=new.port, tls=new.tls, nicks=new.all_nicks,
                            username=new.username, realname=new.realname,
                            **self._connection_settings(new))
        if {"host", "port"} & set(changed):
            # Another server may be another network; what the old one said
            # about itself says nothing about the new one. Said now, for the
            # network frame of an edit; every connection resets it again.
            self._reset_isupport()
        if {"q_username", "stored_q_password"} & set(changed):
            self.qauth = (QAuth(new.q_username, new.q_password, hide_host=new.q_hide_host)
                          if new.q_username else None)
        if channels is not None:
            await self._replace_wanted(channels, channel_keys)

        reconnect = any(f in changed for f in RECONNECT_FIELDS)
        if reconnect and self.enabled and self.conn.running:
            await self.conn.restart("Reconnecting", reason="reconnecting with the new settings")
        elif "nick" in changed and self.conn.registered:
            # The same as /nick, except that the new nick is the one asked for
            # from now on: if it is taken, the minute-by-minute reclaim keeps
            # asking for it, as it does after a fallback at registration.
            self._cancel_reclaim()
            self.conn.send_command("NICK", new.nick)
            self._start_reclaim()
        elif ({"q_username", "stored_q_password"} & set(changed) and self.conn.registered
              and self.qauth is not None and self.qauth.configured):
            command, argument = self.qauth.start()
            self.conn.send_command(command, Q_BOT, argument)
            await self._status("authenticating with Q")
        await self.hub.broadcast(P.frame(P.NETWORK, network=self.to_wire()))

    async def _replace_wanted(self, channels: list[str],
                              keys: dict[str, str] | None = None) -> None:
        """The wanted list, replaced: a channel new to it is joined now, one
        gone from it is parted now, and the order is the one given. The same
        list join and part keep, so an edit and a /join never disagree.

        `keys` maps a channel in the list to the key sent with it. A channel
        sent without one KEEPS the key it has: the network frame shows names
        only, so an edit screen sends back names only, and saving that screen
        must not forget every key (the same rule as a password left null). A
        key goes when its channel leaves the list.
        """
        keys = {fold(name): key for name, key in (keys or {}).items() if key}
        before = {fold(c) for c in self._wanted_channels}
        after = {fold(c) for c in channels}
        for channel in [c for c in self._wanted_channels if fold(c) not in after]:
            await self.part(channel)
        for channel in channels:
            key = keys.get(fold(channel))
            if fold(channel) not in before:
                await self.join(channel, key=key)
            elif key and self._channel_keys.get(fold(channel)) != key:
                # A key for a channel already in the list: remembered, and
                # tried now if we are not in it -- the usual reason to add a
                # key is a channel that has been answering 475.
                buf = self.store.find_buffer(self.network_id, channel)
                if buf is None or not buf.joined:
                    await self.join(channel, key=key)
                else:
                    self._channel_keys[fold(channel)] = key
        self._wanted_channels = list(channels)
        self._save_wanted()

    async def set_enabled(self, enabled: bool) -> None:
        """`network_connect`: off is QUIT and stay off, across restarts too;
        on is connect now, with the backoff back at its first step. On while
        already on is the app's "Reconnect now"."""
        self.store.set_network_enabled(self.network_id, enabled)
        self.enabled = enabled
        if enabled:
            self.conn.connect_now()
        else:
            self._cancel_reclaim()
            await self.conn.stop("Leaving", reason="you turned this network off")
            # Off on purpose is not an error, and a reason from before would
            # read as one.
            self.conn.last_error = None
        await self.hub.broadcast(P.frame(P.NETWORK, network=self.to_wire()))

    # --- connection callbacks ----------------------------------------------

    def _reset_isupport(self) -> None:
        """Forget what the last server said about itself (its 005), raw and
        parsed, back to the defaults assumed before a server has spoken.

        Every connection is a server that has not said yet, and it may be
        another server or another network altogether: an edit of the port
        alone used to keep the old one's NETWORK, PREFIX, STATUSMSG,
        CHANMODES and CHANTYPES, so "%#chan" was still offered to a server
        with no halfops."""
        self.isupport = {key: None for key in ISUPPORT_WIRE}
        self.casemapping = "rfc1459"
        self._ignores.set_casemapping(self.casemapping)
        self.prefix_map = {"@": "o", "+": "v"}
        self.chantypes = "#&"
        self.chanmodes = DEFAULT_CHANMODES
        self.statusmsg = None
        self.join_targets = None
        self.monitor_limit = None

    async def _on_connected(self) -> None:
        self._last_failure_logged = None
        # Before registration, so before any 005 on this connection.
        self._reset_isupport()
        await self._status(f"connecting to {self.config.host}:{self.config.port}")
        await self.hub.broadcast(P.frame(P.NETWORK, network=self.to_wire()))

    async def _on_state_change(self) -> None:
        await self.hub.broadcast(P.frame(P.NETWORK, network=self.to_wire()))

    async def _on_connect_failed(self, reason: str) -> None:
        """No socket at all: refused, unresolvable, a certificate that did not
        verify. Said once per distinct reason, in the status buffer, which used
        to stay empty -- a server that could not be reached looked exactly like
        one that was taking its time."""
        if reason != self._last_failure_logged:
            self._last_failure_logged = reason
            await self._status(
                f"could not connect to {self.config.host}:{self.config.port}: {reason}")

    async def _on_registered(self, nick: str) -> None:
        # Reset per-connection state, or a reconnect never re-joins.
        self._conn_generation += 1
        self._cancel_join_task()
        self._joined_once = False
        self._awaiting_cloak = False
        # Nobody on the new connection saw us typing, so nothing is owed.
        self._typing_sent.clear()
        self.store.set_network_nick(self.network_id, nick)
        self.highlighter.set_nick(nick)
        await self._status(f"registered as {nick}")
        self._start_reclaim()
        self._start_polls()
        # Away is ours, not the server's: a new connection starts present, so
        # whatever was set (by the user, or by auto-away) goes out again at
        # once. It used to live only in memory and was never re-sent, so WHOIS
        # said present while every client still said away.
        if self.away_message:
            self.conn.send_command("AWAY", self.away_message)
        # Told now, on both paths below. The Q path used to return before any
        # network frame, so clients showed "connecting" until they reattached.
        await self.hub.broadcast(P.frame(P.NETWORK, network=self.to_wire()))

        # Authenticate BEFORE joining. Q sets +x on the account, and a host that
        # changes after you are already in a channel is a host the channel
        # already saw -- cloaking late cloaks nothing.
        if self.qauth and self.qauth.configured:
            command, argument = self.qauth.start()
            self.conn.send_command(command, Q_BOT, argument)
            await self._status("authenticating with Q")
            # Joins wait for the auth to resolve, or for a short grace period if
            # Q is slow or silent -- never joining because Q did not answer is
            # worse than joining uncloaked.
            self._join_task = asyncio.create_task(self._join_after_auth())
            return

        await self._do_joins()

    async def _on_disconnected(self, reason: str) -> None:
        self._cancel_reclaim()
        self._conn_generation += 1
        self._cancel_join_task()
        self._finish_list(complete=False)
        self._names_queued.clear()
        # Half a NAMES from the dead link must not be merged into the next.
        self._names_accum.clear()
        self._names_shown.clear()
        self._forget_people()
        await self._status(f"disconnected: {reason}")
        # Every member list we hold is now a lie. Clearing it is better than
        # showing a phantom channel population until the rejoin lands -- and
        # the clients are TOLD, channel by channel, or they carry on showing a
        # live composer and yesterday's member list over a channel we are no
        # longer in. The rejoin on reconnect sends joined:true the same way.
        for buf in self.store.buffers(include_archived=True):
            if buf.network_id == self.network_id and buf.kind == "channel":
                was_joined = buf.joined
                self.store.set_joined(buf.id, False)
                self.store.clear_members(buf.id)
                if was_joined:
                    await self._left_channel(buf.id)
                    # And a line in the conversation itself, where the gap in
                    # it is, rather than only in a status buffer nobody reads:
                    # whatever was said between this and "Reconnected" was
                    # said without us. Once per outage -- only channels we were
                    # in get it, and a failed retry is in none.
                    if not buf.archived and buf.id not in self._lost_channels:
                        self._lost_channels.add(buf.id)
                        self._record(buf.id, P.KIND_SERVER, text=f"Disconnected: {reason}",
                                     extra={"connection": "lost", "reason": reason})
        await self.hub.broadcast(P.frame(P.NETWORK, network=self.to_wire()))

    async def _left_channel(self, buffer_id: int) -> None:
        """Tell every client we are no longer in a channel: the buffer with
        joined:false, then an empty member list. The order is the contract --
        see `buffer` in docs/PROTOCOL.md."""
        await self._announce_buffer(buffer_id)
        await self._broadcast_members(buffer_id)

    # --- getting the configured nick back ----------------------------------

    def _wants_configured_nick(self) -> bool:
        return not self.is_me(self.config.nick)

    def _start_reclaim(self) -> None:
        """Registered on a fallback nick? Keep asking for the real one.

        The configured nick is often taken for a while after a reconnect by the
        old connection's ghost, and QuakeNet does not let you kick it. Without
        this the bouncer registered as `quinn_` and stayed there until somebody
        typed /nick by hand.
        """
        self._cancel_reclaim()
        if self._wants_configured_nick():
            self._reclaim_task = asyncio.create_task(self._reclaim_loop())

    def _cancel_reclaim(self) -> None:
        task, self._reclaim_task = self._reclaim_task, None
        if task is not None and task is not asyncio.current_task():
            task.cancel()

    async def _reclaim_loop(self) -> None:
        """ISON the configured nick every minute; the 303 reply takes it if free.

        ISON rather than trying NICK and reading the refusal: a refused NICK is a
        numeric that lands in the status window once a minute for as long as it
        takes, and ISON is silent.
        """
        while self.conn.registered and self._wants_configured_nick():
            await asyncio.sleep(self.reclaim_interval)
            if not self.conn.registered or not self._wants_configured_nick():
                return
            self.conn.send_command("ISON", self.config.nick,
                                   on_sent=lambda: self._ison_written("reclaim", []))

    def _ison_written(self, purpose: str, asked: list[str]) -> None:
        """An ISON reached the socket: its answer is next in line. Called from
        the send queue (see ircconn.Outbound), so in the order written, which
        is the order the server answers in."""
        now = time.monotonic()
        while self._ison_pending and now - self._ison_pending[0][2] > ISON_STALE:
            self._ison_pending.popleft()
        self._ison_pending.append((purpose, asked, now))

    async def _h_303(self, msg: Message) -> None:      # RPL_ISON
        """The answer to an ISON: which of the nicks asked about are online.

        Three things ask: the reclaim loop (is our configured nick free), the
        presence poll (are the people we have queries with online), and a raw
        /ison someone typed. The reply says none of that, so each ISON notes
        what it asked as it is written and the answers are taken in order. A
        reply with nothing noted is read as the reclaim's, which is what every
        303 was before presence existed.
        """
        online = {fold(n, self.casemapping) for n in msg.param(1).split()}
        purpose, asked, _at = (self._ison_pending.popleft() if self._ison_pending
                               else ("reclaim", [], 0.0))
        if purpose == "presence":
            queries = self.store.open_queries(self.network_id)
            for key in asked:
                self._update_person(key, online=key in online, queries=queries)
            return
        if purpose != "reclaim":
            return
        if self._reclaim_task is None or not self._wants_configured_nick():
            return
        wanted = fold(self.config.nick, self.casemapping)
        if wanted in online:
            return
        await self._status(f"{self.config.nick} is free, taking it back")
        self.conn.send_command("NICK", self.config.nick)

    async def _reclaim_now_if_freed(self, departed: str) -> None:
        """Someone holding our configured nick just quit or renamed: ask for it
        at once rather than at the next ISON, up to a minute later. The usual
        holder is our own ghost timing out after a reconnect, and a minute of
        `quinn_` is a minute of people typing a name that does not reach us.

        Only while the reclaim is running (a nick chosen by hand is never
        overridden), and at most once per INSTANT_RECLAIM_GAP, so a nick that
        flaps cannot turn this into a NICK storm.
        """
        if self._reclaim_task is None or not self.conn.registered:
            return
        if not self._wants_configured_nick():
            return
        if fold(departed, self.casemapping) != fold(self.config.nick, self.casemapping):
            return
        now = time.monotonic()
        if now - self._instant_reclaim_at < INSTANT_RECLAIM_GAP:
            return
        self._instant_reclaim_at = now
        await self._status(f"{self.config.nick} is free, taking it back")
        self.conn.send_command("NICK", self.config.nick)

    # --- people: away and online (G84) -------------------------------------
    #
    # Two questions, answered by whatever the server offers. Away: away-notify
    # (the server tells us as it happens) where CAP negotiated it, otherwise a
    # WHO of each channel every five minutes, whose 352 lines carry H (here) or
    # G (gone). Online: MONITOR where the server has it, otherwise one ISON a
    # minute for the people we have open queries with. QuakeNet has neither
    # away-notify nor MONITOR, so it gets WHO and ISON -- a line every few
    # minutes, sent only when the send queue is idle.

    def _cap_enabled(self, cap: str) -> bool:
        """Was this capability negotiated on the current connection?

        CAP negotiation is section 2 of the wave-4 contract, done on another
        branch. Whichever of the session or the connection ends up holding the
        negotiated set as `caps`, it is read here and only here. Until then
        nothing is negotiated, which is QuakeNet's case anyway (no CAP at all).
        """
        for holder in (self, self.conn):
            caps = getattr(holder, "caps", None)
            if caps:
                return cap in caps
        return False

    def _start_polls(self) -> None:
        self._stop_polls()
        self._poll_task = asyncio.create_task(self._poll_loop(), name="irc-polls")

    def _stop_polls(self) -> None:
        task, self._poll_task = self._poll_task, None
        if task is not None and task is not asyncio.current_task():
            task.cancel()

    async def _poll_loop(self) -> None:
        """Presence and away polls, and the background lines, for one connection.

        One loop rather than a timer per job, ticking once a second: each tick
        may send ONE background line, and only when the send queue is idle
        (see ircconn.spare), so nothing the bouncer asks for itself ever holds
        up a line someone typed.
        """
        started = time.monotonic()
        first = started + self.first_poll_delay
        next_presence, next_who, last_presence = first, first, 0.0
        while self.conn.registered:
            await asyncio.sleep(self.poll_tick)
            if not self.conn.registered:
                return
            now = time.monotonic()
            due = now >= next_presence
            soon = (self._presence_dirty and now >= first
                    and now - last_presence >= self.presence_min_gap)
            if due or soon:
                self._presence_dirty = False
                last_presence = now
                next_presence = now + self.ison_interval
                self._poll_presence()
            if now >= next_who:
                next_who = now + self.who_interval
                self._poll_away()
            self._send_background()

    def _queue_background(self, key: str, command: str, *params: str,
                          on_sent=None) -> None:
        if key in self._background_keys:
            return
        self._background_keys.add(key)
        self._background.append((key, command, params, on_sent))

    def _drop_background(self, prefix: str) -> None:
        """Take every queued line whose key starts with `prefix` back out."""
        if not any(key.startswith(prefix) for key in self._background_keys):
            return
        self._background = deque(item for item in self._background
                                 if not item[0].startswith(prefix))
        self._background_keys = {key for key in self._background_keys
                                 if not key.startswith(prefix)}

    def _send_background(self) -> None:
        if not self._background or not self.conn.spare:
            return
        key, command, params, on_sent = self._background.popleft()
        self._background_keys.discard(key)
        self.conn.send_command(command, *params, on_sent=on_sent)

    def _forget_people(self) -> None:
        """A connection ended: everything known about who is here is stale.

        The open queries that showed a presence are told it is unknown again,
        rather than keeping a green dot for someone we can no longer see.
        """
        self._stop_polls()
        known = set(self._online)
        self._away_people.clear()
        self._online.clear()
        self._who_accum.clear()
        self._fresh_joins.clear()
        self._ison_pending.clear()
        self._monitored.clear()
        # The next server says again whether it has MONITOR (in its 005).
        self.monitor_limit = None
        self._background.clear()
        self._background_keys.clear()
        self._ignore_followed.clear()
        self._modes.clear()
        for key, name in self.store.open_queries(self.network_id).items():
            if key in known:
                buf = self.store.find_buffer(self.network_id, name)
                if buf is not None:
                    self.hub.publish(P.frame(P.BUFFER, buffer=self.buffer_to_wire(buf)))

    def _query_presence(self, name: str) -> str | None:
        """"online", "away", "offline", or None for not known."""
        if not self.conn.registered:
            return None
        key = fold(name, self.casemapping)
        online = self._online.get(key)
        if online is None:
            return None
        if not online:
            return "offline"
        return "away" if key in self._away_people else "online"

    def _update_person(self, nick: str, *, online: bool | None = None,
                       away: bool | None = None,
                       queries: dict[str, str] | None = None,
                       announce: bool = True) -> bool:
        """Record what was learned about one person; tell the clients what
        changed. Returns True when their away changed, so the caller can send
        the member deltas it is in the best position to batch.

        Online is only kept for people we have an open query with: it is only
        ever shown on a query, and remembering it for everyone who ever joined
        a channel would be a table that only grows. `queries` is
        store.open_queries(), passed in by a caller updating many people;
        `announce=False` is for a caller about to send the query's buffer
        frame itself.
        """
        key = fold(nick, self.casemapping)
        if queries is None:
            queries = self.store.open_queries(self.network_id)
        before = self._query_presence(key) if key in queries else None
        was_away = key in self._away_people
        if online is not None and key in queries:
            self._online[key] = online
        if online is False or away is False:
            self._away_people.discard(key)
        elif away:
            self._away_people.add(key)
        if key in queries and announce:
            after = self._query_presence(key)
            if after != before:
                buf = self.store.find_buffer(self.network_id, queries[key])
                if buf is not None:
                    self.hub.publish(P.frame(P.BUFFER, buffer=self.buffer_to_wire(buf)))
        return was_away != (key in self._away_people)

    def _away_deltas(self, nick: str, *, skip: int | None = None) -> None:
        """One member_update per channel the person is in, carrying `away`."""
        away = fold(nick, self.casemapping) in self._away_people
        for buffer_id, stored in self.store.member_buffers(self.network_id, nick):
            if buffer_id != skip:
                self.hub.publish(P.frame(P.MEMBER_UPDATE, buffer=buffer_id,
                                         nick=stored, away=away))

    def _poll_presence(self) -> None:
        """Ask who of the people we have open queries with is online."""
        if not self.conn.registered:
            return
        # A query named "Q@CServe.quakenet.org" (made before such a target
        # stopped opening one) is an address, not a nick ISON or MONITOR can
        # answer for.
        queries = {k: n for k, n in self.store.open_queries(self.network_id).items()
                   if "@" not in n}
        if self.monitor_limit is not None:
            self._sync_monitor(queries)
            return
        # A newer poll replaces whatever an older one left queued. The key
        # used to be the list of names, so on a link too busy to send them
        # every change of open queries added another ISON and none left: the
        # queue grew without bound. Only the newest list is worth asking.
        self._drop_background("ison:")
        for index, batch in enumerate(_batches(sorted(queries.values(), key=str.lower))):
            asked = [fold(n, self.casemapping) for n in batch]
            self._queue_background(
                f"ison:{index}", "ISON", " ".join(batch),
                on_sent=lambda asked=asked: self._ison_written("presence", asked))

    def _sync_monitor(self, queries: dict[str, str]) -> None:
        """Keep the server's MONITOR list the same as our open queries. Only
        the difference goes out, so a quiet minute sends nothing at all."""
        remove = [k for k in self._monitored if k not in queries]
        room = (self.monitor_limit or 10_000) - (len(self._monitored) - len(remove))
        add = [n for k, n in queries.items() if k not in self._monitored][:max(0, room)]
        for batch in _batches(remove, sep=","):
            self._monitored.difference_update(batch)
            self._queue_background("monitor-:" + ",".join(batch), "MONITOR", "-", ",".join(batch))
        for batch in _batches(add, sep=","):
            self._monitored.update(fold(n, self.casemapping) for n in batch)
            self._queue_background("monitor+:" + ",".join(batch), "MONITOR", "+", ",".join(batch))

    def _poll_away(self) -> None:
        """WHO each channel we are in that is small enough, unless the server
        tells us about away changes itself (away-notify)."""
        if not self.conn.registered or self._cap_enabled("away-notify"):
            return
        for buf in self.store.buffers():
            if buf.network_id == self.network_id and buf.kind == "channel" and buf.joined:
                self._queue_who(buf)

    def _queue_who(self, buf) -> None:
        if self._cap_enabled("away-notify"):
            return
        count = self.store.member_count(buf.id)
        if 0 < count <= self.who_max_members:
            self._queue_background("who:" + fold(buf.name, self.casemapping), "WHO", buf.name)

    async def _h_352(self, msg: Message) -> None:      # RPL_WHOREPLY
        # me, channel, user, host, server, nick, flags, "hops realname". The
        # flags start with H (here) or G (gone, i.e. away).
        nick, flags = msg.param(5), msg.param(6)
        if nick:
            self._who_accum.append((nick, flags.startswith("G")))

    async def _h_315(self, msg: Message) -> None:      # RPL_ENDOFWHO
        """The WHO is complete: apply it. The channel it was for gets its whole
        member list once (the first WHO after a join changes many people at
        once); anyone changed who is also in other channels gets a small
        member_update there."""
        entries, self._who_accum = self._who_accum, []
        buf = self.store.find_buffer(self.network_id, msg.param(1))
        channel_id = buf.id if buf is not None and buf.kind == "channel" else None
        queries = self.store.open_queries(self.network_id)
        changed = [nick for nick, away in entries
                   if self._update_person(nick, online=True, away=away, queries=queries)]
        if not changed:
            return
        if channel_id is not None:
            await self._broadcast_members(channel_id)
        for nick in changed:
            self._away_deltas(nick, skip=channel_id)

    async def _h_away(self, msg: Message) -> None:
        """away-notify: `:nick!u@h AWAY :gone` sets it, a bare AWAY clears it."""
        nick = msg.prefix.nick
        if not nick or self.is_me(nick):
            return
        if self._update_person(nick, away=bool(msg.param(0))):
            self._away_deltas(nick)

    async def _h_730(self, msg: Message) -> None:      # RPL_MONONLINE
        for target in msg.param(1).split(","):
            if target:
                self._update_person(target.split("!", 1)[0], online=True)

    async def _h_731(self, msg: Message) -> None:      # RPL_MONOFFLINE
        for target in msg.param(1).split(","):
            if target:
                self._update_person(target.split("!", 1)[0], online=False)

    async def _h_734(self, msg: Message) -> None:      # ERR_MONLISTFULL
        # The server's list is full: whoever did not fit stays "not known",
        # which is what a query with no dot means. Nothing to tell anyone.
        log.info("%s: MONITOR list is full (%s)", self.config.slug, msg.param(1))

    # --- helpers -----------------------------------------------------------

    def _buffer_for(self, name: str, kind: str, *, unarchive: bool = True):
        return self.store.get_or_create_buffer(self.network_id, name, kind,
                                               unarchive=unarchive)

    def _is_channel(self, target: str) -> bool:
        return bool(target) and target[0] in self.chantypes

    def _statusmsg_chars(self) -> str:
        """The prefixes that address part of a channel ("@#chan", "+#chan")."""
        return self.statusmsg if self.statusmsg is not None else "".join(self.prefix_map)

    def _split_statusmsg(self, target: str) -> tuple[str, str]:
        """("@", "#chan") for "@#chan"; ("", target) for anything else.

        A message to "@#chan" is a message to #chan that only its ops see --
        ChanServ's notices to a channel's ops arrive this way. It used to fail
        the channel test on its first character and open a highlighted query
        named "@#chan" that pushed.
        """
        chars = self._statusmsg_chars()
        i = 0
        while i < len(target) and target[i] in chars:
            i += 1
        if 0 < i < len(target) and target[i] in self.chantypes:
            return target[:i], target[i:]
        return "", target

    def _is_ignored(self, prefix: Prefix) -> bool:
        """Is this line's sender blocked? Matched on the whole prefix, so a host
        mask catches every nick on that host; our own lines never are."""
        if not prefix.nick or self.is_me(prefix.nick):
            return False
        if fold(prefix.nick, self.casemapping) in self._ignore_followed:
            return True
        return self._ignores.matches(prefix.nick, prefix.user, prefix.host)

    @staticmethod
    def _is_service(prefix: Prefix) -> bool:
        """NickServ, ChanServ, Q and the rest: bots run by the network whose
        private messages are replies to commands and notices about your
        account, not a conversation with a person."""
        nick = prefix.nick.lower()
        return nick in SERVICE_NICKS or (len(nick) > 4 and nick.endswith("serv"))

    def buffer_to_wire(self, buf) -> dict:
        """A buffer as the `buffer` and `buffers` frames carry it, with what only
        the live session knows: a channel's `modes`, a query's `presence`."""
        wire = buf.to_wire(self.config.slug)
        if buf.kind == "channel":
            wire["modes"] = self._modes.get(buf.id)
        elif buf.kind == "query":
            wire["presence"] = self._query_presence(buf.name)
        return wire

    def members_to_wire(self, buffer_id: int) -> list[dict]:
        """A channel's member list for the `members` frame, each with `away`."""
        members = self.store.members(buffer_id)
        for member in members:
            member["away"] = fold(member["nick"], self.casemapping) in self._away_people
        return members

    async def _status(self, text: str) -> None:
        await self._emit(self.status_buffer.id, P.KIND_SERVER, text=text)

    def _record(self, buffer_id: int, kind: str, **kw):
        """Store one event and queue it for every attached client. Synchronous
        on purpose: the send queue's callbacks use it, and they must not be able
        to stop halfway (see ircconn.Outbound)."""
        if "ts" not in kw:
            # The server's own time for the line being handled, with
            # server-time; otherwise the store's "now". See _EVENT_TS.
            ts = _EVENT_TS.get()
            if ts is not None:
                kw["ts"] = ts
        event = self.store.append_event(
            buffer_id=buffer_id, network_id=self.network_id, kind=kind, **kw
        )
        # No `network` field here. It was redundant -- an event names a buffer,
        # and the buffer already names its network -- and it made `network` mean
        # a slug string on this frame and an object on the `network` frame. One
        # overloaded key in the protocol (`buffer`) is already one too many.
        self.hub.publish(P.frame(P.EVENT, event=event.to_wire()))
        return event

    async def _emit(self, buffer_id: int, kind: str, **kw) -> None:
        """Store one event, then hand it to every attached client."""
        event = self._record(buffer_id, kind, **kw)
        # A mention no longer un-mutes a detached buffer. It used to, for
        # good, so a busy channel that mentioned you once could not stay
        # muted. Whether a line notifies is the buffer's `notify` level now,
        # and `detached` is only about the badge.
        buf = self.store.buffer(buffer_id)
        if buf is not None and self._should_push(event, buf):
            await self._maybe_push(event, buf)

    @staticmethod
    def _should_push(event, buf) -> bool:
        """The buffer's notify level decides: "none" never, "all" every line
        someone else said, "mentions" (a channel's default) only highlights --
        which is every line of a private query, and an invite."""
        if event.self_ or buf.notify == "none":
            return False
        if event.kind == P.KIND_INVITE:
            return True
        if event.kind not in (P.KIND_MESSAGE, P.KIND_ACTION, P.KIND_NOTICE):
            return False
        return buf.notify == "all" or event.highlight

    async def _maybe_push(self, event, buf=None) -> None:
        """A line only becomes a notification when nothing is watching it.

        "Watching" is deliberately narrow: a client that is attached but has the
        app backgrounded still counts as away, because iOS suspends the socket
        and the frame we just broadcast may never be read. The client tells us
        which it is (see `presence` in docs/PROTOCOL.md); until it does, the
        conservative assumption is away.
        """
        if self.hub.has_active_viewer(event.buffer_id):
            log.info("push held back: eid %s in buffer %s, a foreground client has it on screen",
                     event.eid, event.buffer_id)
            return
        buf = buf or self.store.buffer(event.buffer_id)
        if buf is None:
            return
        title = buf.name if buf.kind == "channel" else (event.sender or self.config.name)
        if event.kind == P.KIND_INVITE:
            title = self.config.name
            body = f"{event.sender} {event.text}"
        else:
            body = strip_formatting(event.text or "")
            if buf.kind == "channel" and event.sender:
                body = f"{event.sender}: {body}"
        if not self.store.get_setting("push_preview"):
            # What the lock screen says with previews off: where, and who,
            # but not a word of what.
            if event.kind == P.KIND_INVITE:
                body = f"Invitation from {event.sender}"
            elif buf.kind == "channel":
                body = f"New message in {buf.name}"
            else:
                body = f"Message from {event.sender or buf.name}"
        await self.hub.push(
            Notification(
                title=title,
                body=body[:180],
                buffer_id=event.buffer_id,
                eid=event.eid,
                network=self.config.slug,
                # Unread mentions everywhere; the same sum a read on another
                # device sends later to bring it back down (Hub.read_elsewhere).
                badge=self.store.badge_count(),
                # The nick on its own (payload: relay.from), whatever the body
                # says -- with previews off the body does not name them at all.
                sender=event.sender,
                sound=self.store.get_setting("push_sound") or "default",
            )
        )

    # --- client-initiated actions ------------------------------------------

    def resolve_target(self, target: str):
        """Find or create the buffer for a channel name or a nick.

        This is what makes `/msg someone hello` work in one round trip: the
        client does not have to open a query, wait for its id, and then send.
        """
        if not target:
            raise ValueError("missing target")
        # Checked before the buffer is created, not after: a name IRC cannot
        # carry would otherwise leave a permanent buffer nothing can be sent to.
        if self._is_channel(target):
            check_channel(target)
        else:
            check_param(target, "a nickname")
        kind = "channel" if self._is_channel(target) else "query"
        return self._buffer_for(target, kind)

    async def say(self, buffer_id: int | None = None, text: str = "", *,
                  target: str | None = None, action: bool = False,
                  notice: bool = False, statusmsg: str | None = None,
                  nonce: str | None = None) -> dict | None:
        """queue_say, then wait up to SAY_ECHO_WAIT for its first line's echo
        (see await_echo). What the unit tests and any caller that wants the
        answer in one call use; the gateway calls the two halves itself so a
        client's other frames never wait behind the echo."""
        first = await self.queue_say(buffer_id, text, target=target, action=action,
                                     notice=notice, statusmsg=statusmsg, nonce=nonce)
        return await self.await_echo(first)

    @staticmethod
    async def await_echo(first: asyncio.Future) -> dict | None:
        """The first line's stored event once it has gone out, None when it is
        still queued after SAY_ECHO_WAIT (its echo follows as an ordinary
        `event`), or ValueError("Not sent (...)") when it was dropped."""
        try:
            event, reason = await asyncio.wait_for(asyncio.shield(first), SAY_ECHO_WAIT)
        except asyncio.TimeoutError:
            return None               # still queued; the echo follows when it goes
        if event is None:
            raise ValueError(f"Not sent ({reason})")
        return event

    async def queue_say(self, buffer_id: int | None = None, text: str = "", *,
                        target: str | None = None, action: bool = False,
                        notice: bool = False, statusmsg: str | None = None,
                        nonce: str | None = None) -> asyncio.Future:
        """Send a line to a buffer and echo it back as a stored event.

        Returns at once, once the line is checked and queued, with a future
        for the first line's outcome: (event, None) when it is written, or
        (None, reason) when it is dropped. See await_echo.

        IRC gives no acknowledgement for a PRIVMSG -- the server never tells you
        your own message went out. So the bouncer, not the client, writes the
        echo: that way the line has a real eid, lands in backlog, and appears on
        every one of your devices, not just the one you typed it on. This is the
        single biggest behavioural difference from a plain IRC client.

        THE ECHO IS WRITTEN WHEN THE LINE IS, not when it is queued. It used to
        be stored the moment the line joined the flood queue, so a line still
        queued when the link dropped was thrown away upstream but stayed in
        history -- on every device, in backlog and in search -- as something
        you had said. Now a line becomes an event only once it has been written
        to the socket, and a line that never will be (the link dropped with it
        queued) becomes a `server` event in the same buffer instead, reading
        "Not sent (connection lost): <the text>", so nothing that was typed
        disappears without a word.

        Addressed either by `buffer_id` (the normal case) or by `target`, a
        channel name or nick; a query is created if it does not exist yet.

        `notice` sends a NOTICE instead of a PRIVMSG -- the two are otherwise
        identical here, including the multi-line splitting, which is why it is
        a flag on `say` rather than a separate frame.

        A message that is several lines is several PRIVMSGs (or NOTICEs), each
        with its own stored event: IRC has no multi-line message, and a newline
        handed straight to the server is a second command. The reply is the
        first line's event when that line went out within SAY_ECHO_WAIT, which
        is what the protocol's `ok(req, event=…)` promises -- and None when it
        is still waiting its turn in the queue, in which case the echo arrives
        as an ordinary `event` frame when it is sent.

        `statusmsg` ("@" or "+") sends to only the channel's ops or voiced
        people ("PRIVMSG @#chan"). The echo lands in the channel like any
        other line, with extra.statusmsg saying who it went to. A `target` of
        "@#chan" means the same thing; it used to open a query called "@#chan".

        `nonce` is the client's own name for this send, and it comes back as
        extra.nonce on EVERY event the send produces: each line's echo, and
        each "Not sent" line for one that was dropped. That is what lets a
        client draw a line as pending the moment it is typed and settle it
        when its fate is known, including for a line still in the flood queue
        when `ok` went back without an event, and for the second and later
        lines of a paste, which `ok` never mentioned at all. Clients used to
        match their pending lines to echoes by text, which two identical
        lines sent in a row is enough to get wrong. Stored with the event, so
        a client that reconnects finds it in the backlog. The gateway has
        already checked its shape (see gateway.clean_nonce).
        """
        if buffer_id is None and target:
            status_prefix, bare = self._split_statusmsg(target)
            if status_prefix:
                statusmsg, target = statusmsg or status_prefix, bare
        # "Q@CServe.quakenet.org": a nick at a server, the way QuakeNet asks
        # for Q to be addressed so the line cannot go to an impostor. It is an
        # address to send to, not somebody to have a conversation with: it
        # used to open a query called "Q@CServe.quakenet.org" and MONITOR it.
        # The line goes to it as typed and is kept in the Server buffer, with
        # extra.to naming where it went; the answer comes from "Q" and lands
        # there too (services go to the Server buffer).
        addressed = None
        if buffer_id is None and target and "@" in target and not self._is_channel(target):
            addressed = check_param(target, "a nickname")
        if addressed is not None:
            buf = self.status_buffer
        elif buffer_id is not None:
            buf = self.store.buffer(buffer_id)
            if buf is None or buf.network_id != self.network_id:
                raise ValueError("unknown buffer")
        elif target and self._is_channel(target):
            # A channel is not created by talking to it. Only a channel we are
            # in can be sent to, so a name with no buffer is one we are not in,
            # and making a buffer for it would leave an empty conversation
            # behind the refusal below.
            check_channel(target)
            buf = self.store.find_buffer(self.network_id, target)
            if buf is None:
                raise ValueError(f"You're not in {target}. Join it to send.")
        else:
            buf = self.resolve_target(target or "")

        if buf.kind == "status" and addressed is None:
            raise ValueError("cannot send to the status buffer")
        if not self.conn.registered:
            raise ValueError("not connected to the network")
        if buf.kind == "channel" and not buf.joined:
            # Kicked, parted, or not rejoined yet. The server would answer 404
            # and the line would have sat in history looking delivered; saying
            # so here keeps the draft on the client, which restores it on error.
            if not self._joined_once and fold(buf.name) in {fold(c) for c in self._wanted_channels}:
                # Just reconnected; the join burst has not gone out yet.
                raise ValueError(f"Still joining {buf.name}. Try again in a moment.")
            raise ValueError(f"You're not in {buf.name}. Rejoin to send.")

        # `action` is the explicit form and is what the Swift client sends, since
        # it parses commands itself. The "/me " prefix is kept as a documented
        # convenience for clients that type raw lines -- the terminal client and
        # the web page -- and is normalised here so there is still only one code
        # path below it.
        if text.startswith("/me "):
            action, text = True, text[4:]
        if not text:
            raise ValueError("empty message")
        if action and notice:
            raise ValueError("a message cannot be both an action and a notice")
        if statusmsg:
            if buf.kind != "channel":
                raise ValueError("Only a channel message can go to its ops.")
            allowed = self._statusmsg_chars()
            if len(statusmsg) > len(allowed) or any(c not in allowed for c in statusmsg):
                raise ValueError(f"This server cannot message {statusmsg}{buf.name}.")
        if self.conn.queue_depth > MAX_QUEUED_BEFORE_REFUSING:
            # Refusing is kinder than accepting. An accepted line sits in a
            # queue that is already half a minute deep and arrives into a
            # conversation that has moved on, with an echo in the client the
            # whole time claiming it was sent.
            raise ValueError("sending too fast; wait a moment")

        if action:
            kind, command = P.KIND_ACTION, "PRIVMSG"
        elif notice:
            kind, command = P.KIND_NOTICE, "NOTICE"
        else:
            kind, command = P.KIND_MESSAGE, "PRIVMSG"
        # Where the line goes on the wire: the channel, or "@#chan" for its ops.
        destination = f"{statusmsg}{buf.name}" if statusmsg else buf.name
        echo_extra = {"statusmsg": statusmsg} if statusmsg else None
        if addressed is not None:
            destination, echo_extra = addressed, {"to": addressed}
        # A CTCP ACTION carries its own wrapper bytes inside the same line, so
        # the room left for the text is that much smaller.
        budget = say_budget(destination) - (len(make_ctcp("ACTION", "x")) - 1 if action else 0)
        lines = split_message(text, budget)
        if not lines:
            raise ValueError("empty message")
        if len(lines) > self.conn.queue_room:
            raise ValueError("sending too fast; wait a moment")

        # A `/msg` to someone new creates a buffer the client has never been told
        # about. Announce it before any echo, or the client receives an event
        # for a buffer it does not know -- the ordering rule from PROTOCOL.md.
        if addressed is None:
            await self._announce_buffer(buf.id)

        first: asyncio.Future = asyncio.get_running_loop().create_future()
        # On every event of this send, sent or not. See the note above.
        tag = {"nonce": nonce} if nonce else {}

        def kept(line: str) -> str | None:
            # "IDENTIFY hunter2" to NickServ goes out as typed, and is kept as
            # "IDENTIFY ********": in the echo every device gets, in backlog,
            # in backups. Marked redacted, it is never indexed for search
            # either (see store.SEARCH_TRIGGERS), and our own lines never push.
            return None if action else redact_secret(addressed or buf.name, line)

        def sent(line: str, index: int) -> None:
            # One stored event per line that actually went out, so backlog and
            # the channel agree about what was said. The nick is read now, at
            # the moment of sending, because that is the name it went out under.
            shown = kept(line)
            extra = {**(echo_extra or {}), **({"redacted": True} if shown else {}), **tag}
            event = self._record(buf.id, kind, sender=self.nick, text=shown or line,
                                 self_=True, extra=extra or None)
            if index == 0 and not first.done():
                first.set_result((event.to_wire(), None))

        def dropped(line: str, index: int, reason: str) -> None:
            # Surfaced in the conversation it was meant for, where it will be
            # seen, rather than in the status buffer or the journal. `extra`
            # carries the text on its own so a client can offer to send it
            # again without parsing it back out of the sentence -- except a
            # password, which is not kept anywhere to be offered again.
            shown = kept(line)
            if shown:
                self._record(buf.id, P.KIND_SERVER, text=f"Not sent ({reason}): {shown}",
                             extra={"redacted": True, **tag})
            else:
                self._record(buf.id, P.KIND_SERVER, text=f"Not sent ({reason}): {line}",
                             extra={"not_sent": line, **tag})
            if index == 0 and not first.done():
                first.set_result((None, reason))

        self.note_request(command, buf.id)
        # The line says the typing is over, to everyone who was shown it: a
        # receiver clears "typing" on a message from that person, and the spec
        # asks for no "done" after one. The next keystroke starts afresh.
        self._typing_sent.pop(fold(buf.name, self.casemapping), None)
        for index, line in enumerate(lines):
            payload = make_ctcp("ACTION", line) if action else line
            self.conn.send_command(
                command, destination, payload,
                on_sent=lambda line=line, index=index: sent(line, index),
                on_dropped=lambda reason, line=line, index=index: dropped(line, index, reason),
            )
        return first

    def send_typing(self, buffer_id: int, state: str) -> bool:
        """Tell a channel or a query that we are typing, or have stopped.

        `@+typing=active TAGMSG <target>`, at most once per
        TYPING_ACTIVE_EVERY per target however often a client says so, and one
        "paused" or "done" after an "active", never one on its own. Returns
        whether a line was queued, which only the tests read.

        Silently nothing, never an error, when the network cannot carry it: a
        server without message-tags (QuakeNet) would answer "unknown command"
        to every TAGMSG. Nothing when the buffer is the Server buffer, a
        channel we are not in, or on another network. And nothing unless the
        link has room to spare (IRCConnection.spare): a typing hint costs a
        flood token like any line, and one must never make somebody's message
        wait. A dropped "active" is retried by the next keystroke; a dropped
        "done" is covered by the receiver's own six-second expiry.

        None of this is stored, counted as unread, or seen by auto-away, which
        follows whether a client is attached and nothing a client sends.
        """
        if state not in TYPING_STATES:
            return False
        if not self.conn.registered or "message-tags" not in self.conn.caps:
            return False
        buf = self.store.buffer(buffer_id)
        if buf is None or buf.network_id != self.network_id or buf.kind not in ("channel", "query"):
            return False
        if buf.kind == "channel" and not buf.joined:
            return False
        key = fold(buf.name, self.casemapping)
        now = time.monotonic()
        last = self._typing_sent.get(key)
        if state == "active":
            if last is not None and now - last < TYPING_ACTIVE_EVERY:
                return False
        elif last is None:
            return False
        if not self.conn.spare:
            if state != "active":
                # Owed no longer: the receiver's expiry says it for us.
                self._typing_sent.pop(key, None)
            return False
        if state == "active":
            self._typing_sent[key] = now
        else:
            self._typing_sent.pop(key, None)
        return self.conn.send(f"@+typing={state} " + format_line("TAGMSG", buf.name))

    async def _announce_buffer(self, buffer_id: int) -> None:
        buf = self.store.buffer(buffer_id)
        if buf is not None:
            await self.hub.broadcast(
                P.frame(P.BUFFER, buffer=self.buffer_to_wire(buf))
            )

    async def open_query(self, nick: str) -> dict:
        """Open a private conversation without sending anything to it yet.

        Deliberately separate from `say`: /query is how you open a window to
        type in, and sending an empty message to announce yourself would be
        rude and visible to the other person.
        """
        if self._is_channel(nick):
            raise ValueError("that is a channel, not a nick")
        check_param(nick, "a nickname")
        buf = self._buffer_for(nick, "query")
        if buf.archived:
            self.store.set_archived(buf.id, False)
        # Ask whether they are online soon, rather than at the next minute.
        self._presence_dirty = True
        await self._announce_buffer(buf.id)
        return self.buffer_to_wire(self.store.buffer(buf.id))

    async def close_buffer(self, buffer_id: int) -> None:
        """Hide a buffer. Parts the channel first if we are still in it.

        Never deletes history -- see Store.set_archived. Closing the status
        buffer is refused: it is where the reason you cannot connect appears,
        and a client with no way to see that is a client that cannot be debugged.
        """
        buf = self.store.buffer(buffer_id)
        if buf is None or buf.network_id != self.network_id:
            raise ValueError("unknown buffer")
        if buf.kind == "status":
            raise ValueError("cannot close the status buffer")
        if buf.kind == "channel" and buf.joined:
            await self.part(buf.name, "closing")
        elif buf.kind == "channel":
            # Kicked, or never rejoined: there is nothing to part, but closing
            # it is still deciding to leave. Left in the wanted list it would
            # be joined again on the next reconnect and reopen itself.
            self._unwant(buf.name)
        self.store.set_archived(buf.id, True)
        if buf.kind == "query":
            # No longer watched for presence (and off the MONITOR list).
            self._online.pop(fold(buf.name, self.casemapping), None)
            self._presence_dirty = True
        # Closing is reading. Whatever was unread in it is either seen or not
        # wanted, and a count left on a buffer nobody can see is a badge
        # nothing can clear. If it comes back (someone speaks in it), only what
        # arrives from here on counts.
        eid = self.store.mark_read(buf.id, self.store.newest_eid(buf.id))
        await self.hub.broadcast(P.frame(P.READ_MARKER, buffer=buf.id, eid=eid))
        await self._announce_buffer(buf.id)

    async def set_detached(self, buffer_id: int, detached: bool,
                           until: float | None = None) -> None:
        """Mute a buffer without leaving it.

        Different from /close: the channel stays joined upstream, everything is
        still recorded, and history keeps growing. Only the badge stops. It
        stays muted until the user says otherwise: a mention still counts and
        still notifies (per `notify`), but no longer un-mutes it.
        """
        buf = self.store.buffer(buffer_id)
        if buf is None or buf.network_id != self.network_id:
            raise ValueError("unknown buffer")
        if buf.kind == "status":
            raise ValueError("cannot detach the status buffer")
        # `until` makes the mute end by itself; the gateway's sweep lifts it.
        self.store.set_detached(buffer_id, detached, until)
        await self._announce_buffer(buffer_id)

    async def set_buffer_settings(self, buffer_id: int, *, notify: str | None = None,
                                  pinned: bool | None = None) -> dict:
        """Per-conversation settings: the notify level and the pin. Stored on
        the bouncer so every device agrees, and so the push decision -- which
        is made here, while the phone is asleep -- can follow it."""
        buf = self.store.buffer(buffer_id)
        if buf is None or buf.network_id != self.network_id:
            raise ValueError("unknown buffer")
        self.store.set_buffer_settings(buffer_id, notify=notify, pinned=pinned)
        await self._announce_buffer(buffer_id)
        return self.buffer_to_wire(self.store.buffer(buffer_id))

    def set_highlight_words(self, words: list[str]) -> None:
        self.store.set_highlight_words(self.network_id, words)
        self.highlighter.set_words(words)

    async def set_nick(self, nick: str, origin: int | None = None) -> None:
        check_param(nick, "a nickname")
        if not self.conn.registered:
            raise ValueError("not connected to the network")
        # Note what is NOT done here: the local nick is not updated optimistically.
        # The server may refuse (433 nick in use), and a client showing a nick the
        # network never accepted is worse than one that takes a moment to update.
        # _h_nick applies it when the server confirms.
        # Choosing a nick by hand settles it: from here on the one asked for is
        # the one wanted, and reclaiming the configured name would undo it.
        self._cancel_reclaim()
        self.note_request("NICK", origin)
        self.conn.send_command("NICK", nick)

    async def set_topic(self, buffer_id: int, topic: str) -> None:
        buf = self.store.buffer(buffer_id)
        if buf is None or buf.kind != "channel":
            raise ValueError("not a channel")
        if not self.conn.registered:
            raise ValueError("not connected to the network")
        check_channel(buf.name)
        check_param(topic, "a topic", trailing=True)
        self.note_request("TOPIC", buf.id)
        self.conn.send_command("TOPIC", buf.name, topic)

    async def set_ignored(self, nick: str, ignored: bool) -> None:
        """Block or unblock a nick, or a nick!user@host mask with * and ?.

        A bare nick is the mask nick!*@*. Kept as typed, so the list reads the
        way it was entered and unblocking is the same string. It used to take
        a nick only and store "*!*@spam.host" as a literal nick that matched
        nobody, and answer ok.
        """
        mask = (nick or "").strip()
        if not mask:
            raise ValueError("missing nick")
        check_param(mask, "a nickname or mask")
        if len(mask) > 200:
            raise ValueError("That mask is too long.")
        own = normalize_mask(mask).split("!", 1)[0] if is_mask(mask) else mask
        if self.is_me(own):
            raise ValueError("you cannot block yourself")
        if ignored:
            if mask_matches_everyone(mask):
                raise ValueError("That mask would block everyone.")
            self.store.add_ignore(self.network_id, mask)
        else:
            self.store.remove_ignore(self.network_id, mask)
            # Whoever was being followed through a nick change may have been
            # followed because of this one. Start again from the masks.
            self._ignore_followed.clear()
        self._ignores.set_masks(self.store.ignores(self.network_id))
        await self.hub.broadcast(P.frame(
            P.IGNORES, network=self.config.slug, nicks=self.store.ignores(self.network_id)))

    async def set_away(self, text: str = "") -> None:
        """Mark away, or clear it.

        IRC has one command for both: `AWAY :message` sets it, and a bare
        `AWAY` with no parameter clears it. There is no confirmation numeric
        worth waiting for (a server may send 306/305, but not all do), so this
        applies the change locally and broadcasts it right away rather than
        leaving the client guessing the way `set_nick` deliberately does not.
        """
        text = (text or "").strip()
        if text:
            check_param(text, "an away message", trailing=True)
        # Saved first and sent if we can: set while disconnected, it goes out
        # on the next registration, like every other time it is re-sent.
        self._away = text or None
        # A choice the user made replaces one the bouncer made for them.
        self._auto_away = False
        self.store.set_network_away(self.network_id, self._away)
        if self.conn.registered:
            if text:
                self.conn.send_command("AWAY", text)
            else:
                self.conn.send_command("AWAY")
        await self.hub.broadcast(P.frame(P.NETWORK, network=self.to_wire()))

    @property
    def away_message(self) -> str | None:
        """The away that is in force: the user's own, else the automatic one."""
        if self._away:
            return self._away
        return AUTO_AWAY_MESSAGE if self._auto_away else None

    def set_auto_away(self, active: bool) -> None:
        """Mark away because nobody is attached, or clear that again.

        Only ever layered under the user's own choice: with an away the user
        set, this does nothing either way -- it neither replaces their message
        nor clears it when a client comes back. Synchronous, because the hub
        calls it as clients come and go.
        """
        if active == self._auto_away or self._away is not None:
            return
        self._auto_away = active
        if self.conn.registered:
            if active:
                self.conn.send_command("AWAY", AUTO_AWAY_MESSAGE)
            else:
                self.conn.send_command("AWAY")
        self.hub.publish(P.frame(P.NETWORK, network=self.to_wire()))

    async def invite(self, channel: str, nick: str, origin: int | None = None) -> None:
        check_channel(channel)
        check_param(nick, "a nickname")
        if not self.conn.registered:
            raise ValueError("not connected to the network")
        self.note_request("INVITE", origin)
        self.conn.send_command("INVITE", nick, channel)

    async def raw(self, line: str, origin: int | None = None) -> None:
        """Send one line exactly as typed: /quote, /raw, /ctcp, /mode #x +i.

        The escape hatch for everything the app has no button for. Refused:
        more than one line, more than IRC can carry, the registration commands,
        QUIT and AUTHENTICATE. Everything else goes as is -- a password typed
        to a service included, since nothing of a raw line is kept -- through
        the same flood queue as the rest;
        what the server says back lands per "Errors" in docs/PROTOCOL.md.
        """
        if not isinstance(line, str) or not line.strip():
            raise ValueError("empty line")
        for bad, what in (("\r", "a line break"), ("\n", "a line break"), ("\0", "a NUL")):
            if bad in line:
                raise ValueError(f"one IRC line only; this has {what} in it")
        if len(line.encode("utf-8")) > 510:
            raise ValueError("too long for one IRC line (510 bytes at most)")
        msg = parse_line(line)
        if msg is None or not msg.command:
            raise ValueError("that is not an IRC command")
        command = msg.command.upper()
        if command in RAW_REFUSED:
            raise ValueError(RAW_REFUSED[command])
        if not self.conn.registered:
            raise ValueError("not connected to the network")

        # A few commands change what the bouncer keeps, so they are kept in
        # step rather than going around it.
        if command == "AWAY":
            await self.set_away(msg.param(0))
            return
        if command == "JOIN":
            if not self._joined_once:
                # Before the post-registration join burst, which waits for Q
                # and the cloak: a JOIN now would carry the real host in.
                raise ValueError("Still connecting; try again in a moment.")
            # "JOIN #a,#b key1,key2": the keys are positional, and kept with
            # their channels like one given to the `join` frame (see join).
            keys = msg.param(1).split(",") if msg.param(1) else []
            for index, channel in enumerate(msg.param(0).split(",")):
                if not channel:
                    continue
                key = keys[index] if index < len(keys) else ""
                changed = False
                if fold(channel) not in {fold(c) for c in self._wanted_channels}:
                    self._wanted_channels.append(channel)
                    changed = True
                if key and self._channel_keys.get(fold(channel)) != key:
                    self._channel_keys[fold(channel)] = key
                    changed = True
                if changed:
                    self._save_wanted()
        elif command == "PART":
            for channel in msg.param(0).split(","):
                if channel:
                    self._unwant(channel)
        elif command == "NICK":
            self._cancel_reclaim()
        # A CTCP is noted as such, so its reply can find its way back.
        is_ctcp = command == "PRIVMSG" and msg.param(1).startswith("\x01")
        self.note_request("CTCP" if is_ctcp else command, origin)
        # The answer is shown for RAW_ANSWER_WINDOW from when the line reaches
        # the socket, which behind a full flood queue is later than now; noted
        # at both moments so the window is open either way.
        self._note_raw(command)

        def on_sent() -> None:
            self._note_raw(command)
            # An ISON typed by hand takes its place in the line of ISON
            # answers (see _h_303), so it cannot be mistaken for the presence
            # poll's.
            if command == "ISON":
                self._ison_written("raw", [])

        if not self.conn.send(line, on_sent=on_sent):
            raise ValueError("sending too fast; wait a moment")

    def list_channels(self, mask: str = "") -> asyncio.Future:
        """Ask for the channel list; the future resolves to (channels, complete).

        channels are {"name", "users", "topic"}, most populated first, at most
        LIST_MAX of them. complete is false when the list was cut to that, or
        the server never finished it (LIST_TIMEOUT, a dropped link, 416).
        """
        if self._list is not None:
            raise ValueError("A channel list is already on its way. Wait for it.")
        if not self.conn.registered:
            raise ValueError("not connected to the network")
        mask = (mask or "").strip()
        if mask:
            check_param(mask, "a channel mask")
        future = asyncio.get_running_loop().create_future()
        pending = PendingList(future=future)
        pending.timeout = asyncio.create_task(self._list_deadline(pending))
        self._list = pending
        if mask:
            self.conn.send_command("LIST", mask)
        else:
            self.conn.send_command("LIST")
        return future

    async def _list_deadline(self, pending: PendingList) -> None:
        await asyncio.sleep(self.list_timeout)
        if self._list is pending:
            self._finish_list(complete=False)

    def _finish_list(self, *, complete: bool, error: str | None = None) -> None:
        pending, self._list = self._list, None
        if pending is None:
            return
        if pending.timeout is not None and pending.timeout is not asyncio.current_task():
            pending.timeout.cancel()
        if pending.future.done():
            return
        if error:
            pending.future.set_exception(ValueError(error))
            return
        rows = sorted(pending.rows, key=lambda r: (-r["users"], fold(r["name"])))
        pending.future.set_result((rows[:LIST_MAX], complete and len(rows) <= LIST_MAX))

    async def _h_321(self, msg: Message) -> None:      # RPL_LISTSTART
        pass                                           # the header row; nothing in it

    async def _h_322(self, msg: Message) -> None:      # RPL_LIST
        if self._list is None:
            return
        users = msg.param(2)
        self._list.rows.append({"name": msg.param(1),
                                "users": int(users) if users.isdigit() else 0,
                                "topic": msg.param(3)})

    async def _h_323(self, msg: Message) -> None:      # RPL_LISTEND
        self._finish_list(complete=True)

    async def _h_263(self, msg: Message) -> None:      # RPL_TRYAGAIN
        # "Server load is temporarily too heavy": the list is not coming.
        if self._list is not None and msg.param(1).upper() == "LIST":
            self._finish_list(complete=False,
                              error=msg.param(2) or "the server said to try again later")
        else:
            await self._status(" ".join(msg.params[1:]))

    async def refresh_members(self, buffer_id: int) -> None:
        """Ask the server for NAMES again rather than trust what we hold.

        The member list is the one piece of state where the client can disagree
        with the server and have no way to tell -- see docs/PROTOCOL.md. The
        `members` frame this triggers does not come from here directly; the
        existing 353/366 handlers rebuild the list and rebroadcast it, the same
        as after any other NAMES.
        """
        buf = self.store.buffer(buffer_id)
        if buf is None or buf.network_id != self.network_id or buf.kind != "channel":
            raise ValueError("not a channel")
        if not self.conn.registered:
            raise ValueError("not connected to the network")
        check_channel(buf.name)
        self.note_request("NAMES", buf.id)
        self.conn.send_command("NAMES", buf.name)

    # --- channel operator actions ------------------------------------------

    # Only these may be set on a person. An open-ended mode string from a client
    # would let it send anything at all to the server, including modes that
    # affect the connection rather than the channel.
    USER_MODES = {"o", "v", "h", "b", "q"}

    async def set_channel_mode(self, buffer_id: int, mode: str, nick: str) -> None:
        """Apply a per-user channel mode, e.g. `+o nick` or `-v nick`."""
        buf = self.store.buffer(buffer_id)
        if buf is None or buf.kind != "channel":
            raise ValueError("not a channel")
        if len(mode) != 2 or mode[0] not in "+-" or mode[1] not in self.USER_MODES:
            raise ValueError(f"{mode!r} is not an allowed mode")
        if not nick:
            raise ValueError("missing nick")
        if not self.conn.registered:
            raise ValueError("not connected to the network")
        check_channel(buf.name)
        check_param(nick, "a nickname")

        target = nick
        if mode[1] in ("b", "q"):
            # A ban on a bare nick is trivially evaded by changing it. Use the
            # host if we have seen one, which is what a ban is actually for.
            host = self.store.last_known_host(buf.id, nick)
            target = f"*!*@{host}" if host else f"{nick}!*@*"

        self.note_request("MODE", buf.id)
        self.conn.send_command("MODE", buf.name, mode, target)
        await self._status(f"sent MODE {buf.name} {mode} {target}")

    async def kick(self, buffer_id: int, nick: str, reason: str = "") -> None:
        buf = self.store.buffer(buffer_id)
        if buf is None or buf.kind != "channel":
            raise ValueError("not a channel")
        if not nick:
            raise ValueError("missing nick")
        if self.is_me(nick):
            raise ValueError("you cannot kick yourself")
        if not self.conn.registered:
            raise ValueError("not connected to the network")
        check_channel(buf.name)
        check_param(nick, "a nickname")
        check_param(reason, "a kick reason", trailing=True)
        self.note_request("KICK", buf.id)
        self.conn.send_command("KICK", buf.name, nick, reason or "goodbye")

    async def whois(self, nick: str, req: str | None = None) -> None:
        """Look someone up and answer with one frame instead of nine lines.

        The reply is gathered here rather than in the client because the client
        has nothing to gather it with: the numerics arrive as separate lines,
        name only the nick, and end with a 318 that carries nothing. A card is
        one object or it is a pile of server text, and it was the pile before.

        `req` is the asking client's request id, carried through to the frame so
        that client can tell its own lookup from one another device asked for.
        The frame goes to every attached client either way -- a card opened on
        the phone is worth having on the Mac -- and `ok` still goes back at once,
        because `ok` means the question was asked, not that it was answered.
        """
        if not nick:
            raise ValueError("missing nick")
        check_param(nick, "a nickname")
        if not self.conn.registered:
            raise ValueError("not connected to the network")
        key = fold(nick, self.casemapping)
        # A second lookup for the same nick replaces the first. Two entries
        # under one key could not both be answered, since the numerics name the
        # nick and nothing else, so the older one goes now rather than timing
        # out against a reply that is about to arrive.
        previous = self._whois_pending.pop(key, None)
        if previous is not None:
            previous.cancel()
        pending = PendingWhois(nick=nick, req=req, data={"nick": nick, "channels": []})
        self._whois_pending[key] = pending
        pending.timeout = asyncio.create_task(
            self._whois_deadline(key, self.whois_timeout))
        self.conn.send_command("WHOIS", nick)

    async def _whois_deadline(self, key: str, delay: float) -> None:
        """Answer anyway when the server never finishes the reply.

        The cases this catches are a server that goes quiet mid-reply and a
        connection that drops in the middle of one. In both the client is left
        waiting on a card that will never arrive unless something closes the
        lookup, and saying nothing came back is an answer where a spinner is not.
        """
        await asyncio.sleep(delay)
        pending = self._whois_pending.pop(key, None)
        if pending is not None:
            await self._send_whois(pending, error="no reply from the server")

    async def _end_whois(self, key: str, *, error: str = "") -> None:
        """Close a pending lookup and send its frame; do nothing if there is none.

        No pending lookup is the ordinary case rather than a fault. The bouncer
        sees every numeric the server sends down this connection, including
        replies to nothing it asked for, and a reply that arrives after the
        deadline has already been answered.
        """
        pending = self._whois_pending.pop(key, None)
        if pending is None:
            return
        pending.cancel()
        await self._send_whois(pending, error=error)

    async def _send_whois(self, pending: PendingWhois, *, error: str = "") -> None:
        if error:
            fields = {"nick": pending.nick, "found": False, "error": error}
        else:
            fields = {**WHOIS_FIELDS, **pending.data, "found": True}
        await self.hub.broadcast(P.frame(
            P.WHOIS, req=pending.req, network=self.config.slug, **fields))

    async def join(self, channel: str, origin: int | None = None,
                   key: str | None = None) -> None:
        """Join a channel and keep it in the wanted list. With `key`, the key
        is remembered with the channel and sent with this JOIN and every later
        one -- the rejoin after a netsplit or a restart included. Without one,
        a key already remembered for the channel is used, so a Rejoin button
        that knows only the name still gets back into a +k channel."""
        check_channel(channel)
        if key:
            check_channel_key(key)
        self.note_request("JOIN", origin)
        folded = fold(channel)
        changed = False
        if folded not in {fold(c) for c in self._wanted_channels}:
            self._wanted_channels.append(channel)
            changed = True
        if key and self._channel_keys.get(folded) != key:
            self._channel_keys[folded] = key
            changed = True
        if changed:
            self._save_wanted()
        # Before the post-registration join burst has gone out, the channel is
        # only added to the list and goes out with the burst. That burst waits
        # for Q and the +x cloak (see _join_after_auth), and a JOIN sent ahead
        # of it -- a Rejoin tapped while channels still read joined:false after
        # a reconnect -- would carry the real host into the channel.
        if self.conn.registered and self._joined_once:
            known = self._channel_keys.get(folded)
            self.conn.send_command("JOIN", channel, *([known] if known else []))

    async def part(self, channel: str, reason: str = "", origin: int | None = None) -> None:
        """A deliberate part: the channel leaves the wanted list for good.

        A kick does not come through here and does not touch the list -- being
        kicked is not deciding to leave, and the next reconnect (or restart)
        joins again. A /part is deciding, so it sticks across restarts too.
        """
        check_channel(channel)
        check_param(reason, "a part reason", trailing=True)
        self._unwant(channel)
        if self.conn.registered:
            self.note_request("PART", origin)
            self.conn.send_command("PART", channel, reason or "leaving")

    def _unwant(self, channel: str) -> None:
        # Leaving on purpose settles any outage: a "Reconnected" line on some
        # later, deliberate join would be about an outage long over.
        buf = self.store.find_buffer(self.network_id, channel)
        if buf is not None:
            self._lost_channels.discard(buf.id)
        before = len(self._wanted_channels)
        self._wanted_channels = [
            c for c in self._wanted_channels if fold(c) != fold(channel)
        ]
        # Its key goes with it: a channel left on purpose is not one whose
        # password should stay in the database.
        had_key = self._channel_keys.pop(fold(channel), None) is not None
        if len(self._wanted_channels) != before or had_key:
            self._save_wanted()

    def _save_wanted(self) -> None:
        # Written through on every change. It used to live only in memory, so
        # every deploy quietly undid whatever had been joined or parted from a
        # client since the last one. The keys are written with the list, and
        # only those of channels still in it.
        wanted = {fold(c) for c in self._wanted_channels}
        self._channel_keys = {name: key for name, key in self._channel_keys.items()
                              if name in wanted}
        self.store.set_network_channels(self.network_id, list(self._wanted_channels),
                                        dict(self._channel_keys))

    # --- inbound dispatch --------------------------------------------------

    async def _on_message(self, msg: Message) -> None:
        if msg.command == "005":
            self._keep_isupport(msg)
        token = None
        if msg.tags and msg.command in TIMED_COMMANDS:
            ts = parse_server_time(msg.tags.get("time"))
            if ts is not None:
                # Never in the future: a server clock a few seconds fast would
                # otherwise put lines ahead of everything stamped here.
                token = _EVENT_TS.set(min(ts, time.time()))
        try:
            handler = getattr(self, f"_h_{msg.command.lower()}", None)
            if handler is not None:
                # Looked at first: the handler may close the lookup that says
                # whose reply this is (318 does).
                if msg.command.isdigit() and self._raw_claims(msg):
                    self._raw_answer(msg)
                await handler(msg)
            elif msg.command.isdigit():
                await self._h_numeric(msg)
        finally:
            if token is not None:
                _EVENT_TS.reset(token)

    def _keep_isupport(self, msg: Message) -> None:
        """Keep the raw ISUPPORT values the network frame shows, and send the
        frame once the 005 lines stop coming (a server sends several, all
        after the 001 that sent the frame last)."""
        tokens = parse_isupport(msg.params)
        changed = False
        for key in ISUPPORT_WIRE:
            if key.upper() in tokens and self.isupport.get(key) != tokens[key.upper()]:
                self.isupport[key] = tokens[key.upper()]
                changed = True
        if changed and self._isupport_flush is None:
            def flush() -> None:
                self._isupport_flush = None
                self.hub.publish(P.frame(P.NETWORK, network=self.to_wire()))
            self._isupport_flush = asyncio.get_running_loop().call_later(0.5, flush)

    async def _h_005(self, msg: Message) -> None:
        tokens = parse_isupport(msg.params)
        if "CASEMAPPING" in tokens:
            self.casemapping = tokens["CASEMAPPING"].lower()
            self._ignores.set_casemapping(self.casemapping)
        if "STATUSMSG" in tokens:
            self.statusmsg = tokens["STATUSMSG"]
        if "MONITOR" in tokens:
            value = tokens["MONITOR"]
            self.monitor_limit = int(value) if value.isdigit() else 0
        if "PREFIX" in tokens:
            self.prefix_map = parse_prefix_map(tokens["PREFIX"])
        if "CHANTYPES" in tokens:
            self.chantypes = tokens["CHANTYPES"]
        if "CHANMODES" in tokens:
            self.chanmodes = parse_chanmodes(tokens["CHANMODES"])
        if "TARGMAX" in tokens:
            self.join_targets = targmax(tokens["TARGMAX"], "JOIN")

    async def _h_numeric(self, msg: Message) -> None:
        if msg.command == "416" and self._list is not None:
            # ERR_TOOMANYMATCHES: the server cut the list short. What came is
            # still worth having.
            self._finish_list(complete=False)
        if len(msg.command) == 3 and msg.command[0] in "45":
            self._route_numeric(msg)
            return
        if msg.command in INTERESTING_NUMERICS:
            # Drop the leading "your nick" param that every numeric repeats.
            text = " ".join(msg.params[1:]) if len(msg.params) > 1 else msg.param(0)
            await self._status(text)
        elif self._raw_open():
            # Nothing has a use for it, and someone has just typed a raw line:
            # this is very likely its answer (a ban list, WHOWAS, USERHOST).
            self._raw_answer(msg)

    # --- answers to a `raw` line ---------------------------------------------
    #
    # IRC does not say which command a numeric answers, so this goes by time:
    # for RAW_ANSWER_WINDOW after a client's raw line is written, a numeric
    # that would otherwise be dropped is shown in the Server buffer instead.
    # Errors (4xx, 5xx) never come this way; they are routed to the
    # conversation they concern whether or not anyone typed anything.

    def _note_raw(self, command: str) -> None:
        now = time.monotonic()
        if not self._raw_open():
            self._raw_sent.clear()
        if command not in self._raw_sent:
            # A new question, so a new allowance of lines for its answer.
            self._raw_shown = 0
        self._raw_sent[command] = now

    def _raw_open(self, command: str | None = None) -> bool:
        """Has a raw line (or, with `command`, that raw command) gone out
        within the window?"""
        now = time.monotonic()
        if command is None:
            return any(now - at <= RAW_ANSWER_WINDOW for at in self._raw_sent.values())
        return now - self._raw_sent.get(command, float("-inf")) <= RAW_ANSWER_WINDOW

    def _raw_claims(self, msg: Message) -> bool:
        """Is this numeric, which has a handler of its own, the answer to a
        raw line rather than to something the bouncer asked?

        The handlers for WHOIS, WHO, LIST and ISON replies keep what they are
        given for a whois card, the away poll, a channel browser and the
        presence poll. A reply to one of those typed by hand is none of
        these, and used to be taken by the handler and never seen: a WHOIS
        with no card waiting, a LIST with no browser waiting, an ISON the
        line of ISON answers says was typed, and a WHO sent raw moments ago.
        """
        command = msg.command
        if command in WHOIS_NUMERICS:
            return (self._raw_open("WHOIS")
                    and fold(msg.param(1), self.casemapping) not in self._whois_pending)
        if command in WHO_NUMERICS:
            claimed = self._raw_open("WHO")
            if claimed and command == "315":
                # One WHO, one answer: the next WHO reply is the away poll's.
                self._raw_sent.pop("WHO", None)
            return claimed
        if command in LIST_NUMERICS:
            return self._list is None and self._raw_open("LIST")
        if command == "303":
            return bool(self._ison_pending) and self._ison_pending[0][0] == "raw"
        return False

    def _raw_answer(self, msg: Message) -> None:
        """One line of a server's answer to a raw line, into the Server
        buffer, as the numerics the bouncer shows for itself are (see
        _h_numeric): the parameters after our own nick, joined."""
        self._raw_shown += 1
        if self._raw_shown > RAW_ANSWER_MAX:
            if self._raw_shown == RAW_ANSWER_MAX + 1:
                self._record(self.status_buffer.id, P.KIND_SERVER,
                             text=f"(more than {RAW_ANSWER_MAX} lines of reply; "
                                  "the rest are not shown)")
            return
        text = " ".join(msg.params[1:]) if len(msg.params) > 1 else msg.param(0)
        self._record(self.status_buffer.id, P.KIND_SERVER, text=text,
                     extra={"numeric": msg.command})

    # --- where a server's answer lands --------------------------------------

    def note_request(self, command: str, buffer_id: int | None) -> None:
        """Remember which conversation a command was typed in, for ~10s.

        IRC answers a refusal with a numeric that often names nothing we can
        route by -- "433 * alice :Nickname is already in use" names a nick
        nobody has a query with -- and the conversation the person typed /nick
        into is where they are looking for the answer.
        """
        if buffer_id is None:
            return
        self._recent_requests[command.upper()] = (buffer_id, time.monotonic())

    def _request_buffer(self, numeric: str) -> int | None:
        now = time.monotonic()
        candidates = ERROR_SOURCES.get(numeric)
        best: tuple[int, float] | None = None
        for command, (buffer_id, at) in self._recent_requests.items():
            if now - at > REQUEST_MEMORY:
                continue
            if candidates is not None and command not in candidates:
                continue
            if best is None or at > best[1]:
                best = (buffer_id, at)
        return best[0] if best else None

    def _route_numeric(self, msg: Message) -> None:
        """Put a server's error (or away) reply in the conversation it is about.

        A channel parameter wins, then a nick with a query buffer, then the
        conversation the command came from, then the status buffer. It used to
        be the status buffer or nothing: a refused /topic (482) said nothing
        anywhere, and "/msg typo hi" answered "No such nick" in a buffer
        without a badge.
        """
        params = msg.params[1:]                  # our own nick comes first
        subjects, trailing = params[:-1], (params[-1] if params else "")
        target, routed_by = None, None
        for name in subjects:
            if self._is_channel(name):
                buf = self.store.find_buffer(self.network_id, name)
                if buf is not None and not buf.archived:
                    target, routed_by = buf, name
                    break
        if target is None:
            for name in subjects:
                if name and name != "*" and not self._is_channel(name):
                    buf = self.store.find_buffer(self.network_id, name)
                    if buf is not None and buf.kind == "query" and not buf.archived:
                        target, routed_by = buf, name
                        break
        if target is None:
            buffer_id = self._request_buffer(msg.command)
            buf = self.store.buffer(buffer_id) if buffer_id is not None else None
            if buf is not None and buf.network_id == self.network_id and not buf.archived:
                target = buf
        if target is None:
            target = self.status_buffer
        # The buffer it landed in is not repeated in the line: "You're not
        # channel operator" in #hangout, "No such nick" in the query.
        shown = [p for p in subjects if p and p != "*" and p != routed_by]
        text = f"{' '.join(shown)}: {trailing}" if shown and trailing else (trailing or " ".join(shown))
        self._record(target.id, P.KIND_SERVER, text=text, extra={"numeric": msg.command})

    # --- whois replies -----------------------------------------------------
    #
    # Every one of these numerics puts the nick it is about in the second
    # parameter, after our own, which is the whole of the matching we get.

    def _pending_whois(self, msg: Message) -> PendingWhois | None:
        nick = msg.param(1)
        if not nick:
            return None
        return self._whois_pending.get(fold(nick, self.casemapping))

    async def _h_311(self, msg: Message) -> None:      # RPL_WHOISUSER
        pending = self._pending_whois(msg)
        if pending is None:
            return
        # The realname is read from the end rather than from a fixed index. The
        # "*" before it is a field no server has ever put anything in, and the
        # ones that leave it out would otherwise shift the realname by one.
        realname = msg.params[-1] if len(msg.params) > 4 else ""
        # The server's spelling of the nick wins over the one that was typed:
        # it is what the person is actually called.
        pending.data.update(nick=msg.param(1), user=msg.param(2),
                            host=msg.param(3), realname=realname)

    async def _h_312(self, msg: Message) -> None:      # RPL_WHOISSERVER
        pending = self._pending_whois(msg)
        if pending is not None:
            pending.data.update(server=msg.param(2), server_info=msg.param(3))

    async def _h_313(self, msg: Message) -> None:      # RPL_WHOISOPERATOR
        pending = self._pending_whois(msg)
        if pending is not None:
            pending.data["operator"] = True

    async def _h_317(self, msg: Message) -> None:      # RPL_WHOISIDLE
        pending = self._pending_whois(msg)
        if pending is None:
            return
        idle, signon = msg.param(2), msg.param(3)
        if idle.isdigit():
            pending.data["idle_seconds"] = int(idle)
        # Not every server sends the signon time, and some send something that
        # is not a number at all. A field left as None is a line the card does
        # not draw; a string where an epoch belongs is a rendering bug.
        if signon.isdigit():
            pending.data["signon_at"] = int(signon)

    async def _h_319(self, msg: Message) -> None:      # RPL_WHOISCHANNELS
        pending = self._pending_whois(msg)
        if pending is None:
            return
        # Someone in many channels gets several 319s. They append rather than
        # replace, or the card shows the tail of the list and calls it the list.
        for entry in msg.param(2).split():
            prefix = ""
            while entry and entry[0] in self.prefix_map:
                # Highest prefix only, the same rule the member list uses.
                prefix = prefix or entry[0]
                entry = entry[1:]
            if entry:
                pending.data["channels"].append({"name": entry, "prefix": prefix})

    async def _h_330(self, msg: Message) -> None:      # RPL_WHOISACCOUNT
        # QuakeNet's wording is "is authed as", everyone else says "is logged in
        # as", and the account name is in the same parameter either way.
        pending = self._pending_whois(msg)
        if pending is not None:
            pending.data["account"] = msg.param(2)

    async def _h_338(self, msg: Message) -> None:      # RPL_WHOISACTUALLY
        pending = self._pending_whois(msg)
        if pending is not None:
            pending.data["actual_host"] = msg.param(2)

    async def _h_671(self, msg: Message) -> None:      # RPL_WHOISSECURE
        pending = self._pending_whois(msg)
        if pending is not None:
            pending.data["secure"] = True

    async def _h_301(self, msg: Message) -> None:      # RPL_AWAY
        pending = self._pending_whois(msg)
        if pending is None:
            # 301 arrives unprompted too, when you message someone who is away,
            # and the query with them is where that is worth reading. Most
            # servers send it after every line you send them, so the same
            # message is said once an hour rather than under every line.
            key = (fold(msg.param(1), self.casemapping), msg.param(2))
            now = time.monotonic()
            if now - self._away_replies.get(key, -AWAY_REPLY_QUIET) >= AWAY_REPLY_QUIET:
                self._away_replies[key] = now
                if len(self._away_replies) > 256:
                    self._away_replies = {k: t for k, t in self._away_replies.items()
                                          if now - t < AWAY_REPLY_QUIET}
                self._route_numeric(msg)
            return
        pending.data["away"] = msg.param(2)

    async def _h_318(self, msg: Message) -> None:      # RPL_ENDOFWHOIS
        await self._end_whois(fold(msg.param(1), self.casemapping))

    async def _h_401(self, msg: Message) -> None:      # ERR_NOSUCHNICK
        key = fold(msg.param(1), self.casemapping)
        if key in self._whois_pending:
            await self._end_whois(key, error="no such nick")
            return
        # 401 is not only a whois reply: it is also what a PRIVMSG to someone
        # who has left looks like. With nothing waiting on it, it belongs in the
        # status buffer where it has always been.
        await self._h_numeric(msg)

    async def _h_privmsg(self, msg: Message) -> None:
        await self._handle_text(msg, notice=False)

    async def _h_tagmsg(self, msg: Message) -> None:
        """A TAGMSG: a message with tags and no text. The only one used here
        is +typing, relayed to attached clients as a `typing` frame and never
        stored. Nothing else about TAGMSG is kept (reactions, replies): there
        is no row to hang one on yet.

        "paused" goes to clients as "done". A person who paused is still in
        the conversation, but "bob is typing" with a note that he has stopped
        is one state more than the line under a topic can say usefully.

        Only for a conversation that already exists: typing is not a reason to
        open a query, and a channel we are not in has nobody here to tell.
        """
        typing = msg.tags.get("+typing")
        sender = msg.prefix.nick
        if typing not in TYPING_STATES or not sender or self.is_me(sender):
            return
        if self._is_ignored(msg.prefix):
            return
        _, target = self._split_statusmsg(msg.param(0))
        if self._is_channel(target):
            buf = self.store.find_buffer(self.network_id, target)
            if buf is None or buf.kind != "channel" or not buf.joined:
                return
        else:
            buf = self.store.find_buffer(self.network_id, sender)
            if buf is None or buf.kind != "query" or buf.archived:
                return
        self.hub.publish(P.frame(P.TYPING, buffer=buf.id, nick=sender,
                                 state="active" if typing == "active" else "done"))

    async def _h_notice(self, msg: Message) -> None:
        await self._handle_text(msg, notice=True)

    async def _handle_text(self, msg: Message, *, notice: bool) -> None:
        sender = msg.prefix.nick
        target = msg.param(0)
        text = msg.param(1)

        # Q's replies drive the authentication exchange. Checked before the
        # server-notice test below, because Q is a service with a normal
        # nick!user@host prefix and would otherwise land in a query buffer.
        if notice and sender and sender.lower() == "q" and self.qauth:
            reply = self.qauth.handle_notice(text, msg.prefix.host)
            if reply:
                command, argument = reply
                self.conn.send_command(command, Q_BOT, argument)
                # +x goes out in the same breath as the CHALLENGEAUTH, not after
                # Q confirms the login. Q processes the auth asynchronously, so
                # waiting for its "logged in" notice before asking for the cloak
                # leaves a window where a JOIN could go out uncloaked.
                if self.config.q_hide_host:
                    self.conn.send_command("MODE", self.nick, "+x")
                    self._awaiting_cloak = True
                return
            if self.qauth.state == "failed":
                await self._status(f"Q auth failed: {text}")
                return
            # Anything else from Q is worth seeing but is not a query.
            await self._status(f"-Q- {text}")
            return

        # From the server itself, not from a person. Two shapes: no prefix at
        # all, or a bare hostname prefix with no user@host part -- QuakeNet sends
        # connection notices as `:tngnet.nl.quakenet.org NOTICE relaydev :...`.
        # Without the second test that hostname is read as a nick and opens a
        # query buffer named after the server, which is what it did on the first
        # live run.
        if not sender or (not msg.prefix.user and "." in sender):
            await self._status(text)
            return

        # Blocked: dropped before it is stored, before it is broadcast, and
        # before it can become a push notification. Not stored-but-hidden --
        # "block" should mean the message does not reach you, and a copy kept on
        # the server that a future client might render is not that. Matched on
        # the whole prefix, so a host mask holds through a nick change.
        if self._is_ignored(msg.prefix):
            return

        ctcp = parse_ctcp(text)
        if ctcp and ctcp[0] != "ACTION":
            await self._handle_ctcp_request(msg.prefix, target, ctcp[0], ctcp[1],
                                            notice=notice)
            return

        kind = P.KIND_NOTICE if notice else P.KIND_MESSAGE
        if ctcp and ctcp[0] == "ACTION":
            kind, text = P.KIND_ACTION, ctcp[1]

        # "@#chan": a line for the channel's ops only. Into the channel, marked.
        status_prefix, target = self._split_statusmsg(target)
        extra = {"statusmsg": status_prefix} if status_prefix else None

        if target.startswith("$"):
            # "$*.quakenet.org": an operator's message to everyone on a server
            # or network. Nobody's conversation, and not addressed to you.
            self._record(self.status_buffer.id, kind, sender=sender,
                         sender_host=msg.prefix.host, text=text,
                         extra={"broadcast": target})
            return

        if self._is_channel(target):
            buf = self._buffer_for(target, "channel")
            is_private = False
        elif self._is_service(msg.prefix):
            # NickServ's "this nick is registered", ChanServ's access lists, Q
            # without Q auth set up: replies and account notices, not a
            # conversation. Into the query with them if one is open (you typed
            # /msg NickServ, and the answer belongs beside the question), else
            # the status buffer; never a highlight, never a push. They used to
            # open a highlighted query that buzzed the phone.
            buf = self.store.find_buffer(self.network_id, sender)
            if buf is None or buf.kind != "query" or buf.archived:
                buf = self.status_buffer
            self._record(buf.id, kind, sender=sender, sender_host=msg.prefix.host,
                         text=text, extra=extra)
            return
        else:
            # A message to us personally opens a query buffer named for the sender,
            # not for the target -- the target is our own nick, which would give
            # every conversation the same buffer.
            buf = self._buffer_for(sender, "query")
            is_private = True
            # Whoever just messaged us is online, whatever the last ISON said.
            # Noted before the announce below, so that one frame carries it.
            self._update_person(sender, online=True, announce=False)
            # Someone new opened a query: the client has never heard of this
            # buffer, and an event for an unknown buffer is dropped. Same rule
            # as the outgoing /msg path above. Without this the phone counted
            # the unread and showed nothing to open.
            await self._announce_buffer(buf.id)

        highlight = self.highlighter.matches(text, sender=sender, is_private=is_private)
        await self._emit(
            buf.id, kind,
            sender=sender, sender_host=msg.prefix.host, text=text, highlight=highlight,
            extra=extra,
        )

    async def _join_after_auth(self, timeout: float = 20.0) -> None:
        """Hold the JOINs until Q has answered and the cloak has landed.

        The cloak is the part that actually matters for timing. Joining in the
        same burst as the MODE +x races it, and the loser is a join line
        carrying the machine's real hostname into the channel — permanently, in
        everyone's scrollback. otherbot learned this when the switch from
        plaintext AUTH to CHALLENGEAUTH added a round trip that the old flow had
        not needed, and the raw host started appearing on reconnects.

        It is a deadline, not a barrier: never joining because Q went quiet is
        worse than joining uncloaked, so it gives up and says so.
        """
        # Bound to the connection it was started for. A task outliving its
        # link used to carry on into the next one and JOIN there before that
        # connection's own Q auth and cloak -- the exact leak this waits to
        # prevent -- or queue JOINs on a link that was already dead. It is
        # cancelled on disconnect and stop, and checks its generation as well,
        # because a cancel cannot reach a task that is between two awaits of
        # the old connection's teardown.
        generation = self._conn_generation

        def stale() -> bool:
            return generation != self._conn_generation or not self.conn.registered

        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            if stale():
                return
            if self.qauth and self.qauth.awaiting:
                await asyncio.sleep(0.25)
                continue
            if self._awaiting_cloak:
                await asyncio.sleep(0.25)
                continue
            break
        if stale():
            return

        if self.qauth and self.qauth.state != "authed":
            await self._status(
                f"joining without Q auth ({self.qauth.failure or 'no reply from Q'})")
        elif self._awaiting_cloak:
            await self._status("joining before the cloak was confirmed; host may be visible")
        if stale():
            return
        await self._do_joins()

    def _cancel_join_task(self) -> None:
        task, self._join_task = self._join_task, None
        if task is not None and task is not asyncio.current_task() and not task.done():
            task.cancel()

    async def _do_joins(self) -> None:
        if self._joined_once:
            return
        self._joined_once = True
        # Batched: "JOIN #a,#b,#c", as few lines as fit (see join_lines), the
        # keyed channels first in each line with their keys after the names.
        keys = {c: self._channel_keys[fold(c)] for c in self._wanted_channels
                if fold(c) in self._channel_keys}
        for line in join_lines(list(self._wanted_channels), keys,
                               max_targets=self.join_targets):
            self.conn.send(line)

    # --- SASL outcome, said in the status buffer ----------------------------
    #
    # The exchange itself is ircconn's (CAP, AUTHENTICATE); these are only the
    # server's verdict, for the person reading the status buffer. A refused
    # login also sets last_error, which the network frame carries.

    async def _h_900(self, msg: Message) -> None:      # RPL_LOGGEDIN
        account = msg.param(2)
        await self._status(f"logged in as {account}" if account else "logged in")

    async def _h_904(self, msg: Message) -> None:      # ERR_SASLFAIL
        why = msg.params[-1] if len(msg.params) > 1 else ""
        await self._status(f"SASL login failed: {why}" if why else "SASL login failed")

    async def _h_905(self, msg: Message) -> None:      # ERR_SASLTOOLONG
        await self._h_904(msg)

    async def _h_902(self, msg: Message) -> None:      # ERR_NICKLOCKED
        await self._h_904(msg)

    async def _h_396(self, msg: Message) -> None:
        """RPL_HOSTHIDDEN — the cloak is live. Safe to join now."""
        if self._awaiting_cloak:
            self._awaiting_cloak = False
            await self._status(f"host cloaked as {msg.param(1)}")
            await self._do_joins()

    async def _handle_ctcp_request(self, prefix: Prefix, target: str, verb: str, arg: str,
                                   *, notice: bool) -> None:
        """Answer the CTCPs a well-behaved client answers, and say who asked.

        Answered: VERSION ("geeyem"), PING (echoed back) and CLIENTINFO (the
        verbs understood here). Replies go out as NOTICE, per spec -- a CTCP
        reply sent as PRIVMSG is how two clients end up in an infinite loop
        with each other.

        Every request to us is also written into the status buffer as a
        `server` line ("bob asked for your VERSION", extra.ctcp and
        extra.from), never pushed. They used to be answered silently, so there
        was no way to know anyone had asked.

        Deliberately not answered, though still recorded: TIME, because the
        reply hands out the box's timezone -- which says roughly where it lives
        -- in exchange for nothing anybody wanted; SOURCE, and anything else
        unknown. Not answered and not recorded: a CTCP sent to a channel,
        because that is one request to everyone in it and answering means a
        NOTICE per person present, which is how a client gets killed for
        flooding; and anything past the rate limit, silently -- a reply nobody
        gets is better than the user's own next message waiting behind a flood,
        and a line nobody reads is better than a status buffer full of them.

        DCC offers are CTCPs too, and go to _dcc_offer.
        """
        sender = prefix.nick
        if notice:
            # A reply to a CTCP sent with `raw` (/ctcp nick PING). It used to
            # be dropped, which made /ctcp a question with no answer.
            if self.is_me(target):
                self._record_ctcp_reply(sender, verb, arg)
            return
        if not self.is_me(target):
            return                       # sent to a channel, not to us
        if verb == "DCC":
            await self._dcc_offer(prefix, arg)
            return
        if not self._ctcp_allowed(sender, verb):
            return
        reply = {"PING": arg, "VERSION": APP_NAME, "CLIENTINFO": CTCP_CLIENTINFO}.get(verb)
        answered = reply is not None
        if answered:
            self.conn.send_command("NOTICE", sender, make_ctcp(verb, reply))
        if verb == "PING":
            text = f"{sender} pinged you"
        elif verb in ("VERSION", "CLIENTINFO", "TIME", "SOURCE", "USERINFO", "FINGER"):
            text = f"{sender} asked for your {verb}"
        else:
            text = f"{sender} sent a CTCP {verb}"
        if not answered:
            text += " (not answered)"
        self._record(self.status_buffer.id, P.KIND_SERVER, text=text,
                     extra={"ctcp": verb, "from": sender, "answered": answered})

    async def _dcc_offer(self, prefix: Prefix, arg: str) -> None:
        """A DCC SEND or CHAT offer: shown, in the query with whoever offered.

        DCC is a direct connection between the two machines, and the machine
        here is a bouncer on a server that cannot hand the file on to a phone.
        So it is not supported, but it is no longer invisible either: the offer
        used to vanish, and the person offering waited for an answer that was
        never coming. A notice, not a highlight, never a push -- there is
        nothing to do about it but know.
        """
        sender = prefix.nick
        if not self._ctcp_allowed(sender, "DCC"):
            return
        kind, _, rest = arg.strip().partition(" ")
        kind = kind.upper()
        extra: dict = {"dcc": kind or "?"}
        if kind == "SEND":
            text = f"{sender} offered a file (DCC is not supported)"
            rest = rest.strip()
            name = (rest[1:].partition('"')[0] if rest.startswith('"')
                    else rest.partition(" ")[0])
            if name:
                extra["file"] = strip_formatting(name)[:200]
        elif kind == "CHAT":
            text = f"{sender} offered a chat (DCC is not supported)"
        else:
            text = f"{sender} sent a DCC request (DCC is not supported)"
        buf = self._buffer_for(sender, "query")
        await self._announce_buffer(buf.id)
        self._record(buf.id, P.KIND_NOTICE, sender=sender, sender_host=prefix.host,
                     text=text, extra=extra)

    def _record_ctcp_reply(self, sender: str, verb: str, arg: str) -> None:
        """Store a CTCP reply as a `notice` from whoever answered: in the query
        with them if there is one, else the status buffer. Recorded, never
        answered -- a NOTICE is never replied to, which is what stops two
        clients looping -- and never pushed: it is the answer to a question
        just asked, not news."""
        buf = self.store.find_buffer(self.network_id, sender)
        if buf is None or buf.kind != "query" or buf.archived:
            buf = self.status_buffer
        text = f"CTCP {verb} reply" + (f": {arg}" if arg else "")
        self._record(buf.id, P.KIND_NOTICE, sender=sender, text=text,
                     extra={"ctcp": verb, "reply": arg})

    def _ctcp_allowed(self, sender: str, verb: str = "", now: float | None = None) -> bool:
        """One reply per sender per verb per CTCP_PER_SENDER seconds, and
        CTCP_BURST overall.

        Two limits rather than one because they stop different things: the
        per-sender one stops a single person in a loop, and the overall one
        stops a channel's worth of people doing it at once. Per verb, so a
        VERSION and a PING from the same person a second apart both get their
        answer.
        """
        now = time.monotonic() if now is None else now
        self._ctcp_recent = [t for t in self._ctcp_recent if now - t < CTCP_WINDOW]
        if len(self._ctcp_recent) >= CTCP_BURST:
            return False
        key = f"{fold(sender, self.casemapping)} {verb}"
        last = self._ctcp_last.get(key)
        if last is not None and now - last < CTCP_PER_SENDER:
            return False
        self._ctcp_last[key] = now
        self._ctcp_recent.append(now)
        # Bound the table, or remembering who to throttle becomes the leak the
        # throttle exists to prevent.
        if len(self._ctcp_last) > 1024:
            self._ctcp_last = {k: t for k, t in self._ctcp_last.items()
                               if now - t < CTCP_PER_SENDER}
        return True

    async def _h_invite(self, msg: Message) -> None:
        """Someone invited us to a channel. Kept in the status buffer as an
        `invite` event, a highlight so it is in the mentions inbox and pushes
        like a mention; clients draw it with a Join button. It used to be
        dropped without a word."""
        target, channel, sender = msg.param(0), msg.param(1), msg.prefix.nick
        if not self.is_me(target) or not channel or not sender:
            return                       # someone else's (invite-notify), or malformed
        if self._is_ignored(msg.prefix):
            return
        await self._emit(self.status_buffer.id, P.KIND_INVITE, sender=sender,
                         sender_host=msg.prefix.host, text=f"invited you to {channel}",
                         highlight=True, extra={"channel": channel})
        # The clients count a new line into a badge themselves, and only
        # speech (message, action, notice): an invite raised the Server
        # buffer's count and the mention total only at the next `unread`
        # frame, which could be hours away. The server's counts include it,
        # so they go out now. Old clients handle `unread` already.
        await self.hub.broadcast(P.frame(P.UNREAD, counts=self.store.unread_counts()))

    async def _h_wallops(self, msg: Message) -> None:
        """A WALLOPS (operators to everyone with +w): a notice in the status
        buffer, tagged so a client can tell it from a server notice."""
        sender = msg.prefix.nick or msg.prefix.raw
        if msg.prefix.user and self._is_ignored(msg.prefix):
            return
        await self._emit(self.status_buffer.id, P.KIND_NOTICE, sender=sender,
                         sender_host=msg.prefix.host, text=msg.param(0),
                         extra={"wallops": True})

    async def _h_join(self, msg: Message) -> None:
        channel = msg.param(0)
        nick = msg.prefix.nick
        if self.is_me(nick):
            # Our own join brings a closed channel back; someone else's is only
            # bookkeeping and must not.
            buf = self._buffer_for(channel, "channel")
            self.store.set_joined(buf.id, True)
            await self._announce_buffer(buf.id)
            join_extra = None
            if buf.id in self._lost_channels:
                # The other half of the "Disconnected" line: the gap ends here.
                self._lost_channels.discard(buf.id)
                self._record(buf.id, P.KIND_SERVER, text="Reconnected",
                             extra={"connection": "restored"})
                # Our join right after it is part of the same event: tagged so
                # a client can fold "Reconnected" and "you joined" into the
                # one divider without comparing nicks (ours may be a fallback).
                join_extra = {"rejoin": True}
            # The channel's modes (+ntk), for the buffer frame: the 324 that
            # answers it lands in _h_324. Asked when the send queue is idle, so
            # a join burst never pushes anyone's message back.
            key = fold(channel, self.casemapping)
            self._queue_background("mode:" + key, "MODE", channel)
            self._fresh_joins.add(key)
        else:
            buf = self._buffer_for(channel, "channel", unarchive=False)
            self.store.add_member(buf.id, nick)
            self._member_add(buf.id, nick, "")
            self._update_person(nick, online=True)
            if self._is_ignored(msg.prefix):
                # Still a member (the list is the channel's, not ours), but
                # their comings and goings are not stored or shown.
                return
            join_extra = None
        await self._emit(buf.id, P.KIND_JOIN, sender=nick, sender_host=msg.prefix.host,
                         extra=join_extra)

    async def _h_part(self, msg: Message) -> None:
        channel = msg.param(0)
        nick = msg.prefix.nick
        # unarchive=False: the PART that closing a channel sends comes back
        # here, and must not reopen the channel it just closed.
        buf = self._buffer_for(channel, "channel", unarchive=False)
        if self.is_me(nick):
            self.store.set_joined(buf.id, False)
            self.store.clear_members(buf.id)
            self._modes.pop(buf.id, None)
            await self._left_channel(buf.id)
        else:
            self._member_remove(buf.id, nick)
            if self._is_ignored(msg.prefix):
                return
        await self._emit(buf.id, P.KIND_PART, sender=nick, sender_host=msg.prefix.host,
                         text=msg.param(1))

    async def _h_kick(self, msg: Message) -> None:
        channel, target = msg.param(0), msg.param(1)
        reason = msg.param(2)
        buf = self._buffer_for(channel, "channel", unarchive=False)
        if self.is_me(target):
            # The channel stays in the wanted list (see part): a kick is done to
            # you, not chosen, and a reconnect or restart joins again.
            self.store.set_joined(buf.id, False)
            self.store.clear_members(buf.id)
            self._modes.pop(buf.id, None)
            await self._left_channel(buf.id)
        else:
            self._member_remove(buf.id, target)
        # Who did it is the sender, who it was done to is extra.target, and the
        # reason is both the text (as it always was) and extra.reason, so a
        # client can build "alice kicked you: being loud" without guessing which
        # field means what.
        await self._emit(
            buf.id, P.KIND_KICK, sender=msg.prefix.nick, sender_host=msg.prefix.host,
            text=reason, extra={"target": target, "reason": reason},
        )

    async def _h_quit(self, msg: Message) -> None:
        """A QUIT names no channel, so it has to be fanned out to every buffer
        the person was in -- and only those, or every channel shows a quit for
        someone who was never there."""
        nick = msg.prefix.nick
        reason = msg.param(0)
        # Tagged, not collapsed. Every person's quit stays its own stored event,
        # so "when did X leave" is still answerable and backlog is still a
        # faithful record; the tag is what lets a client render a hundred of them
        # as one row. Presentation is the client's job.
        servers = netsplit_servers(reason)
        extra = {"netsplit": list(servers)} if servers else None
        ignored = self._is_ignored(msg.prefix)

        for buf in self.store.buffers():
            if buf.network_id != self.network_id or buf.kind != "channel":
                continue
            if fold(nick) not in self.store.member_nicks(buf.id):
                continue
            # One small frame per channel, not the channel's whole list: a
            # 149-person netsplit used to send 149 complete member lists
            # (397 KiB) to every client, phones included.
            self._member_remove(buf.id, nick)
            if ignored:
                continue
            # The host, like every join and part: a quit without it was the one
            # system line that could not say who had actually left.
            await self._emit(buf.id, P.KIND_QUIT, sender=nick, sender_host=msg.prefix.host,
                             text=reason, extra=extra)
        self._update_person(nick, online=False)
        self._ignore_followed.discard(fold(nick, self.casemapping))
        await self._reclaim_now_if_freed(nick)

    async def _h_nick(self, msg: Message) -> None:
        old, new = msg.prefix.nick, msg.param(0)
        mine = self.is_me(old)
        # Read before anything is renamed: the prefix the change arrived with
        # is the one a mask was written against.
        ignored = self._is_ignored(msg.prefix)
        if mine:
            self.conn.nick = new
            self.store.set_network_nick(self.network_id, new)
            self.highlighter.set_nick(new)
            await self.hub.broadcast(P.frame(P.NETWORK, network=self.to_wire()))
        elif ignored:
            # Follow them: a plain nick ignore (nick!*@*) would otherwise let
            # them back in by changing it, which is the first thing a spammer
            # does. A host mask would still match; this covers the rest.
            self._ignore_followed.discard(fold(old, self.casemapping))
            self._ignore_followed.add(fold(new, self.casemapping))
        changed = self.store.rename_member(old, new, self.network_id)
        if not mine:
            self._rename_person(old, new)
        for bid in changed:
            self.hub.publish(P.frame(P.MEMBER_UPDATE, buffer=bid, nick=old, new_nick=new))
            if ignored:
                continue
            await self._emit(bid, P.KIND_NICK, sender=old, sender_host=msg.prefix.host,
                             text=new, extra={"new_nick": new})
        if not mine:
            await self._rename_query(old, new, msg.prefix.host, record=not ignored)
            if fold(new, self.casemapping) != fold(old, self.casemapping):
                # A case change (quinn -> QUINN) frees nothing.
                await self._reclaim_now_if_freed(old)

    def _rename_person(self, old: str, new: str) -> None:
        """Carry what is known about someone over to their new nick."""
        old_key, new_key = fold(old, self.casemapping), fold(new, self.casemapping)
        if old_key == new_key:
            return
        if old_key in self._away_people:
            self._away_people.discard(old_key)
            self._away_people.add(new_key)
        if old_key in self._online:
            self._online.pop(old_key)
            self._online[new_key] = True
        # MONITOR follows the new name on the next tick; ISON asks for it anyway.
        self._presence_dirty = True

    async def _rename_query(self, old: str, new: str, host: str, *, record: bool) -> None:
        """The person we have a query with changed nick: the query goes with them.

        Renamed, if nobody else's buffer has the new name. If there is already
        a query under the new nick (you had talked to "dave_" before), the two
        are merged into that one: its history gains every line of the old one,
        in order, and the old buffer is gone (`buffer_removed`). Either way the
        conversation gets a `nick` line saying so. It used to split in two: the
        old query kept the past with no word of what happened, and a new one
        opened for the new nick.
        """
        buf = self.store.find_buffer(self.network_id, old)
        if buf is None or buf.kind != "query":
            return
        removed: int | None = None
        other = self.store.find_buffer(self.network_id, new)
        if other is None or other.id == buf.id:
            # A new name, or the same one in different case.
            self.store.rename_buffer(buf.id, new)
            survivor = buf.id
        elif other.kind == "query":
            self.store.merge_buffers(buf.id, other.id)
            survivor, removed = other.id, buf.id
        else:
            return                       # a channel or the status buffer: leave both
        await self._announce_buffer(survivor)
        if removed is not None:
            await self.hub.broadcast(P.frame(P.BUFFER_REMOVED, buffer=removed))
        if record:
            self._record(survivor, P.KIND_NICK, sender=old, sender_host=host, text=new,
                         extra={"new_nick": new})
        if removed is not None:
            # The survivor's read marker moved (see Store.merge_buffers).
            survivor_buf = self.store.buffer(survivor)
            await self.hub.broadcast(P.frame(P.READ_MARKER, buffer=survivor,
                                             eid=survivor_buf.last_seen_eid))
            await self.hub.broadcast(P.frame(P.UNREAD, counts=self.store.unread_counts()))

    async def _h_topic(self, msg: Message) -> None:
        channel, topic = msg.param(0), msg.param(1)
        buf = self._buffer_for(channel, "channel", unarchive=False)
        self.store.set_topic(buf.id, topic, msg.prefix.nick, time.time())
        await self._emit(buf.id, P.KIND_TOPIC, sender=msg.prefix.nick, text=topic)
        await self.hub.broadcast(
            P.frame(P.BUFFER, buffer=self.buffer_to_wire(self.store.buffer(buf.id)))
        )

    # The topic on join arrives as 332 (what it is) then 333 (who set it,
    # when), or 331 when there is none, and all of it before the 366 that ends
    # the names. A changed buffer is announced once, at 333 or at 366 --
    # never at 332 as well. A rejoin used to send the buffer frame twice, once
    # for the JOIN and once for a 332 that changed nothing; now an unchanged
    # topic sends nothing at all.

    # These replies also answer a /quote TOPIC #x or NAMES #x for a channel we
    # are not in, and until 2026-09-26 that made a buffer for it: a channel the
    # client was never told about, and for a bare NAMES one named "*". Only a
    # channel we are in is updated; anything else is shown as a line where the
    # command was typed (see _reply_as_text).

    def _joined_channel(self, name: str) -> Buffer | None:
        buf = self.store.find_buffer(self.network_id, name) if self._is_channel(name) else None
        return buf if buf is not None and buf.kind == "channel" and buf.joined else None

    def _reply_as_text(self, command: str, numeric: str, text: str) -> None:
        """A reply about something we hold no buffer for, as a line in the
        conversation the command came from (/quote notes it), else the status
        buffer. Never a new buffer."""
        target = None
        entry = self._recent_requests.get(command)
        if entry is not None and time.monotonic() - entry[1] <= REQUEST_MEMORY:
            buf = self.store.buffer(entry[0])
            if buf is not None and buf.network_id == self.network_id and not buf.archived:
                target = buf
        self._record((target or self.status_buffer).id, P.KIND_SERVER, text=text,
                     extra={"numeric": numeric})

    async def _h_332(self, msg: Message) -> None:      # RPL_TOPIC, on join
        channel, topic = msg.param(1), msg.param(2)
        buf = self._joined_channel(channel)
        if buf is None:
            self._reply_as_text("TOPIC", msg.command, f"{channel}: {topic}")
            return
        if topic != buf.topic:
            # A different topic: who set it and when are unknown until 333.
            self.store.set_topic(buf.id, topic)
            self._topic_dirty.add(buf.id)

    async def _h_331(self, msg: Message) -> None:      # RPL_NOTOPIC
        buf = self._joined_channel(msg.param(1))
        if buf is None:
            self._reply_as_text("TOPIC", msg.command,
                                f"{msg.param(1)}: {msg.param(2) or 'No topic is set'}")
            return
        if buf.topic is not None:
            self.store.set_topic(buf.id, None)
            self._topic_dirty.add(buf.id)

    async def _h_333(self, msg: Message) -> None:      # RPL_TOPICWHOTIME
        # Some servers send the full nick!user@host, some the nick alone.
        by = msg.param(2).split("!", 1)[0] or None
        at = float(msg.param(3)) if msg.param(3).isdigit() else None
        buf = self._joined_channel(msg.param(1))
        if buf is None:
            when = (time.strftime(" on %Y-%m-%d %H:%M UTC", time.gmtime(at))
                    if at is not None else "")
            if by:
                self._reply_as_text("TOPIC", msg.command,
                                    f"{msg.param(1)}: topic set by {by}{when}")
            return
        if (by, at) != (buf.topic_by, buf.topic_at):
            self.store.set_topic_meta(buf.id, by, at)
            self._topic_dirty.add(buf.id)
        await self._flush_topic(buf.id)

    async def _flush_topic(self, buffer_id: int) -> None:
        if buffer_id in self._topic_dirty:
            self._topic_dirty.discard(buffer_id)
            await self._announce_buffer(buffer_id)

    async def _h_mode(self, msg: Message) -> None:
        target = msg.param(0)
        if not self._is_channel(target):
            return
        buf = self._buffer_for(target, "channel", unarchive=False)
        # Prefix changes are applied here, from PREFIX, and sent as one
        # member_update each -- the way ZNC, soju and IRCCloud do it. This used
        # to ask the server for NAMES after every MODE line and send the whole
        # list when it came back: a Q auto-op burst after a netjoin was sixty
        # NAMES in the flood queue (Riley's own line refused for half a minute)
        # and sixty complete member lists to every client.
        unsure = False
        modes_changed = False
        if buf.joined:
            changes = parse_mode_changes(msg.param(1), msg.params[2:],
                                         "".join(self.prefix_map.values()), self.chanmodes)
            for sign, mode, nick in changes:
                if nick is not None and mode in self.prefix_map.values():
                    unsure |= not self._apply_prefix_mode(buf.id, sign, mode, nick)
            modes_changed = self._apply_channel_modes(buf.id, changes)
        await self._emit(
            buf.id, P.KIND_MODE, sender=msg.prefix.nick or msg.prefix.raw,
            text=" ".join(msg.params[1:]),
        )
        if modes_changed:
            # After the mode line, like a topic change: the event says who did
            # it, the buffer frame what the channel is now.
            await self._announce_buffer(buf.id)
        if unsure:
            self._queue_names(target)

    # --- channel modes (G70) -------------------------------------------------

    def _apply_channel_modes(self, buffer_id: int, changes) -> bool:
        """Fold a MODE line's channel settings (+n, +t, +k key, -l...) into the
        buffer's modes. Returns True if they changed.

        Prefix modes (+o nick) are people, handled above; list modes (+b mask)
        are lists, not settings, and neither appears in "+ntk". Only applied
        once the 324 has said where the channel starts from -- a +t on top of
        not knowing is not "+t".
        """
        current = self._modes.get(buffer_id)
        if current is None:
            return False
        list_modes = self.chanmodes[0]
        people = set(self.prefix_map.values())
        letters = list(current.lstrip("+"))
        for sign, mode, _param in changes:
            if mode in people or mode in list_modes:
                continue
            if sign == "+" and mode not in letters:
                letters.append(mode)
            elif sign == "-" and mode in letters:
                letters.remove(mode)
        new = "+" + "".join(letters) if letters else ""
        if new == current:
            return False
        self._modes[buffer_id] = new
        return True

    async def _h_324(self, msg: Message) -> None:      # RPL_CHANNELMODEIS
        """The answer to the MODE sent after a join: me, #chan, "+ntk", then
        the parameters (a key, a limit), which the buffer frame leaves out --
        a channel key is a password, and it would be on every screen."""
        buf = self.store.find_buffer(self.network_id, msg.param(1))
        if buf is None or buf.kind != "channel":
            return
        letters = "".join(ch for ch in msg.param(2) if ch not in "+-")
        modes = "+" + letters if letters else ""
        if self._modes.get(buf.id) != modes:
            self._modes[buf.id] = modes
            await self._announce_buffer(buf.id)

    async def _h_329(self, msg: Message) -> None:      # RPL_CREATIONTIME
        pass                                           # when the channel was made; unused

    # --- member deltas -----------------------------------------------------
    #
    # A full `members` frame goes out after NAMES (366), on attach, when we
    # leave a channel, and whenever the bouncer cannot be sure of a change.
    # Everything else is one of these three small frames. The store is kept up
    # to date either way; the frames only say what changed in it.

    def _member_add(self, buffer_id: int, nick: str, prefix: str) -> None:
        away = fold(nick, self.casemapping) in self._away_people
        self.hub.publish(P.frame(P.MEMBER_ADD, buffer=buffer_id,
                                 member={"nick": nick, "prefix": prefix, "away": away}))

    def _member_remove(self, buffer_id: int, nick: str) -> None:
        stored = self.store.member(buffer_id, nick)
        self.store.remove_member(buffer_id, nick)
        # The stored spelling, which is what the client's list holds.
        self.hub.publish(P.frame(P.MEMBER_REMOVE, buffer=buffer_id,
                                 nick=stored["nick"] if stored else nick))

    def _prefix_rank(self, symbol: str) -> int:
        """0 for the highest prefix (@ on most networks), larger for lower ones,
        and past the end for no prefix at all. PREFIX lists them in order."""
        order = list(self.prefix_map)
        return order.index(symbol) if symbol in order else len(order)

    def _apply_prefix_mode(self, buffer_id: int, sign: str, mode: str, nick: str) -> bool:
        """Apply one +o/-v style change to the stored member and tell the
        clients. Returns False when the result is a guess NAMES should settle.

        Only the highest prefix is kept, which is what NAMES reports without
        multi-prefix. Giving a prefix is therefore always certain: the new one
        shows if it outranks what is there. Taking away the one that shows is
        not: someone deopped may still be voiced, and nothing here knows. That
        case shows no prefix for now and asks the server.
        """
        member = self.store.member(buffer_id, nick)
        if member is None:
            return False                     # someone we have no record of
        symbol = next(s for s, m in self.prefix_map.items() if m == mode)
        current = member["prefix"]
        certain = True
        if sign == "+":
            new = symbol if self._prefix_rank(symbol) < self._prefix_rank(current) else current
        elif current == symbol:
            new, certain = "", False
        else:
            new = current                    # it was not the one showing
        if new != current:
            self.store.set_member_prefix(buffer_id, nick, new)
            self.hub.publish(P.frame(P.MEMBER_UPDATE, buffer=buffer_id,
                                     nick=member["nick"], prefix=new))
        return certain

    def _queue_names(self, channel: str) -> None:
        """Ask for NAMES, unless one for this channel is already waiting.

        One NAMES per channel waiting, not one per MODE line. At one line every
        two seconds a burst of sixty used to queue two minutes of NAMES in
        front of anything the user typed. A NAMES still waiting will be
        answered after every mode seen so far, so a second one would only
        repeat it; once it has been written, the next queues afresh.

        It waits NAMES_SETTLE before joining the send queue at all, so a
        burst of deops that arrives over a second or two -- which is how a
        server delivers one -- is one NAMES and one full list rather than one
        per read that happened to find the send queue empty.
        """
        key = fold(channel, self.casemapping)
        if not self.conn.registered or key in self._names_queued:
            return
        self._names_queued.add(key)

        def send() -> None:
            if not self.conn.registered:
                self._names_queued.discard(key)
                return
            self.conn.send_command(
                "NAMES", channel,
                on_sent=lambda: self._names_queued.discard(key),
                on_dropped=lambda _reason: self._names_queued.discard(key),
            )

        if self.names_settle > 0:
            asyncio.get_running_loop().call_later(self.names_settle, send)
        else:
            send()

    async def _h_353(self, msg: Message) -> None:      # RPL_NAMREPLY
        channel = msg.param(2)
        names = msg.param(3).split()
        acc = self._names_accum.setdefault(fold(channel), [])
        # The spelling to show it by, if it turns out not to be ours; see _h_366.
        self._names_shown[fold(channel)] = channel
        for entry in names:
            prefix = ""
            while entry and entry[0] in self.prefix_map:
                # Only the highest prefix is kept for display; the full set would
                # need a mode model the client does not have a use for yet.
                prefix = prefix or entry[0]
                entry = entry[1:]
            # With userhost-in-names each entry is nick!user@host.
            entry = entry.split("!", 1)[0]
            if entry:
                acc.append((entry, prefix))

    async def _h_366(self, msg: Message) -> None:      # RPL_ENDOFNAMES
        channel = msg.param(1)
        if channel == "*" or not self._is_channel(channel):
            # The end of a bare NAMES: one 366 for every 353 before it, one per
            # channel on the network plus "*" for people in none. Each list is
            # finished here, or it would sit in the accumulator and be merged
            # into that channel's next real join.
            for key in list(self._names_accum):
                await self._end_names(self._names_shown.get(key, key), msg.command)
            return
        await self._end_names(channel, msg.command)

    async def _end_names(self, channel: str, numeric: str) -> None:
        key = fold(channel)
        names = self._names_accum.pop(key, [])
        self._names_shown.pop(key, None)
        buf = self._joined_channel(channel)
        if buf is None:
            # A channel we are not in (or "*"): shown, never made a buffer of.
            if names:
                listed = " ".join(f"{prefix}{nick}" for nick, prefix in names)
                self._reply_as_text("NAMES", numeric, f"{channel}: {listed}")
            return
        self.store.replace_members(buf.id, names)
        await self._broadcast_members(buf.id)
        # A topic from a server that sent no 333.
        await self._flush_topic(buf.id)
        # A channel just joined: who is away there is worth knowing now, not at
        # the next five-minute poll. Queued behind the join burst, like MODE.
        key = fold(channel, self.casemapping)
        if key in self._fresh_joins:
            self._fresh_joins.discard(key)
            self._queue_who(buf)

    async def _broadcast_members(self, buffer_id: int) -> None:
        await self.hub.broadcast(
            P.frame(P.MEMBERS, buffer=buffer_id, members=self.members_to_wire(buffer_id))
        )
