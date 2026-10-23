"""The downstream gateway: one aiohttp server carrying both the websocket and
the small amount of HTTP the clients need.

One server rather than two because everything here shares the same auth and the
same process, and because the eventual nginx config on the VPS is then one
proxy_pass block instead of two. See docs/ARCHITECTURE.md, "Deployment".

Auth happens at the websocket handshake, before any frame is processed. A
connection that has not presented a valid token is closed rather than left open
in an unauthenticated state -- there is no "anonymous but connected" state to
reason about, which is one fewer way to get this wrong. And it keeps happening
after that: a token revoked while its socket is open closes that socket (see
_token_sweep), because a lost phone's connection outlives the moment it was
opened.
"""

from __future__ import annotations

import asyncio
import base64
import collections
import gzip
import hashlib
import hmac
import ipaddress
import json
import logging
import re
import secrets
import string
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import time
from pathlib import Path

from aiohttp import WSCloseCode, WSMsgType, web

from . import protocol as P
from . import APP_NAME
from .config import Config
from . import firstrun
from .store import PUSH_SOUNDS
from .hub import Hub
from .ircproto import strip_formatting
from .netfields import network_fields
from .netguard import check_host_public, check_push_endpoint, check_url
from .previews import LinkPreviews
from .uploads import NOT_DELETED, NOT_PREPARED, NOT_SET_UP, UploadConfig, Uploader
from .store import NOTIFY_LEVELS, Store

log = logging.getLogger("relay.gateway")

# Failed authentications tolerated from one address before it is refused.
AUTH_MAX_FAILURES = 10
AUTH_WINDOW = 60.0
# Addresses remembered at once; the one that failed longest ago goes first.
# An IPv6 address counts by its /64, which is what one customer is given.
AUTH_TRACKED_MAX = 4096
# Failures from everyone together in one window. Past it every attempt that
# does not bring a valid token is refused until the window moves on -- a
# valid token never reaches the throttle, so this cannot lock Riley out.
AUTH_GLOBAL_MAX = 600

# How often expired uploads are looked for.
UPLOAD_SWEEP_INTERVAL = 60.0
# How often a timed mute (a `detach` with `until`) is checked for its end, and
# the furthest ahead one may be set.
MUTE_SWEEP_INTERVAL = 15.0
MAX_TIMED_MUTE = 366 * 86400

# A client can create networks; without a ceiling that is unbounded resource
# growth -- each one is a real outbound TCP connection and a set of tables.
MAX_NETWORKS = 16

# The websocket subprotocol. A client offers this plus, if it is a browser, a
# second entry carrying its token; the server selects and echoes this one.
WS_PROTOCOL = "geeyem.v1"
WS_TOKEN_PREFIX = "geeyem.token."

# An APNs device token is hex and 64 characters today. The limit is generous
# rather than exact, because Apple has lengthened it before; what matters is
# that it is bounded and that nothing but hex reaches the database.
MAX_DEVICE_TOKEN = 200
PLATFORMS = {"ios", "macos"}
ENVIRONMENTS = {"sandbox", "production"}

# Each client's outbound queue, in bytes of JSON. Frames are ASCII (json.dumps
# escapes the rest), so characters and bytes are the same count.
#
# Past CLIENT_QUEUE_MAX the client is closed and told to reconnect: it has
# fallen so far behind that catching up means replaying megabytes it will then
# have to render, and reconnecting gets it the same state in one burst. It is
# sized to hold a whole initial burst (every buffer's backlog) with room to
# spare, because that burst is queued in one go.
#
# CLIENT_QUEUE_SOFT is where the client's OWN requests start waiting for its
# queue to drain. Replies to what a client asked for -- backlog pages, search
# results -- apply backpressure to that client's own read loop, and nothing
# else. Broadcasts never wait, at any size; they are what the IRC loop sends.
CLIENT_QUEUE_MAX = 8 * 1024 * 1024
CLIENT_QUEUE_SOFT = 1024 * 1024

# One frame write that has not finished in this long means the client is not
# reading. A phone on a bad cell link stalls for seconds, not this long, and a
# suspended app or a sleeping laptop never finishes at all.
CLIENT_SEND_TIMEOUT = 20.0

# How long a close handshake is given before the socket is simply dropped. A
# client that is not reading will never read the close frame either.
CLIENT_CLOSE_GRACE = 2.0

# How often attached clients' tokens are rechecked. The CLI revokes a token in
# another process, so the bouncer cannot be told; it has to look. Every frame a
# client sends is checked too, so this only matters for sockets that are
# listening without talking -- which, for a lost phone, is all of them.
TOKEN_RECHECK_INTERVAL = 15.0

# A reattaching client that says which eid it already holds (`?since=`) gets
# every buffer's events after it instead of the newest `initial_backlog`, up to
# this many per buffer. Past it the client keeps a hole just after what it held
# and pages into it; 500 is the backlog page cap too, so one request fills it.
RESUME_MAX_PER_BUFFER = 500

# Highlight words are matched against every line on every network, so the
# list is bounded; nobody needs a hundred.
MAX_HIGHLIGHT_WORDS = 50
MAX_HIGHLIGHT_WORD = 64
# Nick colors: a hue per nick key, shared by every device. The key is the
# client's own folded form of a nick, so it is as short as a nick.
MAX_NICK_COLORS = 1000
MAX_NICK_COLOR_KEY = 64
NICK_PALETTE_ID = re.compile(r"[a-z0-9-]{1,24}")

# The close codes this gateway uses on its own initiative, and what each tells
# the client. See docs/PROTOCOL.md, "Closes".
CLOSE_REVOKED = WSCloseCode.POLICY_VIOLATION        # 1008: the token is no longer valid
CLOSE_FELL_BEHIND = WSCloseCode.INTERNAL_ERROR      # 1011: reconnect and resync

# An `export` link: single use, and gone after this long whether used or not.
# The link is the credential -- a download started from an <a href> cannot
# carry the token -- so it is 256 random bits, lives five minutes and works once.
EXPORT_TTL = 300.0
MAX_EXPORTS = 32
# Events read per database page while an export streams out.
EXPORT_PAGE = 1000

# A Web Push subscription as a browser hands it over. The endpoint is a URL at
# the browser's push service; p256dh is an uncompressed P-256 point (65 bytes)
# and auth a 16-byte secret, both base64url.
MAX_WEBPUSH_ENDPOINT = 2048
MAX_WEBPUSH_PER_TOKEN = 10

# Link previews one client may have waiting at once. Each waits for one of the
# fetcher's four slots, and nothing used to bound how many waited: 5000 frames
# at a slow site were 5000 tasks parked in memory. A screen of backlog where
# every line is a link is fifty; a client asking for more than this at once
# is in a loop.
MAX_PREVIEWS_PER_CLIENT = 100

# A pairing code: what a signed-in device shows (as a QR code, a link, or
# eight characters to type) and a new device hands to POST /pair for a token
# of its own. Single use, and gone after PAIR_TTL whether used or not, like an
# export link -- but short enough to read aloud, which an export link is not,
# so what protects it is different: it lives five minutes, at most
# MAX_PAIRINGS exist at once, and every wrong guess counts against the same
# per-address throttle as a wrong token (see handle_pair). 31 symbols to the
# eighth is 8.5e11 codes; at the throttle's ceiling for everyone together
# (AUTH_GLOBAL_MAX a minute) a code's whole life is 3000 guesses.
PAIR_TTL = 300.0
MAX_PAIRINGS = 5
PAIR_CODE_LENGTH = 8
# No 0 or O, no 1, I or L: nothing that reads as something else off a screen
# or over the phone. Upper case only; what is typed is upper-cased first.
PAIR_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
# A token's label is what the Devices list calls it ("Riley's iPhone").
MAX_LABEL = 64
# The body of a POST /pair is a code and a label. Anything longer is not one.
MAX_PAIR_BODY = 4096

# A `say` nonce: the client's own name for one send (see session.queue_say).
# Short and plain, because it is stored with every event of that send for good.
_NONCE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


@dataclass
class ExportTicket:
    buffer_id: int
    fmt: str
    tz: Any
    created: float
    session: Any


@dataclass
class PairTicket:
    code: str
    label: str
    host: str             # where the pairing client reached this bouncer
    token_id: int         # the token that asked; the code dies with it
    created: float


def clean_nonce(value: Any) -> str | None:
    """A `say` frame's nonce, or None when it is absent or not one. A bad
    nonce is ignored, not refused: the line still goes, and a client that sent
    one it will not recognise has only lost its own bookkeeping."""
    return value if isinstance(value, str) and _NONCE.match(value) else None


def clean_label(value: Any) -> str | None:
    """A device's name: 1 to MAX_LABEL printable characters once trimmed, or
    None when it is not that."""
    if not isinstance(value, str):
        return None
    label = " ".join(value.split())
    if not label or len(label) > MAX_LABEL or not label.isprintable():
        return None
    return label


def clean_pair_code(value: Any) -> str:
    """A code as someone typed it, in the form codes are kept in: upper case,
    without the spaces or dashes a person puts in to keep their place. ""
    when it could not be one, which matches nothing."""
    if not isinstance(value, str) or len(value) > 4 * PAIR_CODE_LENGTH:
        return ""
    code = "".join(ch for ch in value.upper() if ch not in " -\t")
    return code if len(code) == PAIR_CODE_LENGTH else ""


def _export_line(event, tz) -> str:
    """One event as a line of a plain-text log: "[YYYY-MM-DD HH:MM] <nick> text".

    Formatting codes out (a text file cannot show them), and the system lines
    in words, the way a client would show them.
    """
    when = datetime.fromtimestamp(event.ts, tz).strftime("%Y-%m-%d %H:%M")
    who = event.sender or ""
    text = strip_formatting(event.text or "")
    extra = event.extra or {}
    kind = event.kind
    if kind == "message":
        body = f"<{who}> {text}"
    elif kind == "action":
        body = f"* {who} {text}"
    elif kind == "notice":
        body = f"-{who}- {text}" if who else text
    elif kind == "join":
        body = f"--> {who} joined"
    elif kind == "part":
        body = f"<-- {who} left" + (f" ({text})" if text else "")
    elif kind == "quit":
        body = f"<-- {who} quit" + (f" ({text})" if text else "")
    elif kind == "kick":
        body = f"<-- {extra.get('target', '?')} was kicked by {who}" + (f" ({text})" if text else "")
    elif kind == "nick":
        body = f"--- {who} is now known as {text}"
    elif kind == "topic":
        body = f"--- {who} set the topic: {text}"
    elif kind == "mode":
        body = f"--- {who} set mode {text}"
    elif kind == "invite":
        body = f"--- {who} {text}"
    else:
        body = f"--- {text}"
    # A line that went to the channel's ops only ("@#chan") says so.
    if extra.get("statusmsg"):
        body = f"[{extra['statusmsg']}] {body}"
    return f"[{when}] {body}"


def _safe_filename(text: str) -> str:
    """"local-#two-2026-09-22" -> "local-two-2026-09-22", the documented shape.
    A run of anything else, dashes included, is one dash: "-#" used to become
    "--"."""
    cleaned = re.sub(r"[^A-Za-z0-9._]+", "-", text).strip("-.")
    return cleaned[:60] or "log"


class Client:
    """One attached websocket, with its own outbound queue and writer.

    Nothing outside this class writes to the socket. Frames are queued with
    enqueue() (broadcasts: never waits) or send() (this client's own replies:
    waits only when this client is behind), and one writer task drains the
    queue in order. A client that stops reading therefore stops only itself:
    its queue grows until it is closed, and the IRC read loop that produced
    the frames never knows. See the module note in hub.py for the failure this
    replaced.
    """

    _next_id = 0

    def __init__(self, ws: web.WebSocketResponse, token_id: int, hub: Hub,
                 transport: asyncio.BaseTransport | None = None):
        Client._next_id += 1
        self.id = Client._next_id
        self.ws = ws
        self.token_id = token_id
        self.hub = hub
        self.presence: str = "unknown"
        self.focused_buffer: int | None = None
        # When this client last sent a frame; its "foreground" expires past
        # hub.PRESENCE_TTL of silence (see Hub.has_active_viewer).
        self.last_heard: float = time.monotonic()
        self.origin: str | None = None
        # The host this client reached the bouncer through and the scheme a
        # link back to it should carry. What `pair` builds its links from;
        # set at the handshake (see Gateway.handle_ws).
        self.host: str = ""
        self.link_scheme: str = "https"
        # `link_preview` requests of this client's still being answered.
        self.previews_pending = 0
        # The raw TCP transport, so a client that will not read can be dropped
        # without waiting on a close handshake it will never answer.
        self.transport = transport
        self.closing = False
        self._outbox: collections.deque[str] = collections.deque()
        self._outbox_bytes = 0
        self._wake = asyncio.Event()      # set when there is something to write
        self._room = asyncio.Event()      # set when the queue is below SOFT
        self._room.set()
        self._writer_task: asyncio.Task | None = None
        self._close_task: asyncio.Task | None = None
        self._close_started = False
        # True while the writer has a frame out of the queue and not yet on
        # the socket; see close_when_drained.
        self._writing = False
        # Broadcasts held back while the initial burst is being written, in
        # the order they came, or None when nothing is being held. See hold().
        self._held: list[str] | None = None
        self._held_bytes = 0

    def start(self) -> None:
        self._writer_task = asyncio.create_task(self._drain(), name=f"ws-send-{self.id}")

    # --- the initial burst -------------------------------------------------
    #
    # A client is added to the hub BEFORE its burst is built, so that nothing
    # said while the burst is being written is missed. Until 2026-10 that also
    # meant a live frame went straight into the queue, wherever the burst had
    # got to: `send` waits whenever the queue is over CLIENT_QUEUE_SOFT, the
    # IRC loop runs in the gap, and a line said just then reached the client
    # as an `event` for a buffer whose `backlog` had not been sent yet -- and
    # then again inside that backlog, which was read from the store a moment
    # later. So broadcasts are held while the burst is written, and let go
    # after it, in order, without the ones the burst already carried.

    def hold(self) -> None:
        """Start holding broadcasts (enqueue) back. This client's own frames
        (send) still go straight to the queue: they are the burst."""
        self._held, self._held_bytes = [], 0

    def release(self, sent_upto: dict[int, int] | None = None) -> None:
        """The burst is queued: queue what was held, in the order it came.

        `sent_upto` is, per buffer, the newest eid the burst's own backlog
        frame carried. A held `event` at or below it is a line the burst read
        from the store after it was broadcast, and is dropped here rather
        than delivered twice. Everything else that was held says how things
        are rather than what happened (a buffer, a member list, a count, a
        read marker), and is safe to hear again in order.
        """
        held, self._held, self._held_bytes = self._held, None, 0
        for data in held or ():
            if sent_upto and data.startswith('{"type":"event"'):
                try:
                    event = json.loads(data)["event"]
                    if event["eid"] <= sent_upto.get(event["buffer"], 0):
                        continue
                except (ValueError, KeyError, TypeError):
                    pass
            self._queue(data)

    # --- queueing ----------------------------------------------------------

    def enqueue(self, data: str) -> None:
        """Queue an already-serialised frame. Never waits.

        Over the limit, the client is closed rather than the frame dropped: a
        client missing one frame silently is a client whose state is wrong with
        nothing to tell it so, and one that reconnects is right again.

        This is the way in for broadcasts (Hub.publish), so while the initial
        burst is being written the frame is held instead; see hold().
        """
        if self.closing:
            return
        if self._held is not None:
            if self._held_bytes + len(data) > CLIENT_QUEUE_MAX:
                log.warning("client %d fell behind during its initial burst; closing it",
                            self.id)
                self.close_soon(CLOSE_FELL_BEHIND, "fell behind; reconnect to catch up")
                return
            self._held.append(data)
            self._held_bytes += len(data)
            return
        self._queue(data)

    def _queue(self, data: str) -> None:
        if self.closing:
            return
        if self._outbox_bytes + len(data) > CLIENT_QUEUE_MAX:
            log.warning("client %d fell behind (%d bytes queued); closing it",
                        self.id, self._outbox_bytes)
            self.close_soon(CLOSE_FELL_BEHIND, "fell behind; reconnect to catch up")
            return
        self._outbox.append(data)
        self._outbox_bytes += len(data)
        if self._outbox_bytes > CLIENT_QUEUE_SOFT:
            self._room.clear()
        self._wake.set()

    async def send(self, frame: dict[str, Any]) -> None:
        """Queue a reply to this client. Waits while this client is behind."""
        data = P.dumps(frame)
        while self._outbox_bytes > CLIENT_QUEUE_SOFT and not self.closing:
            await self._room.wait()
        self._queue(data)

    async def ok(self, req: str | None, **fields: Any) -> None:
        await self.send(P.frame(P.OK, req=req, **fields))

    async def error(self, req: str | None, message: str) -> None:
        await self.send(P.frame(P.ERROR, req=req, message=message))

    @property
    def queued_bytes(self) -> int:
        return self._outbox_bytes

    # --- writing -----------------------------------------------------------

    async def _drain(self) -> None:
        while not self.closing:
            if not self._outbox:
                self._wake.clear()
                await self._wake.wait()
                continue
            data = self._outbox.popleft()
            self._outbox_bytes -= len(data)
            if self._outbox_bytes <= CLIENT_QUEUE_SOFT:
                self._room.set()
            self._writing = True
            try:
                await asyncio.wait_for(self.ws.send_str(data), CLIENT_SEND_TIMEOUT)
                self._writing = False
            except asyncio.TimeoutError:
                log.warning("client %d stalled: one frame took over %.0fs; closing it",
                            self.id, CLIENT_SEND_TIMEOUT)
                self.close_soon(CLOSE_FELL_BEHIND, "not reading; reconnect to catch up")
                return
            except (ConnectionResetError, RuntimeError, OSError):
                # The socket went away. The read loop will notice and detach;
                # anything still queued is for a connection that no longer exists.
                self._release()
                return
            except Exception:
                log.exception("client %d: send failed", self.id)
                self._release()
                return

    # --- closing -----------------------------------------------------------

    def _release(self) -> None:
        """Stop accepting frames, drop what is queued, wake anyone waiting."""
        self.closing = True
        self._outbox.clear()
        self._outbox_bytes = 0
        self._held, self._held_bytes = None, 0
        self._room.set()
        self._wake.set()
        self.hub.discard(self)

    def close_soon(self, code: int, reason: str) -> None:
        """close(), from somewhere that cannot await (a broadcast, a writer)."""
        if self._close_task is None:
            self._close_task = asyncio.create_task(self.close(code, reason))

    async def close(self, code: int, reason: str) -> None:
        """Close with a code and a reason, or drop the connection trying.

        The close frame is the polite version and works for a client that is
        slow but reading. A client that is not reading at all never sees it,
        and aiohttp would wait for its reply; after CLIENT_CLOSE_GRACE the TCP
        connection is aborted instead, which the read loop sees at once.
        """
        if self._close_started:
            return
        self._close_started = True
        self._release()
        writer = self._writer_task
        if writer is not None and writer is not asyncio.current_task() and not writer.done():
            writer.cancel()
        try:
            await asyncio.wait_for(
                self.ws.close(code=code, message=reason.encode()[:120]), CLIENT_CLOSE_GRACE)
            return
        except Exception:
            pass
        if self.transport is not None:
            try:
                self.transport.abort()
            except Exception:
                pass

    async def close_when_drained(self, code: int, reason: str) -> None:
        """close(), once what is already queued has been written -- for the
        one case where the last frame matters: a client that revoked its own
        token is owed the `ok` before the 1008. close() itself throws the
        queue away, which is right for a client being cut off and wrong for
        one being answered. Bounded by CLIENT_CLOSE_GRACE: a client that is
        not reading is closed anyway."""
        deadline = time.monotonic() + CLIENT_CLOSE_GRACE
        while ((self._outbox or self._writing) and not self.closing
               and time.monotonic() < deadline):
            await asyncio.sleep(0.01)
        await self.close(code, reason)

    async def finish(self) -> None:
        """The handler is done with this client: stop the writer."""
        self._release()
        task = self._writer_task
        if task is not None and not task.done() and task is not asyncio.current_task():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass


def _extract_token(request: web.Request) -> str | None:
    """Accept the token from the Authorization header or the websocket subprotocol.

    The header is the right way and what the Swift client uses. A browser cannot
    set one on a `WebSocket`, but it can name subprotocols, and those travel in
    a handshake header rather than in the URL -- so the credential stays out of
    access logs, browser history and any Referer. A token is `relay_` plus
    URL-safe base64, every character of which is legal in an RFC 6455
    subprotocol name, so nothing has to be encoded.

    The query string is deliberately not read at all. A URL is the one place a
    credential gets copied, bookmarked and logged by things nobody controls.
    """
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    for entry in request.headers.get("Sec-WebSocket-Protocol", "").split(","):
        entry = entry.strip()
        if entry.startswith(WS_TOKEN_PREFIX):
            return entry[len(WS_TOKEN_PREFIX):]
    return None


_SCRIPT_BLOCK = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
_HOST_CHARS = re.compile(r"^[A-Za-z0-9.\-:\[\]]+$")


def inline_script_hashes(html: str) -> list[str]:
    """The base64 SHA-256 of each inline <script> in a page, in order, for a
    Content-Security-Policy script-src. A <script src=…> has nothing inline to
    hash and is skipped.

    The browser hashes the script as its HTML parser read it, not as the file
    has it, so the text gets the parser's two changes first: line endings
    become LF, and a NUL becomes U+FFFD. index.html has literal NULs (a
    separator in the member list's change signature), and hashing the raw
    file blocked that whole script.
    """
    out = []
    for attrs, text in _SCRIPT_BLOCK.findall(html):
        if re.search(r"\bsrc\s*=", attrs, re.IGNORECASE):
            continue
        text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\0", "�")
        digest = base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode()
        if digest not in out:
            out.append(digest)
    return out


def _safe_host(host: str | None) -> str:
    """The request's Host, when it is only a hostname and a port. It goes into
    a response header, so anything else is dropped rather than quoted."""
    host = (host or "").strip()
    return host if host and _HOST_CHARS.match(host) else ""


def _throttle_key(peer: str) -> str:
    """The failed-token throttle's bucket for an address: an IPv4 address as
    it is, an IPv6 one by its /64 -- the block one customer is given, so
    stepping through it is not a fresh start each time."""
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ipaddress.IPv6Network(f"{ip}/64", strict=False))
    return peer


def _etag_matches(request: web.Request, etag: str) -> bool:
    """Does If-None-Match name this ETag (or *)? The weak comparison, which is
    the one If-None-Match uses: W/"x" matches "x"."""
    try:
        sent = request.if_none_match
    except ValueError:
        return False
    if not sent:
        return False
    value = etag.strip('"')
    return any(tag.value in (value, "*") for tag in sent)


def _accepts_gzip(request: web.Request) -> bool:
    """Does Accept-Encoding allow gzip? Named, or covered by "*", and not
    refused with q=0. Every browser and the iOS app say gzip; curl without
    --compressed and a careless monitor do not, and get the page as it is."""
    allowed = False
    for part in request.headers.get("Accept-Encoding", "").split(","):
        name, _, params = part.strip().partition(";")
        name = name.strip().lower()
        if name not in ("gzip", "x-gzip", "*"):
            continue
        quality = 1.0
        for param in params.split(";"):
            key, _, value = param.strip().partition("=")
            if key.strip().lower() == "q":
                try:
                    quality = float(value)
                except ValueError:
                    quality = 0.0
        if quality <= 0:
            # An explicit refusal of gzip wins over a "*" that would allow it.
            if name != "*":
                return False
            continue
        allowed = True
    return allowed


def _loopback_host(host: str) -> bool:
    """Is this Host header a name for this machine: localhost, something
    under .localhost, or a loopback address, with or without a port?"""
    name = host.strip().lower()
    if name.startswith("["):
        name = name[1:].partition("]")[0]
    elif name.count(":") == 1:
        name = name.partition(":")[0]
    if name == "localhost" or name.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def _from_loopback(request: web.Request) -> bool:
    """Did this connection come from this machine -- which, behind the
    Cloudflare Tunnel, means from cloudflared? Only then are the forwarding
    headers it adds believed; from anywhere else they are whatever the caller
    typed."""
    try:
        return ipaddress.ip_address(request.remote or "").is_loopback
    except ValueError:
        return False


# Set from config.json's `trust_proxy` (see _from_proxy).
TRUST_PROXY = web.AppKey("trust_proxy", bool)


def _from_proxy(request: web.Request) -> bool:
    """Is this connection from the proxy in front of the bouncer, whose
    forwarding headers say how the browser arrived? From this machine, always
    (cloudflared, a local nginx). From anywhere, only with `trust_proxy` on:
    on Fly.io, Railway or Render, or in a Docker network, the platform's proxy
    is the only thing that can reach the port, and it does not connect from
    loopback."""
    return _from_loopback(request) or request.app.get(TRUST_PROXY) is True


def _forwarded_scheme(request: web.Request) -> str | None:
    """"https" or "http" for the scheme the browser used to reach the tunnel,
    or None when nobody in front said (a local rig, the iOS app over
    WireGuard). Cloudflare sets both X-Forwarded-Proto and Cf-Visitor on
    every request it proxies, overwriting what the client sent."""
    if not _from_proxy(request):
        return None
    proto = request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower()
    visitor = request.headers.get("Cf-Visitor", "")
    try:
        visitor = str(json.loads(visitor).get("scheme", "")).lower() if visitor else ""
    except (ValueError, AttributeError):
        visitor = ""
    if "https" in (proto, visitor):
        return "https"
    if "http" in (proto, visitor):
        return "http"
    return None


def _public_host(request: web.Request) -> str:
    """The host a link back to this bouncer should name: X-Forwarded-Host
    from the proxy in front (_from_proxy), else Host. Behind cloudflared,
    Host is 127.0.0.1:8770, which is nobody's way in."""
    forwarded = request.headers.get("X-Forwarded-Host") if _from_proxy(request) else None
    return _safe_host((forwarded or "").split(",")[0]) or _safe_host(request.host)


def _link_scheme(request: web.Request, host: str) -> str:
    """"https" for a link back to this bouncer, except on a rig: "http" only
    for plain http from this machine, to a loopback name, with nothing in
    front saying it was https."""
    if (not request.secure and _forwarded_scheme(request) is None
            and _from_loopback(request) and _loopback_host(host)):
        return "http"
    return "https"


# What every response carries, whatever route made it (errors included).
# Permissions-Policy turns off the powerful features the page never uses; it
# does use the clipboard and the share sheet, so those are left alone.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": ("camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
                           "serial=(), hid=(), midi=(), display-capture=(), "
                           "browsing-topics=()"),
}
# For a response that sets no policy of its own (JSON, icons, errors): it runs
# nothing and may not be framed. Not for /sw.js: a service worker's policy
# comes from its own script's headers, and this one would stop it fetching.
DEFAULT_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
# A year. Sent only on a response to a request that came in over https, so a
# local rig on plain http is never told to refuse plain http.
HSTS = "max-age=31536000"


def _origin_host(origin: str) -> str | None:
    """"https://example.com:443" -> "example.com", the port kept only when it
    is not the scheme's own. None when it is not an http(s) origin at all
    (including the "null" a file:// page sends)."""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(origin.strip())
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    default = 443 if parts.scheme == "https" else 80
    return parts.hostname.lower() + (f":{port}" if port and port != default else "")


def _host_key(host: str) -> str:
    """A Host header in the form _origin_host gives: lowercase, without the
    default ports (the scheme is not known here, so 80 and 443 both go)."""
    host = host.strip().lower()
    for default in (":443", ":80"):
        if host.endswith(default):
            return host[: -len(default)]
    return host


def _origin(frame: dict) -> int | None:
    """The optional `buffer` on a frame that is not addressed by buffer (nick,
    join, part, invite, raw): the conversation the command was typed in. Only
    used to put the server's refusal, if one comes, where it was asked."""
    value = frame.get("buffer")
    return int(value) if value is not None else None


def _parse_since(request: web.Request) -> int | None:
    """`?since=<eid>` on the socket URL, or None when absent or not a number.

    The query string is not read for anything else (see _extract_token): an
    eid is a cursor, not a credential, and a URL is a fine place for one.
    """
    raw = request.query.get("since")
    if raw is None:
        return None
    try:
        since = int(raw)
    except ValueError:
        return None
    return since if since >= 0 else None


class Gateway:
    def __init__(self, config: Config, store: Store, hub: Hub):
        self.config = config
        self.store = store
        self.hub = hub
        # client_max_size bounds a request BODY, and the only route that reads
        # one is POST /pair, whose body is a code and a name. aiohttp's
        # megabyte default was a megabyte anyone could make the bouncer read
        # without a token. (Websocket frames have their own limit, in
        # handle_ws.)
        self.app = web.Application(middlewares=[self._https_only],
                                   client_max_size=MAX_PAIR_BODY)
        self.app[TRUST_PROXY] = bool(config.trust_proxy)
        self.app.on_response_prepare.append(self._security_headers)
        self.app.router.add_get("/health", self.handle_health)
        self.app.router.add_get("/ws", self.handle_ws)
        # Where a new device trades a pairing code for a token of its own.
        # The one route that takes a POST, and the one that hands out a
        # credential; see handle_pair.
        self.app.router.add_post("/pair", self.handle_pair)
        # First run: the page that mints the first token, open only while
        # there is none (see open_setup and relay/firstrun.py).
        self.app.router.add_get("/setup", self.handle_setup_page)
        self.app.router.add_post("/setup", self.handle_setup)
        # A link card's picture, fetched by the bouncer so the phone never
        # contacts the site (see relay/previews.py), and a one-time log
        # download. Both are addressed by an unguessable path rather than the
        # token, because an <img> and an <a download> cannot send a header.
        self.app.router.add_get("/p/{mac}/{digest}", self.handle_preview_image)
        self.app.router.add_get("/export/{ticket}", self.handle_export, allow_head=False)
        # The web client, served by the bouncer itself, so the same hostname is
        # both the API and the app -- open https://your-bouncer/ in a browser
        # and you are there. Anything else means telling people to run a second
        # web server for one static file.
        # The repo has bouncer/relay/ with web/ two levels up; a deployment has
        # geyem/relay/ with web/ one level up. Look in both rather than assuming
        # the layout, which is how this silently 404'd the first time.
        here = Path(__file__).resolve().parent
        candidates = [here.parent.parent / "web", here.parent / "web"]
        self._web_root = next((c for c in candidates if (c / "index.html").exists()),
                              candidates[0])
        if (self._web_root / "index.html").exists():
            self.app.router.add_get("/", self.handle_web)
            # Installable: a manifest and the two icons it names. An IRC client
            # people keep open all day belongs in a dock or on a home screen,
            # and without these it is a browser tab with a grey square.
            #
            # Named routes rather than a static directory: the only files under
            # web/ that should be reachable are the ones listed here, and an
            # allow-list cannot be walked out of the way a path can.
            self.app.router.add_get("/manifest.webmanifest", self.handle_manifest)
            for name in self.WEB_ASSETS:
                self.app.router.add_get("/" + name, self.handle_asset)
            # The service worker: Web Push and the offline shell. Its own
            # handler for the header that lets it control the whole origin.
            self.app.router.add_get("/sw.js", self.handle_service_worker)
            log.info("serving the web client from %s", self._web_root)
        else:
            log.info("no web/ directory alongside the bouncer; / will 404")
        self._runner: web.AppRunner | None = None
        # index.html as served, its script hashes, its ETag and its gzipped
        # bytes, keyed by the file's mtime and size.
        self._index_cache: tuple[tuple, str, str, str, bytes] | None = None
        # A web asset's content hash, by name, keyed by the file's mtime and size.
        self._asset_versions: dict[str, tuple[tuple[int, int], str]] = {}
        # Failed-token times by address (see _record_failure), oldest address
        # first, and the newest AUTH_GLOBAL_MAX failures from everyone.
        self._auth_failures: collections.OrderedDict[str, collections.deque] = \
            collections.OrderedDict()
        self._all_failures: collections.deque[float] = collections.deque(maxlen=AUTH_GLOBAL_MAX)
        self._sweep_task: asyncio.Task | None = None
        self._upload_sweep_task: asyncio.Task | None = None
        self._mute_sweep_task: asyncio.Task | None = None
        # Keys whose timed delete has failed, so a refusal is logged once and
        # not every minute for ever.
        self._upload_sweep_failed: set[str] = set()
        # Replies answered later than their request (a channel list), held so
        # they are not garbage collected before they are sent.
        self._reply_tasks: set[asyncio.Task] = set()
        self.token_recheck_interval = TOKEN_RECHECK_INTERVAL
        upload_config = UploadConfig.from_env()
        self.uploader = Uploader(upload_config) if upload_config else None
        if self.uploader:
            log.info("uploads enabled -> %s", upload_config.public_base)
        self.previews = (LinkPreviews(store, allow_private_hosts=config.allow_private_hosts)
                         if config.link_previews else None)
        # Outstanding `export` links, by their random path part.
        self._exports: dict[str, ExportTicket] = {}
        # Outstanding pairing codes, oldest first. In memory like the export
        # links, and for the same reason: a code that lives five minutes has
        # no business outliving a restart, and nothing is lost when it does
        # not -- the person asks for another.
        self._pairings: collections.OrderedDict[str, PairTicket] = collections.OrderedDict()
        # The first-run setup, while this bouncer has no token (open_setup).
        self.setup: firstrun.FirstRun | None = None

    def open_setup(self) -> bool:
        """Serve /setup if no device can sign in yet, and print its code.
        Called once at startup (app.py); does nothing when a token exists."""
        if self.setup is not None or self.store.active_token_ids():
            return False
        self.setup = firstrun.FirstRun(self.store)
        self.setup.announce(force=True)
        return True

    async def start(self) -> None:
        # shutdown_timeout is the second half of the fix in stop(): even with
        # every client closed by hand, one socket that will not finish must not
        # be able to hold the process past systemd's patience.
        self._runner = web.AppRunner(self.app, access_log=None, shutdown_timeout=3)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.config.listen_host, self.config.listen_port)
        await site.start()
        self._sweep_task = asyncio.create_task(self._token_sweep(), name="token-sweep")
        self._mute_sweep_task = asyncio.create_task(self._mute_sweep(), name="mute-sweep")
        if self.uploader is not None:
            self._upload_sweep_task = asyncio.create_task(
                self._upload_sweep(), name="upload-sweep")
        log.info("gateway listening on %s:%d", self.config.listen_host, self.config.listen_port)

    async def stop(self) -> None:
        """Close the attached clients first, then the server.

        aiohttp's runner cleanup waits for attached websockets to finish, and a
        phone with a suspended socket never does: a deploy's stop hung for the
        full 15 seconds and was SIGKILLed, so the QUIT upstream never went out
        and the channel saw a ping timeout instead. Closing each socket with a
        real 1001 means every client knows to reconnect and the runner has
        nothing left to wait on -- and one that will not even take the close
        frame is dropped after CLIENT_CLOSE_GRACE rather than waited on.
        """
        if self._sweep_task is not None:
            self._sweep_task.cancel()
        if self._upload_sweep_task is not None:
            self._upload_sweep_task.cancel()
        if self._mute_sweep_task is not None:
            self._mute_sweep_task.cancel()
        clients = list(self.hub.clients)
        if clients:
            log.info("closing %d attached client(s)", len(clients))
            await asyncio.gather(
                *(c.close(WSCloseCode.GOING_AWAY, "server restarting") for c in clients),
                return_exceptions=True,
            )
        if self._runner:
            await self._runner.cleanup()
        if self.previews is not None:
            await self.previews.close()

    async def _token_sweep(self) -> None:
        """Close every socket whose token has been revoked since it attached.

        `python -m relay token revoke` runs in another process and only writes
        the database, so this is how the bouncer finds out. It used to check
        the token at the handshake and never again: a revoked phone kept its
        socket, kept reading backlog and could still speak as you.
        """
        while True:
            await asyncio.sleep(self.token_recheck_interval)
            try:
                await self.close_revoked_clients()
            except Exception:
                log.exception("token recheck failed")

    async def _mute_sweep(self) -> None:
        """Lift the mutes whose time has come (the `until` of a `detach`)."""
        while True:
            try:
                await self.lift_expired_mutes()
            except Exception:
                log.exception("mute sweep failed")
            await asyncio.sleep(MUTE_SWEEP_INTERVAL)

    async def lift_expired_mutes(self, now: float | None = None) -> int:
        """Unmute every buffer whose timed mute has ended, as if the person had
        done it: the `buffer` frame, then fresh unread counts. Returns how many."""
        lifted = 0
        for buffer_id in self.store.expired_mutes(time.time() if now is None else now):
            session = self._session_for_buffer(buffer_id)
            if session is None:
                self.store.set_detached(buffer_id, False)
                continue
            await session.set_detached(buffer_id, False)
            lifted += 1
        if lifted:
            await self.hub.broadcast(P.frame(P.UNREAD, counts=self.store.unread_counts()))
        return lifted

    async def _upload_sweep(self) -> None:
        """Delete the files whose time has come (the `ttl` of an upload_url).

        Once a minute, a few at a time, each in a thread like a delete by
        hand. A file that cannot be deleted is retried on the next pass and
        logged once; one that is already gone counts as done.
        """
        while True:
            await asyncio.sleep(UPLOAD_SWEEP_INTERVAL)
            try:
                await self.sweep_uploads()
            except Exception:
                log.exception("upload sweep failed")

    async def sweep_uploads(self) -> int:
        uploader = self.uploader
        if uploader is None or not uploader.available:
            return 0
        done = 0
        for row in self.store.due_uploads(time.time()):
            key = row["key"]
            try:
                await asyncio.to_thread(
                    uploader.delete, f"{uploader.config.public_base}/{key}")
            except Exception as exc:
                if key not in self._upload_sweep_failed:
                    self._upload_sweep_failed.add(key)
                    log.warning("could not delete an expired upload (%s): %s",
                                key[:7], exc)
                continue
            self._upload_sweep_failed.discard(key)
            self.store.mark_upload_deleted(key, time.time())
            done += 1
        if done:
            log.info("deleted %d expired upload(s)", done)
        return done

    async def close_revoked_clients(self) -> int:
        if not self.hub.clients:
            return 0
        active = self.store.active_token_ids()
        revoked = [c for c in list(self.hub.clients) if c.token_id not in active]
        for client in revoked:
            await self._close_revoked(client)
        return len(revoked)

    async def _close_revoked(self, client: "Client") -> None:
        log.warning("client %d: its token was revoked; closing it", client.id)
        # The CLI deletes these as it revokes; this covers a token revoked some
        # other way (an older CLI, a hand-edited row).
        self.store.forget_devices_for_token(client.token_id)
        await client.close(CLOSE_REVOKED, "token revoked")

    # --- HTTP --------------------------------------------------------------

    @web.middleware
    async def _https_only(self, request: web.Request, handler):
        """A page fetched over plain http through the tunnel is sent to https.

        The page is where the token is typed, and a plain-http copy of it is
        one anyone on the path could rewrite to send the token somewhere
        else. Only GETs and HEADs are moved (a redirect is a navigation); the
        socket and /health are left as they are, because neither is a page
        and a client that dials them over http would not follow a redirect
        anyway. They are refused instead, when they carry a token (see
        _plain_http_refused). Nothing moves on a local rig, where nobody in
        front says how the browser arrived.
        """
        if (request.method in ("GET", "HEAD") and request.path not in ("/ws", "/health")
                and _forwarded_scheme(request) == "http"):
            host = _safe_host(request.host)
            if host:
                raise web.HTTPPermanentRedirect(f"https://{host}{request.path_qs}")
        return await handler(request)

    async def _security_headers(self, request: web.Request,
                                response: web.StreamResponse) -> None:
        """The headers every response gets, errors included. A route that
        sets its own (the page's CSP, an icon's Cache-Control) keeps it."""
        if isinstance(response, web.WebSocketResponse):
            return
        headers = response.headers
        for name, value in SECURITY_HEADERS.items():
            headers.setdefault(name, value)
        if request.path != "/sw.js":
            headers.setdefault("Content-Security-Policy", DEFAULT_CSP)
        # Nothing is cacheable unless its route says so: /health with a token
        # is private, and an error page is not worth keeping.
        headers.setdefault("Cache-Control", "no-store")
        if _forwarded_scheme(request) == "https":
            headers.setdefault("Strict-Transport-Security", HSTS)

    # Everything under web/ that the page is allowed to ask for, and the type
    # each one is served as. Anything not in here does not exist.
    WEB_ASSETS = {
        "icon-192.png": "image/png",
        "icon-512.png": "image/png",
        # Drawn with its own safe zone, so Android and the home screen can crop
        # it to their shape without cutting into the mark ("maskable").
        "icon-maskable-512.png": "image/png",
        # The one reading face the page carries itself; the others it offers
        # are on the device already. Also the face the app icon is set in.
        "newsreader.woff2": "font/woff2",
    }

    def asset_version(self, name: str) -> str:
        """A short hash of a web asset's bytes, for its URL: `icon-192.png?v=<this>`.

        The icons used to be served under one address forever with a day of
        public caching, so a new icon did not reach anyone whose browser, service
        worker or Cloudflare edge had the old one: on 2026-09-23 the new icon was
        live on two hostnames and the old one was still being served from the
        edge on a third, 15 hours after the deploy. With the content in the
        address, a new icon is a new URL no cache has seen. "" if the file is
        missing, and then the plain name is used."""
        path = self._web_root / name
        try:
            stat = path.stat()
        except OSError:
            return ""
        key = (stat.st_mtime_ns, stat.st_size)
        cached = self._asset_versions.get(name)
        if cached and cached[0] == key:
            return cached[1]
        version = hashlib.sha256(path.read_bytes()).hexdigest()[:12]
        self._asset_versions[name] = (key, version)
        return version

    def _versioned(self, name: str) -> str:
        version = self.asset_version(name)
        return f"{name}?v={version}" if version else name

    async def handle_manifest(self, request: web.Request) -> web.Response:
        """The web app manifest.

        Generated rather than a file, so the name and the colours are written
        once -- here -- instead of once here and once in a JSON file that would
        drift from it.

        `start_url` is "." so an install picks up whatever host it was installed
        from: this bouncer is reached through a tunnel with two hostnames, and a
        manifest that hardcoded one of them would install an app pointing at the
        other one.
        """
        return web.json_response(
            {
                "name": "geeyem",
                "short_name": "geeyem",
                "description": "IRC, kept connected.",
                "start_url": ".",
                "scope": ".",
                "display": "standalone",
                "background_color": "#0e0f13",
                "theme_color": "#0e0f13",
                "icons": [
                    {"src": self._versioned("icon-192.png"), "sizes": "192x192",
                     "type": "image/png", "purpose": "any"},
                    {"src": self._versioned("icon-512.png"), "sizes": "512x512",
                     "type": "image/png", "purpose": "any"},
                    {"src": self._versioned("icon-maskable-512.png"), "sizes": "512x512",
                     "type": "image/png", "purpose": "maskable"},
                ],
            },
            headers={"Cache-Control": "no-cache"},
            content_type="application/manifest+json",
        )

    async def handle_asset(self, request: web.Request) -> web.Response:
        """One of WEB_ASSETS, by name. Never a path the caller composed."""
        name = request.path.lstrip("/")
        content_type = self.WEB_ASSETS.get(name)
        if content_type is None:
            raise web.HTTPNotFound()
        try:
            body = (self._web_root / name).read_bytes()
        except OSError:
            raise web.HTTPNotFound(text="asset not installed")
        return web.Response(
            body=body,
            content_type=content_type,
            headers={
                "X-Content-Type-Options": "nosniff",
                # Asked for with ?v=<its own hash> (asset_version), it can never
                # change, so it is cached for good. Asked for by its bare name
                # (an old install, the service worker's shell list), it is
                # revalidated every time: that address is the one a day of
                # caching made stale.
                "Cache-Control": ("public, max-age=31536000, immutable"
                                  if request.query.get("v") else "no-cache"),
            },
        )

    async def handle_service_worker(self, request: web.Request) -> web.Response:
        """web/sw.js, the service worker that receives Web Push.

        `Service-Worker-Allowed: /` lets it control the whole origin, and
        no-cache makes the browser check for a new one on every load -- a
        stale service worker is how a PWA keeps running last month's code.
        """
        try:
            body = (self._web_root / "sw.js").read_bytes()
        except OSError:
            raise web.HTTPNotFound(text="service worker not installed")
        return web.Response(
            body=body,
            content_type="application/javascript",
            headers={
                "Service-Worker-Allowed": "/",
                "Cache-Control": "no-cache",
                "X-Content-Type-Options": "nosniff",
            },
        )

    async def handle_preview_image(self, request: web.Request) -> web.Response:
        """A link card's picture: /p/<mac>/<hash>, fetched by the bouncer.

        Anything that is not a picture this bouncer handed out -- a bad MAC,
        an unknown hash, a fetch that failed, bytes that are not PNG, JPEG, GIF
        or WebP -- is the same 404, so the path cannot be used to probe
        anything. What is served is locked down as if it were hostile, since it
        came from a stranger's site and is served from this origin: its type
        from its own first bytes, nosniff, and a CSP that runs nothing.
        """
        if self.previews is None:
            raise web.HTTPNotFound()
        found = await self.previews.image(request.match_info.get("mac", ""),
                                          request.match_info.get("digest", ""))
        if found is None:
            raise web.HTTPNotFound()
        content_type, body = found
        return web.Response(
            body=body,
            content_type=content_type,
            headers={
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'none'; sandbox",
                "Content-Disposition": "inline",
                # Private: the path is the only secret, so no shared cache
                # (a CDN in front) should keep a copy of it.
                "Cache-Control": "private, max-age=86400",
                "Referrer-Policy": "no-referrer",
            },
        )

    async def handle_export(self, request: web.Request) -> web.StreamResponse:
        """A buffer's whole history as a download, from a link `export` made.

        Streamed a page at a time, so a year of a busy channel does not sit in
        memory. The link is spent the moment it is used.
        """
        self._expire_exports()
        ticket = self._exports.pop(request.match_info.get("ticket", ""), None)
        if ticket is None:
            raise web.HTTPNotFound(text="That download link has expired. Ask for a new one.")
        buf = self.store.buffer(ticket.buffer_id)
        if buf is None:
            raise web.HTTPNotFound(text="That conversation no longer exists.")
        stamp = datetime.now(ticket.tz).strftime("%Y-%m-%d")
        name = _safe_filename(f"{ticket.session.config.slug}-{buf.name}-{stamp}")
        response = web.StreamResponse(headers={
            "Content-Type": ("application/json" if ticket.fmt == "json"
                             else "text/plain; charset=utf-8"),
            "Content-Disposition": f'attachment; filename="{name}.{ticket.fmt}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        })
        await response.prepare(request)
        if ticket.fmt == "json":
            head = {"network": ticket.session.config.slug, "buffer": buf.id, "name": buf.name,
                    "kind": buf.kind, "exported_at": time.time()}
            await response.write(json.dumps(head)[:-1].encode() + b',"events":[')
        after, first = 0, True
        while True:
            events = self.store.backlog_after(buf.id, after, limit=EXPORT_PAGE)
            if not events:
                break
            if ticket.fmt == "json":
                chunk = ",".join(P.dumps(e.to_wire()) for e in events)
                await response.write(((b"" if first else b",") + chunk.encode()))
            else:
                chunk = "".join(_export_line(e, ticket.tz) + "\n" for e in events)
                await response.write(chunk.encode("utf-8"))
            first = False
            after = events[-1].eid
            await asyncio.sleep(0)       # let the IRC loop in between pages
        if ticket.fmt == "json":
            await response.write(b"]}")
        await response.write_eof()
        return response

    def _expire_exports(self) -> None:
        now = time.monotonic()
        for key in [k for k, t in self._exports.items() if now - t.created > EXPORT_TTL]:
            self._exports.pop(key, None)

    async def handle_web(self, request: web.Request) -> web.Response:
        """The single-page web client.

        Unauthenticated, because it is a static page that asks for a token --
        the same shape as any login page. It carries no data; the websocket it
        opens is what needs the credential.

        Revalidated rather than refetched: the browser (and the service
        worker, which asks with cache "no-cache") sends back the ETag it has,
        and an unchanged page is a 304 with no body instead of the whole file
        on every load. A deploy changes the file, so the next load gets it.

        Compressed for anyone who can take it (2026-10). The page is one
        690 KB file that gzips to about 220 KB. Behind Cloudflare that never
        mattered -- the edge compresses what it serves -- but someone running
        their own bouncer with nothing in front of it sent the whole 690 KB
        on every load that was not a 304. Compressed once per version of the
        page and kept beside its ETag (_read_index), not once per request.
        """
        if self.setup is not None and self.setup.open:
            # Nobody can sign in yet, so the sign-in page would only ask for
            # a token that does not exist. Not permanent: it lasts until the
            # first token is made.
            raise web.HTTPFound("/setup")
        index = self._web_root / "index.html"
        try:
            body, script_hashes, etag, gzipped = self._read_index(index)
        except OSError:
            raise web.HTTPNotFound(text="web client not installed")
        # One ETag for the page, compressed or not: it names the version of
        # the page (a hash of its text), which is the question a revalidation
        # asks, and it is the value `hello` carries as `build`. The two
        # encodings are kept apart by `Vary` below, not by the validator.
        compressed = _accepts_gzip(request)
        own_host = _safe_host(request.host)
        # The page's own host over wss, spelled out as well as 'self': CSP3
        # lets 'self' cover the websocket schemes, but not every browser that
        # is still in use read it that way. ws:// only when the page itself
        # came over plain http (a rig): a page served over https has no
        # business opening an unencrypted socket, even to its own host.
        https = request.secure or _forwarded_scheme(request) == "https"
        sockets = ""
        if own_host:
            sockets = f" wss://{own_host}" + ("" if https else f" ws://{own_host}")
        headers = {
            # It is one self-contained file with no external resources, so
            # the policy can be strict: nothing loads from anywhere else.
            #
            # Scripts run only if they are the page's own inline blocks,
            # each allowed by its SHA-256, computed here from the file as
            # it is served. It used to be 'unsafe-inline', which also let
            # through any script an injected line of HTML could carry.
            # Styles keep 'unsafe-inline': the page sets styles inline all
            # over, and a style cannot run anything.
            "Content-Security-Policy": (
                "default-src 'none'; "
                f"script-src {script_hashes}; "
                "style-src 'unsafe-inline'; "
                "img-src 'self' https: data: blob:; "
                # Only this bouncer, and the storage host when uploads are
                # on: the browser PUTs the file straight to a presigned URL
                # there, and without it every web upload was refused before
                # it left the page. It used to be any ws: or wss: at all.
                f"connect-src 'self'{sockets}{self._upload_origin()}; "
                # default-src 'none' covers manifest-src too, and a manifest
                # it refuses is an app that cannot be installed, with the
                # refusal reported as a console warning nobody reads.
                "manifest-src 'self'; "
                # newsreader.woff2, the Newsreader choice under Settings.
                "font-src 'self'; "
                # /sw.js, the service worker Web Push arrives through.
                # Without this it falls back to script-src, which allows
                # no script by URL, and registering it fails.
                "worker-src 'self'; "
                "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
            ),
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            # Kept, but never used without asking first: a copy from
            # before a deploy must not open. no-cache is exactly that, and
            # the ETag makes the asking cheap.
            "Cache-Control": "no-cache",
            "ETag": etag,
            # What is sent depends on what the request said it could take, so
            # a cache between here and the browser has to keep the two apart
            # -- on every answer, the uncompressed one and the 304 included,
            # or a cache that saw one first would serve it to everybody.
            "Vary": "Accept-Encoding",
        }
        # The 304 carries the same policy as the 200. A cache refreshes the
        # headers it kept from the ones on a 304, and the connect-src above
        # is worked out per request (the host, http or https), so the kept
        # copy must not go on with whatever it was first given.
        if _etag_matches(request, etag):
            return web.Response(status=304, headers=headers)
        if compressed:
            # The CSP's hashes are of the scripts as the browser reads them,
            # which is after it has undone this: they are the same either way.
            headers["Content-Encoding"] = "gzip"
            return web.Response(body=gzipped, content_type="text/html", charset="utf-8",
                                headers=headers)
        return web.Response(text=body, content_type="text/html", headers=headers)

    def page_build(self) -> str | None:
        """An opaque id of the web page being served: its ETag without the
        quotes, or None when there is no page. `hello` carries it, so a page
        that has been open since before a deploy can see that it is no longer
        the page the bouncer serves and offer to reload."""
        try:
            return self._read_index(self._web_root / "index.html")[2].strip('"')
        except OSError:
            return None

    def _read_index(self, index: Path) -> tuple[str, str, str, bytes]:
        """index.html, the script-src sources that let its inline scripts
        run (one 'sha256-…' per <script> block), its ETag, and the page
        gzipped.

        Read on every request, as before (a deploy replaces the file under a
        running bouncer), but hashed and compressed only when the file has
        changed. The hash is of the text between <script> and </script>
        exactly as it is in the file, which is what the browser hashes.
        """
        stat = index.stat()
        # The icon's version is part of the key: a new icon under an unchanged
        # page must still change the link the page carries.
        icon_version = self.asset_version("icon-192.png")
        key = (stat.st_mtime_ns, stat.st_size, icon_version)
        if self._index_cache is not None and self._index_cache[0] == key:
            return self._index_cache[1:]
        body = index.read_text()
        # The home-screen icon link, versioned like the manifest's (asset_version).
        if icon_version:
            body = body.replace('href="icon-192.png"', f'href="icon-192.png?v={icon_version}"')
        sources = " ".join(f"'sha256-{digest}'" for digest in inline_script_hashes(body))
        # Of the content, not the mtime and size the cache is keyed by: a
        # redeploy of the same file is the same page, and two bouncers
        # serving one file agree on it.
        encoded = body.encode("utf-8")
        etag = '"' + hashlib.sha256(encoded).hexdigest()[:32] + '"'
        # Level 9 because it is done once per deploy and served thousands of
        # times; mtime=0 so the same page is the same bytes on every bouncer
        # and after every restart (gzip otherwise stamps the time into it).
        gzipped = gzip.compress(encoded, compresslevel=9, mtime=0)
        # A page with no inline script still needs a script-src that allows
        # nothing, not an empty directive.
        self._index_cache = (key, body, sources or "'none'", etag, gzipped)
        return body, sources or "'none'", etag, gzipped

    async def handle_health(self, request: web.Request) -> web.Response:
        """Liveness, and nothing else, unless you present a token.

        This used to return the networks, the nick and the message count to
        anyone who asked. That was defensible while the only way to reach it was
        the WireGuard tunnel; it stopped being defensible the moment a public
        hostname pointed at it. Anyone who guessed the name learned the owner's
        IRC nick, which network they are on, whether they are online right now,
        and roughly how much they talk.

        The unauthenticated body is now the minimum a monitor needs: is it up,
        and (2026-09-26) is it on IRC. `irc` is one boolean -- at least one
        network registered upstream -- so a monitor can tell "the bouncer is up
        but QuakeNet is not" from "all well" without learning which network,
        which nick, or how many there are. `ok` alone said up while the only
        thing the bouncer exists to do had been down for an hour.
        """
        irc = any(s.conn.registered for s in self.hub.sessions.values())
        anonymous = web.json_response({"ok": True, "protocol": P.PROTOCOL_VERSION, "irc": irc})
        token = _extract_token(request)
        if token is None:
            return anonymous
        # A monitor asking "is it up" over http is fine; a token is not.
        self._plain_http_refused(request)
        # A wrong token here is a failure like one at /ws, and counts against
        # the same throttle: the long body and the short one answer "is this
        # token good", and that question was free here while /ws charged for
        # it. A throttled address is told so, without the lookup: 429, as /ws
        # answers. It used to get the short body with a 200 -- which is also
        # exactly what a WRONG token gets, so the web client, checking its
        # token before attaching, read a minute's throttle as its token
        # having been refused and signed the person out.
        peer = self._peer(request)
        if self._rate_limited(peer):
            return web.json_response(
                {"error": "too many failed attempts; wait a minute"}, status=429)
        if self.store.verify_token(token) is None:
            self._record_failure(peer)
            return anonymous
        return web.json_response({
            "ok": True,
            "protocol": P.PROTOCOL_VERSION,
            "irc": irc,
            "clients": len(self.hub.clients),
            "networks": [s.to_wire() for s in self.hub.sessions.values()],
            "max_eid": self.store.max_eid(),
        })

    # --- pairing -----------------------------------------------------------

    def _expire_pairings(self) -> None:
        now = time.monotonic()
        for code in [c for c, t in self._pairings.items() if now - t.created > PAIR_TTL]:
            self._pairings.pop(code, None)

    def _new_pairing(self, client: Client, label: str) -> PairTicket:
        """Mint a code for the `pair` frame. At most MAX_PAIRINGS wait at
        once; one more pushes the oldest out rather than being refused, so
        opening "Add a device" a sixth time still shows a code that works --
        and the one it replaced answers "expired", which is true."""
        return self._make_pairing(label, client.host, client.token_id)

    def _make_pairing(self, label: str, host: str, token_id: int) -> PairTicket:
        self._expire_pairings()
        while len(self._pairings) >= MAX_PAIRINGS:
            self._pairings.popitem(last=False)
        code = ""
        while not code or code in self._pairings:
            code = "".join(secrets.choice(PAIR_ALPHABET) for _ in range(PAIR_CODE_LENGTH))
        ticket = PairTicket(code, label, host, token_id, time.monotonic())
        self._pairings[code] = ticket
        return ticket

    def _redeem_pairing(self, code: str) -> PairTicket | None:
        """The ticket for a code, taken out of the table, or None.

        Compared with every waiting code in constant time, and all of them
        each time whether or not one has matched: how long a refusal takes
        says nothing about how close the guess was. A code whose maker has
        since been signed out is gone with it.
        """
        self._expire_pairings()
        found = None
        attempt = code.encode()
        for known, ticket in self._pairings.items():
            if hmac.compare_digest(known.encode(), attempt):
                found = ticket
        if found is None:
            return None
        self._pairings.pop(found.code, None)
        return found if self.store.token_active(found.token_id) else None

    async def handle_pair(self, request: web.Request) -> web.Response:
        """POST /pair {"code": …, "label": optional}: a pairing code for a
        token. No Authorization header -- the code is the credential, and the
        device presenting it has no token yet; that is the point.

        The same doors as /ws, since what comes back is a way in:
          - not over plain http through the tunnel (_plain_http_refused): the
            code went in the clear on the way here and the token would on the
            way back;
          - not from a page on another site (_origin_allowed). The page the
            bouncer serves calls this from its own origin, and the iOS app
            sends no Origin at all, as with /ws;
          - a throttled address is refused before the code is looked at, and
            a wrong code is a failure like a wrong token. That order is the
            reverse of /ws, on purpose: a token is 256 bits and the throttle
            there only saves work, but a code is eight characters, and here
            the throttle is what makes guessing one hopeless.

        A wrong, used and expired code are all the same 404 with the same
        words. The reply is not cacheable (no-store, as every reply here is
        unless its route says otherwise) and the token is never logged.
        """
        self._plain_http_refused(request)
        if not self._origin_allowed(request):
            log.warning("refused a pairing from origin %r (host %r)",
                        request.headers.get("Origin"), request.host)
            raise web.HTTPForbidden(text="this page may not pair with this bouncer")
        peer = self._peer(request)
        if self._rate_limited(peer):
            log.warning("auth rate limit hit for %s (pairing)", peer)
            return web.json_response(
                {"error": "Too many attempts. Wait a minute and try again."}, status=429)
        try:
            # Bounded by the application's client_max_size (see __init__).
            body = json.loads(await request.read())
        except (ValueError, UnicodeDecodeError):
            body = None
        if not isinstance(body, dict):
            return web.json_response({"error": "Send a pairing code."}, status=400)
        ticket = self._redeem_pairing(clean_pair_code(body.get("code")))
        if ticket is None:
            self._record_failure(peer)
            log.warning("rejected a pairing code from %s", peer)
            return web.json_response(
                {"error": "That code is not valid or has expired."}, status=404)
        # The new device may name itself; otherwise it is called what the
        # device that made the code called it.
        label = clean_label(body.get("label")) or ticket.label
        token = self.store.create_token(label)
        log.info("paired a new device (%r) with a code made under token %d",
                 label, ticket.token_id)
        return web.json_response({"token": token, "host": ticket.host, "label": label})

    # --- first run -----------------------------------------------------------

    def _setup_response(self, page: str, status: int = 200) -> web.Response:
        """A setup page: no-store (one of them carries a token), and a policy
        that lets it run its own copy buttons and post only to itself."""
        scripts = " ".join(f"'sha256-{d}'" for d in inline_script_hashes(page)) or "'none'"
        return web.Response(text=page, status=status, content_type="text/html", headers={
            "Content-Security-Policy": (
                f"default-src 'none'; script-src {scripts}; style-src 'unsafe-inline'; "
                "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"),
            "Cache-Control": "no-store",
        })

    def _setup_networks(self) -> list[str]:
        return [s.config.name for s in self.hub.sessions.values()]

    async def handle_setup_page(self, request: web.Request) -> web.Response:
        """GET /setup: the form while no device can sign in, else a page that
        says it is done (404, so nothing mistakes it for a form)."""
        setup = self.setup
        if setup is None or not setup.open:
            return self._setup_response(firstrun.closed_page(), status=404)
        # Whoever opened the page is probably about to look for the code.
        setup.announce()
        return self._setup_response(firstrun.form_page(networks=self._setup_networks()))

    async def handle_setup(self, request: web.Request) -> web.Response:
        """POST /setup: the setup code, the first device's name and,
        optionally, an IRC network. Mints the first token and shows it.

        The same doors as /pair, in the same order and for the same reason:
        no plain http through a proxy, no foreign Origin, and the throttle
        before the code, which counts a wrong one like a wrong token. Nothing
        else in the form is read until the code is right, and nothing is
        stored until all of it is: a refusal leaves the code good for the
        next try.
        """
        setup = self.setup
        if setup is None or not setup.open:
            return self._setup_response(firstrun.closed_page(), status=404)
        self._plain_http_refused(request)
        if not self._origin_allowed(request):
            log.warning("refused a setup from origin %r (host %r)",
                        request.headers.get("Origin"), request.host)
            raise web.HTTPForbidden(text="this page may not set up this bouncer")
        form = await request.post()
        values = {k: str(form.get(k, "")) for k in firstrun.FORM_FIELDS}
        networks = self._setup_networks()

        def refuse(error: str, status: int) -> web.Response:
            return self._setup_response(
                firstrun.form_page(values, error, networks), status=status)

        peer = self._peer(request)
        if self._rate_limited(peer):
            log.warning("auth rate limit hit for %s (setup)", peer)
            return refuse("Too many attempts. Wait a minute and try again.", 429)
        if not setup.check(values["code"]):
            self._record_failure(peer)
            log.warning("rejected a setup code from %s", peer)
            return refuse("That setup code is not right. Copy it from the bouncer's log.", 403)
        if setup.busy:
            return refuse("Setup is already being finished. Reload in a moment.", 409)
        label = clean_label(values["label"])
        if label is None:
            return refuse(f"Give this device a name of 1 to {MAX_LABEL} characters.", 400)

        choice = values["network"] or "none"
        frame: dict | None = None
        if choice in firstrun.PRESETS:
            name, host, port, tls = firstrun.PRESETS[choice]
            frame = {"name": name, "host": host, "port": port, "tls": tls}
        elif choice == "other":
            host = values["host"].strip()
            frame = {"name": host, "host": host, "port": values["port"].strip() or None,
                     "tls": bool(values["tls"])}
        elif choice != "none":
            return refuse("Pick a network from the list.", 400)

        setup.busy = True
        try:
            network = None
            if frame is not None:
                frame["nick"] = values["nick"].strip()
                frame["channels"] = values["channels"].replace(",", " ").split()
                if self.hub.add_network is None:
                    return refuse("This bouncer cannot add networks.", 400)
                try:
                    fields = await network_fields(
                        frame, adding=True, allow_private_hosts=self.config.allow_private_hosts)
                    fields.setdefault("channels", [])
                    added = await self.hub.add_network(**fields)
                except ValueError as exc:
                    return refuse(str(exc), 400)
                network = added.get("name") if isinstance(added, dict) else frame["name"]
            # A token made some other way while the network was being added
            # closed setup; this one is not owed a second.
            if not setup.open:
                return self._setup_response(firstrun.closed_page(), status=404)
            token = self.store.create_token(label)
            setup.finish()
        finally:
            setup.busy = False
        token_id = self.store.token_id(token)
        host = _public_host(request)
        scheme = _link_scheme(request, host)
        # The browser that did the setup is a device of its own: a pairing
        # code for it, in the fragment, as `pair` makes one.
        ticket = self._make_pairing("Web browser", host, token_id)
        log.info("first run finished: a token for %r%s", label,
                 f" and the network {network}" if network else "")
        return self._setup_response(firstrun.done_page(
            host=host if scheme == "https" else f"{scheme}://{host}",
            token=token, label=label,
            link=firstrun.connect_link(host, token, scheme),
            web_url=f"{scheme}://{host}/#pair={ticket.code}",
            network=network))

    async def _protect_upload_links(self, text: str) -> None:
        """Mark the uploads a line links to as uncacheable (uploads.CACHE_CONTROL).

        Never stops the line: if storage is slow or says no, the line goes out
        and the journal says why. The cost is that this one file may be cached
        for a few hours, which only matters if it is deleted.
        """
        uploader = self.uploader
        if uploader is None or not uploader.available:
            return
        keys = uploader.keys_in(text)
        if not keys:
            return
        # The link is going out, so the file is one the person means to keep
        # on show: it joins "my uploads". (Before the storage call, which can
        # fail without making that any less true.)
        try:
            self.store.mark_uploads_sent(keys)
        except Exception:
            log.warning("could not note that an upload was sent", exc_info=True)

        def protect_all() -> int:
            return sum(1 for key in keys if uploader.protect(key))

        try:
            changed = await asyncio.wait_for(asyncio.to_thread(protect_all), timeout=8)
        except Exception:
            log.warning("could not mark %d upload(s) uncacheable before sending the line",
                        len(keys), exc_info=True)
            return
        if changed:
            log.info("marked %d upload(s) uncacheable", changed)

    def _upload_origin(self) -> str:
        """' https://host' for the presigned-upload endpoint, or ''."""
        if self.uploader is None:
            return ""
        from urllib.parse import urlparse
        parsed = urlparse(self.uploader.config.endpoint)
        if parsed.scheme != "https" or not parsed.hostname:
            return ""
        # Path-style URLs go to the endpoint host itself; virtual-hosted ones to
        # <bucket>.<host>. Both, so the choice boto makes cannot break it. The
        # port goes on both: a CSP source without one means 443 only, and an
        # endpoint on :9900 used to be allowed as plain https://host.
        host = parsed.hostname.lower()
        try:
            port = parsed.port
        except ValueError:
            return ""
        suffix = f":{port}" if port and port != 443 else ""
        bucket = self.uploader.config.bucket.lower()
        return f" https://{host}{suffix} https://{bucket}.{host}{suffix}"

    def _media_host(self) -> str | None:
        if self.uploader is None:
            return None
        from urllib.parse import urlparse
        return (urlparse(self.uploader.config.public_base).hostname or "").lower() or None

    # --- websocket ---------------------------------------------------------

    def _rate_limited(self, peer: str) -> bool:
        """Has this address failed too many times recently?

        A token is 256 bits, so brute force is not the worry -- the worry is an
        endpoint that will accept unlimited attempts forever, which is free
        CPU-burning for anyone who finds the hostname and an unbounded log.
        """
        now = time.monotonic()
        recent = self._all_failures
        if len(recent) >= AUTH_GLOBAL_MAX and now - recent[0] < AUTH_WINDOW:
            return True
        failures = self._auth_failures.get(_throttle_key(peer))
        if not failures:
            return False
        return sum(1 for t in failures if now - t < AUTH_WINDOW) >= AUTH_MAX_FAILURES

    def _record_failure(self, peer: str) -> None:
        """Every step here is constant time. The table used to be rebuilt in
        full on every failure once it passed 4096 addresses, and an IPv6
        client has a /64 of addresses to fail from: with 30000 of them seen
        in a minute one failure cost 3 ms, so a few hundred a second held
        the event loop outright."""
        now = time.monotonic()
        key = _throttle_key(peer)
        failures = self._auth_failures.pop(key, None)
        if failures is None:
            failures = collections.deque(maxlen=AUTH_MAX_FAILURES)
        failures.append(now)
        self._auth_failures[key] = failures          # newest failure last
        while len(self._auth_failures) > AUTH_TRACKED_MAX:
            self._auth_failures.popitem(last=False)
        self._all_failures.append(now)

    @staticmethod
    def _peer(request: web.Request) -> str:
        """Who is knocking, for the failed-auth throttle.

        Behind the Cloudflare Tunnel every connection arrives from
        cloudflared on this machine, so the forwarded header is what tells
        clients apart. It is believed only from there: a connection from
        anywhere else could put any address it liked in it, and used to be
        able to pick whose bucket its failures went into.
        """
        remote = request.remote or "?"
        if _from_loopback(request):
            forwarded = (request.headers.get("CF-Connecting-IP")
                         or request.headers.get("X-Forwarded-For", "").split(",")[0].strip())
            if forwarded:
                return forwarded
        elif _from_proxy(request):
            # A platform's proxy appends the address it saw to whatever the
            # caller sent, so the last entry is the one it vouches for; the
            # first is whatever the caller typed.
            forwarded = request.headers.get("X-Forwarded-For", "").split(",")[-1].strip()
            if forwarded:
                return forwarded
        return remote

    def _origin_allowed(self, request: web.Request) -> bool:
        """A browser may open /ws only from the page this bouncer serves.

        Browsers send Origin on every websocket handshake and nothing else
        does by default: the iOS app, wsclient.py and the tests send none, and
        are let through. A browser page on some other site is refused before
        the token is even looked at. The token already stops a page that does
        not have it; this stops one that somehow does (a token pasted into
        the wrong site) from using it from there.

        "Own" is the Host the request came in on (the tunnel passes the public
        hostname through), or X-Forwarded-Host from a proxy that rewrites
        Host, or anything in config.json's `allowed_origins`. X-Forwarded-Host
        is believed only from the proxy in front (_from_proxy: loopback, or
        anywhere with `trust_proxy`), like every other forwarding header
        here (_peer, _forwarded_scheme): from anywhere else it is whatever the
        caller typed, and the check is only as good as what it believes.
        """
        origin = request.headers.get("Origin")
        if origin is None:
            return True
        host = _origin_host(origin)
        if host is None:
            return False
        own = {_host_key(request.host or "")}
        forwarded = request.headers.get("X-Forwarded-Host") if _from_proxy(request) else None
        if forwarded:
            own.add(_host_key(forwarded.split(",")[0]))
        allowed = {_origin_host(o) for o in self.config.allowed_origins}
        return host in own or host in allowed

    @staticmethod
    def _plain_http_refused(request: web.Request) -> None:
        """A token that came over plain http through the tunnel is refused
        before it is looked at.

        The token rides in the handshake (a header, or the subprotocol list),
        so a socket dialled as ws:// through the tunnel has already sent it in
        the clear by the time it arrives; being answered would teach the
        client that this works. Only when cloudflared says the browser used
        http: a local rig, where nobody in front says anything, is plain http
        by design and is let through. Cloudflare's "Always Use HTTPS" should
        stop this at the edge; this holds whatever it is set to.
        """
        if _forwarded_scheme(request) == "http":
            log.warning("refused a token over plain http from %s", Gateway._peer(request))
            raise web.HTTPForbidden(text="use https: this bouncer takes no token over plain http")

    async def handle_ws(self, request: web.Request) -> web.WebSocketResponse:
        self._plain_http_refused(request)
        if not self._origin_allowed(request):
            log.warning("refused a websocket from origin %r (host %r)",
                        request.headers.get("Origin"), request.host)
            raise web.HTTPForbidden(text="this page may not connect to this bouncer")

        # The token first, and the throttle only for a token that fails. The
        # throttle used to come first, so ten bad attempts from one address
        # (or from anyone able to claim that address) locked out the good
        # token too, for a minute at a time.
        peer = self._peer(request)
        token = _extract_token(request)
        token_id = self.store.verify_token(token) if token else None
        if token_id is None:
            if self._rate_limited(peer):
                log.warning("auth rate limit hit for %s", peer)
                raise web.HTTPTooManyRequests(text="too many failed attempts; wait a minute")
            self._record_failure(peer)
            log.warning("rejected websocket with a bad token from %s", peer)
            # 401 before the upgrade, so a bad token fails as an HTTP error the
            # client can actually read, rather than as a websocket that opens
            # and immediately closes with an opaque code.
            raise web.HTTPUnauthorized(text="invalid or missing token")

        ws = web.WebSocketResponse(
            heartbeat=30,
            max_msg_size=4 * 1024 * 1024,
            # Selected and echoed back, so a browser that offered it knows the
            # server understood the handshake. The token entry it also offered
            # is never echoed: naming it in the response would put it back into
            # a header a proxy might log, which is the thing this avoids.
            protocols=(WS_PROTOCOL,),
            # No permessage-deflate. Through the Cloudflare Tunnel the
            # negotiation disagreed somewhere between browser, edge and
            # aiohttp, and every frame arrived as "Received frame with non-zero
            # reserved bits" -- one client dropped every 33 seconds for a day.
            # These frames are small JSON objects, so compression was buying
            # close to nothing in exchange for that.
            compress=False,
        )
        await ws.prepare(request)
        client = Client(ws, token_id, self.hub, transport=request.transport)
        # The page's own origin (https://bouncer.example), from a browser only.
        # A Web Push subscription made on this socket names it as its VAPID
        # contact; see relay/webpush.py.
        client.origin = request.headers.get("Origin")
        # Where this client reached us, for the links `pair` hands out: the
        # Host it asked for (the tunnel passes the public hostname through),
        # and https -- unless this is a rig on this machine, reached by a
        # loopback name over plain http with nobody in front saying otherwise.
        # A pairing link carries a code that becomes a token; the only place
        # it may say http is where there is no https to say.
        client.host = _public_host(request)
        client.link_scheme = _link_scheme(request, client.host)
        client.start()
        # Held from before it joins the hub until its burst is queued, so no
        # live frame can land inside the burst (see Client.hold).
        client.hold()
        # Not ready: taking an automatic away back waits for the hello (see
        # Hub.add), which _send_initial_state queues first.
        self.hub.add(client, ready=False)
        try:
            sent_upto = await self._send_initial_state(client, since=_parse_since(request))
            client.release(sent_upto)
            await self._read_loop(client)
        finally:
            self.hub.discard(client)
            await client.finish()
        return ws

    async def _send_initial_state(self, client: Client,
                                  since: int | None = None) -> dict[int, int]:
        """Everything a client needs to draw its sidebar and the top of each
        conversation, in one burst, before any live frame can arrive.

        Returns, per buffer, the newest eid its backlog frame carried: what
        Client.release needs to drop a live event the burst already included.

        Ordering matters: hello, then networks, then buffers, then the unread
        counts, then backlog. A client that receives a live event for a buffer it
        has not been told about yet has to either queue it or drop it, and both
        are bugs -- so buffers always precede events.

        `since` is the newest eid the client already holds, from `?since=` on
        the socket URL. With it, each buffer's backlog is what came after that
        eid rather than the newest `initial_backlog` lines -- which, for a phone
        that was away for more than a page of chatter, used to leave a hole it
        had no way to see: the burst's newest fifty sat on top of lines from an
        hour ago with nothing between them. A `since` past the newest eid the
        bouncer has ever stored is from some other database (a reinstall, a
        restore) and is ignored.
        """
        max_eid = self.store.max_eid()
        resume = since is not None and since <= max_eid
        build = self.page_build()
        token = self.store.token(client.token_id) or {}
        sent_upto: dict[int, int] = {}
        await client.send(P.frame(
            P.HELLO,
            protocol=P.PROTOCOL_VERSION,
            server=APP_NAME,
            max_eid=max_eid,
            # Whether `?since=` was honoured, so the client knows the backlog
            # that follows continues what it holds rather than replacing it.
            # Also true when nothing is new anywhere and no backlog follows.
            resumed=resume,
            initial_backlog=self.config.initial_backlog,
            # So the client can hide the attach button entirely rather than
            # offering something that fails once a photo has been chosen. False
            # too when the bucket is configured but boto3 is not installed.
            can_upload=self.uploader is not None and self.uploader.available,
            # Link cards: the `link_preview` frame is answered.
            link_previews=self.previews is not None,
            # The VAPID public key a browser subscribes to Web Push with, or
            # null when web push is unavailable. See `register_webpush`.
            webpush_key=self.hub.webpush.public_key if self.hub.webpush else None,
            # The host the bucket is served from. The app draws pictures from it
            # inline even with previews off: fetching them tells nobody new
            # where the phone is, because the server is the user's own.
            media_host=self._media_host(),
            # Lets the app decide between showing conversations and showing the
            # "which server, which nick" screen, without guessing from an empty
            # buffer list -- which would also be empty while merely reconnecting.
            has_networks=bool(self.hub.sessions),
            can_add_networks=self.hub.add_network is not None,
            # Whether `register_push` leads anywhere: false with no APNs key,
            # so the app can say that this bouncer cannot notify rather than
            # registering into a void and promising notifications.
            apns=self.hub.apns_configured,
            # An id of this database, changed by a restore: a client holding
            # lines cached under another one drops them, and does not send
            # `?since=`. See Store.epoch.
            epoch=self.store.epoch,
            # Which access token this socket attached with, so a Devices list
            # can mark "this device" and a client knows its own name here.
            token={"id": client.token_id, "label": token.get("label", "")},
            # The pairing frames (`pair`, `tokens`, `revoke_token`) and
            # POST /pair are here.
            can_pair=True,
            # `detach` takes an `until`, and the bouncer lifts the mute itself.
            timed_mute=True,
            # An id of the web page this bouncer serves, when it serves one
            # (left out otherwise). A page that sees a different value on a
            # later hello than on its first is no longer the deployed page.
            **({"build": build} if build else {}),
        ))
        # Hello is queued; an automatic away can be taken back now, and the
        # network frames below already show it gone.
        self.hub.client_ready()
        # Straight after hello, so a client knows the highlight words and the
        # notification settings before the first event it might draw.
        await client.send(self.settings_frame())

        for session in self.hub.sessions.values():
            await client.send(P.frame(P.NETWORK, network=session.to_wire()))

        buffers = self.store.buffers()
        await client.send(P.frame(
            P.BUFFER_LIST,
            buffers=[self._buffer_wire(b) for b in buffers],
        ))
        await client.send(P.frame(P.UNREAD, counts=self.store.unread_counts()))
        for session in self.hub.sessions.values():
            await client.send(P.frame(
                P.IGNORES, network=session.config.slug,
                nicks=self.store.ignores(session.network_id)))

        for buf in buffers:
            if buf.kind == "channel" and buf.joined:
                await client.send(P.frame(
                    P.MEMBERS, buffer=buf.id, members=self._members_wire(buf.id)
                ))
            if resume:
                events, complete = self.store.events_since(
                    buf.id, since, limit=RESUME_MAX_PER_BUFFER)
                # A buffer where nothing happened gets no frame at all: the
                # client already holds all of it.
                if events:
                    sent_upto[buf.id] = events[-1].eid
                    await client.send(P.frame(
                        P.BACKLOG,
                        buffer=buf.id,
                        events=[e.to_wire() for e in events],
                        direction="after",
                        after_eid=since,
                        # true: these are every event after `after_eid`, so
                        # they join straight onto what the client held. false:
                        # capped, and there is a hole between `after_eid` and
                        # the first of these.
                        complete=complete,
                    ))
                continue
            events = self.store.backlog(buf.id, limit=self.config.initial_backlog)
            if events:
                sent_upto[buf.id] = events[-1].eid
                await client.send(P.frame(
                    P.BACKLOG,
                    buffer=buf.id,
                    events=[e.to_wire() for e in events],
                    # `complete` tells the client whether scrolling up needs
                    # another round trip or has genuinely reached the beginning.
                    complete=len(events) < self.config.initial_backlog,
                ))
        return sent_upto

    async def _read_loop(self, client: Client) -> None:
        async for msg in client.ws:
            if client.closing:
                break
            if msg.type == WSMsgType.TEXT:
                client.last_heard = time.monotonic()
                # Every frame, not only the handshake. One indexed lookup; the
                # sweep covers sockets that never send anything.
                if not self.store.token_active(client.token_id):
                    await self._close_revoked(client)
                    break
                try:
                    frame = msg.json()
                except Exception:
                    await client.error(None, "malformed json")
                    continue
                # Valid JSON is not necessarily a frame. A bare list or string
                # used to reach the dispatcher, where frame.get() raised
                # AttributeError -- inside the except clause meant to report it,
                # which took the whole connection down with it.
                if not isinstance(frame, dict):
                    await client.error(None, "frame must be an object")
                    continue
                try:
                    await self._dispatch(client, frame)
                except (KeyError, ValueError, TypeError) as exc:
                    # A field that is missing or is not the type it has to be:
                    # the client's mistake, and one it can fix. Naming the frame
                    # is more use to it than a Python exception would be.
                    log.info("malformed %r frame from client %d: %s: %s",
                             frame.get("type"), client.id, type(exc).__name__, exc)
                    await client.error(frame.get("req"),
                                       f"malformed {frame.get('type')} frame")
                except Exception:
                    # Ours, not theirs. The text of an internal exception can
                    # carry a path or a query, so the client is told the fact
                    # and the journal keeps the detail.
                    log.exception("client request failed")
                    await client.error(frame.get("req"), "internal error")
            elif msg.type == WSMsgType.ERROR:
                # The socket is already unusable; aiohttp will not deliver
                # anything else. Breaking ends the handler cleanly and lets the
                # finally block detach, rather than looping on a dead iterator.
                exc = client.ws.exception()
                # A heartbeat that went unanswered is iOS suspending the app
                # with its socket open -- expected many times a day, and it
                # filled the journal with WARNINGs nobody could act on. INFO
                # since 2026-09-26; anything else stays a warning.
                level = (logging.INFO if isinstance(exc, asyncio.TimeoutError)
                         and "PONG" in str(exc) else logging.WARNING)
                log.log(level, "client %d: websocket error: %s", client.id, exc)
                break

    async def _dispatch(self, client: Client, frame: dict) -> None:
        type_ = frame.get("type")
        req = frame.get("req")

        if type_ == P.C_PING:
            # Carries presence, because the client is already sending a keepalive
            # and a separate presence frame would be a second timer to get wrong.
            if presence := frame.get("presence"):
                client.presence = presence
            if "focused_buffer" in frame:
                client.focused_buffer = frame.get("focused_buffer")
            await client.send(P.frame(P.PONG, req=req))
            return

        if type_ == P.C_BACKLOG:
            buffer_id = int(frame["buffer"])
            # Clamped at both ends. A negative limit used to reach SQLite as
            # LIMIT -1, which is "no limit": the whole buffer in one frame.
            limit = max(1, min(int(frame.get("limit") or 50), self.config.max_backlog_page))
            around = frame.get("around_eid")
            after = frame.get("after_eid")
            before = frame.get("before_eid")

            if around is not None:
                events = self.store.backlog_around(buffer_id, int(around), limit=limit)
                # `complete` describes the OLDER edge only; there is no single
                # answer for a two-sided query and pretending otherwise would
                # make a client stop paging in the wrong direction. It is true
                # when nothing in this buffer is older than the page's first
                # line. It used to compare with eid 1 -- the first line on the
                # whole bouncer -- so it was never true for any other buffer.
                complete = not events or not self.store.has_older(buffer_id, events[0].eid)
                direction = "around"
            elif after is not None:
                events = self.store.backlog_after(buffer_id, int(after), limit=limit)
                complete = len(events) < limit
                direction = "after"
            else:
                events = self.store.backlog(
                    buffer_id, before_eid=int(before) if before else None, limit=limit
                )
                complete = len(events) < limit
                direction = "before"

            await client.send(P.frame(
                P.BACKLOG,
                req=req,
                buffer=buffer_id,
                events=[e.to_wire() for e in events],
                complete=complete,
                direction=direction,
            ))
            return

        if type_ == P.C_SAY:
            text = frame.get("text") or ""
            if not text.strip():
                await client.error(req, "empty message")
                return
            # A link to one of this bouncer's own uploads is marked uncacheable
            # BEFORE the line goes out, because nobody can fetch the address
            # until then. Later is too late: the first fetch caches the file at
            # the edge for hours, and a delete would not reach that copy.
            await self._protect_upload_links(text)
            action = bool(frame.get("action"))
            notice = bool(frame.get("notice"))
            # "@" or "+": to the channel's ops or voiced people only.
            statusmsg = frame.get("statusmsg") or None
            if statusmsg is not None and not isinstance(statusmsg, str):
                await client.error(req, "statusmsg must be text, like \"@\"")
                return
            # The client's own name for this send, copied onto every event it
            # produces (extra.nonce). One that is not a nonce is ignored.
            nonce = clean_nonce(frame.get("nonce"))
            # Addressed by buffer id normally, or by `target` (a nick or channel)
            # when the buffer may not exist yet -- which is what /msg needs.
            try:
                if frame.get("buffer") is not None:
                    buffer_id = int(frame["buffer"])
                    session = self._session_for_buffer(buffer_id)
                    if session is None:
                        await client.error(req, "unknown buffer")
                        return
                    first = await session.queue_say(buffer_id, text, action=action,
                                                    notice=notice, statusmsg=statusmsg,
                                                    nonce=nonce)
                else:
                    session = self._session_for(frame.get("network"))
                    if session is None:
                        await client.error(req, "unknown network")
                        return
                    first = await session.queue_say(text=text, target=frame.get("target"),
                                                    action=action, notice=notice,
                                                    statusmsg=statusmsg, nonce=nonce)
            except ValueError as exc:
                # Everything refused in session.say -- a line IRC cannot carry,
                # too many lines at once, a queue already minutes deep, a
                # channel we are not in -- says so in a sentence meant for
                # whoever typed it. Pass it through.
                await client.error(req, str(exc))
                return
            # The line is queued. Waiting here for its echo (up to
            # SAY_ECHO_WAIT) used to hold every other frame from this client
            # for that long: a pasted 8-line burst, one `say` a line, held an
            # unrelated reply 1.5 s. The wait goes on beside the frame loop
            # instead; the `ok` still carries the echo when it came in time.
            self._spawn_reply(self._say_reply(client, req, first))
            return

        if type_ == P.C_TYPING:
            # No reply at all, not even to a req: this goes out every few
            # seconds while someone types, and an `ok` for each would double
            # the traffic for an answer nobody waits on. Whether it reaches the
            # network (message-tags negotiated, the debounce, room in the
            # flood bucket) is the session's business, and a typing hint that
            # does not go is not an error anyone can act on.
            buffer_id = int(frame["buffer"])
            state = frame.get("state")
            session = self._session_for_buffer(buffer_id)
            if session is not None and isinstance(state, str):
                session.send_typing(buffer_id, state)
            return

        if type_ == P.C_QUERY:
            session = self._session_for(frame.get("network"))
            if session is None:
                await client.error(req, "unknown network")
                return
            try:
                buffer = await session.open_query(frame.get("nick") or "")
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            await client.ok(req, buffer=buffer)
            return

        if type_ == P.C_CLOSE:
            buffer_id = int(frame["buffer"])
            session = self._session_for_buffer(buffer_id)
            if session is None:
                await client.error(req, "unknown buffer")
                return
            before = self.store.buffer(buffer_id)
            try:
                await session.close_buffer(buffer_id)
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            await self.hub.broadcast(P.frame(P.UNREAD, counts=self.store.unread_counts()))
            # Closing is reading (see session.close_buffer): if that moved the
            # marker, the other devices' notifications for it come down too.
            after = self.store.buffer(buffer_id)
            if before is not None and after is not None \
                    and after.last_seen_eid > before.last_seen_eid:
                self.hub.read_elsewhere(client.token_id, buffer_id, after.last_seen_eid)
            await client.ok(req)
            return

        if type_ == P.C_NICK:
            session = self._session_for(frame.get("network"))
            if session is None:
                await client.error(req, "unknown network")
                return
            try:
                await session.set_nick(frame.get("nick") or "", origin=_origin(frame))
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            await client.ok(req)
            return

        if type_ == P.C_TOPIC:
            buffer_id = int(frame["buffer"])
            session = self._session_for_buffer(buffer_id)
            if session is None:
                await client.error(req, "unknown buffer")
                return
            try:
                await session.set_topic(buffer_id, frame.get("topic") or "")
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            await client.ok(req)
            return

        if type_ == P.C_DETACH:
            buffer_id = int(frame["buffer"])
            session = self._session_for_buffer(buffer_id)
            if session is None:
                await client.error(req, "unknown buffer")
                return
            try:
                detached = bool(frame.get("detached", True))
                until = frame.get("until")
                if until is not None:
                    # Unix seconds, in the future and not absurdly far: a mute
                    # that ends by itself, for "an hour" or "until tomorrow".
                    if (isinstance(until, bool) or not isinstance(until, (int, float))
                            or not time.time() < until <= time.time() + MAX_TIMED_MUTE):
                        await client.error(req, "until must be a time within the next year")
                        return
                await session.set_detached(buffer_id, detached, float(until) if detached and until is not None else None)
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            await self.hub.broadcast(P.frame(P.UNREAD, counts=self.store.unread_counts()))
            await client.ok(req)
            return

        if type_ == P.C_ADD_NETWORK:
            if self.hub.add_network is None:
                await client.error(req, "server cannot add networks")
                return
            if len(self.hub.sessions) >= MAX_NETWORKS:
                await client.error(req, f"at the limit of {MAX_NETWORKS} networks")
                return
            # Every field checked before anything is stored or dialled, the
            # host included: it must be a public address (see
            # relay/netguard.py). See relay/netfields.py for the rules.
            try:
                fields = await network_fields(
                    frame, adding=True, allow_private_hosts=self.config.allow_private_hosts)
                fields.setdefault("channels", [])
                # Broadcasts the network and its Server buffer to every
                # client before anything happens in it (relay/app.py).
                network = await self.hub.add_network(**fields)
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            await client.ok(req, network=network)
            return

        if type_ == P.C_EDIT_NETWORK:
            if self.hub.edit_network is None:
                await client.error(req, "server cannot edit networks")
                return
            session = self._session_for(frame.get("network"))
            if session is None:
                await client.error(req, "unknown network")
                return
            try:
                fields = await network_fields(
                    frame, adding=False, allow_private_hosts=self.config.allow_private_hosts,
                    current=session.config)
                if not fields:
                    raise ValueError("Nothing to change.")
                # The session broadcasts the new `network` to every client.
                network = await self.hub.edit_network(session.config.slug, fields)
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            await client.ok(req, network=network)
            return

        if type_ == P.C_NETWORK_CONNECT:
            if self.hub.connect_network is None:
                await client.error(req, "server cannot connect networks")
                return
            session = self._session_for(frame.get("network"))
            if session is None:
                await client.error(req, "unknown network")
                return
            connect = frame.get("connect")
            if not isinstance(connect, bool):
                await client.error(req, "connect must be true or false")
                return
            network = await self.hub.connect_network(session.config.slug, connect)
            await client.ok(req, network=network)
            return

        if type_ == P.C_REMOVE_NETWORK:
            if self.hub.remove_network is None:
                await client.error(req, "server cannot remove networks")
                return
            try:
                await self.hub.remove_network(frame.get("network") or "")
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            await self.hub.broadcast(P.frame(P.BUFFER_LIST, buffers=[
                self._buffer_wire(b) for b in self.store.buffers()
            ]))
            await client.ok(req)
            return

        if type_ == P.C_IGNORE:
            session = self._session_for(frame.get("network"))
            if session is None:
                await client.error(req, "unknown network")
                return
            try:
                await session.set_ignored(frame.get("nick") or "",
                                          bool(frame.get("ignored", True)))
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            await client.ok(req)
            return

        if type_ == P.C_UPLOAD_URL:
            if self.uploader is None:
                await client.error(req, NOT_SET_UP)
                return
            try:
                size = int(frame.get("size") or 0)
            except (TypeError, ValueError):
                await client.error(req, "That file's size is not a number.")
                return
            try:
                ttl_raw = frame.get("ttl")
                if ttl_raw in (None, 0, "0"):
                    ttl = None
                else:
                    try:
                        ttl = int(ttl_raw)
                    except (TypeError, ValueError):
                        await client.error(req, "That is not a time a file can be kept for.")
                        return
                result = self.uploader.presign(
                    filename=frame.get("filename") or "file",
                    content_type=frame.get("content_type") or "",
                    size=size,
                    ttl=ttl,
                )
            except ValueError as exc:
                # Already a sentence for the person (see uploads.presign).
                await client.error(req, str(exc))
                return
            except ImportError:
                log.exception("could not presign an upload: boto3 will not import")
                await client.error(req, NOT_SET_UP)
                return
            except Exception:
                # The detail (a botocore error, a bad endpoint) is for the
                # journal. The person gets a sentence, never an exception name.
                log.exception("could not presign an upload")
                await client.error(req, NOT_PREPARED)
                return
            try:
                key = self.uploader.key_for_url(result["public_url"])
                if key:
                    self.store.record_upload(
                        key, result["content_type"], size, time.time(),
                        result.get("expires_at"))
            except Exception:
                # Not recording costs the "my uploads" list and the timer for
                # this one file; it must not cost the upload.
                log.warning("could not record an upload", exc_info=True)
            await client.ok(req, upload=result)
            return

        if type_ == P.C_LIST_UPLOADS:
            try:
                limit = max(1, min(int(frame.get("limit") or 50), 200))
                before = float(frame["before"]) if frame.get("before") is not None else None
            except (TypeError, ValueError):
                await client.error(req, "malformed list_uploads frame")
                return
            base = self.uploader.config.public_base if self.uploader else ""
            rows = self.store.list_uploads(before=before, limit=limit)
            await client.send(P.frame(
                P.UPLOADS,
                req=req,
                uploads=[{
                    "url": f"{base}/{r['key']}",
                    "content_type": r["content_type"],
                    "size": r["size"],
                    "created": r["created"],
                    "expires_at": r["expires"],
                } for r in rows],
                # Page with `before` = the last `created` while this is false.
                complete=len(rows) < limit,
            ))
            return

        if type_ == P.C_DELETE_UPLOAD:
            if self.uploader is None:
                await client.error(req, NOT_SET_UP)
                return
            url = frame.get("url")
            if not isinstance(url, str) or not url:
                await client.error(req, "That link is not a file this bouncer uploaded.")
                return
            try:
                # A network call to storage, and this is the one event loop
                # every connection shares: run it off the loop.
                key = await asyncio.to_thread(self.uploader.delete, url)
            except ValueError as exc:
                # Already a sentence for the person (see uploads.delete).
                await client.error(req, str(exc))
                return
            except ImportError:
                log.exception("could not delete an upload: boto3 will not import")
                await client.error(req, NOT_SET_UP)
                return
            except Exception:
                # A botocore error for the journal; the person gets a sentence.
                log.exception("could not delete an upload")
                await client.error(req, NOT_DELETED)
                return
            # The year and month only: the rest of the key is the secret that
            # was protecting the file, and the journal is not where it belongs.
            log.info("deleted an upload (%s)", key[:7])
            self.store.mark_upload_deleted(key, time.time())
            await client.ok(req, deleted=url)
            return

        if type_ == P.C_SEARCH:
            query = (frame.get("query") or "").strip()
            # `from` is the contract's name; `sender` is what older clients send.
            sender = (frame.get("from") or frame.get("sender") or "").strip() or None
            if len(query) < 2 and not sender:
                await client.error(req, "search for at least two characters")
                return
            # Parsed before the search, so a field of the wrong type is a
            # "malformed search frame" rather than Python's words for it.
            buffer_id = int(frame["buffer"]) if frame.get("buffer") is not None else None
            since = float(frame["since"]) if frame.get("since") is not None else None
            until = float(frame["until"]) if frame.get("until") is not None else None
            before_eid = int(frame["before_eid"]) if frame.get("before_eid") else None
            limit = max(1, min(int(frame.get("limit") or 50), 200))
            try:
                results = self.store.search(
                    query, buffer_id=buffer_id, sender=sender, since=since, until=until,
                    limit=limit, before_eid=before_eid,
                )
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            # Each hit carries its buffer so the client can label it and jump
            # there; a list of messages with no context is not searchable by eye.
            await client.send(P.frame(
                P.SEARCH_RESULTS,
                req=req,
                query=query,
                results=[e.to_wire() for e in results],
                # true: nothing older matches. Page with before_eid otherwise.
                complete=len(results) < limit,
            ))
            return

        if type_ in (P.C_CHANMODE, P.C_KICK):
            buffer_id = int(frame["buffer"])
            session = self._session_for_buffer(buffer_id)
            if session is None:
                await client.error(req, "unknown buffer")
                return
            try:
                if type_ == P.C_CHANMODE:
                    await session.set_channel_mode(buffer_id, frame.get("mode") or "",
                                                   frame.get("nick") or "")
                else:
                    await session.kick(buffer_id, frame.get("nick") or "",
                                       frame.get("reason") or "")
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            await client.ok(req)
            return

        if type_ == P.C_AWAY:
            session = self._session_for(frame.get("network"))
            if session is None:
                await client.error(req, "unknown network")
                return
            # `message` is the contract's name, `text` what older clients
            # send; clients send both. Missing, null or "" clears it.
            message = frame.get("message") or frame.get("text") or ""
            if not isinstance(message, str):
                await client.error(req, "the away message must be text")
                return
            try:
                await session.set_away(message)
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            await client.ok(req)
            return

        if type_ == P.C_INVITE:
            session = self._session_for(frame.get("network"))
            if session is None:
                await client.error(req, "unknown network")
                return
            channel = frame.get("channel") or ""
            if not channel:
                await client.error(req, "missing channel")
                return
            try:
                await session.invite(channel, frame.get("nick") or "", origin=_origin(frame))
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            await client.ok(req)
            return

        if type_ == P.C_NAMES:
            buffer_id = int(frame["buffer"])
            session = self._session_for_buffer(buffer_id)
            if session is None:
                await client.error(req, "unknown buffer")
                return
            try:
                await session.refresh_members(buffer_id)
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            await client.ok(req)
            return

        if type_ == P.C_WHOIS:
            session = self._session_for(frame.get("network"))
            if session is None:
                await client.error(req, "unknown network")
                return
            try:
                # `req` travels with the lookup so the `whois` frame that lands
                # later can be matched to the client that asked for it. The `ok`
                # is immediate and means only that the question went to IRC --
                # the answer is its own frame, seconds later or never.
                await session.whois(frame.get("nick") or "", req)
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            await client.ok(req)
            return

        if type_ in (P.C_JOIN, P.C_PART):
            session = self._session_for(frame.get("network"))
            if session is None:
                await client.error(req, "unknown network")
                return
            channel = frame.get("channel") or ""
            if not channel:
                await client.error(req, "missing channel")
                return
            # A +k channel's key, on `join` only. Remembered with the channel
            # and sent on every rejoin; never echoed back in any frame.
            key = frame.get("key") if type_ == P.C_JOIN else None
            if key is not None and not isinstance(key, str):
                await client.error(req, "the channel key must be text")
                return
            try:
                if type_ == P.C_JOIN:
                    await session.join(channel, origin=_origin(frame), key=key or None)
                else:
                    await session.part(channel, frame.get("reason", "") or "",
                                       origin=_origin(frame))
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            await client.ok(req)
            return

        if type_ == P.C_MARK_READ:
            buffer_id = int(frame["buffer"])
            eid = int(frame["eid"])
            buf = self.store.buffer(buffer_id)
            old_eid = buf.last_seen_eid if buf is not None else None
            new_eid = self.store.mark_read(buffer_id, eid)
            # Told to everyone, not just the sender: reading on the phone has to
            # clear the badge on the Mac. That is the feature.
            await self.hub.broadcast(
                P.frame(P.READ_MARKER, buffer=buffer_id, eid=new_eid)
            )
            await self.hub.broadcast(P.frame(P.UNREAD, counts=self.store.unread_counts()))
            # And to the devices that are not attached, which is where the
            # notifications for these lines are sitting: a push, after a
            # pause, to every device but the reader's own. Only when the
            # marker actually moved -- clients repeat a mark_read freely.
            if old_eid is not None and new_eid > old_eid:
                self.hub.read_elsewhere(client.token_id, buffer_id, new_eid)
            await client.ok(req, eid=new_eid)
            return

        if type_ == P.C_BUFFERS:
            # A client that received an event for a buffer it has never heard
            # of asks for the list again rather than dropping the line. Cheap
            # to answer, and it means one missed announce cannot hide a
            # conversation until the next attach.
            #
            # `archived: true` adds the closed ones, each marked archived, for
            # a client that shows a Closed section. Only on request: the
            # initial burst leaves them out, because a client that picks "the
            # first channel" to land on at launch (both of today's do, when no
            # channel is joined yet, as after a restart) would land in one.
            include_archived = frame.get("archived") is True
            await client.send(P.frame(
                P.BUFFER_LIST, req=req,
                buffers=[self._buffer_wire(b)
                         for b in self.store.buffers(include_archived=include_archived)],
            ))
            return

        if type_ == P.C_RAW:
            session = self._session_for(frame.get("network"))
            if session is None:
                await client.error(req, "unknown network")
                return
            try:
                await session.raw(frame.get("line"), origin=_origin(frame))
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            # `ok` means it went into the send queue. What the server makes of
            # it arrives as events (see "Errors" in docs/PROTOCOL.md).
            await client.ok(req)
            return

        if type_ == P.C_LIST:
            session = self._session_for(frame.get("network"))
            if session is None:
                await client.error(req, "unknown network")
                return
            try:
                future = session.list_channels(frame.get("mask") or "")
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            # The server can take many seconds to list everything. Answered
            # from a task, so this client's other frames are not held behind
            # it, and only to this client: it can be hundreds of kilobytes.
            task = asyncio.create_task(self._answer_list(client, req, session, future))
            self._reply_tasks.add(task)
            task.add_done_callback(self._reply_tasks.discard)
            return

        if type_ == P.C_MENTIONS:
            # The mentions inbox: every highlight on every network, newest
            # first, paged by eid like search. The partial index on
            # highlight=1 was built for this and had no caller.
            limit = max(1, min(int(frame.get("limit") or 50), 200))
            before = int(frame["before_eid"]) if frame.get("before_eid") else None
            events = self.store.highlights(limit=limit, before_eid=before)
            await client.send(P.frame(
                P.MENTIONS, req=req,
                events=[e.to_wire() for e in events],
                # true: nothing older. Page on with before_eid = the last eid.
                complete=len(events) < limit,
            ))
            return

        if type_ == P.C_BUFFER_SETTINGS:
            buffer_id = int(frame["buffer"])
            session = self._session_for_buffer(buffer_id)
            if session is None:
                await client.error(req, "unknown buffer")
                return
            notify, pinned = frame.get("notify"), frame.get("pinned")
            if notify is not None and notify not in NOTIFY_LEVELS:
                await client.error(req, f"notify must be one of {', '.join(NOTIFY_LEVELS)}")
                return
            if pinned is not None and not isinstance(pinned, bool):
                await client.error(req, "pinned must be true or false")
                return
            if notify is None and pinned is None:
                await client.error(req, "nothing to change: send notify or pinned")
                return
            # The session broadcasts the changed `buffer` to every client.
            buffer = await session.set_buffer_settings(buffer_id, notify=notify, pinned=pinned)
            await client.ok(req, buffer=buffer)
            return

        if type_ == P.C_MARK_ALL_READ:
            network_id = None
            if frame.get("network"):
                session = self.hub.sessions.get(frame["network"])
                if session is None:
                    await client.error(req, "unknown network")
                    return
                network_id = session.network_id
            before = {b.id: b.last_seen_eid for b in self.store.buffers()}
            moved = []
            for buffer_id, eid in self.store.mark_all_read(network_id):
                self.hub.publish(P.frame(P.READ_MARKER, buffer=buffer_id, eid=eid))
                if eid > before.get(buffer_id, eid):
                    moved.append((buffer_id, eid))
            await self.hub.broadcast(P.frame(P.UNREAD, counts=self.store.unread_counts()))
            # The other devices are told by push (see mark_read). Everything
            # read is one push saying so. One network of several is not
            # "everything" -- that would take down the other networks'
            # notifications with it -- so it is a push for each buffer whose
            # marker moved, and most of those are never sent (the hub drops
            # one that has nothing to take down).
            if moved:
                if network_id is None or len(self.hub.sessions) <= 1:
                    self.hub.read_elsewhere(client.token_id, None)
                else:
                    for buffer_id, eid in moved:
                        self.hub.read_elsewhere(client.token_id, buffer_id, eid)
            await client.ok(req)
            return

        if type_ == P.C_SET_SETTINGS:
            try:
                words = self._parse_highlight_words(frame.get("highlight_words"))
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            flags = {}
            for key in ("push_preview", "auto_away"):
                if frame.get(key) is not None:
                    if not isinstance(frame[key], bool):
                        await client.error(req, f"{key} must be true or false")
                        return
                    flags[key] = frame[key]
            sound = frame.get("push_sound")
            if sound is not None:
                if sound not in PUSH_SOUNDS:
                    await client.error(req, "push_sound must be one of " + ", ".join(PUSH_SOUNDS))
                    return
                flags["push_sound"] = sound
            palette = frame.get("nick_palette")
            if palette is not None:
                # Lenient on purpose: a client falls back to its default for an
                # id it does not know, so a new set never needs a bouncer change.
                if not isinstance(palette, str) or not NICK_PALETTE_ID.fullmatch(palette):
                    await client.error(req, "nick_palette must be 1 to 24 lowercase letters, "
                                            "digits or hyphens")
                    return
                flags["nick_palette"] = palette
            try:
                colors = self._parse_nick_colors(frame.get("nick_colors"))
            except ValueError as exc:
                await client.error(req, str(exc))
                return
            if colors is not None:
                flags["nick_colors"] = colors
            # Checked in full before anything is applied: a frame with one bad
            # field changes nothing, rather than half of what it asked.
            for slug, list_ in words.items():
                self.hub.sessions[slug].set_highlight_words(list_)
            for key, value in flags.items():
                self.store.set_setting(key, value)
            await client.ok(req)
            await self.hub.broadcast(self.settings_frame())
            if "auto_away" in flags:
                self.hub.auto_away_changed()
            return

        if type_ == P.C_MEMBERS:
            buffer_id = int(frame["buffer"])
            await client.send(P.frame(
                P.MEMBERS, req=req, buffer=buffer_id, members=self._members_wire(buffer_id)
            ))
            return

        if type_ == P.C_LINK_PREVIEW:
            if self.previews is None:
                await client.error(req, "Link previews are off on this bouncer.")
                return
            url = frame.get("url")
            if not isinstance(url, str) or not url.strip():
                await client.error(req, "missing url")
                return
            if client.previews_pending >= MAX_PREVIEWS_PER_CLIENT:
                await client.error(req, "Too many link previews at once. Try again in a moment.")
                return
            # Up to five seconds of someone else's server: answered from a
            # task, so this client's other frames are not held behind it.
            client.previews_pending += 1
            task = asyncio.create_task(self._answer_preview(client, req, url))
            self._reply_tasks.add(task)
            task.add_done_callback(self._reply_tasks.discard)
            return

        if type_ == P.C_EXPORT:
            buffer_id = int(frame["buffer"])
            session = self._session_for_buffer(buffer_id)
            if session is None:
                await client.error(req, "unknown buffer")
                return
            fmt = frame.get("format") or "txt"
            if fmt not in ("txt", "json"):
                await client.error(req, "format must be txt or json")
                return
            tz = timezone.utc
            if frame.get("tz"):
                # Optional: the IANA zone the times in a txt log are written in
                # (the client's own). UTC without it.
                try:
                    from zoneinfo import ZoneInfo

                    tz = ZoneInfo(str(frame["tz"]))
                except Exception:
                    await client.error(req, "That time zone is not one I know.")
                    return
            self._expire_exports()
            if len(self._exports) >= MAX_EXPORTS:
                await client.error(req, "Too many downloads waiting. Try again in a few minutes.")
                return
            ticket = secrets.token_urlsafe(32)
            self._exports[ticket] = ExportTicket(buffer_id, fmt, tz, time.monotonic(), session)
            await client.ok(req, url=f"/export/{ticket}", expires_in=int(EXPORT_TTL))
            return

        if type_ == P.C_CLEAR_BUFFER:
            buffer_id = int(frame["buffer"])
            session = self._session_for_buffer(buffer_id)
            if session is None:
                await client.error(req, "unknown buffer")
                return
            # In chunks, yielding between them: a busy channel's years are a lot
            # of rows, each with a search-index entry, and the IRC loop must not
            # stall behind the delete (see Store.clear_events).
            while self.store.clear_events(buffer_id):
                await asyncio.sleep(0)
            await self.hub.broadcast(P.frame(P.BUFFER_CLEARED, buffer=buffer_id))
            await self.hub.broadcast(P.frame(P.UNREAD, counts=self.store.unread_counts()))
            await client.ok(req)
            return

        if type_ == P.C_REGISTER_WEBPUSH:
            await self._register_webpush(client, req, frame.get("subscription"))
            return

        if type_ == P.C_UNREGISTER_WEBPUSH:
            endpoint = frame.get("endpoint")
            if not isinstance(endpoint, str) or not endpoint:
                await client.error(req, "missing endpoint")
                return
            # ok whether or not there was one, like unregister_push.
            self.store.unregister_webpush(client.token_id, endpoint)
            await client.ok(req)
            return

        if type_ == P.C_REGISTER_PUSH:
            # Checked rather than stored as sent. A device token is used to
            # address APNs and the platform decides which APNs -- garbage here
            # is a row that fails every push attempt forever, discovered only
            # when a notification does not arrive.
            device_token = str(frame.get("device_token") or "").strip()
            platform = str(frame.get("platform", "ios"))
            environment = str(frame.get("environment", "sandbox"))
            if not device_token:
                await client.error(req, "missing device_token")
                return
            if len(device_token) > MAX_DEVICE_TOKEN or not all(
                    c in string.hexdigits for c in device_token):
                await client.error(req, "device_token must be hex")
                return
            if platform not in PLATFORMS:
                await client.error(req, f"platform must be one of {sorted(PLATFORMS)}")
                return
            if environment not in ENVIRONMENTS:
                await client.error(req, f"environment must be one of {sorted(ENVIRONMENTS)}")
                return
            self.store.register_device(client.token_id, device_token, platform, environment)
            await client.ok(req)
            return

        if type_ == P.C_UNREGISTER_PUSH:
            # Sign-out. Without it a signed-out phone kept getting every PM on
            # its lock screen, because nothing ever removed its row. Only the
            # row registered under this client's own token is removed, and the
            # reply is `ok` whether or not there was one: signing out twice is
            # not an error, and the answer should not reveal whose device it is.
            device_token = str(frame.get("device_token") or "").strip()
            if not device_token:
                await client.error(req, "missing device_token")
                return
            if len(device_token) > MAX_DEVICE_TOKEN or not all(
                    c in string.hexdigits for c in device_token):
                await client.error(req, "device_token must be hex")
                return
            self.store.unregister_device(client.token_id, device_token)
            await client.ok(req)
            return

        if type_ == P.C_TOKENS:
            # The Devices list: every token that still works, which is every
            # device that can attach. Any attached client may ask -- there is
            # one user, and each of their devices holds one of these -- and
            # none of it is a secret: the label, two times, and whether
            # notifications are registered under it. Never the token.
            await client.send(P.frame(P.TOKENS, req=req, tokens=[
                {
                    "id": t["id"],
                    "label": t["label"],
                    # Whole seconds: these are for "added in March" and "last
                    # used an hour ago", and a client that reads them as
                    # integers must not trip over a fraction.
                    "created_at": int(t["created_at"] or 0),
                    "last_used_at": (int(t["last_used_at"])
                                     if t["last_used_at"] is not None else None),
                    "current": t["id"] == client.token_id,
                    "push": t["push"],
                }
                for t in self.store.active_tokens()
            ]))
            return

        if type_ == P.C_REVOKE_TOKEN:
            token_id = frame.get("id")
            if isinstance(token_id, bool) or not isinstance(token_id, int):
                await client.error(req, "id must be a token's id")
                return
            if not self.store.token_active(token_id):
                await client.error(req, "That device is not signed in.")
                return
            # The same thing `python -m relay token revoke` does: the token
            # stops working and the devices registered under it stop being
            # pushed to. Then its sockets, now rather than at the next sweep.
            self.store.revoke_token(token_id)
            log.info("token %d revoked by a client (token %d)", token_id, client.token_id)
            for other in [c for c in list(self.hub.clients)
                          if getattr(c, "token_id", None) == token_id and c is not client]:
                await self._close_revoked(other)
            await client.ok(req)
            if token_id == client.token_id:
                # Signing this device out. It is owed the `ok` first, so the
                # close waits for the queue rather than emptying it.
                self._spawn_reply(client.close_when_drained(CLOSE_REVOKED, "token revoked"))
            return

        if type_ == P.C_PAIR:
            label = clean_label(frame.get("label"))
            if label is None:
                await client.error(
                    req, f"Give the new device a name of 1 to {MAX_LABEL} characters.")
                return
            if not client.host:
                # No usable Host on the handshake, so no link could be made
                # that leads back here.
                await client.error(req, "This connection has no address to make a link from.")
                return
            ticket = self._new_pairing(client, label)
            log.info("pairing code made for %r by token %d", label, client.token_id)
            await client.send(P.frame(
                P.PAIR, req=req,
                code=ticket.code,
                expires_in=int(PAIR_TTL),
                # For a browser: the page redeems `#pair=` at load. In the
                # fragment, which a browser never sends to anyone, rather
                # than the query, which it sends to every proxy on the way.
                url=f"{client.link_scheme}://{ticket.host}/#pair={ticket.code}",
                # For the iOS app, which asks "Connect to <host>?" first.
                # The app reads a bare host as https, so the one case that
                # is not -- a bouncer reached over plain http on loopback, a
                # development setup -- names its scheme, or the link would
                # lead to an address that does not answer.
                app_url="geeyem://pair?host={}&code={}".format(
                    ticket.host if client.link_scheme == "https"
                    else quote(f"{client.link_scheme}://{ticket.host}", safe=""),
                    ticket.code),
            ))
            return

        await client.error(req, f"unknown frame type: {type_!r}")

    async def _answer_preview(self, client: Client, req, url: str) -> None:
        try:
            await self._answer_preview_now(client, req, url)
        finally:
            client.previews_pending -= 1

    async def _answer_preview_now(self, client: Client, req, url: str) -> None:
        try:
            card = await self.previews.preview(url)
        except ValueError as exc:
            if not client.closing:
                await client.error(req, str(exc))
            return
        except asyncio.CancelledError:
            return
        except Exception:
            log.exception("link preview failed")
            if not client.closing:
                await client.error(req, "That page could not be read.")
            return
        if client.closing:
            return
        await client.send(P.frame(
            P.LINK_PREVIEW, req=req, url=url, title=card.get("title"),
            description=card.get("description"), site=card.get("site"),
            image=card.get("image")))

    async def _register_webpush(self, client: Client, req, subscription) -> None:
        """Keep a browser's push subscription, after checking every part of it.

        The endpoint is where the bouncer will POST, so it gets the same rule as
        a link preview: https, and a public address -- a subscription is not a
        way to make the bouncer post to something on its own network. A test
        rig (allow_private_hosts) may use plain http on 127.0.0.1.
        """
        from .webpush import unb64u

        if self.hub.webpush is None:
            await client.error(req, "Web push is not available on this bouncer.")
            return
        if not isinstance(subscription, dict):
            await client.error(req, "missing subscription")
            return
        endpoint = subscription.get("endpoint")
        keys = subscription.get("keys") or {}
        p256dh = keys.get("p256dh") if isinstance(keys, dict) else None
        auth = keys.get("auth") if isinstance(keys, dict) else None
        if not isinstance(endpoint, str) or not endpoint or len(endpoint) > MAX_WEBPUSH_ENDPOINT:
            await client.error(req, "That push subscription has no usable endpoint.")
            return
        allow_private = self.config.allow_private_hosts
        try:
            host = check_push_endpoint(endpoint, allow_private=allow_private)
            await check_host_public(host, allow_private=allow_private)
        except ValueError as exc:
            await client.error(req, str(exc))
            return
        try:
            key_bytes = unb64u(p256dh) if isinstance(p256dh, str) else b""
            auth_bytes = unb64u(auth) if isinstance(auth, str) else b""
        except Exception:
            key_bytes, auth_bytes = b"", b""
        if len(key_bytes) != 65 or key_bytes[0] != 4 or len(auth_bytes) != 16:
            await client.error(req, "That push subscription's keys are not valid.")
            return
        mine = [s for s in self.store.webpush_subscriptions()
                if s["token_id"] == client.token_id and s["endpoint"] != endpoint]
        if len(mine) >= MAX_WEBPUSH_PER_TOKEN:
            await client.error(req, "Too many browsers are signed up for notifications.")
            return
        origin = client.origin if (client.origin or "").startswith("https://") else None
        self.store.register_webpush(client.token_id, endpoint, p256dh, auth, subject=origin)
        await client.ok(req)

    def _spawn_reply(self, coro) -> None:
        """Answer a frame later, beside the client's frame loop."""
        task = asyncio.create_task(coro)
        self._reply_tasks.add(task)
        task.add_done_callback(self._reply_tasks.discard)

    async def _say_reply(self, client: Client, req, first: asyncio.Future) -> None:
        """The `ok` (with the echo when the line went out within
        SAY_ECHO_WAIT) or the `error` for one queued `say`."""
        from .session import NetworkSession
        try:
            event = await NetworkSession.await_echo(first)
        except ValueError as exc:
            if not client.closing:
                await client.error(req, str(exc))
            return
        except asyncio.CancelledError:
            return
        if client.closing:
            return
        # No `event` when the line is still waiting its turn in the flood
        # queue: the echo is stored when the line is written, and arrives as
        # an ordinary `event` frame then. See session.queue_say.
        await client.ok(req, **({"event": event} if event is not None else {}))

    async def _answer_list(self, client: Client, req, session, future) -> None:
        try:
            channels, complete = await future
        except ValueError as exc:
            await client.error(req, str(exc))
            return
        except asyncio.CancelledError:
            return
        if client.closing:
            return
        await client.send(P.frame(
            P.CHANNEL_LIST, req=req, network=session.config.slug,
            channels=channels, complete=complete,
        ))

    def settings_frame(self) -> dict:
        """The user's settings: per-network highlight words, and the global
        push_preview, auto_away, push_sound, nick_colors and nick_palette. Sent after
        hello and whenever changed."""
        return P.frame(
            P.SETTINGS,
            highlight_words={slug: s.highlighter.words for slug, s in self.hub.sessions.items()},
            **self.store.settings(),
        )

    def _parse_highlight_words(self, value) -> dict[str, list[str]]:
        """{slug: [word, ...]} from a set_settings frame, cleaned, or a
        ValueError with a sentence. Blank words go, duplicates (by case) go,
        and the rest must be something IRC could put on one line."""
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError("highlight_words must map each network to a list of words")
        out: dict[str, list[str]] = {}
        for slug, words in value.items():
            if slug not in self.hub.sessions:
                raise ValueError(f"unknown network: {slug}")
            if not isinstance(words, list) or not all(isinstance(w, str) for w in words):
                raise ValueError("highlight_words must map each network to a list of words")
            cleaned, seen = [], set()
            for word in words:
                word = " ".join(word.split())
                if not word or word.casefold() in seen:
                    continue
                if len(word) > MAX_HIGHLIGHT_WORD:
                    raise ValueError(f"a highlight word is at most {MAX_HIGHLIGHT_WORD} characters")
                seen.add(word.casefold())
                cleaned.append(word)
            if len(cleaned) > MAX_HIGHLIGHT_WORDS:
                raise ValueError(f"at most {MAX_HIGHLIGHT_WORDS} highlight words per network")
            out[slug] = cleaned
        return out

    def _parse_nick_colors(self, value) -> dict[str, int] | None:
        """The nick colors as they will be stored once a set_settings `value`
        ({key: hue, key: null, ...}) is merged into the current ones, or None if
        the frame has none, or a ValueError with a sentence. A null removes a
        key; keys not named are left alone."""
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError("nick_colors must map each nick to a hue, or null to clear it")
        current = self.store.get_setting("nick_colors")
        merged = dict(current) if isinstance(current, dict) else {}
        for key, hue in value.items():
            if (not isinstance(key, str) or not key or len(key) > MAX_NICK_COLOR_KEY
                    or any(c.isspace() or unicodedata.category(c).startswith("C") for c in key)):
                raise ValueError(f"a nick color key is 1 to {MAX_NICK_COLOR_KEY} characters "
                                 "with no spaces")
            if hue is None:
                merged.pop(key, None)
            elif isinstance(hue, bool) or not isinstance(hue, int) or not 0 <= hue <= 359:
                raise ValueError("a nick color is a whole number of degrees, 0 to 359")
            else:
                merged[key] = hue
        if len(merged) > MAX_NICK_COLORS:
            raise ValueError(f"at most {MAX_NICK_COLORS} nick colors")
        return merged

    def _slug_for(self, network_id: int) -> str:
        for session in self.hub.sessions.values():
            if session.network_id == network_id:
                return session.config.slug
        return "?"

    def _buffer_wire(self, buf) -> dict:
        """A buffer for a `buffers` frame, with its session's live fields
        (a channel's `modes`, a query's `presence`) when it has one."""
        for session in self.hub.sessions.values():
            if session.network_id == buf.network_id:
                return session.buffer_to_wire(buf)
        return buf.to_wire("?")

    def _members_wire(self, buffer_id: int) -> list[dict]:
        session = self._session_for_buffer(buffer_id)
        if session is None:
            return self.store.members(buffer_id)
        return session.members_to_wire(buffer_id)

    def _session_for(self, slug: str | None):
        """The session a client meant.

        `network` may be omitted when only one is configured -- which is the
        common case and saves every client from tracking a slug it has no choice
        about. With several configured it is required, because guessing would
        send someone's message to the wrong network.
        """
        if slug:
            return self.hub.sessions.get(slug)
        if len(self.hub.sessions) == 1:
            return next(iter(self.hub.sessions.values()))
        return None

    def _session_for_buffer(self, buffer_id: int):
        buf = self.store.buffer(buffer_id)
        if buf is None:
            return None
        for session in self.hub.sessions.values():
            if session.network_id == buf.network_id:
                return session
        return None
