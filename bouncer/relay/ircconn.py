"""One upstream IRC connection, as an asyncio task that reconnects forever.

This class knows about sockets, registration, keepalive and reconnection. It
knows nothing about buffers, backlog or clients -- it hands every parsed line to
a callback and lets `session.py` decide what any of it means. That split is what
lets the whole IRC-facing half be tested against a local server with no database
and no websocket in the picture.

Reconnection is the entire reason this project exists, so it is not an
afterthought here: the connection comes back by itself, with backoff, and the
session re-joins on top of it. A bouncer that needs a human to restart it is
just an IRC client on a server.
"""

from __future__ import annotations

import asyncio
import base64
import errno
import logging
import random
import re
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Awaitable, Callable

from .netguard import BlockedAddress, resolve_public
from .ircproto import (Message, decode_line, encode_line, format_line, parse_line,
                       redact_line)

log = logging.getLogger("relay.irc")

# If the server has said nothing for this long, ping it ourselves. A
# silent-but-open TCP connection is the common failure -- the far side is gone
# and nothing has noticed; TCP will happily hold a dead connection open for many
# minutes -- and every minute of it is messages landing nowhere. The server's
# own PONG (or anything else it says) resets the clock, so a healthy link costs
# one line a minute at most, and QuakeNet's own pings usually cost us nothing.
# soju pings after the same minute.
IDLE_PING_AFTER = 60.0

# And this long for anything at all to come back after that PING, before the
# link is called dead and rebuilt. A half-open link used to take four minutes to
# notice (two minutes idle, then two more waiting); it now takes at most 90s.
PONG_TIMEOUT = 30.0

# Flood control, as a token bucket: FLOOD_BURST lines may go out back to back,
# and after that one line every FLOOD_INTERVAL seconds. This is the shape of the
# rule the server itself enforces. QuakeNet runs ircu, which charges roughly two
# seconds per line a client sends against a clock allowed to run about ten
# seconds ahead of real time; past that it stops reading the socket, the lines
# pile up in its receive queue, and when that queue overflows the client is
# killed with "Excess Flood". Four lines and then one every two seconds stays
# inside it with room to spare. It is also close to irssi's defaults (five at
# once, then one per 2.2s), which have lived with ircu servers for decades.
#
# The old rule was one line every 0.6 seconds with no burst allowance, which is
# over three lines a second sustained: the server's clock runs ahead by about
# 1.4 seconds per line, so a ten-line paste was already brushing the limit.
FLOOD_BURST = 4
FLOOD_INTERVAL = 2.0

# At one line every two seconds, 200 lines is almost seven minutes of backlog.
# Past that the queue is not a buffer any more, it is a place lines go to be
# sent long after they meant anything -- and an unbounded one is a way for
# anything that can make us send (a CTCP flood, a client in a loop) to grow
# memory without limit. The user's own text is refused long before this; see
# MAX_QUEUED_BEFORE_REFUSING in session.py.
SEND_QUEUE_MAX = 200

# The longest line a server may send, in bytes before its LF. IRC's own limit
# is 512 and IRCv3 message tags add up to 8191 more, so anything past this is
# not a line. The read buffer used to grow until a LF arrived: a server (or
# anyone on the plaintext path to it) that never sent one grew it without
# limit, and `buffer += chunk` copied all of it on every read -- 48 MB with no
# newline took the process's peak memory up by over 2 GB on the rig.
MAX_LINE_IN = 16 * 1024

# A link that registered and then stayed up at least this long was a healthy
# link, so losing it starts the reconnect backoff again from the bottom. The
# threshold is only there for the one pathological shape: a server that
# accepts registration and drops us straight away, every time. Resetting on
# that would reconnect every two seconds forever, which is how an address gets
# throttled or banned.
HEALTHY_AFTER = 5.0

# Registration has to finish in a bounded time too, or a server that accepts the
# TCP connection and then says nothing (a common shape for a ban) wedges us. It
# used to be defined here and never used: a server that refused every nick, or
# never sent 001, held the link "connecting" forever.
REGISTER_TIMEOUT = 60.0

# What last_error says when registration ran out of time with nothing more
# specific to say.
NOT_ACCEPTED = "The server did not accept the connection"

# After the configured nick and its alternatives are all refused at
# registration, this many more are tried (nick_, nick__, then three with
# digits) before the connection is given up as refused. A 432 (a nick the
# server will not allow at all, "9lives") is refused in every one of them, and
# walking suffixes forever was the hang.
MAX_NICK_SUFFIXES = 5

# IRCv3 capabilities asked for when the server offers them. Everything else a
# server offers is left off: echo-message and batch/chathistory change what
# arrives in ways the rest of the bouncer does not handle yet. `sasl` is asked
# for on top of these only when a SASL login is configured.
REQUESTED_CAPS = (
    "server-time", "message-tags", "multi-prefix", "userhost-in-names",
    "away-notify", "account-notify", "extended-join", "chghost", "setname",
    "invite-notify",
)
SASL_MECHANISMS = ("PLAIN", "EXTERNAL")

# How long the CAP REQ / SASL exchange may take before CAP END goes out anyway.
# The server holds registration until CAP END, so a server that never answers
# a REQ or an AUTHENTICATE would otherwise hold us until REGISTER_TIMEOUT.
CAP_TIMEOUT = 10.0

# A SASL payload goes in pieces of at most this many base64 characters.
SASL_CHUNK = 400


class PingTimeout(ConnectionError):
    """We pinged an idle link and nothing came back."""


class RegistrationFailed(ConnectionError):
    """The server never let us register: every nick refused, or no 001 within
    REGISTER_TIMEOUT. The message is last_error, already in words."""


def describe_failure(exc: BaseException) -> str:
    """Why a link ended or never started, in words a person would use.

    This is what the network frame's `last_error` shows and what the status
    buffer says, so it is the answer to "why am I not connected". The Python
    exception text is the wrong answer: "[Errno 61] Connect call failed
    ('127.0.0.1', 6667)" says less than "connection refused" and says it worse.
    Order matters, because the ssl and socket errors are all OSErrors.
    """
    if isinstance(exc, (RegistrationFailed, BlockedAddress)):
        return str(exc)
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "TLS certificate did not verify"
    if isinstance(exc, ssl.SSLError):
        return "TLS handshake failed"
    if isinstance(exc, socket.gaierror):
        return "DNS lookup failed"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, PingTimeout):
        return "ping timeout"
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "connection timed out"
    if isinstance(exc, ConnectionResetError):
        return "connection reset"
    if isinstance(exc, OSError):
        by_errno = {
            errno.EHOSTUNREACH: "host unreachable",
            errno.ENETUNREACH: "network unreachable",
            errno.ETIMEDOUT: "connection timed out",
            errno.ECONNREFUSED: "connection refused",
            errno.ECONNRESET: "connection reset",
        }
        if exc.errno in by_errno:
            return by_errno[exc.errno]
        # A name with several addresses (IPv6 and IPv4, or a round robin)
        # that all failed comes back from asyncio as ONE OSError with no errno
        # and every address's error in its text: "Multiple exceptions: [Errno
        # 61] Connect call failed ('::1', 6667, 0, 0), [Errno 61] ...". Said
        # once, in words, when they all failed the same way.
        codes = {int(c) for c in re.findall(r"\[Errno (\d+)\]", str(exc))}
        if str(exc).startswith("Multiple exceptions") and codes:
            words = {by_errno.get(c) for c in codes}
            if len(words) == 1 and None not in words:
                return words.pop()
            return "could not reach any of the server's addresses"
        # A ConnectionError raised here with a sentence ("server closed the
        # connection") is already in words; an OSError's strerror nearly is.
        text = (exc.strerror or str(exc) or type(exc).__name__)
        return text[:1].lower() + text[1:]
    return str(exc) or type(exc).__name__


@dataclass
class Outbound:
    """One line waiting for the flood limiter, and who wants to know its fate.

    `on_sent` runs once the line has actually been written to the socket, and
    `on_dropped` (with a reason) if it never will be: the link went down with
    it still queued, or the queue was full. Both are plain functions, not
    coroutines, and run inline in the sender. That is deliberate. A callback
    that awaited could be cancelled halfway through by a disconnect, which is
    exactly when the answer matters, and a line would then be neither sent nor
    dropped as far as anyone upstairs could tell.
    """

    line: str
    on_sent: Callable[[], None] | None = None
    on_dropped: Callable[[str], None] | None = None


class IRCConnection:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        tls: bool,
        nicks: list[str],
        username: str,
        realname: str,
        on_message: Callable[[Message], Awaitable[None]],
        on_connected: Callable[[], Awaitable[None]] | None = None,
        on_disconnected: Callable[[str], Awaitable[None]] | None = None,
        on_registered: Callable[[str], Awaitable[None]] | None = None,
        on_connect_failed: Callable[[str], Awaitable[None]] | None = None,
        on_state_change: Callable[[], Awaitable[None]] | None = None,
        password: str = "",
        sasl_mechanism: str = "",
        sasl_username: str = "",
        sasl_password: str = "",
        tls_cert: str = "",
        guard_address: bool = False,
    ):
        self.host, self.port, self.tls = host, port, tls
        self.nicks = nicks or ["relay"]
        self.username, self.realname = username, realname
        # Server password (PASS), SASL login and client certificate. Held in
        # memory for the life of the connection, never logged: _write_now logs
        # through ircproto.redact_line.
        self.password = password
        self.sasl_mechanism = sasl_mechanism.upper()
        self.sasl_username, self.sasl_password = sasl_username, sasl_password
        self.tls_cert = tls_cert
        # Dial only public addresses, checked on every connect. Set for a host
        # that came from a client; see netguard.resolve_public.
        self.guard_address = guard_address
        # IRCv3: what the server offered (name -> value) and what it agreed to.
        self.caps_offered: dict[str, str] = {}
        self.caps: set[str] = set()
        # None until the server answers CAP LS (it may never: QuakeNet does not
        # speak CAP), then "ls" while a multi-line LS arrives, "req" while our
        # REQ is out, "sasl" during AUTHENTICATE, "done" once CAP END is sent.
        self._cap_state: str | None = None
        self._cap_deadline: float | None = None
        # "SASL login failed" when the server refused the login. Registration
        # carries on without it, and last_error keeps saying so after 001.
        self._sasl_error: str | None = None
        self._sasl_ok = False
        # The first refusal of a nick during registration, in the server's own
        # words, for last_error if registration never completes.
        self._registration_error: str | None = None
        # Tunable, so a test can run the clocks in seconds.
        self.register_timeout = REGISTER_TIMEOUT
        self.idle_ping_after = IDLE_PING_AFTER
        self.pong_timeout = PONG_TIMEOUT
        self.cap_timeout = CAP_TIMEOUT
        self._on_message = on_message
        self._on_connected = on_connected
        self._on_disconnected = on_disconnected
        self._on_registered = on_registered
        # A connection attempt that failed before a socket existed. It used to
        # be logged and nothing else, so a refused or unresolvable server left
        # the status buffer empty and the app with no reason to show.
        self._on_connect_failed = on_connect_failed
        # last_error or next_retry_at changed; the session re-sends the
        # network frame so a client can show the reason and a countdown.
        self._on_state_change = on_state_change
        # Why the link last ended or failed, in words; None once registered.
        self.last_error: str | None = None
        # When the next attempt starts (unix seconds) while waiting to
        # reconnect; None while connected or connecting.
        self.next_retry_at: float | None = None
        # The server's ERROR line, if it sent one before closing: "Closing
        # Link: quinn[host] (Excess Flood)" is the real reason, and "server
        # closed the connection" is only what it looked like from here.
        self._server_error: str | None = None

        self.nick: str = self.nicks[0]
        self.registered = False
        self.connected = False
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._task: asyncio.Task | None = None
        self._stopping = False
        # What the channels and the status buffer are told when stop() ends a
        # live link: a deploy, a network turned off, new settings.
        self._stop_reason = "the bouncer stopped"
        # The reconnect backoff's step, and the event that cuts a backoff wait
        # short ("Reconnect now"; see connect_now).
        self._attempt = 0
        self._wake = asyncio.Event()
        self._nick_index = 0
        self._registered_event = asyncio.Event()
        # When the current connection registered; None until it has. Read by
        # the reconnect loop to tell a healthy link that dropped from a server
        # that is refusing us. See HEALTHY_AFTER.
        self._registered_at: float | None = None
        # Flood protection: one outbound queue, drained by exactly one sender
        # task per connection through a token bucket (see FLOOD_BURST). Every
        # caller stays inside the server's limit without having to know it.
        #
        # EXACTLY ONE. The sender used to be started on every connect and
        # never stopped, so after N reconnects there were N+1 of them draining
        # the same queue, each keeping its own pace -- a paste went out N+1
        # lines at a time and QuakeNet killed the link for flooding, which
        # added another. It is now bound to the writer it was started for,
        # cancelled and awaited when that connection ends, and replaced only
        # after the old one is gone.
        self._send_queue: asyncio.Queue[Outbound] = asyncio.Queue(maxsize=SEND_QUEUE_MAX)
        self._sender_task: asyncio.Task | None = None
        # The line the sender has taken off the queue but not finished
        # writing. If the link dies while it waits for a token, that line is
        # as unsent as the ones still queued and has to be reported with them.
        self._in_flight: Outbound | None = None
        self.send_burst = FLOOD_BURST
        self.send_interval = FLOOD_INTERVAL
        self._tokens = float(FLOOD_BURST)
        self._tokens_at = time.monotonic()

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stopping = False
            self._stop_reason = "the bouncer stopped"
            self._task = asyncio.create_task(self._run_forever(), name=f"irc:{self.host}")

    @property
    def running(self) -> bool:
        """True while the connect-and-reconnect loop is alive (connected,
        connecting, or waiting to retry); False once stopped."""
        return self._task is not None and not self._task.done()

    async def stop(self, quit_message: str = "relay shutting down",
                   reason: str = "the bouncer stopped") -> None:
        """Say goodbye upstream and stay down.

        `reason` is what everything downstream is told: the status buffer's
        "disconnected: …", each channel's "Disconnected: …" line, and the
        "Not sent (…)" for anything still queued. A deploy is "the bouncer
        stopped"; a network turned off from the app says so instead.
        """
        self._stopping = True
        self._stop_reason = reason
        self.next_retry_at = None
        if self.connected and self._writer is not None:
            try:
                await self._write_now(format_line("QUIT", quit_message))
                await asyncio.wait_for(self._writer.drain(), timeout=3)
            except Exception:
                pass
        # Cancelling the run task runs its finally block, which stops the
        # sender and reports whatever was still queued as not sent.
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        await self._stop_sender()
        self._close_transport()
        self._drop_queued(reason)

    def connect_now(self) -> None:
        """Connect now, with the backoff back at its first step.

        The app's "Reconnect now", and turning a network back on. A link that
        is up, or already dialling, is left alone; one waiting out a backoff
        stops waiting; one that was stopped starts.
        """
        self._attempt = 0
        if not self.running:
            self.start()
        else:
            self._wake.set()

    async def restart(self, quit_message: str, reason: str) -> None:
        """Drop the link and dial again at once: the server, the port, the
        login or the TLS setting changed, and none of that can be changed on a
        connection that is already open."""
        await self.stop(quit_message, reason=reason)
        self._attempt = 0
        self.start()

    def configure(self, *, host: str, port: int, tls: bool, nicks: list[str],
                  username: str, realname: str, password: str = "",
                  sasl_mechanism: str = "", sasl_username: str = "",
                  sasl_password: str = "", tls_cert: str = "",
                  guard_address: bool = False) -> None:
        """New connection settings, used from the next connection on. The
        current one keeps what it registered with; see restart."""
        self.host, self.port, self.tls = host, port, tls
        self.nicks = list(nicks) or ["relay"]
        self.username, self.realname = username, realname
        self.password = password
        self.sasl_mechanism = sasl_mechanism.upper()
        self.sasl_username, self.sasl_password = sasl_username, sasl_password
        self.tls_cert = tls_cert
        self.guard_address = guard_address

    async def wait_registered(self, timeout: float | None = None) -> bool:
        try:
            await asyncio.wait_for(self._registered_event.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            return False

    @property
    def stopping(self) -> bool:
        """True once stop() has been called: the link is going away on purpose."""
        return self._stopping

    async def _notify_state(self) -> None:
        if self._on_state_change:
            try:
                await self._on_state_change()
            except Exception:
                log.exception("on_state_change handler failed")

    async def _run_forever(self) -> None:
        self._attempt = 0
        while not self._stopping:
            reason: str | None = None
            try:
                self.next_retry_at = None
                await self._notify_state()
                await self._connect_once()
                self._attempt = 0      # a clean session resets the backoff
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("%s: connection ended: %s: %s", self.host, type(exc).__name__, exc)
                reason = self._server_error or describe_failure(exc)
            finally:
                # Stopped on purpose, the purpose is the reason -- even when the
                # server's close (it answers our QUIT by hanging up) reached the
                # read loop first and looked like any other dropped link.
                if self._stopping:
                    reason = self._stop_reason
                elif reason is None:
                    reason = self._server_error or "connection lost"
                if not self._stopping:
                    self.last_error = reason
                was_connected = self.connected
                self.connected = False
                self.registered = False
                self._registered_event.clear()
                # The sender goes first, before anything else can await: it is
                # bound to this connection's writer and must be gone before the
                # next connection starts its own.
                await self._stop_sender()
                self._close_transport()
                # Anything still queued was meant for this connection and is not
                # going to be sent on the next one -- replaying it after a
                # reconnect would post something typed minutes ago into a
                # conversation that has moved on. Said so, line by line, to
                # whoever queued it, rather than logged and forgotten.
                self._drop_queued(self._stop_reason if self._stopping else "connection lost")
                if was_connected and self._on_disconnected:
                    try:
                        await self._on_disconnected(reason)
                    except Exception:
                        log.exception("on_disconnected handler failed")
                elif not was_connected and not self._stopping and self._on_connect_failed:
                    try:
                        await self._on_connect_failed(reason)
                    except Exception:
                        log.exception("on_connect_failed handler failed")

            if self._stopping:
                break
            # A link that registered and then stayed up was healthy, so this is
            # a first failure, not the latest in a run. The backoff used to
            # reset only when _connect_once returned normally -- which it never
            # does, it ends by raising -- so every drop over the life of the
            # process pushed the next reconnect further out, until a single
            # blip on a link that had been fine for a week cost five minutes.
            if (self._registered_at is not None
                    and time.monotonic() - self._registered_at >= HEALTHY_AFTER):
                self._attempt = 0
            self._attempt += 1
            delay = self._backoff(self._attempt)
            log.info("%s: reconnecting in %.1fs (attempt %d)", self.host, delay, self._attempt)
            self.next_retry_at = time.time() + delay
            await self._notify_state()
            # A wait connect_now() can cut short: "Reconnect now" should not
            # mean "in up to five minutes".
            self._wake.clear()
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass

    def _backoff(self, attempt: int) -> float:
        # Exponential backoff capped at 5 minutes, with jitter. The jitter is
        # not decoration: without it every network reconnects in lockstep
        # after a VPS reboot and QuakeNet sees a burst from one IP.
        return min(300.0, 2.0 ** min(attempt, 8)) * (0.7 + random.random() * 0.6)

    async def _connect_once(self) -> None:
        ctx = None
        if self.tls:
            ctx = ssl.create_default_context()
            if self.tls_cert:
                # The client certificate SASL EXTERNAL (and CertFP) log in with.
                ctx.load_cert_chain(self.tls_cert)
        log.info("%s:%d: connecting%s", self.host, self.port, " (tls)" if self.tls else "")
        self._registered_at = None
        self._server_error = None
        # A host a client gave us is resolved and checked every time, not only
        # when it was typed: a name can point somewhere else tomorrow. The
        # connection then goes to the checked address, with the name kept for
        # TLS, so what was checked is what is dialled.
        addresses = (await resolve_public(self.host, self.port) if self.guard_address
                     else [self.host])
        tls_name = {"server_hostname": self.host} if ctx is not None else {}
        failure: BaseException | None = None
        for address in addresses:
            try:
                self._reader, self._writer = await asyncio.wait_for(
                    asyncio.open_connection(address, self.port, ssl=ctx, **tls_name), timeout=30
                )
                break
            except (OSError, asyncio.TimeoutError) as exc:
                failure = exc
        else:
            assert failure is not None
            raise failure
        self.connected = True
        # A new connection is a new flood clock on the server's side, so the
        # bucket starts full again.
        self._tokens, self._tokens_at = float(self.send_burst), time.monotonic()
        if self._on_connected:
            await self._on_connected()

        await self._start_sender(self._writer)
        await self._register()
        await self._read_loop()

    def _close_transport(self) -> None:
        if self._writer is not None:
            try:
                self._writer.close()
            except Exception:
                pass
        self._reader = self._writer = None

    async def _start_sender(self, writer: asyncio.StreamWriter) -> None:
        # Never two. Whatever was running is stopped and awaited before its
        # replacement exists, even though the finally block in _run_forever
        # should already have done it -- this is the invariant the whole flood
        # limit rests on, so it is enforced where the task is created too.
        await self._stop_sender()
        self._sender_task = asyncio.create_task(self._drain_send_queue(writer), name="irc-send")

    async def _stop_sender(self) -> None:
        task, self._sender_task = self._sender_task, None
        if task is None or task.done():
            return
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    def _drop_queued(self, reason: str) -> None:
        """Report every line that will now never be sent, then forget them."""
        dropped: list[Outbound] = []
        if self._in_flight is not None:
            dropped.append(self._in_flight)
            self._in_flight = None
        while True:
            try:
                dropped.append(self._send_queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        if dropped:
            log.warning("%s: %d queued line(s) not sent (%s)", self.host, len(dropped), reason)
        for item in dropped:
            self._report_dropped(item, reason)

    @staticmethod
    def _report_dropped(item: Outbound, reason: str) -> None:
        if item.on_dropped is None:
            return
        try:
            item.on_dropped(reason)
        except Exception:
            log.exception("on_dropped handler failed")

    # --- registration ------------------------------------------------------

    async def _register(self) -> None:
        """CAP LS 302, PASS, NICK, USER, all at once.

        CAP LS goes first and the rest does NOT wait for its answer. A server
        that speaks CAP holds registration until we send CAP END, so NICK and
        USER sitting in its buffer change nothing there; a server that does not
        (QuakeNet: snircd answers 421 or nothing at all) registers on NICK and
        USER exactly as it did before CAP was sent, with no pause for a reply
        that is never coming. This is the order the IRCv3 docs recommend and
        what irssi, WeeChat and HexChat all send.

        Q auth is not here: it needs a registered connection. See session.py.
        """
        self._nick_index = 0
        self.nick = self.nicks[0]
        self.caps_offered, self.caps = {}, set()
        self._cap_state, self._cap_deadline = None, None
        self._sasl_error, self._sasl_ok = None, False
        self._registration_error = None
        await self._write_now("CAP LS 302")
        if self.password:
            await self._write_now(format_line("PASS", self.password))
        await self._write_now(format_line("NICK", self.nick))
        await self._write_now(format_line("USER", self.username, "0", "*", self.realname))

    async def _on_registration_complete(self, nick: str) -> None:
        self.nick = nick
        self.registered = True
        self._registered_at = time.monotonic()
        self._cap_deadline = None
        # A SASL login was configured and did not happen: refused (904), no
        # answer, or a server that does not offer it (or offers CAP not at
        # all). Registration carried on without it, as it should.
        if self._sasl_wanted() and not self._sasl_ok:
            self._sasl_error = self._sasl_error or "SASL login failed"
        # Working again: whatever ended the last link is history now, and the
        # network frame sent on registration says so -- except a SASL login
        # that did not happen, which is why this connection is not logged in
        # and stays the answer to "why" until the next connection tries again.
        self.last_error = self._sasl_error
        self._registered_event.set()
        log.info("%s: registered as %s", self.host, nick)
        if self._on_registered:
            await self._on_registered(nick)

    async def _next_nick(self, msg: Message) -> None:
        """The server refused the nick during registration (432 erroneous, 433
        in use, 436 collision, 437 unavailable). Walk the alternatives, then
        the suffixes, then give up with the server's own words."""
        if self._registration_error is None:
            text = msg.params[-1] if len(msg.params) >= 3 else ""
            refused = msg.param(1) or self.nick
            self._registration_error = f"{refused}: {text}" if text else None
        self._nick_index += 1
        if self._nick_index < len(self.nicks):
            candidate = self.nicks[self._nick_index]
        else:
            step = self._nick_index - len(self.nicks)
            if step >= MAX_NICK_SUFFIXES:
                raise RegistrationFailed(self._registration_error or NOT_ACCEPTED)
            base = self.nicks[0]
            candidate = (base + "_" * (step + 1) if step < 2
                         else f"{base}{random.randint(100, 999)}")
        self.nick = candidate
        await self._write_now(format_line("NICK", candidate))

    # --- CAP and SASL --------------------------------------------------------

    def _sasl_wanted(self) -> bool:
        if self.sasl_mechanism not in SASL_MECHANISMS:
            return False
        if self.sasl_mechanism == "PLAIN":
            return bool(self.sasl_username and self.sasl_password)
        return True

    def _wanted_caps(self, offered: dict[str, str]) -> list[str]:
        wanted = [c for c in REQUESTED_CAPS if c in offered]
        if self._sasl_wanted() and "sasl" in offered and not self.registered:
            # A value, when there is one, lists the mechanisms on offer.
            mechanisms = offered["sasl"]
            if not mechanisms or self.sasl_mechanism in mechanisms.upper().split(","):
                wanted.append("sasl")
            else:
                log.warning("%s: SASL %s is not offered (%s)", self.host,
                            self.sasl_mechanism, mechanisms)
        return wanted

    async def _cap_end(self) -> None:
        if self._cap_state == "done":
            return
        self._cap_state, self._cap_deadline = "done", None
        await self._write_now("CAP END")

    async def _on_cap(self, msg: Message) -> None:
        """CAP LS / ACK / NAK / NEW / DEL. Never shown: it is the connection
        negotiating with itself."""
        sub = msg.param(1).upper()
        args = msg.params[2:]
        names = (args[-1] if args else "").split()
        if sub == "LS":
            for token in names:
                name, _, value = token.partition("=")
                self.caps_offered[name.lower()] = value
            if len(args) >= 2 and args[0] == "*":
                self._cap_state = self._cap_state or "ls"      # more lines to come
                return
            if self.registered or self._cap_state not in (None, "ls"):
                return
            wanted = self._wanted_caps(self.caps_offered)
            if wanted:
                self._cap_state = "req"
                self._cap_deadline = time.monotonic() + self.cap_timeout
                await self._write_now(format_line("CAP", "REQ", " ".join(wanted)))
            else:
                await self._cap_end()
        elif sub == "ACK":
            for name in names:
                if name.startswith("-"):
                    self.caps.discard(name[1:].lower())
                else:
                    self.caps.add(name.lower())
            if self.registered or self._cap_state != "req":
                return
            if "sasl" in self.caps and self._sasl_wanted():
                self._cap_state = "sasl"
                self._cap_deadline = time.monotonic() + self.cap_timeout
                await self._write_now(format_line("AUTHENTICATE", self.sasl_mechanism))
            else:
                await self._cap_end()
        elif sub == "NAK":
            # The whole REQ is refused together. Registering without the
            # extras is better than negotiating them one by one.
            if not self.registered:
                await self._cap_end()
        elif sub == "NEW":
            offered = {}
            for token in names:
                name, _, value = token.partition("=")
                offered[name.lower()] = value
            self.caps_offered.update(offered)
            wanted = [c for c in REQUESTED_CAPS if c in offered and c not in self.caps]
            if wanted and self.registered:
                await self._write_now(format_line("CAP", "REQ", " ".join(wanted)))
        elif sub == "DEL":
            for name in names:
                self.caps_offered.pop(name.lower(), None)
                self.caps.discard(name.lower())

    def _sasl_payload(self) -> list[str]:
        """What follows `AUTHENTICATE +`: the login, base64 in 400-character
        pieces, with a lone `+` after a final piece of exactly 400."""
        if self.sasl_mechanism == "EXTERNAL":
            # The certificate is the credential; an account name, if given,
            # is only which account to log in to.
            if not self.sasl_username:
                return ["+"]
            raw = self.sasl_username.encode()
        else:
            raw = "\0".join((self.sasl_username, self.sasl_username,
                             self.sasl_password)).encode()
        encoded = base64.b64encode(raw).decode()
        chunks = [encoded[i:i + SASL_CHUNK] for i in range(0, len(encoded), SASL_CHUNK)]
        if len(encoded) % SASL_CHUNK == 0:
            chunks.append("+")
        return chunks

    async def _on_sasl_numeric(self, msg: Message) -> None:
        if self._cap_state != "sasl":
            return
        if msg.command in ("903", "907"):           # logged in / already logged in
            self._sasl_ok = True
            await self._cap_end()
        elif msg.command in ("902", "904", "905"):  # nick locked, failed, too long
            self._sasl_error = "SASL login failed"
            log.warning("%s: SASL login failed: %s", self.host, msg.params[-1] if msg.params else "")
            await self._cap_end()
        elif msg.command == "906":                  # aborted
            await self._cap_end()

    async def _cap_timed_out(self) -> None:
        """The server went quiet partway through CAP REQ or SASL. Register
        without whatever was left, rather than wait out REGISTER_TIMEOUT."""
        if self._cap_state == "sasl":
            self._sasl_error = "SASL login failed"
            log.warning("%s: no answer to SASL; registering without it", self.host)
        await self._cap_end()

    # --- reading -----------------------------------------------------------

    async def _read_loop(self) -> None:
        # Held locally: the sender may close the transport under us when a
        # write fails, and the pending read then ends with EOF like any drop.
        reader = self._reader
        assert reader is not None
        buffer = bytearray()
        awaiting_pong = False
        register_by = time.monotonic() + self.register_timeout
        while True:
            if self.registered:
                timeout = self.pong_timeout if awaiting_pong else self.idle_ping_after
            else:
                # Not registered yet: no pinging (a server has nothing to say
                # to PING before 001), but two deadlines of our own. The CAP
                # one ends a stalled REQ or SASL exchange with CAP END; the
                # registration one gives the link up.
                now = time.monotonic()
                if now >= register_by:
                    raise RegistrationFailed(self._registration_error or NOT_ACCEPTED)
                if self._cap_deadline is not None and now >= self._cap_deadline:
                    await self._cap_timed_out()
                    continue
                timeout = register_by - now
                if self._cap_deadline is not None:
                    timeout = min(timeout, self._cap_deadline - now)
            try:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
            except asyncio.TimeoutError:
                if not self.registered:
                    continue                  # a deadline above has come due
                if awaiting_pong:
                    # We pinged, nothing came back. The link is dead even though
                    # the socket is still open; drop it and let the reconnect
                    # loop rebuild it.
                    raise PingTimeout("no response to PING")
                awaiting_pong = True
                await self._write_now(format_line("PING", str(int(time.time()))))
                continue
            awaiting_pong = False
            if not chunk:
                raise ConnectionError("server closed the connection")
            buffer += chunk
            if b"\n" not in chunk:
                # Nothing to hand on yet. Only the unfinished line is held, and
                # never more of it than a line can be.
                if len(buffer) > MAX_LINE_IN:
                    raise ConnectionError(
                        f"the server sent a line longer than {MAX_LINE_IN} bytes")
                continue
            # Split once, rather than partition per line: each partition copied
            # everything after the line it cut off.
            *lines, rest = bytes(buffer).split(b"\n")
            buffer = bytearray(rest)
            if len(buffer) > MAX_LINE_IN:
                raise ConnectionError(
                    f"the server sent a line longer than {MAX_LINE_IN} bytes")
            for raw in lines:
                # IRC predates UTF-8 and QuakeNet does not enforce it: a single
                # latin-1 nick must not be able to kill the connection, so decode
                # is always total, never strict -- and falls back to cp1252 per
                # line rather than replacing, so the text survives. See
                # ircproto.decode_line.
                line = decode_line(raw).rstrip("\r")
                if not line:
                    continue
                msg = parse_line(line)
                if msg is None:
                    continue
                await self._handle(msg)

    async def _handle(self, msg: Message) -> None:
        # Two commands are answered here rather than in the session, because they
        # are about the connection itself and must work even if nothing is
        # listening downstream.
        if msg.command == "PING":
            await self._write_now(format_line("PONG", msg.param(0)))
            return
        if msg.command == "ERROR":
            log.warning("%s: ERROR from server: %s", self.host, msg.param(0))
            # The server says why before it closes the link; keep it as the
            # reason, since what follows looks like any other closed socket.
            self._server_error = msg.param(0) or "the server sent ERROR"

        # CAP and AUTHENTICATE are the connection negotiating with itself, and
        # are never passed on.
        if msg.command == "CAP":
            await self._on_cap(msg)
            return
        if msg.command == "AUTHENTICATE":
            if self._cap_state == "sasl" and msg.param(0) == "+":
                for chunk in self._sasl_payload():
                    await self._write_now(format_line("AUTHENTICATE", chunk))
            return

        if not self.registered:
            if msg.command == "001":                       # RPL_WELCOME
                await self._on_registration_complete(msg.param(0) or self.nick)
            elif msg.command in ("432", "433", "436", "437"):
                # Erroneous, in use, collision, unavailable: another nick.
                await self._next_nick(msg)
                return
            elif msg.command in ("421", "451") and msg.param(1).upper() == "CAP":
                # "Unknown command": a server that does not speak CAP, like
                # QuakeNet's. Registration goes on without it, and the refusal
                # is not worth a line in the status buffer on every connect.
                return
            elif msg.command in ("900", "902", "903", "904", "905", "906", "907"):
                await self._on_sasl_numeric(msg)           # and on to the session

        try:
            await self._on_message(msg)
        except Exception:
            log.exception("message handler failed for %s", msg.command)

    # --- writing -----------------------------------------------------------

    async def _write_now(self, line: str) -> None:
        """Bypass the queue. For protocol-level replies (PONG, registration) only:
        these must not sit behind a queue of user text or the server times us out.

        Bypassing the queue is not bypassing the count. Once registered, the
        server charges every line the same, PONG included, so every write here
        spends a token -- the bucket may go below zero, and the queue then
        waits for it to recover.

        Registration is not charged. CAP, PASS, NICK, USER, AUTHENTICATE and
        the PONG to a connect cookie go before the server starts its flood
        clock for us (ircu starts counting a client's lines once it is a user;
        so do hybrid, InspIRCd and solanum), and charging them left a SASL
        network's bucket at -3 on 001: the first JOIN then waited ten seconds.
        """
        if self._writer is None:
            raise ConnectionError("not connected")
        if log.isEnabledFor(logging.DEBUG):
            # With -v every line is logged. A password is not: PASS, a SASL
            # payload and an IDENTIFY to a service are cut to their verb.
            log.debug(">> %s", redact_line(line))
        self._refill()
        if self.registered:
            self._tokens -= 1.0
        self._writer.write(encode_line(line) + b"\r\n")
        await self._writer.drain()

    def _refill(self) -> None:
        now = time.monotonic()
        self._tokens = min(float(self.send_burst),
                           self._tokens + (now - self._tokens_at) / self.send_interval)
        self._tokens_at = now

    async def _wait_for_token(self) -> None:
        self._refill()
        while self._tokens < 1.0:
            await asyncio.sleep((1.0 - self._tokens) * self.send_interval)
            self._refill()

    @property
    def queue_depth(self) -> int:
        """Lines still waiting to go out. Callers use it to refuse work before
        adding to a queue that is already minutes deep."""
        return self._send_queue.qsize() + (1 if self._in_flight is not None else 0)

    @property
    def queue_room(self) -> int:
        """How many more lines the queue will take right now."""
        return SEND_QUEUE_MAX - self._send_queue.qsize()

    @property
    def spare(self) -> bool:
        """Could a line the bouncer wants for itself go now without delaying
        anything the user types? Nothing queued, and two tokens left, so that
        after it goes the user's next line still has one to go out at once.

        What the session's background lines wait for (MODE after a join, the
        WHO and ISON polls): they are worth sending, but never at the price of
        someone's message sitting behind them.
        """
        if not self.registered or self.queue_depth:
            return False
        self._refill()
        return self._tokens >= 2.0

    def send(self, line: str, *, on_sent: Callable[[], None] | None = None,
             on_dropped: Callable[[str], None] | None = None) -> bool:
        """Queue a line for the rate limiter. Never blocks, never raises.

        Returns False, and reports the line dropped, when the queue is full.
        """
        item = Outbound(line, on_sent, on_dropped)
        try:
            self._send_queue.put_nowait(item)
        except asyncio.QueueFull:
            # Dropping the newest line is the least bad option: blocking would
            # stall whatever is calling (the IRC read loop, in the CTCP case),
            # and growing the queue further only delays the user's own messages
            # by more. The warning is what makes it visible in the journal.
            log.warning("%s: outbound queue full at %d lines; dropped one",
                        self.host, SEND_QUEUE_MAX)
            self._report_dropped(item, "sending too fast")
            return False
        return True

    def send_command(self, command: str, *params: str,
                     on_sent: Callable[[], None] | None = None,
                     on_dropped: Callable[[str], None] | None = None) -> bool:
        return self.send(format_line(command, *params), on_sent=on_sent, on_dropped=on_dropped)

    async def _drain_send_queue(self, writer: asyncio.StreamWriter) -> None:
        """The one sender for one connection. Ends when that connection does."""
        while self._writer is writer:
            item = await self._send_queue.get()
            self._in_flight = item
            await self._wait_for_token()
            if self._writer is not writer:
                # The link went while this line waited for its turn. It stays in
                # flight so the disconnect reports it with the rest.
                return
            try:
                await self._write_now(item.line)
            except Exception as exc:
                # The socket is broken even if the read loop has not noticed yet.
                # Closing it makes the read loop notice now, so the disconnect
                # path runs, reports this line and everything behind it as not
                # sent, and reconnects -- rather than leaving a queue with no
                # sender until the idle ping finally gives up.
                log.warning("%s: write failed (%s); dropping the connection", self.host, exc)
                self._close_transport()
                return
            self._in_flight = None
            if item.on_sent is not None:
                try:
                    item.on_sent()
                except Exception:
                    log.exception("on_sent handler failed")
