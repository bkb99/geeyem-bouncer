"""The hub: who is attached right now, and what they should be told.

Kept separate from the websocket plumbing so that `session.py` can broadcast
without importing aiohttp, and so the IRC half can be tested with a hub that has
no clients in it at all.

THE RULE: nothing in here waits on a client. A broadcast serialises the frame
once and hands the string to each client's own outbound queue; each client has
its own writer task that does the actual socket writes, and a client that stops
reading falls behind on its own and is cut loose on its own (see gateway.Client).
It used to await a send to every client in turn, which meant one laptop asleep
with its tab open froze the IRC read loop -- PONGs included, until QuakeNet
timed the bouncer out.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Protocol

from . import protocol as P
from .push import Notification, NullPushProvider, PushProvider, ReadReceipt
from .store import Store

log = logging.getLogger("relay.hub")

# After a notification for a conversation makes a sound, further ones for the
# same conversation inside this window arrive quietly: shown and counted, but no
# sound and no lit screen. A burst of twenty mentions used to buzz the phone
# twenty times. See Notification.quiet for how "quietly" is said to APNs.
PUSH_QUIET_WINDOW = 60.0

# With the `auto_away` setting on, this long with no client attached marks the
# user away (soju does the same). Ten minutes rides out a phone locking and a
# laptop lid closing for a moment without flapping away and back.
AUTO_AWAY_AFTER = 600.0

# A client's "foreground" counts only while it is heard from: its ping is every
# ~30s, so past this it has most likely gone (a phone suspended mid-conversation
# sends nothing, and its socket lingers until the websocket heartbeat gives up,
# up to ~45s). Until 2026-09-26 the stale presence stood for that whole time and
# a mention in the open conversation did not push.
#
# Two pings and a margin, not one. It was 40 until 2026-10: ten seconds over a
# 30-second ping, so a single ping that ran late -- a browser throttling a
# background tab's timers, a phone on a slow cell -- expired the presence of
# someone looking straight at the conversation, and a mention in it pushed to
# every device they own. At 70 one late or lost ping is ridden out and it takes
# two in a row to read as gone. The price is the other direction: a phone that
# is suspended without saying so goes on counting as watching for up to 70
# seconds rather than 40. The apps say "background" as they leave, which ends
# it at once; this only bounds the case where that frame never arrived.
PRESENCE_TTL = 70.0

# How long after a read on one device before the others are told by push (see
# Hub.read_elsewhere), counted per buffer from the first read not yet sent.
# Reading is a run of `mark_read` frames, one as each new line is seen, and a
# push for each would be a stream of them at a phone in a pocket: Apple delivers
# a background push when it suits the device and stops delivering to an app that
# is sent too many.
READ_PUSH_DEBOUNCE = 2.0


class ClientLike(Protocol):
    """What the hub needs from an attached client. Implemented by gateway.Client."""

    presence: str            # "foreground" | "background" | "unknown"
    focused_buffer: int | None
    # time.monotonic() of the last frame from this client. Optional on the
    # fakes the tests use: missing means "just heard from".
    last_heard: float


    def enqueue(self, data: str) -> None: ...


class Hub:
    def __init__(self, store: Store, push_provider: PushProvider):
        self.store = store
        self.push_provider = push_provider
        self.clients: set[ClientLike] = set()
        # Filled in by app.py once the sessions exist. The hub needs them to
        # route a client's `say` to the right network.
        self.sessions: dict[str, Any] = {}
        # Set by app.py. The gateway calls these when a client asks to connect
        # to or forget a network; the hub is just the place both can see.
        self.add_network = None
        self.remove_network = None
        # And these when a client edits a network or turns it on or off.
        self.edit_network = None
        self.connect_network = None
        # Web Push to browsers (relay.webpush.WebPushSender), set by app.py.
        # None: only APNs.
        self.webpush = None
        # When each buffer last had a notification that made a sound.
        self._last_audible_push: dict[int, float] = {}
        self.push_quiet_window = PUSH_QUIET_WINDOW
        self.presence_ttl = PRESENCE_TTL
        # Deliveries in progress. Held so they are not garbage collected
        # mid-flight; see push().
        self._push_tasks: set[asyncio.Task] = set()
        # Auto-away: how long with nobody attached before the bouncer marks the
        # user away (when the `auto_away` setting is on), the timer counting
        # it down, and whether it has fired and not yet been undone.
        self.auto_away_after = AUTO_AWAY_AFTER
        self._idle_task: asyncio.Task | None = None
        self.auto_away_active = False
        # Reads waiting to be pushed to the other devices (see read_elsewhere):
        # per buffer id -- None for "everything" -- the token that read and the
        # eid it read to, and the timer that will send it.
        self.read_push_debounce = READ_PUSH_DEBOUNCE
        self._reads_pending: dict[int | None, tuple[int, int | None]] = {}
        self._read_timers: dict[int | None, asyncio.TimerHandle] = {}
        self._read_pushes_off = False        # set at shutdown
        # What the other devices have last been told, so a read that changes
        # nothing for them is not pushed at all: the buffers with no alert
        # pushed since their last read receipt, and the badge last sent.
        # Empty and None at startup, which is "not known": the first read of
        # each buffer after a restart is always sent.
        self._read_settled: set[int] = set()
        self._badge_sent: int | None = None

    @property
    def apns_configured(self) -> bool:
        """Is there an APNs provider behind `register_push`, or only the one
        that logs? What `hello.apns` says, so the app can tell someone that
        this bouncer cannot notify them rather than registering into a void."""
        return not isinstance(self.push_provider, NullPushProvider)

    def add(self, client: ClientLike, *, ready: bool = True) -> None:
        """Attach a client. `ready=False` holds back taking an automatic away
        back until client_ready(): the gateway attaches a socket before its
        hello is queued (so nothing live is missed), and the `network` frame
        that clearing the away publishes reached the new client ahead of its
        hello until 2026-09-26 -- the first frame on a socket must be hello."""
        self.clients.add(client)
        log.info("client attached (%d now)", len(self.clients))
        # Someone is back: stop counting, and take back an automatic away.
        self._cancel_idle()
        if ready:
            self.client_ready()

    def client_ready(self) -> None:
        """A client has been sent its hello: an automatic away can go."""
        if self.auto_away_active:
            self.auto_away_active = False
            for session in list(self.sessions.values()):
                session.set_auto_away(False)

    def discard(self, client: ClientLike) -> None:
        if client in self.clients:
            self.clients.discard(client)
            log.info("client detached (%d left)", len(self.clients))
            if not self.clients:
                self.start_idle_timer()

    # --- auto-away ---------------------------------------------------------

    def start_idle_timer(self) -> None:
        """Start counting towards auto-away, if nobody is attached. Called when
        the last client leaves, and once at startup, when nobody ever was."""
        if self.clients or (self._idle_task is not None and not self._idle_task.done()):
            return
        try:
            self._idle_task = asyncio.get_running_loop().create_task(
                self._idle_then_away(), name="auto-away")
        except RuntimeError:
            self._idle_task = None           # no loop: a unit test's hub

    def _cancel_idle(self) -> None:
        task, self._idle_task = self._idle_task, None
        if task is not None and not task.done() and task is not asyncio.current_task():
            task.cancel()

    async def _idle_then_away(self) -> None:
        await asyncio.sleep(self.auto_away_after)
        if self.clients or not self.store.get_setting("auto_away"):
            return
        log.info("nobody attached for %.0fs; marking away", self.auto_away_after)
        self.auto_away_active = True
        for session in list(self.sessions.values()):
            session.set_auto_away(True)

    def auto_away_changed(self) -> None:
        """The `auto_away` setting was changed. Turned off, an automatic away
        in force is taken back; turned on, the count starts if nobody is here
        (it cannot be, today: the setting is changed from an attached client)."""
        if self.store.get_setting("auto_away"):
            self.start_idle_timer()
        elif self.auto_away_active:
            self.auto_away_active = False
            for session in list(self.sessions.values()):
                session.set_auto_away(False)

    def publish(self, frame: dict[str, Any]) -> None:
        """Queue a frame for every attached client. Never waits, never raises.

        Serialised once, not once per client: the same string goes into every
        queue.
        """
        if not self.clients:
            return
        data = P.dumps(frame)
        for client in list(self.clients):
            try:
                client.enqueue(data)
            except Exception:
                log.exception("could not queue a frame for a client")

    async def broadcast(self, frame: dict[str, Any]) -> None:
        """The awaitable spelling of publish(), for the many callers that
        already await it. It does not wait on any socket; see the module note."""
        self.publish(frame)

    def has_active_viewer(self, buffer_id: int) -> bool:
        """Is someone actually looking at this buffer right now?

        Only a foregrounded client counts, and only one with this buffer on
        screen. Anything else -- backgrounded, attached but unfocused, presence
        never reported -- is treated as away, so the notification goes out. An
        extra notification is a small annoyance; a missed one is the failure the
        user notices.
        """
        now = time.monotonic()
        return any(
            c.presence == "foreground" and c.focused_buffer == buffer_id
            and now - getattr(c, "last_heard", now) <= self.presence_ttl
            for c in self.clients
        )

    def _quiet_for(self, buffer_id: int, now: float | None = None) -> bool:
        """Should this notification be delivered without a sound?

        Measured from the last one that DID make a sound, not from the last one
        at all: otherwise a conversation that kept going at one mention every
        fifty seconds would never make a sound again.
        """
        now = time.monotonic() if now is None else now
        last = self._last_audible_push.get(buffer_id)
        if last is not None and now - last < self.push_quiet_window:
            return True
        self._last_audible_push[buffer_id] = now
        return False

    async def push(self, notification: Notification) -> None:
        """Hand a notification to the provider, without waiting for it.

        Delivery is an HTTP round trip to Apple per device, and this is called
        from the IRC read loop. Awaiting it there meant a slow or unreachable
        APNs held up every line behind the mention, which is the same failure
        as a slow client and gets the same answer: the read loop never waits
        on anything downstream.
        """
        # Only devices registered under a token that is still valid. A revoked
        # token's phone must stop receiving message text on its lock screen.
        # Browsers the same: Web Push follows exactly these rules, from the same
        # Notification -- the same decision to push, the same text, the same
        # quiet window -- so a web client and the phone never disagree.
        devices = self.store.devices()
        browsers = self.store.webpush_subscriptions() if self.webpush is not None else []
        if not devices and not browsers:
            log.debug("highlight with no registered devices; nothing to push")
            return
        notification.quiet = self._quiet_for(notification.buffer_id)
        log.info("push: eid %s in buffer %s -> %d device(s), %d browser(s)%s",
                 notification.eid, notification.buffer_id, len(devices), len(browsers),
                 " (quiet: no sound)" if notification.quiet else "")
        if devices:
            # A notification for this buffer may now be up on a phone, with
            # this badge: the next read of it elsewhere is worth a push.
            self._read_settled.discard(notification.buffer_id)
            if notification.badge is not None:
                self._badge_sent = notification.badge
            self._spawn(self._deliver(notification, devices))
        if browsers:
            self._spawn(self._deliver_web(notification, browsers))

    # --- read elsewhere ----------------------------------------------------

    def read_elsewhere(self, token_id: int, buffer_id: int | None,
                       eid: int | None = None) -> None:
        """A read marker advanced under `token_id`: after a pause, tell every
        APNs device NOT registered under that token, by background push, so it
        can take down the notifications that have now been read and set its
        badge. `buffer_id` None is "everything" (`mark_all_read`).

        Never waits and never raises; the gateway calls it in the middle of
        answering a frame. Only APNs: a browser's push service penalises a
        push that shows nothing, and an open page hears the `read_marker` on
        its socket anyway.

        Debounced per buffer, counted from the first read not yet sent, so a
        run of reads is one push carrying the newest eid -- and so someone
        reading along with a busy channel cannot hold the push off for ever,
        which restarting the wait on every read would do.

        "Everything" is not debounced. It is one deliberate action, not a
        run of them, and it stands for whatever single buffers were still
        waiting, so those are dropped and it goes at once: its push says
        "take them all down" with no eid to stop at, and every moment it
        waits is a moment in which a NEW mention could arrive on the phone
        and be taken down with the rest.
        """
        if self._read_pushes_off:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return                                       # no loop: a unit test's hub
        if buffer_id is None:
            for timer in self._read_timers.values():
                timer.cancel()
            self._read_timers.clear()
            self._reads_pending.clear()
            self._reads_pending[None] = (token_id, None)
            self._send_read(None)
            return
        self._reads_pending[buffer_id] = (token_id, eid)
        if buffer_id not in self._read_timers:
            self._read_timers[buffer_id] = loop.call_later(
                self.read_push_debounce, self._send_read, buffer_id)

    def cancel_read_pushes(self) -> None:
        """Shutting down: the reads still waiting are not sent. The devices
        learn the markers when they next attach, as they always could."""
        self._read_pushes_off = True
        for timer in self._read_timers.values():
            timer.cancel()
        self._read_timers.clear()
        self._reads_pending.clear()

    def _send_read(self, buffer_id: int | None) -> None:
        """The debounce ran out: push the read, if it tells anyone anything."""
        self._read_timers.pop(buffer_id, None)
        pending = self._reads_pending.pop(buffer_id, None)
        if pending is None:
            return
        try:
            token_id, eid = pending
            devices = [d for d in self.store.devices() if d.get("token_id") != token_id]
            if not devices:
                return
            badge = self.store.badge_count()
            # Nothing to take down and nothing to correct: no alert has gone
            # out for this buffer since the last receipt for it, and the badge
            # the devices hold is already right. This is most reads -- the
            # desktop following a channel as it scrolls -- and each would
            # otherwise be a push that wakes the phone to do nothing.
            if (buffer_id is not None and buffer_id in self._read_settled
                    and badge == self._badge_sent):
                return
            if buffer_id is None:
                self._read_settled = {b.id for b in self.store.buffers(include_archived=True)}
            else:
                self._read_settled.add(buffer_id)
            self._badge_sent = badge
            self._spawn(self._deliver_read(ReadReceipt(buffer_id, eid, badge), devices))
        except Exception:
            log.exception("could not push a read to the other devices")

    async def _deliver_read(self, receipt: ReadReceipt, devices: list[dict]) -> None:
        # A provider from before read receipts (a test's recorder) has no
        # send_read; it is simply not told.
        send_read = getattr(self.push_provider, "send_read", None)
        if send_read is None:
            return
        try:
            await send_read(receipt, devices)
        except Exception:
            log.exception("read push delivery failed")

    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._push_tasks.add(task)
        task.add_done_callback(self._push_tasks.discard)

    async def _deliver_web(self, notification: Notification, browsers: list[dict]) -> None:
        try:
            await self.webpush.send(notification, browsers)
        except Exception:
            log.exception("web push delivery failed")

    async def _deliver(self, notification: Notification, devices: list[dict]) -> None:
        try:
            await self.push_provider.send(notification, devices)
        except NotImplementedError:
            log.info("push provider not implemented yet: [%s] %s",
                     notification.title, notification.body)
        except Exception:
            log.exception("push delivery failed")
