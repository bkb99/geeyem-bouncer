"""Push notifications for highlights that arrive while nothing is watching.

Deliberately behind an interface with a no-op default. The bouncer must run, and
be developed against, with no APNs key present -- pushing is the last mile, not a
precondition. With no key configured this logs the notification it would have
sent, which is also exactly what you want in local testing.

The real provider is APNs over HTTP/2 with token (.p8) auth: a single ES256 JWT,
refreshed every 45 minutes, sent as `authorization: bearer`. That needs an
HTTP/2 client (httpx[http2]) and `cryptography` for the signature; both are in
requirements.txt and neither is imported until a key is configured.
See docs/ARCHITECTURE.md, "Push notifications".

Two things are pushed. A Notification is the alert: a line that should be seen.
A ReadReceipt is its opposite, sent once the line HAS been seen somewhere else:
a background push that shows nothing, and lets the other devices take the alert
back down and correct their badge.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

log = logging.getLogger("relay.push")


@dataclass
class Notification:
    title: str          # "#hangout" or the sender's nick for a query
    body: str           # "<nick> the line that mentioned you"
    buffer_id: int
    eid: int
    network: str
    badge: int | None = None
    # A follow-up inside the hub's quiet window (see hub.PUSH_QUIET_WINDOW):
    # delivered and listed, but without a sound and without lighting the screen.
    #
    # Apple's way of saying that is two keys, both in the aps dictionary. Leaving
    # out "sound" is what makes an alert silent -- there is no "sound": null.
    # And "interruption-level": "passive" (iOS 15+) adds it to Notification
    # Centre without waking the screen or breaking through Focus; older iOS
    # ignores the key and still gets the silence from the missing sound. Passive
    # needs no entitlement, unlike time-sensitive and critical.
    #
    # What is deliberately NOT used any more: apns-collapse-id. It made each
    # notification for a conversation REPLACE the one before it, so alice's
    # mention erased bob's question from the lock screen. thread-id already
    # groups a conversation's notifications into one stack without losing any.
    quiet: bool = False
    # The notification category the app registered its actions under. iOS
    # shows the Reply and Mark as Read actions only on a notification that
    # names it, so every message push (a mention, a PM, a notify "all" line,
    # an invite -- which is every push there is today) carries "message".
    # None leaves the key out, for some future push that is not a message.
    category: str | None = "message"
    # Who said it: the nick, as the event's `from` has it. In the payload's
    # `relay` so the app's notification extension can tell who a notification
    # is from without parsing "nick: text" back out of the alert body -- which,
    # with previews off, is not even there to parse.
    sender: str | None = None
    # The sound the person chose (store setting `push_sound`): "default", "none",
    # or the name of a sound bundled in the iOS app. The app plays
    # "<name>.caf"; an app that lacks the file plays the default instead, which
    # is how iOS treats a missing one, so a new name is safe to send early.
    sound: str = "default"

    # How APNs is to treat it (see apns.APNsClient.headers). An alert is
    # delivered at once: a highlight is the whole reason this service exists,
    # and delaying it to save battery defeats the point.
    apns_push_type = "alert"
    apns_priority = "10"

    def to_apns_payload(self, thread_id: str) -> dict:
        aps: dict = {
            "alert": {"title": self.title, "body": self.body},
            "thread-id": thread_id,
            # A highlight is worth waking the app for so it can pre-fetch the
            # surrounding backlog; the user opening the notification then
            # lands on a conversation that is already there.
            "mutable-content": 1,
            **({"badge": self.badge} if self.badge is not None else {}),
            **({"category": self.category} if self.category else {}),
        }
        if self.quiet:
            aps["interruption-level"] = "passive"
        elif self.sound == "none":
            pass            # a banner, no sound: the key is simply left out
        elif self.sound == "default":
            aps["sound"] = "default"
        else:
            aps["sound"] = f"{self.sound}.caf"
        return {
            "aps": aps,
            "relay": {
                "buffer": self.buffer_id,
                "eid": self.eid,
                "network": self.network,
                **({"from": self.sender} if self.sender else {}),
            },
        }


@dataclass
class ReadReceipt:
    """A read marker moved on one device; the others are told, silently.

    Reading #hangout on the Mac used to leave its banners on the phone's
    lock screen, and its number on the app icon, until the phone was next
    opened. This is the push that takes them down: no alert and no sound, only
    `content-available`, which wakes the app for a moment in the background to
    remove the delivered notifications for that buffer at or below `eid` and
    to set the badge.

    `buffer_id` None means everything was read at once (`mark_all_read`), and
    the app clears every notification it has up.
    """

    buffer_id: int | None
    eid: int | None
    # The same number an alert sent now would carry (Store.badge_count).
    badge: int = 0

    # Apple's rules for a push that shows nothing: the type must say
    # "background" and the priority must be 5. A background push sent at 10 is
    # refused, and one without the type is not delivered at all on iOS 13+.
    apns_push_type = "background"
    apns_priority = "5"

    def to_apns_payload(self) -> dict:
        read: dict = ({"all": True} if self.buffer_id is None
                      else {"buffer": self.buffer_id, "eid": self.eid})
        return {
            "aps": {"content-available": 1, "badge": self.badge},
            "relay": {"read": read},
        }


class PushProvider(Protocol):
    async def send(self, notification: Notification, devices: list[dict]) -> None: ...

    async def send_read(self, receipt: ReadReceipt, devices: list[dict]) -> None: ...


class NullPushProvider:
    """Logs and drops. The default until an APNs key exists."""

    async def send(self, notification: Notification, devices: list[dict]) -> None:
        log.info(
            "PUSH (not sent, no APNs configured) -> %d device(s)%s: [%s] %s",
            len(devices), " quiet" if notification.quiet else "",
            notification.title, notification.body,
        )

    async def send_read(self, receipt: ReadReceipt, devices: list[dict]) -> None:
        # DEBUG, not INFO: one of these can follow every read, and a line in
        # the journal for each would bury the alerts above, which are the ones
        # worth seeing on a rig.
        log.debug("READ PUSH (not sent, no APNs configured) -> %d device(s): %s",
                  len(devices), receipt.to_apns_payload()["relay"]["read"])


class APNsPushProvider:
    """Real delivery, via relay.apns.

    Holds one client per environment. A device registers as sandbox or
    production depending on how the app was signed, and sending a sandbox token
    to the production host fails with a reason that reads like a bad token --
    which sends you looking in exactly the wrong place. Keeping them apart at
    this level is what stops that.
    """

    def __init__(self, key_path: str, key_id: str, team_id: str, topic: str, sandbox: bool = True,
                 forget_device=None):
        from .apns import APNsClient

        self.key_path, self.key_id = key_path, key_id
        self.team_id, self.topic = team_id, topic
        self.default_sandbox = sandbox
        # Called with a device token that APNs says is dead.
        self.forget_device = forget_device
        self._clients: dict[bool, APNsClient] = {}
        self._make_client = lambda sb: APNsClient(
            key_path=key_path, key_id=key_id, team_id=team_id, topic=topic, sandbox=sb
        )

    def client_for(self, sandbox: bool):
        if sandbox not in self._clients:
            self._clients[sandbox] = self._make_client(sandbox)
        return self._clients[sandbox]

    async def send(self, notification: Notification | ReadReceipt,
                   devices: list[dict]) -> None:
        by_environment: dict[bool, list[str]] = {}
        for device in devices:
            sandbox = device.get("environment", "sandbox") != "production"
            by_environment.setdefault(sandbox, []).append(device["apns_token"])

        for sandbox, tokens in by_environment.items():
            results = await self.client_for(sandbox).send(notification, tokens)
            for result in results:
                if result.drop and self.forget_device:
                    self.forget_device(result.device_token)

    async def send_read(self, receipt: ReadReceipt, devices: list[dict]) -> None:
        """The same road as an alert -- the same split by environment, the
        same forgetting of a device Apple says is gone -- with the receipt's
        own payload and headers (see apns.APNsClient.headers)."""
        await self.send(receipt, devices)

    async def aclose(self) -> None:
        for client in self._clients.values():
            await client.aclose()


def build_provider(config, forget_device=None) -> PushProvider:
    """A real provider when every piece of APNs configuration is present, and a
    logging no-op otherwise.

    All four are required together: a key path with no team id is a
    misconfiguration that would fail on the first highlight, at which point the
    useful signal is long gone. Failing over to the no-op and saying so at
    startup is louder than a stack trace at 3am.
    """
    pieces = (config.apns_key_path, config.apns_key_id, config.apns_team_id, config.apns_topic)
    if all(pieces):
        log.info("APNs configured for topic %s (%s)", config.apns_topic,
                 "sandbox" if config.apns_use_sandbox else "production")
        return APNsPushProvider(*pieces, config.apns_use_sandbox, forget_device=forget_device)
    if any(pieces):
        log.warning("APNs is partly configured and will NOT be used; need key path, "
                    "key id, team id and topic. Falling back to logging pushes.")
    return NullPushProvider()
