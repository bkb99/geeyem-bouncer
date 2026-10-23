"""Wiring: build the store, the hub, the sessions and the gateway, then run."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import signal

from .config import Config, NetworkConfig
from .gateway import Gateway
from .hub import Hub
from .ircproto import fold
from .netfields import split_channel_keys
from . import protocol as P
from .push import build_provider
from .session import NetworkSession
from .store import Store

log = logging.getLogger("relay")

# The loop-lag probe (watch_loop_lag): how often it looks, how late it has to
# wake before that is worth a line, and the least time between two lines.
LAG_PROBE_INTERVAL = 0.5
LAG_WARN_AFTER = 0.25
LAG_REPORT_EVERY = 60.0


async def watch_loop_lag(interval: float = LAG_PROBE_INTERVAL,
                         threshold: float = LAG_WARN_AFTER,
                         report_every: float = LAG_REPORT_EVERY) -> None:
    """Say so in the journal when the event loop was held.

    Everything runs on one loop: the IRC links and their PONGs, every client's
    frames, and every SQLite query (see the threading note in store.py). One
    slow thing therefore stops all of it, and nothing measured that -- a search
    that scanned the whole history, or an export paging a large buffer, showed
    up only as everyone's messages arriving late for no visible reason. This
    is the cheap half of the answer: it does not fix a slow call, it makes one
    visible, with a time to look for in the journal beside it.

    It sleeps `interval` and sees how late it woke. The loop cannot have run
    anything during the lateness, so that is how long something held it -- or
    how long the whole process was not running (a suspended laptop, a VPS whose
    neighbour took the CPU), which reads the same from in here and is worth
    knowing about too.

    At most one line per `report_every`, however often it happens: the first
    stall is reported at once, and the ones in the quiet period after it are
    counted and reported, with the worst of them, by the next line. A loop
    that is stalling constantly is a line a minute, not a line a stall.
    """
    loop = asyncio.get_running_loop()
    last_report = float("-inf")
    held_back, worst = 0, 0.0
    while True:
        before = loop.time()
        await asyncio.sleep(interval)
        now = loop.time()
        lag = now - before - interval
        if lag <= threshold:
            continue
        if now - last_report < report_every:
            held_back += 1
            worst = max(worst, lag)
            continue
        more = (f"; and {held_back} more since the last report, the longest {worst * 1000:.0f} ms"
                if held_back else "")
        log.warning("the event loop was blocked for %.0f ms%s", lag * 1000, more)
        last_report, held_back, worst = now, 0, 0.0


class Relay:
    def __init__(self, config: Config):
        self.config = config
        self.store = Store(config.db_path)
        # The provider needs to be able to forget a device APNs reports as gone,
        # and the store is what owns that list.
        self.hub = Hub(self.store, build_provider(config, forget_device=self.store.forget_device))
        self.hub.webpush = build_webpush(self.store, config)
        self.gateway = Gateway(config, self.store, self.hub)
        self.sessions: list[NetworkSession] = []
        self._lag_task: asyncio.Task | None = None

    async def run(self) -> None:
        # Networks come from two places: config.json, and whatever a client has
        # added since. The file wins on conflict -- it is the one a human edited
        # deliberately -- but it is no longer the only way in, so the app can ask
        # for a nick and a server on first launch instead of making someone SSH
        # to a box to edit a file. And a client can now EDIT a network from the
        # file too: the fields it edited are kept in the database and win over
        # the file from then on, while every field it did not touch keeps
        # following the file (see network_from_file).
        records = {r["slug"]: r for r in self.store.networks()}
        nets: list[NetworkConfig] = []
        for net in self.config.networks:
            if not net.enabled:
                log.info("network %s is disabled, skipping", net.slug)
                continue
            record = records.get(net.slug)
            # A "#chan key" entry in the file is a channel and its key. Taken
            # apart here, before the list goes anywhere, so `channels` is
            # names only from this line on: it is what the network frame shows.
            names, file_keys = split_channel_keys(net.channels)
            net = dataclasses.replace(net, channels=names,
                                      channel_keys={**net.channel_keys, **file_keys})
            config_channels = list(net.channels)
            net = network_from_file(net, record)
            # Persist what the file says (with the client's edits on top), so
            # the client sees one list and `source` records which is which.
            self.store.save_network(
                slug=net.slug, name=net.name, host=net.host, port=net.port,
                tls=net.tls, nick=net.nick, username=net.username,
                realname=net.realname, channels=net.channels, source="config",
                config_channels=config_channels, alt_nicks=net.alt_nicks,
                q_username=net.q_username, channel_keys=net.channel_keys,
            )
            nets.append(net)
        from_file = {n.slug for n in self.config.networks}
        for slug, record in records.items():
            if slug not in from_file:
                nets.append(network_from_record(record))

        for net in nets:
            self._attach(net)

        self.hub.add_network = self.add_network
        self.hub.remove_network = self.remove_network
        self.hub.edit_network = self.edit_network
        self.hub.connect_network = self.connect_network

        if not self.sessions:
            # Not an error: this is a fresh install, and the gateway comes up
            # anyway so a client can attach, see hello.has_networks is false,
            # and add one. Say so once, rather than a silent process that
            # looks like it is doing nothing.
            log.info("no networks configured; waiting for a client to add one")

        await self.gateway.start()
        if self.config.first_run_setup:
            # After start, so the page answers by the time its code is printed.
            self.gateway.open_setup()
        for session in self.sessions:
            session.start()
        # Nobody is attached yet, so auto-away starts counting from now.
        self.hub.auto_away_after = self.config.auto_away_after
        self.hub.start_idle_timer()
        self._lag_task = asyncio.create_task(watch_loop_lag(), name="loop-lag")

        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            # A bouncer gets SIGTERM on every deploy. Handling it means sending a
            # real QUIT upstream, so the channel sees "relay restarting" instead
            # of a ping timeout two minutes later.
            try:
                loop.add_signal_handler(sig, stop.set)
            except NotImplementedError:
                pass
        log.info("relay up; %d network(s)", len(self.sessions))
        await stop.wait()
        log.info("shutting down")
        await self.shutdown()

    def _attach(self, net: NetworkConfig) -> NetworkSession:
        session = NetworkSession(net, self.store, self.hub,
                                 allow_private_hosts=self.config.allow_private_hosts)
        self.sessions.append(session)
        self.hub.sessions[net.slug] = session
        return session

    async def add_network(self, *, name: str, host: str, port: int, tls: bool,
                          nick: str, channels: list[str], **extra) -> dict:
        """Connect to a network a client just described. Starts it immediately.

        `extra` is whatever else the client sent that edit_network also takes
        (alt_nicks, username, realname, password, sasl, Q login), already
        checked by relay/netfields.py and named as NetworkConfig fields.
        """
        slug = _slugify(name or host)
        if slug in self.hub.sessions:
            raise ValueError(f"already connected to {name}")
        username = extra.pop("username", "") or nick
        realname = extra.pop("realname", "") or nick
        # {name: key} from "#secret hunter2" entries; kept by folded name.
        channel_keys = {fold(c): k for c, k in (extra.pop("channel_keys", None) or {}).items()}
        net = NetworkConfig(slug=slug, name=name or host, host=host, port=port,
                            tls=tls, nick=nick, username=username, realname=realname,
                            channels=channels, source="client",
                            channel_keys=channel_keys, **extra)
        network_id = self.store.save_network(
            slug=slug, name=net.name, host=host, port=port, tls=tls, nick=nick,
            username=username, realname=realname, channels=channels, source="client",
            enabled=True, alt_nicks=net.alt_nicks, q_username=net.q_username,
            channel_keys=channel_keys)
        secrets = {"server_password": net.password, "sasl_mechanism": net.sasl_mechanism,
                   "sasl_username": net.sasl_username, "sasl_password": net.sasl_password,
                   "q_password": net.stored_q_password}
        self.store.set_network_fields(network_id, {k: v for k, v in secrets.items() if v})
        session = self._attach(net)
        # Every client hears of the network and its Server buffer before the
        # first line lands in it ("connecting to ..."), per the ordering rule
        # in docs/PROTOCOL.md: an event never names a buffer a client has not
        # been told about. The gateway does not broadcast the network again.
        await self.hub.broadcast(P.frame(P.NETWORK, network=session.to_wire()))
        await session._announce_buffer(session.status_buffer.id)
        session.start()
        log.info("network %s added by a client (%s:%d as %s)", slug, host, port, nick)
        return session.to_wire()

    async def edit_network(self, slug: str, changes: dict) -> dict:
        session = self.hub.sessions.get(slug)
        if session is None:
            raise ValueError("unknown network")
        await session.edit(changes)
        log.info("network %s edited by a client (%s)", slug, ", ".join(sorted(changes)))
        return session.to_wire()

    async def connect_network(self, slug: str, connect: bool) -> dict:
        session = self.hub.sessions.get(slug)
        if session is None:
            raise ValueError("unknown network")
        await session.set_enabled(connect)
        log.info("network %s turned %s by a client", slug, "on" if connect else "off")
        return session.to_wire()

    async def remove_network(self, slug: str) -> None:
        session = self.hub.sessions.get(slug)
        if session is None:
            raise ValueError("unknown network")
        record = self.store.network_by_slug(slug)
        if record and record.get("source") == "config":
            # config.json would recreate it on the next restart, so removing it
            # here would look like a deletion that silently failed.
            raise ValueError("that network is defined in config.json; remove it there")
        # Stopped first, while its buffers still exist: stopping records the
        # "Disconnected" lines, and a session stopped after its rows were gone
        # would write into buffers that are not there. Then the rows, in one
        # transaction, and only once that has committed does the network leave
        # memory. A delete that failed (2026-09-26: a foreign key it missed)
        # used to leave the network gone live and back after a restart; now the
        # session is started again and the client told, so memory and the
        # database always agree.
        await session.stop()
        if record:
            try:
                self.store.delete_network(record["id"])
            except Exception as exc:
                log.exception("network %s: delete failed; putting it back", slug)
                session.start()
                raise ValueError("could not remove that network; it is still there") from exc
        self.sessions = [s for s in self.sessions if s is not session]
        self.hub.sessions.pop(slug, None)
        log.info("network %s removed by a client", slug)

    async def shutdown(self) -> None:
        # Gateway first. Closing the clients hands each one a real 1001 so it
        # reconnects rather than waiting out a timeout, and it takes the
        # websockets out from under aiohttp's cleanup -- which is what made a
        # stop hang for 15 seconds and get SIGKILLed before the QUIT below went
        # out. Then the sessions say goodbye upstream.
        if self._lag_task is not None:
            self._lag_task.cancel()
        self.hub.cancel_read_pushes()
        await self.gateway.stop()
        await asyncio.gather(*(s.stop() for s in self.sessions), return_exceptions=True)
        if self.hub.webpush is not None:
            await self.hub.webpush.aclose()
        self.store.close()


# The fields of a config.json network a client can edit, as NetworkConfig names
# mapped to the database columns they are kept in.
EDITABLE_FROM_CLIENT = {
    "name": "name", "host": "host", "port": "port", "tls": "tls", "nick": "nick",
    "alt_nicks": "alt_nicks", "username": "username", "realname": "realname",
    "q_username": "q_username",
}


def _secrets_from_record(record: dict) -> dict:
    """The secrets a client set, as NetworkConfig fields. Only ever the
    database's: nothing in config.json sets them."""
    return {
        "password": record.get("server_password") or "",
        "sasl_mechanism": (record.get("sasl_mechanism") or "").upper(),
        "sasl_username": record.get("sasl_username") or "",
        "sasl_password": record.get("sasl_password") or "",
        "stored_q_password": record.get("q_password") or "",
    }


def network_from_file(net: NetworkConfig, record: dict | None) -> NetworkConfig:
    """A config.json network as it runs: the file's settings, with whatever a
    client edited (and the secrets it set) taken from the database.

    Only the fields named in the record's `edited` list come from it; every
    other one follows the file, so a later change to config.json still lands
    for anything nobody touched from a client. The channels are the saved
    wanted list adjusted for what changed in the file (merge_wanted_channels).
    """
    # Keys by folded name from here on, whatever spelling the file used.
    file_keys = {fold(c): k for c, k in net.channel_keys.items()}
    net = dataclasses.replace(net, source="config", edited=[], channel_keys=file_keys)
    if record is None:
        return net
    edited = [f for f in record.get("edited") or [] if f in EDITABLE_FROM_CLIENT]
    changes: dict = {}
    for field_name in edited:
        value = record.get(EDITABLE_FROM_CLIENT[field_name])
        if field_name == "tls":
            value = bool(value)
        elif field_name == "q_username":
            value = value or ""
        elif field_name == "alt_nicks":
            value = list(value or [])
        changes[field_name] = value
    # The wanted list is what was saved last time, adjusted for whatever
    # changed in the file since. It used to be the file's list, written
    # over the saved one on every start -- so each deploy undid every
    # /join and /part made from a client.
    channels = merge_wanted_channels(record["channels"], record["config_channels"],
                                     list(net.channels))
    # The keys follow their channels: the ones a client gave (saved), with
    # any the file itself names on top, for the channels still wanted.
    wanted = {fold(c) for c in channels}
    keys = {name: key for name, key in {**(record.get("channel_keys") or {}),
                                        **file_keys}.items() if name in wanted}
    return dataclasses.replace(
        net, **changes, **_secrets_from_record(record), edited=edited,
        channels=channels, channel_keys=keys)


def network_from_record(record: dict) -> NetworkConfig:
    """A network a client added, from the database, which is all there is of it."""
    return NetworkConfig(
        slug=record["slug"], name=record["name"], host=record["host"],
        port=record["port"], tls=bool(record["tls"]), nick=record["nick"],
        alt_nicks=list(record.get("alt_nicks") or []),
        username=record["username"] or record["nick"],
        realname=record["realname"] or record["nick"],
        channels=list(record["channels"]),
        channel_keys=dict(record.get("channel_keys") or {}),
        q_username=record.get("q_username") or "",
        source="client",
        **_secrets_from_record(record),
    )


def merge_wanted_channels(saved: list[str], config_before: list[str],
                          config_now: list[str]) -> list[str]:
    """The channels to join at startup, for a network defined in config.json.

    `saved` is the wanted list as the last run left it: every /join and /part
    made from a client, written through as it happened. `config_before` is what
    the file said at the last start and `config_now` is what it says now. Only
    the difference between those two is a decision made in the file:

      - a channel added to the file since last time is joined;
      - a channel removed from the file since last time is left;
      - a file channel the user has since parted STAYS parted -- it is in both
        file lists, so the file has not changed its mind about it, and the part
        was the later decision. This is the one that used to come back on every
        deploy.

    Everything else is the saved list as it was. Names compare under rfc1459
    folding, and the saved spelling wins.
    """
    before = {fold(c) for c in config_before}
    now = {fold(c) for c in config_now}
    out = [c for c in saved if not (fold(c) in before and fold(c) not in now)]
    have = {fold(c) for c in out}
    for channel in config_now:
        key = fold(channel)
        if key not in before and key not in have:
            out.append(channel)
            have.add(key)
    return out


def build_webpush(store: Store, config: Config):
    """Web Push, always on: the VAPID key pair is made on first start, so
    there is nothing to configure. None only if the crypto library cannot load,
    in which case hello carries no webpush_key and the web client does not
    offer notifications it could not get."""
    try:
        from .webpush import WebPushSender

        return WebPushSender(store, subject=config.webpush_subject,
                             allow_private_hosts=config.allow_private_hosts)
    except Exception:
        log.exception("web push is unavailable")
        return None


def _slugify(text: str) -> str:
    """A stable identifier from a network name. Used as the wire-level key."""
    cleaned = "".join(c.lower() if c.isalnum() else "-" for c in text).strip("-")
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned or "network"
