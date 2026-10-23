"""Configuration: one JSON file plus environment overrides for the secrets.

Secrets do NOT go in the JSON file. The JSON is meant to be committable-shaped
(it describes networks and ports, not credentials); anything that would be
damaging to leak is read from the environment, which on the VPS means systemd's
EnvironmentFile, the same shape the otherbot already uses for its R2 keys.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_CONFIG_PATH = Path(
    os.environ.get("RELAY_CONFIG", Path(__file__).resolve().parent.parent / "config.json")
)


@dataclass
class NetworkConfig:
    """One upstream IRC server the bouncer stays connected to."""

    slug: str                      # stable id used in the wire protocol and the db
    name: str                      # display name ("QuakeNet")
    host: str
    port: int = 6667
    tls: bool = False
    nick: str = "relay"
    # Falling back through these in order when the server says the nick is taken.
    alt_nicks: list[str] = field(default_factory=list)
    username: str = "relay"
    realname: str = "relay"
    channels: list[str] = field(default_factory=list)
    # Extra words that count as a highlight for this network beyond the current nick.
    highlight_words: list[str] = field(default_factory=list)
    # Q authentication. The USERNAME lives here; the PASSWORD deliberately does
    # not -- it comes from the environment as GEYEM_Q_PASSWORD (or
    # GEYEM_Q_PASSWORD_<SLUG> with several networks), so it is never in a file
    # that could be committed or copied. See relay/qauth.py.
    q_username: str = ""
    # Ask Q for usermode +x after authenticating, which replaces the visible
    # host with <account>.users.quakenet.org.
    q_hide_host: bool = True
    enabled: bool = True
    # A PEM file holding a client certificate and its key, presented on a TLS
    # connection. What SASL EXTERNAL (and CertFP) identify you by. A path on
    # the bouncer, so only config.json can set it.
    tls_cert: str = ""

    # --- set from a client (edit_network), kept in SQLite, never in the file --
    # These are the secrets. The file is meant to be committable-shaped, so
    # nothing here is read from it in practice: app.py fills them in from the
    # database, where `edit_network` puts them (the db is mode 600 and backed
    # up encrypted). The Q password of a network defined in the file still
    # comes from the environment; see q_password.
    password: str = ""               # server password, sent as PASS
    sasl_mechanism: str = ""         # "PLAIN" | "EXTERNAL" | "" for none
    sasl_username: str = ""
    sasl_password: str = ""
    stored_q_password: str = ""      # a Q password a client set
    # The key of each channel in `channels` that has one (+k), by the
    # channel's folded name; sent with its JOIN on every connect. Filled in
    # by app.py from the database, and from any "#chan key" entry in the
    # file's own `channels` (see netfields.split_channel_keys).
    channel_keys: dict[str, str] = field(default_factory=dict)
    # "config" for a network defined in config.json, "client" for one a client
    # added. Decides where the Q password comes from and whether a client may
    # remove the network.
    source: str = "config"
    # The fields of a config.json network a client has edited. They are read
    # from the database from then on; see app.Relay.run.
    edited: list[str] = field(default_factory=list)

    @property
    def q_password(self) -> str:
        """The environment for a network in config.json (Riley's QuakeNet reads
        GEYEM_Q_PASSWORD, and a client edit cannot move it), else whatever a
        client stored. A client network never reads the environment: the one
        password on the box is for the network it was put there for, not for
        any server that asks for a Q login."""
        if self.source == "config":
            from_env = (os.environ.get(f"GEYEM_Q_PASSWORD_{self.slug.upper()}")
                        or os.environ.get("GEYEM_Q_PASSWORD", ""))
            if from_env:
                return from_env
        return self.stored_q_password

    @property
    def q_password_from_env(self) -> bool:
        return self.source == "config" and bool(
            os.environ.get(f"GEYEM_Q_PASSWORD_{self.slug.upper()}")
            or os.environ.get("GEYEM_Q_PASSWORD", ""))

    @property
    def sasl(self) -> dict | None:
        """The SASL login as the wire shows it: never the password."""
        if not self.sasl_mechanism:
            return None
        return {"mechanism": self.sasl_mechanism, "username": self.sasl_username}

    @property
    def all_nicks(self) -> list[str]:
        return [self.nick, *self.alt_nicks]


@dataclass
class Config:
    listen_host: str = "127.0.0.1"
    listen_port: int = 8765
    db_path: str = "relay.db"
    networks: list[NetworkConfig] = field(default_factory=list)
    # How much backlog a client gets per buffer when it first attaches.
    initial_backlog: int = 50
    max_backlog_page: int = 500
    # (`client_idle_timeout` used to be here and nothing ever read it. What
    # decides a silent client is gone is the websocket heartbeat in
    # Gateway.handle_ws, and hub.PRESENCE_TTL for whether it still counts as
    # watching. A config.json that still sets it is fine: unknown keys are
    # ignored by load below.)
    # With the `auto_away` setting on (a client turns it on; see PROTOCOL.md,
    # `settings`), how long nobody may be attached before the bouncer marks
    # the user away. Here so a test rig can make it seconds.
    auto_away_after: float = 600.0
    # Browser origins allowed to open /ws besides the bouncer's own (the page
    # it serves at /). Only needed if the web client is hosted somewhere else;
    # see Gateway.handle_ws.
    allowed_origins: list[str] = field(default_factory=list)
    # APNs. None of this is required to run — with no key configured the push
    # layer logs what it would have sent and returns. See push.py.
    apns_key_path: str | None = None
    apns_key_id: str | None = None
    apns_team_id: str | None = None
    apns_topic: str | None = None          # the app's bundle id
    apns_use_sandbox: bool = True
    # Addresses the bouncer itself fetches from -- link previews and their
    # images, Web Push endpoints -- must be public: loopback, private ranges,
    # link-local (169.254.169.254 is the cloud metadata service) and multicast
    # are refused at every hop. A local test rig, where everything is on
    # 127.0.0.1, turns this on. Shared with section 1's host check for networks:
    # add_network and edit_network refuse a server that is not public, and a
    # client's server is checked again on every connect. See relay/netguard.py.
    allow_private_hosts: bool = False
    # Link cards (the `link_preview` frame). On by default: nothing is fetched
    # until a client asks, and clients only ask with their own setting on.
    link_previews: bool = True
    # The VAPID `sub` claim when a subscription came with no https origin to
    # use instead. Apple's push service refuses a subject it cannot read as a
    # mailto: or https: address. Also RELAY_WEBPUSH_SUBJECT.
    webpush_subject: str | None = None

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "Config":
        path = Path(path or DEFAULT_CONFIG_PATH)
        raw: dict = {}
        if path.exists():
            raw = json.loads(path.read_text())

        # Keys beginning with "_" are documentation for whoever opens the file
        # (see config.example.json) and are not settings. Same for any key inside
        # a network block.
        networks = [
            NetworkConfig(**{k: v for k, v in n.items() if not k.startswith("_")})
            for n in raw.pop("networks", [])
        ]
        cfg = cls(**{k: v for k, v in raw.items() if k in cls.__dataclass_fields__})
        cfg.networks = networks

        # Environment wins over the file, so a systemd unit can move the port or
        # point at a different database without editing the checked-out config.
        if v := os.environ.get("RELAY_LISTEN_HOST"):
            cfg.listen_host = v
        if v := os.environ.get("RELAY_LISTEN_PORT"):
            cfg.listen_port = int(v)
        if v := os.environ.get("RELAY_DB"):
            cfg.db_path = v
        for env_key, attr in (
            ("RELAY_APNS_KEY_PATH", "apns_key_path"),
            ("RELAY_APNS_KEY_ID", "apns_key_id"),
            ("RELAY_APNS_TEAM_ID", "apns_team_id"),
            ("RELAY_APNS_TOPIC", "apns_topic"),
        ):
            if v := os.environ.get(env_key):
                setattr(cfg, attr, v)

        # Sandbox vs production is the setting most likely to be wrong, and
        # getting it wrong produces "BadDeviceToken" -- which reads like the
        # token is broken and sends you looking in the wrong place. So it is
        # settable from the environment alongside the rest, not just the file.
        if v := os.environ.get("RELAY_APNS_SANDBOX"):
            cfg.apns_use_sandbox = v.strip().lower() not in ("0", "false", "no")
        if v := os.environ.get("RELAY_WEBPUSH_SUBJECT"):
            cfg.webpush_subject = v

        # Relative db paths resolve against the config file's directory, not the
        # process's cwd -- a one-off script run from elsewhere would otherwise
        # quietly create its own empty database. (The otherbot learned this one the
        # hard way with METRICS_FILE.)
        if not os.path.isabs(cfg.db_path):
            cfg.db_path = str((path.parent / cfg.db_path).resolve())

        return cfg
