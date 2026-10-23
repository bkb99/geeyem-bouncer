"""What a client may put in `add_network` and `edit_network`, checked.

Every one of these ends up in a line the bouncer sends upstream -- NICK, USER,
JOIN, PASS, AUTHENTICATE -- on every reconnect, forever. A CR or LF in any of
them is a second IRC command the client typed and the bouncer replays; a space
in a nick shifts every parameter after it. `add_network` used to check the host
and the port and take the rest as sent, so "a,b", a 200-character nick and
"#a\\r\\nPRIVMSG x :y" were all accepted and stored.

So each field is checked here, in full, before anything is stored or sent, and
a refusal is a sentence for the person filling in the form. The result is keyed
by NetworkConfig field name, which is what app.py and session.py apply.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .netguard import check_host_public
from .config import NetworkConfig
from .ircproto import MAX_CHANNEL_KEY

MAX_HOST = 253                 # DNS's own limit
MAX_NAME = 64
MAX_NICK = 32
MAX_ALT_NICKS = 5
MAX_USERNAME = 32
MAX_REALNAME = 128
MAX_CHANNEL = 50
MAX_CHANNELS = 64
MAX_SECRET = 300

SASL_MECHANISMS = ("PLAIN", "EXTERNAL")

# RFC 2812's nickname: a letter or one of []\`_^{|} first, then those, digits
# and "-". Networks allow longer nicks than the RFC's nine, so only the
# characters are the RFC's; the length is ours.
_NICK_FIRST = r"A-Za-z\[\]\\`_^{|}"
_NICK = re.compile(rf"^[{_NICK_FIRST}][{_NICK_FIRST}0-9-]*$")

# Where the server's name ends and something else begins.
_LINE_BREAKERS = ("\r", "\n", "\0")


def _text(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{what} must be text.")
    return value


def _no_breaks(value: str, what: str) -> str:
    if any(c in value for c in _LINE_BREAKERS):
        raise ValueError(f"{what} can't have a line break in it.")
    return value


def clean_name(value: Any) -> str:
    name = _no_breaks(_text(value, "The network name"), "The network name").strip()
    if not name:
        raise ValueError("The network needs a name.")
    if len(name) > MAX_NAME:
        raise ValueError(f"A network name can be at most {MAX_NAME} characters.")
    return name


def clean_host(value: Any) -> str:
    """A server's hostname or IP address, not a URL. People paste
    "irc://host" or "host:6667" and the connection then fails with a DNS error
    that explains nothing; the port has its own field."""
    host = _text(value, "The server").strip()
    if not host:
        raise ValueError("A server is needed.")
    if len(host) > MAX_HOST or any(c.isspace() or c in _LINE_BREAKERS for c in host):
        raise ValueError("That is not a server address.")
    try:
        ipaddress.IPv6Address(host)
        return host                     # a bare IPv6 address has colons in it
    except ValueError:
        pass
    if "/" in host or ":" in host:
        raise ValueError("Give the server on its own. The port has its own field.")
    return host


def clean_port(value: Any, tls: bool) -> int:
    """Omitted means the usual one for the kind of connection. Sent means
    what was sent, including a 0, which is a mistake worth naming rather than
    quietly turning into 6667."""
    if value in (None, ""):
        return 6697 if tls else 6667
    if isinstance(value, bool):
        raise ValueError("The port must be a number between 1 and 65535.")
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError("The port must be a number between 1 and 65535.") from None
    if not 1 <= port <= 65535:
        raise ValueError("The port must be a number between 1 and 65535.")
    return port


def clean_bool(value: Any, what: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{what} must be true or false.")
    return value


def clean_nick(value: Any, what: str = "A nickname") -> str:
    nick = _text(value, what).strip()
    if not nick:
        raise ValueError(f"{what} is needed.")
    if len(nick) > MAX_NICK:
        raise ValueError(f"{what} can be at most {MAX_NICK} characters.")
    if nick[0].isdigit() or nick[0] == "-":
        raise ValueError(f"{what} can't start with a number or a dash.")
    if not _NICK.match(nick):
        raise ValueError(f"{what} can only use letters, numbers and these: - _ [ ] {{ }} \\ | ^ `")
    return nick


def clean_alt_nicks(value: Any, nick: str | None) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("The other nicknames must be a list.")
    out: list[str] = []
    seen = {nick.lower()} if nick else set()
    for entry in value:
        if isinstance(entry, str) and not entry.strip():
            continue
        alt = clean_nick(entry, "Each other nickname")
        if alt.lower() not in seen:
            seen.add(alt.lower())
            out.append(alt)
    if len(out) > MAX_ALT_NICKS:
        raise ValueError(f"At most {MAX_ALT_NICKS} other nicknames.")
    return out


def clean_username(value: Any) -> str:
    """The ident, USER's first parameter. Empty means "the nick"."""
    username = _no_breaks(_text(value, "The username"), "The username").strip()
    if any(c.isspace() or c == "@" for c in username):
        raise ValueError("A username can't have spaces or @ in it.")
    if len(username) > MAX_USERNAME:
        raise ValueError(f"A username can be at most {MAX_USERNAME} characters.")
    return username


def clean_realname(value: Any) -> str:
    """USER's last parameter, which may have spaces. Empty means "the nick"."""
    realname = _no_breaks(_text(value, "The real name"), "The real name").strip()
    if len(realname) > MAX_REALNAME:
        raise ValueError(f"A real name can be at most {MAX_REALNAME} characters.")
    return realname


def split_channel_key(entry: str) -> tuple[str, str]:
    """"#secret hunter2" -> ("#secret", "hunter2"); "#open" -> ("#open", "").

    A channel entry is a name, or a name, one space and the channel's key:
    the way /join takes them, and a space cannot be in either half. Nothing
    is checked here; clean_channel_entries does that for what a client sends.
    """
    name, _, key = entry.strip().partition(" ")
    return name, key


def split_channel_keys(entries: list[str]) -> tuple[list[str], dict[str, str]]:
    """A list of channel entries as (names, {name: key}), unchecked: for
    config.json's own `channels`, which is its owner's to get right. The point
    is that a key written there is taken OUT of the name -- left in, it would
    be sent to every client in the network frame's `channels`."""
    names: list[str] = []
    keys: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, str) or not entry.strip():
            continue
        name, key = split_channel_key(entry)
        names.append(name)
        if key.strip():
            keys[name] = key.strip()
    return names, keys


def clean_channel_entries(value: Any) -> tuple[list[str], dict[str, str]]:
    """The channels joined on every connect, and the keys of those that have
    one: (names, {name: key}). A name without a leading # gets one, the way a
    person types it; a name IRC could not carry is refused rather than stored
    and joined wrong on every reconnect.

    An entry may be "#secret hunter2": the name, one space, the key. A refusal
    names the channel and never the key -- an error is shown on a screen and
    kept in a log, and the key is a password.
    """
    if value is None:
        return [], {}
    if not isinstance(value, list):
        raise ValueError("The channels must be a list.")
    out: list[str] = []
    keys: dict[str, str] = {}
    seen: set[str] = set()
    for entry in value:
        entry = _no_breaks(_text(entry, "A channel"), "A channel name").strip()
        if not entry:
            continue
        channel, key = split_channel_key(entry)
        if not channel.startswith(("#", "&")):
            channel = "#" + channel
        if any(ord(c) < 32 for c in channel):
            raise ValueError("A channel name can't have control characters in it.")
        if any(c.isspace() or c == "," for c in channel):
            raise ValueError(f"{channel[:MAX_CHANNEL]} is not a channel name. "
                             "Channel names can't have spaces or commas.")
        if len(channel) > MAX_CHANNEL:
            raise ValueError(f"A channel name can be at most {MAX_CHANNEL} characters.")
        if key:
            # More than one space lands here too: "#a b c" is the channel #a
            # and a key of "b c", which no JOIN could carry.
            if any(c.isspace() or c == "," or ord(c) < 32 for c in key) or key.startswith(":"):
                raise ValueError(f"The key for {channel} can't have spaces or commas in it. "
                                 "Write the channel, one space, then its key.")
            if len(key) > MAX_CHANNEL_KEY:
                raise ValueError(f"The key for {channel} can be at most "
                                 f"{MAX_CHANNEL_KEY} characters.")
        if channel.lower() not in seen:
            seen.add(channel.lower())
            out.append(channel)
        if key:
            # Given twice, the later key is the one meant.
            keys[next(c for c in out if c.lower() == channel.lower())] = key
    if len(out) > MAX_CHANNELS:
        raise ValueError(f"At most {MAX_CHANNELS} channels.")
    return out, keys


def clean_channels(value: Any) -> list[str]:
    """The names alone; see clean_channel_entries."""
    return clean_channel_entries(value)[0]


def clean_secret(value: Any, what: str) -> str:
    """A password. Spaces are allowed (PASS sends it as a trailing parameter);
    line breaks are not. "" means none."""
    if value is None:
        return ""
    secret = _no_breaks(_text(value, what), what)
    if len(secret) > MAX_SECRET:
        raise ValueError(f"{what} can be at most {MAX_SECRET} characters.")
    return secret


def clean_account(value: Any, what: str) -> str:
    if value is None:
        return ""
    account = _no_breaks(_text(value, what), what).strip()
    if any(c.isspace() for c in account):
        raise ValueError(f"{what} can't have spaces in it.")
    if len(account) > MAX_USERNAME * 2:
        raise ValueError(f"{what} is too long.")
    return account


def clean_sasl(value: Any, current: NetworkConfig | None) -> dict[str, str]:
    """{mechanism, username, password} or null, as NetworkConfig fields.

    The password may be left out to keep the one already stored: the network
    frame never sends it back, so an edit screen cannot resend it."""
    if value is None:
        return {"sasl_mechanism": "", "sasl_username": "", "sasl_password": ""}
    if not isinstance(value, dict):
        raise ValueError("The SASL login must be a mechanism, a username and a password.")
    mechanism = _text(value.get("mechanism") or "PLAIN", "The SASL mechanism").strip().upper()
    if mechanism not in SASL_MECHANISMS:
        raise ValueError("The SASL mechanism must be PLAIN or EXTERNAL.")
    username = clean_account(value.get("username"), "The SASL username")
    password = clean_secret(value.get("password"), "The SASL password")
    if not password and current is not None and current.sasl_mechanism:
        password = current.sasl_password
    if mechanism == "PLAIN":
        if not username:
            raise ValueError("SASL PLAIN needs a username.")
        if not password:
            raise ValueError("SASL PLAIN needs a password.")
    else:
        password = ""                   # EXTERNAL logs in with the certificate
    return {"sasl_mechanism": mechanism, "sasl_username": username,
            "sasl_password": password}


def refuse_cleartext_login(out: dict[str, Any], current: NetworkConfig | None) -> None:
    """A login that would go over a plain connection is refused.

    PASS and SASL PLAIN carry the password itself, and the bouncer sends them
    on every reconnect, forever: on a network without TLS that is the
    password in the clear to everyone on the path, again and again, with
    nothing on the screen to say so. EXTERNAL carries no secret, but it logs
    in with a certificate only a TLS connection can present, so without TLS
    it can only ever fail.

    What is checked is the network as it would be after this frame, so
    turning TLS off under a stored password is refused as well as sending a
    password with TLS off. Only when the frame touches one of the three,
    though: an edit that renames a network stored like this before the rule
    existed does not make it any worse, and is not the moment to refuse.
    """
    if not {"tls", "password", "sasl_mechanism"} & out.keys():
        return
    tls = out.get("tls", current.tls if current else False)
    if tls:
        return
    mechanism = out.get("sasl_mechanism", current.sasl_mechanism if current else "")
    password = out.get("password", current.password if current else "")
    if mechanism == "PLAIN":
        raise ValueError("That SASL login would be sent unencrypted. Turn on TLS first.")
    if mechanism == "EXTERNAL":
        raise ValueError("SASL EXTERNAL logs in with a certificate, which needs TLS. "
                         "Turn on TLS first.")
    if password:
        raise ValueError("That server password would be sent unencrypted. Turn on TLS first.")


async def network_fields(frame: dict, *, adding: bool, allow_private_hosts: bool,
                         current: NetworkConfig | None = None) -> dict[str, Any]:
    """The checked fields of an add_network or edit_network frame, as
    NetworkConfig field names. Raises ValueError with a sentence.

    For an edit, only the fields the frame carries are returned, and a field
    sent as null is left alone, secrets included: `password: ""` and
    `q_password: ""` clear theirs, null keeps it (a client that serialises an
    untouched field as null must not wipe a password it never had). `sasl:
    null` and `q_username` null or "" clear, as docs/PROTOCOL.md says. For an
    add, host and nick are required and the port defaults by `tls`.
    """
    out: dict[str, Any] = {}
    if adding:
        out["host"] = clean_host(frame.get("host"))
        out["nick"] = clean_nick(frame.get("nick"))
        out["tls"] = clean_bool(frame.get("tls", False), "tls")
        out["port"] = clean_port(frame.get("port"), out["tls"])
        name = frame.get("name")
        out["name"] = clean_name(name) if isinstance(name, str) and name.strip() else out["host"]
    else:
        if frame.get("name") is not None:
            out["name"] = clean_name(frame["name"])
        if frame.get("host") is not None:
            out["host"] = clean_host(frame["host"])
        if frame.get("tls") is not None:
            out["tls"] = clean_bool(frame["tls"], "tls")
        if frame.get("port") is not None:
            tls = out.get("tls", current.tls if current else False)
            out["port"] = clean_port(frame["port"], tls)
        if frame.get("nick") is not None:
            out["nick"] = clean_nick(frame["nick"])

    nick = out.get("nick") or (current.nick if current else None)
    if frame.get("alt_nicks") is not None:
        out["alt_nicks"] = clean_alt_nicks(frame["alt_nicks"], nick)
    if frame.get("username") is not None:
        out["username"] = clean_username(frame["username"]) or nick or ""
    if frame.get("realname") is not None:
        out["realname"] = clean_realname(frame["realname"]) or nick or ""
    if frame.get("channels") is not None:
        # Names in `channels`, and the keys that came with them beside it
        # ({name: key}, often empty): a "#secret hunter2" entry is the only
        # way a key arrives here, and it is never sent back.
        out["channels"], out["channel_keys"] = clean_channel_entries(frame["channels"])
    if frame.get("password") is not None:
        out["password"] = clean_secret(frame["password"], "The server password")
    if "sasl" in frame:
        out.update(clean_sasl(frame["sasl"], current))
    if "q_username" in frame:
        out["q_username"] = clean_account(frame["q_username"], "The Q account")
    if frame.get("q_password") is not None:
        out["stored_q_password"] = clean_secret(frame["q_password"], "The Q password")
    # Not the Q password: Q is sent CHALLENGEAUTH, a keyed hash of it, never
    # the password itself (relay/qauth.py).
    refuse_cleartext_login(out, current)

    # Checked last and only if everything else passed: it is a DNS lookup.
    # Every address the name resolves to must be public (relay/netguard.py);
    # a client's server is checked again on every connect.
    if "host" in out:
        await check_host_public(out["host"], allow_private=allow_private_hosts)
    return out
