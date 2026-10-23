"""Parsing and formatting of the IRC wire protocol.

Hand-rolled rather than pulled from a library, for the same reason the otherbot
hand-rolls it: the protocol is small, the edge cases that matter are the ones
QuakeNet actually produces, and a dependency here would be a dependency in the
one part of the system that must never be surprising.

Everything in this module is pure -- no sockets, no state. That is what makes it
testable without a server.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# --- casemapping -----------------------------------------------------------
#
# IRC nick/channel comparison is case-insensitive, but not with ASCII rules:
# under rfc1459 the bytes {|}^ are the lowercase forms of []\~. QuakeNet uses
# rfc1459. Getting this wrong means "Riley[m]" and "riley{m}" are treated as two
# different people, which shows up as a duplicated nick in the member list and a
# highlight that does not fire.
_RFC1459_LOWER = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ[]\\~",
    "abcdefghijklmnopqrstuvwxyz{}|^",
)
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def fold(name: str, casemapping: str = "rfc1459") -> str:
    """Fold a nick or channel name to its comparison form."""
    if casemapping == "ascii":
        return name.translate(_ASCII_LOWER)
    return name.translate(_RFC1459_LOWER)


# --- formatting codes ------------------------------------------------------
#
# Stripped only where a plain-text copy is wanted (highlight matching, push
# notification bodies). The stored text keeps its codes: rendering them is the
# client's business, and throwing them away at ingest would be irreversible.
_CTRL = re.compile(
    r"\x03(?:\d{1,2}(?:,\d{1,2})?)?"   # colour, with optional fg[,bg]
    r"|\x04[0-9a-fA-F]{6}"             # hex colour
    r"|[\x00-\x08\x0a-\x1f]"           # bold/italic/underline/reverse/reset etc
)


def strip_formatting(text: str) -> str:
    return _CTRL.sub("", text)


@dataclass
class Prefix:
    """The `nick!user@host` that a server-sent line came from."""

    raw: str = ""
    nick: str = ""
    user: str = ""
    host: str = ""

    @property
    def is_server(self) -> bool:
        # A server prefix has no '!' and no '@' -- it is a bare hostname.
        return bool(self.raw) and not self.user and not self.nick_looks_like_user

    @property
    def nick_looks_like_user(self) -> bool:
        return "@" in self.raw or "!" in self.raw


def parse_prefix(raw: str) -> Prefix:
    if not raw:
        return Prefix()
    nick, user, host = raw, "", ""
    if "!" in nick:
        nick, _, rest = nick.partition("!")
        user, _, host = rest.partition("@")
    elif "@" in nick:
        nick, _, host = nick.partition("@")
    return Prefix(raw=raw, nick=nick, user=user, host=host)


@dataclass
class Message:
    """One parsed line from the server."""

    command: str
    params: list[str] = field(default_factory=list)
    prefix: Prefix = field(default_factory=Prefix)
    tags: dict[str, str] = field(default_factory=dict)
    raw: str = ""

    def param(self, index: int, default: str = "") -> str:
        """params[index] without the IndexError. Servers omit trailing params."""
        return self.params[index] if index < len(self.params) else default


def decode_line(raw: bytes) -> str:
    """Bytes off the wire to text, one line at a time, never raising.

    IRC predates UTF-8 and QuakeNet does not enforce it, so a channel holds a
    mix: most clients send UTF-8, and older Windows ones send cp1252 (latin-1
    plus curly quotes, dashes and the euro sign). Decoding everything as UTF-8
    with errors="replace" turned "café" from those clients into "caf\\ufffd",
    and that is what got stored and indexed -- the original byte is gone, so no
    later fix could recover the history.

    The fallback is per line, which is what IRCCloud, HexChat, Quassel and
    ZNC's charset module all do. A valid UTF-8 line is almost never valid
    cp1252 text by accident and vice versa, so trying UTF-8 first costs
    nothing. cp1252 leaves five bytes undefined (0x81, 0x8D, 0x8F, 0x90, 0x9D);
    latin-1 defines all 256, so it is the last resort that cannot fail.
    """
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return raw.decode("cp1252")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


# IRCv3 message-tags: what a backslash followed by each character stands for.
_TAG_ESCAPES = {":": ";", "s": " ", "\\": "\\", "r": "\r", "n": "\n"}


def unescape_tag_value(value: str) -> str:
    """A tag value as the IRCv3 spec unescapes it, in ONE left-to-right pass.

    It used to be a chain of str.replace calls (fixed 2026-09-26), which read
    an escape twice or in the wrong order: an escaped backslash followed by a
    literal "s" came out as a space. The spec's other rules: an unknown escape
    drops the backslash and keeps the character, and a lone backslash at the
    end is dropped.
    """
    if "\\" not in value:
        return value
    out: list[str] = []
    i, n = 0, len(value)
    while i < n:
        c = value[i]
        if c != "\\":
            out.append(c)
            i += 1
        elif i + 1 < n:
            nxt = value[i + 1]
            out.append(_TAG_ESCAPES.get(nxt, nxt))
            i += 2
        else:
            i += 1                     # a trailing lone backslash is dropped
    return "".join(out)


def parse_line(line: str) -> Message | None:
    """Parse one line. Returns None for a line that carries no command.

    Handles IRCv3 message tags even though we do not request the capability
    yet, because a server may send them once we do and a parser that chokes on
    an '@' prefix is a parser that drops the whole connection later.
    """
    line = line.rstrip("\r\n")
    if not line:
        return None

    raw = line
    tags: dict[str, str] = {}
    if line.startswith("@"):
        tagpart, _, line = line.partition(" ")
        for item in tagpart[1:].split(";"):
            if not item:
                continue
            key, _, value = item.partition("=")
            tags[key] = unescape_tag_value(value)
        line = line.lstrip(" ")

    prefix = Prefix()
    if line.startswith(":"):
        prefixpart, _, line = line.partition(" ")
        prefix = parse_prefix(prefixpart[1:])
        line = line.lstrip(" ")

    if not line:
        return None

    # The trailing parameter starts at " :" and is the only one allowed spaces.
    # Split on the SPACE character only (RFC 1459 and the IRCv3 grammar), not
    # on str.split()'s "any whitespace", which until 2026-09-26 also broke a
    # middle parameter at a tab, a form feed or a Unicode space (U+00A0,
    # U+3000) -- all ordinary bytes inside a parameter. Runs of spaces are fine.
    if line.startswith(":"):
        # A line can also be exactly ":trailing" with no preceding params.
        params = [line[1:]]
    else:
        head, sep, trailing = line.partition(" :")
        params = [p for p in head.split(" ") if p]
        if sep:
            params.append(trailing)

    if not params:
        return None
    command, params = params[0].upper(), params[1:]
    return Message(command=command, params=params, prefix=prefix, tags=tags, raw=raw)


def format_line(command: str, *params: str) -> str:
    """Build a line to send. The last param is sent as trailing when it needs to be."""
    parts = [command]
    for i, p in enumerate(params):
        last = i == len(params) - 1
        if last and (p == "" or " " in p or p.startswith(":")):
            parts.append(":" + p)
        else:
            parts.append(p)
    return " ".join(parts)


# The most bytes of one line before its CRLF. RFC 1459's 512 includes the two.
LINE_BYTES = 510


_LINE_END = re.compile(r"[\r\n\0]")


def encode_line(line: str) -> bytes:
    """One outgoing line as bytes, cut to LINE_BYTES on a character boundary.

    The cut used to be a plain byte slice, so a long TOPIC or AWAY in anything
    but ASCII lost half of its last character and the server relayed the
    stray byte to everyone as a replacement box. Cutting the encoded form and
    decoding it back with `ignore` drops exactly that half character.

    And it ends at the first CR, LF or NUL, whoever built it. Everything a
    client typed is refused before it gets here (check_param), but some lines
    carry text from IRC itself: a CTCP PING is answered with its own argument,
    and a server PING with its own token. Lines are split at LF on the way in,
    so a bare CR in the middle of one arrives intact, and servers that end a
    line at CR (ircu, which is QuakeNet's) read what follows it as a second
    command -- from us. "\\x01PING 1\\rQUIT :bye\\x01" sent to our nick made the
    bouncer quit. The last place before the socket is the one place that
    cannot be forgotten by a new caller.
    """
    end = _LINE_END.search(line)
    if end is not None:
        line = line[: end.start()]
    data = line.encode("utf-8", errors="replace")
    if len(data) > LINE_BYTES:
        data = data[:LINE_BYTES].decode("utf-8", errors="ignore").encode("utf-8")
    return data


# --- server-time -------------------------------------------------------------
#
# With the IRCv3 server-time capability every line carries `@time=` in UTC,
# millisecond precision, always with the Z. Parsed by hand rather than with
# datetime.fromisoformat, which only learned the Z in Python 3.11.
_SERVER_TIME = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$")


def parse_server_time(value: str | None) -> float | None:
    """Unix seconds from an `@time=` tag, or None when absent or malformed."""
    if not value:
        return None
    match = _SERVER_TIME.match(value.strip())
    if match is None:
        return None
    import calendar

    year, month, day, hour, minute, second = (int(g) for g in match.groups()[:6])
    try:
        whole = calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0))
    except (ValueError, OverflowError):
        return None
    fraction = match.group(7)
    return whole + (int(fraction) / 10 ** len(fraction) if fraction else 0.0)


# --- secrets typed to services ---------------------------------------------
#
# On most networks the only way to identify, before SASL, was to type it:
# "/msg NickServ IDENTIFY hunter2". That line is a `say` like any other, so its
# echo was stored, sent to every device, indexed for search and backed up. The
# line still goes to the service exactly as typed -- that is what the person
# asked for -- but what the bouncer KEEPS of it stops at the verb.
REDACTED = "********"

# Services by name. Q goes by two, and every other service on every network
# ends in "Serv" (NickServ, ChanServ, AuthServ on GameSurge, HostServ...).
_SERVICE_NAMES = {"q", "nickserv", "chanserv"}
_SERVICE_FULL = {"q@cserve.quakenet.org"}

# The verbs whose arguments are a password, or carry one, across the common
# services packages:
#   Anope/Atheme/Ergo NickServ: IDENTIFY and its short form ID, LOGIN, REGISTER,
#     GROUP, GHOST, RECOVER, RELEASE, REGAIN, SETPASS, PASSWD (Ergo),
#     SAREGISTER (Ergo, an oper registering someone), and SET/SASET PASSWORD
#     (handled below, since the verb is two or three words).
#   Q on QuakeNet: AUTH, CHALLENGEAUTH (a password hash, as good as one),
#     NEWPASS, and HELLO (registration: it carries an email address, which is
#     not a password but is not something to index and back up either).
#   ChanServ's IDENTIFY and REGISTER for a channel are the same verbs.
SECRET_VERBS = frozenset((
    "IDENTIFY", "ID", "LOGIN", "AUTH", "CHALLENGEAUTH", "REGISTER", "SAREGISTER",
    "GROUP", "GHOST", "RECOVER", "RELEASE", "REGAIN", "SETPASS", "PASSWD",
    "NEWPASS", "HELLO",
))

# The commands many ircds accept as a shortcut for a line to a service:
# "NS IDENTIFY x" is "PRIVMSG NickServ :IDENTIFY x". A raw line typed that way
# carries the same secret, so the wire log treats it the same.
SERVICE_ALIASES = frozenset((
    "NS", "NICKSERV", "CS", "CHANSERV", "HS", "HOSTSERV", "MS", "MEMOSERV",
    "OS", "OPERSERV", "BS", "BOTSERV",
))


def is_service(target: str) -> bool:
    """Is this a network service a password might be typed to?"""
    lowered = (target or "").strip().lower()
    if lowered in _SERVICE_FULL:
        return True
    name = lowered.split("@", 1)[0]
    return name in _SERVICE_NAMES or (len(name) > 4 and name.endswith("serv"))


def redact_secret(target: str, text: str) -> str | None:
    """What may be kept of a line to `target`: the verb and "********".

    None when the line is not a secret to a service, which is nearly always.
    "IDENTIFY hunter2" becomes "IDENTIFY ********"; "SET PASSWORD x" keeps
    both words of the verb. The verb is kept as typed, so the stored line
    still says what was done.
    """
    if not text or not is_service(target):
        return None
    return _redact_verb(text)


def _redact_verb(text: str) -> str | None:
    """"IDENTIFY hunter2" -> "IDENTIFY ********", or None when the words are
    not a secret verb. The target has already been judged a service."""
    words = text.split()
    if not words:
        return None
    first = words[0].upper()
    upper = [w.upper() for w in words[:3]]
    if first in ("SET", "SASET") and "PASSWORD" in upper[1:3]:
        # SET PASSWORD x, SASET nick PASSWORD x, and old Anope's
        # SET #channel PASSWORD x: everything up to PASSWORD is kept.
        verb_words = upper.index("PASSWORD", 1) + 1
    elif first in SECRET_VERBS:
        verb_words = 1
    else:
        return None
    kept = " ".join(words[:verb_words])
    return f"{kept} {REDACTED}" if len(words) > verb_words else kept


def redact_line(line: str) -> str:
    """A whole outgoing line as it may be logged: a PRIVMSG or NOTICE secret
    to a service, a server PASS and a SASL payload are cut down to their verb."""
    msg = parse_line(line)
    if msg is None:
        return line
    if msg.command == "PASS":
        return f"PASS {REDACTED}"
    if msg.command == "AUTHENTICATE" and msg.param(0) not in ("+", "*", "PLAIN", "EXTERNAL"):
        return f"AUTHENTICATE {REDACTED}"
    if msg.command == "OPER" and len(msg.params) >= 2:
        return f"OPER {msg.param(0)} {REDACTED}"
    if msg.command == "JOIN" and len(msg.params) >= 2:
        # "JOIN #a,#b key1,key2": a channel key is a password too, and the
        # bouncer now sends them on every reconnect.
        return f"JOIN {msg.param(0)} {REDACTED}"
    if msg.command in SERVICE_ALIASES or msg.command in SECRET_VERBS:
        # "NS ID x" and a bare "IDENTIFY x", which some ircds route to NickServ.
        words = " ".join(msg.params)
        kept = _redact_verb(words) if msg.command in SERVICE_ALIASES else \
            _redact_verb(f"{msg.command} {words}")
        if kept is not None:
            return f"{msg.command} {kept}" if msg.command in SERVICE_ALIASES else kept
    if msg.command in ("PRIVMSG", "NOTICE") and len(msg.params) >= 2:
        kept = redact_secret(msg.param(0), msg.param(1))
        if kept is not None:
            return f"{msg.command} {msg.param(0)} :{kept}"
    return line


# --- outbound safety -------------------------------------------------------
#
# Every command the bouncer sends upstream is built out of something a client
# asked for: a channel name, a nick, a topic, a message. A newline in any of
# them is not a stray character, it is a second command -- "hello\r\nJOIN #x" is
# a whole extra line to the server, and the client typed it. So nothing goes out
# without passing through here first.
#
# The rules are the wire format's own. A non-trailing parameter is delimited by
# spaces and so cannot contain one, and an empty one would shift every parameter
# after it along by a place. The trailing parameter may contain anything except
# the three bytes that end or frame a line.

_LINE_BREAKERS = (("\r", "a carriage return"), ("\n", "a newline"), ("\0", "a null byte"))


def check_param(value: str, what: str = "that", *, trailing: bool = False) -> str:
    """Refuse a parameter IRC cannot carry. Returns it, so it reads inline.

    Raises ValueError with a sentence meant for the person who typed it; the
    gateway turns that into an `error` frame.
    """
    for char, name in _LINE_BREAKERS:
        if char in value:
            raise ValueError(f"{what} cannot contain {name}")
    if not trailing:
        if not value:
            raise ValueError(f"{what} cannot be empty")
        if " " in value:
            raise ValueError(f"{what} cannot contain a space")
    return value


def check_channel(name: str) -> str:
    """A channel name, with the comma rule on top.

    IRC reads `#a,#b` as two channels, so a comma in one name is a JOIN of
    somewhere else -- silently, and with nothing in the client to show for it.
    """
    check_param(name, "a channel name")
    if "," in name:
        raise ValueError("a channel name cannot contain a comma")
    return name


# The longest channel key the bouncer will keep. Servers stop well short of
# this (ircu's KEYLEN is 23, others 32); it is a bound, not a rule of IRC's.
MAX_CHANNEL_KEY = 64


def check_channel_key(key: str) -> str:
    """A channel key (+k), as JOIN carries it.

    One parameter, so no space; and no comma, because JOIN's keys are a
    comma-separated list matched to its channels by position -- a comma in
    one key would hand every channel after it the wrong key. The sentence
    never repeats the key: it is a password, and an error is something a
    client shows and a log keeps.
    """
    if not isinstance(key, str):
        raise ValueError("a channel key must be text")
    check_param(key, "a channel key")
    if "," in key:
        raise ValueError("a channel key cannot contain a comma")
    if key.startswith(":"):
        raise ValueError("a channel key cannot start with a colon")
    if len(key) > MAX_CHANNEL_KEY:
        raise ValueError(f"a channel key can be at most {MAX_CHANNEL_KEY} characters")
    return key


# --- message splitting -----------------------------------------------------
#
# An IRC line is 512 bytes including the CRLF, and the server puts our own
# `:nick!user@host ` on the front before anyone else sees it. That prefix is not
# ours to measure: the host comes from the server and changes the moment a cloak
# lands. So a fixed allowance stands in for it. Too generous loses a few
# characters to an early split; too mean loses the end of somebody's sentence,
# which is the failure that matters.
IRC_LINE_LIMIT = 512
PREFIX_HEADROOM = 100

# One `say` is one thing the person typed. A pasted wall of text is still that,
# but at some size it stops being a message and becomes a flood that the
# outbound queue drains for a minute while their next line waits behind it.
MAX_SAY_LINES = 10

# The most characters one `say` may carry. The send queue holds 200 lines of
# at most 510 bytes, so anything longer could never be sent and was refused
# anyway -- but only after it had been wrapped, and wrapping re-encodes what is
# left of the line for every piece it cuts off: a 4 MB line of emoji held the
# event loop (every other client and the IRC link) for nine seconds before the
# refusal. Refused up front now, before any of that work.
MAX_SAY_TEXT = 200 * 510

_NEWLINES = re.compile(r"\r\n|\r|\n")


def say_budget(target: str) -> int:
    """How many bytes of message text a PRIVMSG to `target` has room for."""
    overhead = len(f"PRIVMSG {target} :\r\n".encode("utf-8", errors="replace"))
    return IRC_LINE_LIMIT - overhead - PREFIX_HEADROOM


def join_lines(channels: list[str], keys: dict[str, str] | None = None, *,
               max_targets: int | None = None, budget: int = LINE_BYTES) -> list[str]:
    """The JOIN lines for a list of channels: as few as fit.

    "JOIN #a,#b,#c" is one line where three used to be three, and at one line
    per two seconds after the first four that is the difference between being
    in every channel a second after connecting and half a minute later.

    Keys are positional ("JOIN #k1,#k2,#plain key1,key2"), so the keyed
    channels go first in every line and the plain ones after them. A line
    stops at `budget` bytes and at `max_targets` channels (ISUPPORT
    TARGMAX=JOIN:n) when the server gave one.
    """
    keys = {c: k for c, k in (keys or {}).items() if k}
    ordered = [c for c in channels if c in keys] + [c for c in channels if c not in keys]

    def line(names: list[str]) -> str:
        wanted = [keys[c] for c in names if c in keys]
        return f"JOIN {','.join(names)}" + (f" {','.join(wanted)}" if wanted else "")

    lines: list[str] = []
    current: list[str] = []
    for channel in ordered:
        trial = current + [channel]
        too_many = max_targets is not None and len(trial) > max_targets
        if current and (too_many or len(line(trial).encode("utf-8")) > budget):
            lines.append(line(current))
            current = [channel]
        else:
            current = trial
    if current:
        lines.append(line(current))
    return lines


def targmax(value: str | None, command: str) -> int | None:
    """One command's limit from ISUPPORT TARGMAX ("JOIN:5,PRIVMSG:4,NAMES:"),
    or None when there is none (not listed, or listed with no number)."""
    for item in (value or "").split(","):
        name, _, limit = item.partition(":")
        if name.strip().upper() == command and limit.strip().isdigit():
            return max(1, int(limit))
    return None


def split_message(text: str, budget: int, *, max_lines: int = MAX_SAY_LINES) -> list[str]:
    """One typed message, as the lines that will actually go out.

    Two reasons a line splits. Newlines, because a paste arrives as a single
    `say` frame and an IRC line cannot contain one at all -- the old behaviour
    was to hand it to the server and hope. And length, because the server
    truncates at 512 bytes, and losing the end of a sentence with nothing said
    about it is the kind of quiet data loss nobody notices until it matters.
    """
    if len(text) > MAX_SAY_TEXT:
        raise ValueError("that is too long to send in one go; send it in pieces")
    if "\0" in text:
        # CR and LF mean "new line" and split the message; a NUL means
        # nothing, and IRC ends the line at it, so the channel got everything
        # before it while the echo kept the rest. Refused the way check_param
        # refuses it everywhere else; the client keeps the draft.
        raise ValueError("A message cannot contain a null character.")
    lines = [line for line in _NEWLINES.split(text) if line.strip()]
    if len(lines) > max_lines:
        raise ValueError(f"that is more than {max_lines} lines; send it in pieces")
    out: list[str] = []
    for line in lines:
        out.extend(_wrap(line, budget))
    return out


def _wrap(line: str, budget: int) -> list[str]:
    out: list[str] = []
    while len(line.encode("utf-8", errors="replace")) > budget:
        # Cut on a byte budget but land on a character boundary: slicing the
        # encoded form can leave half a multibyte character, and `ignore` drops
        # exactly that half.
        head = line.encode("utf-8", errors="replace")[:budget].decode("utf-8", errors="ignore")
        # Prefer a word boundary, but only one in the second half of the piece.
        # A single long word with one early space in front of it would otherwise
        # split into a two-character line and the whole word on the next.
        cut = head.rfind(" ")
        if cut > len(head) // 2:
            head = head[:cut]
        if not head:                       # pathological: one enormous character
            head = line[:1]
        out.append(head)
        line = line[len(head):].lstrip(" ")
    if line:
        out.append(line)
    return out


# --- CTCP ------------------------------------------------------------------
#
# The only CTCP that matters for display is ACTION (/me). The rest (VERSION,
# PING, TIME) are answered by the session, not rendered.
CTCP_DELIM = "\x01"


def parse_ctcp(text: str) -> tuple[str, str] | None:
    """Return (verb, argument) for a CTCP payload, or None if it is a plain message."""
    if len(text) < 2 or not text.startswith(CTCP_DELIM):
        return None
    body = text[1:]
    if body.endswith(CTCP_DELIM):
        body = body[:-1]
    verb, _, arg = body.partition(" ")
    return verb.upper(), arg


def make_ctcp(verb: str, arg: str = "") -> str:
    body = f"{verb} {arg}".strip()
    return f"{CTCP_DELIM}{body}{CTCP_DELIM}"


# --- ignore masks ------------------------------------------------------------
#
# An ignore is a `nick!user@host` mask with `*` and `?` wildcards, matched
# against the whole prefix a line arrives with. A bare nick is `nick!*@*`, which
# is what it always meant; `*!*@spam.host` is the one that survives a nick
# change, because the host is the part a nick change does not touch.
#
# Not fnmatch: fnmatch reads `[` as the start of a character class, and `[` is an
# ordinary nick character under rfc1459 ("Riley[m]"). Only `*` and `?` are
# special here, which is what every IRC server means by a mask too.

def normalize_mask(text: str) -> str:
    """An ignore as typed, as a full nick!user@host mask.

    `bob` -> `bob!*@*`, `bob!~b` -> `bob!~b@*`, `~b@host` -> `*!~b@host`. The
    list keeps what was typed; this is only the form that gets matched.
    """
    if "!" in text:
        nick, _, rest = text.partition("!")
        user, sep, host = rest.partition("@")
        return f"{nick or '*'}!{user or '*'}@{(host or '*') if sep else '*'}"
    if "@" in text:
        user, _, host = text.partition("@")
        return f"*!{user or '*'}@{host or '*'}"
    return f"{text}!*@*"


def is_mask(text: str) -> bool:
    """Is this more than a bare nick? A nick cannot contain any of these."""
    return any(ch in text for ch in "!@*?")


def mask_matches_everyone(text: str) -> bool:
    """`*`, `*!*@*`, `*@*`, and `*!*@*.*`: a mask whose nick, user and host
    are each nothing but wildcards and dots. The dots used to get it past
    this: `*!*@*.*` is every host with a dot in it, which is every host."""
    nick, _, rest = normalize_mask(text).partition("!")
    user, _, host = rest.partition("@")
    return all(ch in "*?." for part in (nick, user, host) for ch in part)


def compile_mask(mask: str, casemapping: str = "rfc1459") -> re.Pattern[str]:
    """A compiled matcher for one mask, over a folded `nick!user@host`."""
    folded = fold(normalize_mask(mask), casemapping)
    body = "".join(".*" if ch == "*" else "." if ch == "?" else re.escape(ch)
                   for ch in folded)
    return re.compile(body + r"\Z", re.DOTALL)


class IgnoreMatcher:
    """Every ignore of one network, compiled once, matched per line.

    Compiled when the list or the casemapping changes, not per line: a busy
    channel is a few lines a second and the list is a handful of masks.
    """

    def __init__(self, masks: list[str] | None = None, casemapping: str = "rfc1459"):
        self.casemapping = casemapping
        self._patterns: list[re.Pattern[str]] = []
        self.set_masks(masks or [])

    def set_masks(self, masks: list[str]) -> None:
        self.masks = list(masks)
        self._patterns = [compile_mask(m, self.casemapping) for m in self.masks]

    def set_casemapping(self, casemapping: str) -> None:
        if casemapping != self.casemapping:
            self.casemapping = casemapping
            self.set_masks(self.masks)

    def matches(self, nick: str, user: str = "", host: str = "") -> bool:
        if not self._patterns or not nick:
            return False
        subject = fold(f"{nick}!{user}@{host}", self.casemapping)
        return any(p.match(subject) for p in self._patterns)


# --- netsplits -------------------------------------------------------------
#
# When two servers lose each other, everyone behind the far one quits at the
# same instant with an identical message naming the two servers:
#
#     :nick!u@h QUIT :irc.quakenet.org irc.tng.net
#
# A hundred of those, then a hundred joins when it heals, is two screens of
# noise burying the conversation. Recognising the shape is what lets a client
# collapse it into one row.
#
# The test is deliberately strict -- exactly two whitespace-separated tokens,
# each containing a dot -- because the cost of a false positive (a real goodbye
# hidden inside a "netsplit" summary) is worse than the cost of a miss. "brb
# dinner.time" has two tokens but only one dot, so it stays a normal quit.
_NETSPLIT_QUIT = re.compile(r"^\S+\.\S+[ ]\S+\.\S+$")


def netsplit_servers(quit_reason: str | None) -> tuple[str, str] | None:
    """The two servers named by a netsplit quit message, or None if it is a
    normal quit."""
    if not quit_reason or not _NETSPLIT_QUIT.match(quit_reason):
        return None
    a, b = quit_reason.split()
    return a, b


# --- ISUPPORT --------------------------------------------------------------

def parse_isupport(params: list[str]) -> dict[str, str]:
    """Parse the tokens of a 005 RPL_ISUPPORT line into a dict.

    The first param is our own nick and the last is the human-readable
    "are supported by this server", so neither is a token.
    """
    out: dict[str, str] = {}
    for token in params[1:-1]:
        key, _, value = token.partition("=")
        out[key.upper()] = value
    return out


def parse_prefix_map(spec: str) -> dict[str, str]:
    """Turn the ISUPPORT PREFIX value `(ohv)@%+` into {'@': 'o', '%': 'h', '+': 'v'}."""
    if not spec.startswith("(") or ")" not in spec:
        return {"@": "o", "+": "v"}
    modes, _, symbols = spec[1:].partition(")")
    return dict(zip(symbols, modes))


# What rfc1459 servers mean when they send no CHANMODES token: bans are a list,
# a key always takes an argument, a limit only when set, the rest never do.
DEFAULT_CHANMODES = ("b", "k", "l", "imnpst")


def parse_chanmodes(spec: str) -> tuple[str, str, str, str]:
    """Turn the ISUPPORT CHANMODES value `b,k,l,imnpst` into its four groups.

    A: list modes (always a parameter), B: always a parameter, C: a parameter
    only when set, D: never. A server may add groups after the fourth; they
    are ignored, which is what the spec asks of a client that does not know
    what they mean.
    """
    parts = (spec.split(",") + ["", "", "", ""])[:4]
    return parts[0], parts[1], parts[2], parts[3]


def parse_mode_changes(modes: str, args: list[str], prefix_modes: str,
                       chanmodes: tuple[str, str, str, str] = DEFAULT_CHANMODES,
                       ) -> list[tuple[str, str, str | None]]:
    """Split a channel MODE line into (sign, mode, parameter) triples.

    `+ov-b alice bob *!*@spam` is three changes, and which of them eats a
    parameter is not in the line: it depends on the mode, and for group C on
    the sign. Getting that wrong shifts every parameter after it by one, so a
    +l in front of a +o would have opped the limit. Prefix modes (o, v, and
    whatever PREFIX adds) always take a nick. A mode the server never
    described is assumed to take nothing, the least harmful guess.
    """
    list_modes, always, when_set, _never = chanmodes
    out: list[tuple[str, str, str | None]] = []
    sign = "+"
    queue = list(args)
    for ch in modes:
        if ch in "+-":
            sign = ch
            continue
        takes = (ch in prefix_modes or ch in list_modes or ch in always
                 or (ch in when_set and sign == "+"))
        param = queue.pop(0) if takes and queue else None
        out.append((sign, ch, param))
    return out
