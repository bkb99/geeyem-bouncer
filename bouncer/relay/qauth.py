"""QuakeNet Q authentication, via CHALLENGEAUTH.

Q accepts two forms. The obvious one is:

    PRIVMSG Q@CServe.quakenet.org :AUTH <username> <password>

which sends the password as a plain IRC message. QuakeNet offers **no TLS on
any server** -- verified against the round-robin and two named servers -- so
that password would cross the open internet in the clear, through however many
networks sit between the VPS and Sweden. That form is not implemented here and
should not be.

CHALLENGEAUTH is the other form. Q issues a challenge, the client answers with
an HMAC of it, and the password never leaves the machine:

    ->  PRIVMSG Q@CServe.quakenet.org :CHALLENGE
    <-  NOTICE  CHALLENGE <challenge> <space separated algorithms>
    ->  PRIVMSG Q@CServe.quakenet.org :CHALLENGEAUTH <user> <response> HMAC-SHA-256

The digest construction matches the one in otherbot's ircio.py, which has been
authenticating against Q on this account since 2026-08-29. Three details were
taken from it after a first version got them wrong, and each fails silently:

  - The intermediate digests are HEX STRINGS at both levels, not raw bytes.
  - The username is folded with RFC1459 rules ([ ] \\ become { } |), not plain
    lowercase, so an account with a bracket in it authenticates.
  - Only a notice from CServe's own host counts as a challenge. See
    `handle_notice`.
"""

from __future__ import annotations

import hashlib
import hmac
import logging

from .ircproto import fold

log = logging.getLogger("relay.qauth")

Q_BOT = "Q@CServe.quakenet.org"
# The host a genuine Q notice comes from. Checked before answering a challenge.
Q_HOST = "cserve.quakenet.org"

# Q truncates at ten characters and always has. A longer password is not an
# error; the extra characters are simply not part of the secret, which is worth
# knowing before concluding the digest is wrong.
PASSWORD_LENGTH = 10


def challenge_response(username: str, password: str, challenge: str) -> str:
    """The HMAC-SHA-256 answer to a Q challenge.

        key      = sha256( lower(username) + ":" + sha256(password[:10]).hex() ).hex()
        response = hmac_sha256( key, challenge ).hex()

    The username is folded with RFC1459 rules and the password truncated before
    hashing -- both are part of the algorithm rather than tidying. The
    intermediate digests are hex STRINGS at both levels; using raw bytes
    produces a well-formed response that Q silently rejects.
    """
    truncated = password[:PASSWORD_LENGTH]
    inner = hashlib.sha256(truncated.encode()).hexdigest()
    key = hashlib.sha256(f"{fold(username)}:{inner}".encode()).hexdigest()
    return hmac.new(key.encode(), challenge.encode(), hashlib.sha256).hexdigest()


def pick_algorithm(offered: str) -> str | None:
    """Choose the strongest algorithm Q offers that we implement.

    Only SHA-256 is implemented. If Q ever stops offering it the right move is
    to fail and say so, not to quietly fall back to MD5 -- a downgrade nobody
    noticed is worse than an auth that did not happen.
    """
    algorithms = {a.strip().upper() for a in offered.split()}
    return "HMAC-SHA-256" if "HMAC-SHA-256" in algorithms else None


class QAuth:
    """Drives the challenge exchange for one connection.

    The password is held in memory only, never written to the database, never
    logged, and never sent. It arrives from the environment (GEYEM_Q_PASSWORD)
    so it is not in the config file either.
    """

    def __init__(self, username: str, password: str, *, hide_host: bool = True):
        self.username = username
        self._password = password
        self.hide_host = hide_host
        self.state = "idle"          # idle | challenged | authed | failed
        self.failure: str | None = None

    @property
    def configured(self) -> bool:
        return bool(self.username and self._password)

    def start(self) -> tuple[str, str]:
        """The line to send to begin. Returns (command, argument) for PRIVMSG."""
        self.state = "challenged"
        return ("PRIVMSG", "CHALLENGE")

    @property
    def awaiting(self) -> bool:
        """Still mid-exchange, so joins should wait."""
        return self.state in ("idle", "challenged", "answered")

    def handle_notice(self, text: str, sender_host: str = "") -> tuple[str, str] | None:
        """Feed every NOTICE from Q here.

        Returns the next line to send, or None when there is nothing to do.

        `sender_host` is checked against CServe's own hostname before a
        challenge is answered, and that check is NOT cosmetic: without it anyone
        can NOTICE us a nonce of their choosing and collect an HMAC computed
        under our key, which is an offline attack on the password. A nick check
        alone is not enough.
        """
        parts = text.split()
        if not parts:
            return None

        if parts[0].upper() == "CHALLENGE" and len(parts) >= 2:
            if self.state != "challenged":
                return None
            # The whole host, not a substring of it: "cserve.quakenet.org" is
            # also in "cserve.quakenet.org.evil.example" (G78). Q's own prefix
            # is Q!TheQBot@CServe.quakenet.org, which ZNC matches in full too.
            if sender_host.strip().lower().rstrip(".") != Q_HOST:
                log.warning("Q auth: ignoring a CHALLENGE from %r, not from %s",
                            sender_host, Q_HOST)
                return None
            challenge = parts[1]
            offered = " ".join(parts[2:])
            algorithm = pick_algorithm(offered)
            if algorithm is None:
                self.state, self.failure = "failed", f"no supported algorithm in: {offered}"
                log.error("Q auth: %s", self.failure)
                return None
            response = challenge_response(self.username, self._password, challenge)
            # The response is a digest, not a secret, but there is no reason to
            # put it in a log either.
            log.info("Q auth: answering challenge as %s", self.username)
            self.state = "answered"
            return ("PRIVMSG", f"CHALLENGEAUTH {self.username} {response} {algorithm}")

        lowered = text.lower()
        if "you are now logged in as" in lowered or "auth successful" in lowered:
            self.state = "authed"
            log.info("Q auth: authenticated as %s", self.username)
            return None

        if "username or password incorrect" in lowered or "auth failed" in lowered:
            self.state = "failed"
            self.failure = text
            # Deliberately loud. A bouncer that quietly runs unauthenticated
            # looks identical to one that worked until someone notices the host
            # is not cloaked.
            log.error("Q auth FAILED: %s", text)
            return None

        return None
