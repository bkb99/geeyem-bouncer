"""Does this line mention me?

Decided server-side, on purpose. The client cannot decide it: the whole point of
the bouncer is that the phone is asleep when the line arrives, and a highlight
that is only computed when a client is attached is a push notification that
never fires. It is also the one rule that must be identical on iOS, macOS and
web, and there is exactly one copy of it here.
"""

from __future__ import annotations

import re

from .ircproto import fold, strip_formatting


def _word_pattern(word: str) -> re.Pattern[str]:
    """A nick matches on word boundaries, but IRC nicks contain characters that
    `\\b` does not treat as word characters -- `[]\\`^{|}` and `-` are all legal
    in a nick. So the boundary is defined the other way round: what may sit next
    to a match is anything that is NOT a nick character.

    Without this, "Riley" fires on "Rileys", and "q" fires on every word with a q
    in it. Both were real annoyances in clients that used a naive `in` test.
    """
    nick_chars = r"A-Za-z0-9\[\]\\`_^{|}-"
    return re.compile(
        rf"(?<![{nick_chars}]){re.escape(word)}(?![{nick_chars}])",
        re.IGNORECASE,
    )


class HighlightMatcher:
    """Holds the compiled patterns for one network and re-compiles on nick change."""

    def __init__(self, nick: str, extra_words: list[str] | None = None,
                 own_nicks: list[str] | None = None):
        self._extra = list(extra_words or [])
        self._nick = nick
        # The configured nick and the alt nicks, matched whatever nick is in
        # use. Until 2026-09-26 only the current one was: on the fallback
        # (quinn_) "quinn: you there?" was not a mention and pushed nothing, and
        # people keep typing the name they know, not the one the ghost left us.
        self._own = list(own_nicks or [])
        self._compile()

    def _compile(self) -> None:
        words = [self._nick, *self._own, *self._extra]
        seen: set[str] = set()
        self._patterns = []
        for w in words:
            if w and fold(w) not in seen:
                seen.add(fold(w))
                self._patterns.append(_word_pattern(w))

    def set_own_nicks(self, nicks: list[str]) -> None:
        """The nicks that are ours on this network (configured, then alts)."""
        self._own = list(nicks)
        self._compile()

    @property
    def nick(self) -> str:
        return self._nick

    @property
    def words(self) -> list[str]:
        """The extra words, besides the nick."""
        return list(self._extra)

    def set_words(self, words: list[str]) -> None:
        self._extra = list(words)
        self._compile()

    def set_nick(self, nick: str) -> None:
        if fold(nick) == fold(self._nick):
            return
        self._nick = nick
        self._compile()

    def matches(self, text: str, *, sender: str | None = None, is_private: bool = False) -> bool:
        """True if this line should count as a highlight.

        A private message is always a highlight -- someone opened a query with
        you, there is no other reason for it to exist.

        Matching runs against the formatting-stripped copy so a nick wearing a
        colour code (`\\x0304Riley`) still fires. The stored text keeps the codes.
        """
        if sender and fold(sender) == fold(self._nick):
            return False          # never highlight on your own line
        if is_private:
            return True
        if not text:
            return False
        plain = strip_formatting(text)
        return any(p.search(plain) for p in self._patterns)
