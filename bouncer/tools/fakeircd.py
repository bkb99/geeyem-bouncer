#!/usr/bin/env python3
"""A minimal IRC server, for tests that must not touch a real network.

It implements exactly the subset the bouncer talks to: registration, JOIN with a
NAMES reply, PRIVMSG echoed to the other clients in the channel, PING/PONG, QUIT.
That is enough to exercise the whole receive AND send path -- including the parts
that would otherwise require posting into #hangout to verify.

Plus TAGMSG, for IRCv3 +typing: a peer that asks for message-tags with CAP REQ
is acknowledged, and TAGMSG's client-only tags (+typing) are passed to the
others who asked for it. CAP LS is still not answered, so registration is the
plain one every test relies on; a test that wants the bouncer to take
message-tags announces it with CAP NEW through RAWTO, which is how a server
offers a capability after registration.

Plus LIST, and a few control commands any peer can send, for the things a test
cannot otherwise make a server do: `RAWTO <nick> ::<line>` sends one raw line to
that peer (note the doubled colon: the first ends the parameters), `KILLPEER
<nick> :<reason>` throws it off with ERROR the way a flood kill does,
`FAKECHANNELS <n>` plants n extra rows in the LIST reply, `FAKEKEY <channel>
<key>` gives a channel a key so that a JOIN without it is answered 475, and
`BANLIST <channel>` answers with a ban list (367, 368), which is a reply the
bouncer has no handler for.

    python tools/fakeircd.py --port 6699
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass, field


# eq=False so a Peer stays hashable: the default dataclass __eq__ sets __hash__
# to None, and these live in a set.
@dataclass(eq=False)
class Peer:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    nick: str = ""
    user: str = ""
    channels: set[str] = field(default_factory=set)
    registered: bool = False
    quit_reason: str = "connection closed"
    away: str | None = None
    # Capabilities acknowledged to this peer (CAP REQ). Only message-tags.
    caps: set[str] = field(default_factory=set)

    def send(self, line: str) -> None:
        self.writer.write(line.encode() + b"\r\n")


# What CAP REQ is acknowledged for. Anything else is NAKed.
OFFERED_CAPS = {"message-tags"}


class FakeIRCd:
    def __init__(self, host: str = "127.0.0.1", port: int = 6699, name: str = "fake.irc"):
        self.host, self.port, self.name = host, port, name
        self.peers: set[Peer] = set()
        self.server: asyncio.AbstractServer | None = None
        # Extra rows for LIST, planted by the FAKECHANNELS control command.
        self.fake_list: list[tuple[str, int, str]] = []
        # Channel keys (+k), by lower-cased channel, set with FAKEKEY.
        self.keys: dict[str, str] = {}

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, self.host, self.port)

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    def members(self, channel: str) -> list[Peer]:
        return [p for p in self.peers if channel.lower() in {c.lower() for c in p.channels}]

    def broadcast(self, channel: str, line: str, exclude: Peer | None = None) -> None:
        for p in self.members(channel):
            if p is not exclude:
                p.send(line)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = Peer(reader, writer)
        self.peers.add(peer)
        try:
            while True:
                raw = await reader.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", "replace").strip()
                if line:
                    self._command(peer, line)
                await writer.drain()
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            for ch in list(peer.channels):
                self.broadcast(ch, f":{peer.nick}!u@h QUIT :{peer.quit_reason}", exclude=peer)
            self.peers.discard(peer)
            writer.close()

    def _command(self, peer: Peer, line: str) -> None:
        # A client's tags come first. Only the client-only ones ("+typing")
        # are ever passed on, and only on TAGMSG.
        tags = ""
        if line.startswith("@"):
            tagpart, _, line = line.partition(" ")
            tags = ";".join(t for t in tagpart[1:].split(";") if t.startswith("+"))
            line = line.lstrip(" ")
        parts = line.split(" :", 1)
        words = parts[0].split()
        trailing = parts[1] if len(parts) > 1 else None
        cmd = words[0].upper()
        args = words[1:] + ([trailing] if trailing is not None else [])

        if cmd == "NICK":
            if peer.registered:
                # A rename after registration is announced to everyone who can
                # see the person, which is how the bouncer learns its own new
                # nick -- it does not assume the change was accepted.
                old_nick, peer.nick = peer.nick, args[0]
                peer.send(f":{old_nick}!u@h NICK :{peer.nick}")
                for ch in peer.channels:
                    self.broadcast(ch, f":{old_nick}!u@h NICK :{peer.nick}", exclude=peer)
            else:
                peer.nick = args[0]
                self._maybe_register(peer)
        elif cmd == "USER":
            peer.user = args[0]
            self._maybe_register(peer)
        elif cmd == "PING":
            peer.send(f":{self.name} PONG {self.name} :{args[0] if args else ''}")
        elif cmd == "JOIN":
            # "JOIN #a,#b key1,key2": the keys go with the channels by
            # position. A channel given a key with FAKEKEY lets in only a
            # JOIN that brings it, and answers 475 otherwise, as +k does.
            keys = args[1].split(",") if len(args) > 1 else []
            for index, channel in enumerate(args[0].split(",")):
                wanted = self.keys.get(channel.lower())
                if wanted and (keys[index] if index < len(keys) else "") != wanted:
                    peer.send(f":{self.name} 475 {peer.nick} {channel} "
                              f":Cannot join channel (+k)")
                    continue
                peer.channels.add(channel)
                self.broadcast(channel, f":{peer.nick}!u@h JOIN {channel}")
                peer.send(f":{self.name} 332 {peer.nick} {channel} :a topic for testing")
                names = " ".join(p.nick for p in self.members(channel))
                peer.send(f":{self.name} 353 {peer.nick} = {channel} :{names}")
                peer.send(f":{self.name} 366 {peer.nick} {channel} :End of /NAMES list.")
        elif cmd == "PART":
            channel = args[0]
            peer.channels.discard(channel)
            self.broadcast(channel, f":{peer.nick}!u@h PART {channel}")
            peer.send(f":{peer.nick}!u@h PART {channel}")
        elif cmd == "CAP":
            sub = args[0].upper() if args else ""
            if sub == "REQ":
                wanted = (args[1] if len(args) > 1 else "").split()
                if all(w.lstrip("-") in OFFERED_CAPS for w in wanted):
                    for w in wanted:
                        (peer.caps.discard if w.startswith("-") else peer.caps.add)(w.lstrip("-"))
                    peer.send(f":{self.name} CAP {peer.nick or '*'} ACK :{' '.join(wanted)}")
                else:
                    peer.send(f":{self.name} CAP {peer.nick or '*'} NAK :{' '.join(wanted)}")
        elif cmd == "TAGMSG":
            # Only to peers that took message-tags, as a real server does: a
            # client without it would not know what the line was.
            target = args[0]
            if not tags:
                return
            out = f"@{tags} :{peer.nick}!u@h TAGMSG {target}"
            receivers = (self.members(target) if target.startswith("#")
                         else [p for p in self.peers if p.nick.lower() == target.lower()])
            for p in receivers:
                if p is not peer and "message-tags" in p.caps:
                    p.send(out)
        elif cmd == "PRIVMSG" or cmd == "NOTICE":
            target, text = args[0], args[1] if len(args) > 1 else ""
            out = f":{peer.nick}!u@h {cmd} {target} :{text}"
            if target.startswith("#"):
                # Echoed to everyone EXCEPT the sender, exactly as a real server
                # does -- that asymmetry is why the bouncer writes its own echo.
                self.broadcast(target, out, exclude=peer)
            else:
                for p in self.peers:
                    if p.nick.lower() == target.lower():
                        p.send(out)
        elif cmd == "MODE":
            # Enough to let the bouncer's operator actions be tested: echo the
            # change to the channel the way a real server does. No attempt at
            # tracking who may set what -- that is the real server's job.
            channel = args[0]
            rest = " ".join(args[1:])
            self.broadcast(channel, f":{peer.nick}!u@h MODE {channel} {rest}")
        elif cmd == "KICK":
            channel, target = args[0], args[1]
            reason = args[2] if len(args) > 2 else ""
            self.broadcast(channel, f":{peer.nick}!u@h KICK {channel} {target} :{reason}")
            for p in self.peers:
                if p.nick.lower() == target.lower():
                    p.channels.discard(channel)
        elif cmd == "TOPIC":
            channel, topic = args[0], args[1] if len(args) > 1 else ""
            self.broadcast(channel, f":{peer.nick}!u@h TOPIC {channel} :{topic}")
        elif cmd == "WHOIS":
            # The full shape a real server sends, because the bouncer collects
            # these nine lines into one frame and a reply of two lines would
            # test the collecting and none of the collected.
            who = args[0]
            target = next((p for p in self.peers if p.nick.lower() == who.lower()), None)
            if target is None:
                peer.send(f":{self.name} 401 {peer.nick} {who} :No such nick/channel")
                peer.send(f":{self.name} 318 {peer.nick} {who} :End of /WHOIS list.")
                return
            peer.send(f":{self.name} 311 {peer.nick} {target.nick} ~{target.nick} "
                      f"{target.nick}.users.fake.irc * :a test user")
            peer.send(f":{self.name} 312 {peer.nick} {target.nick} {self.name} "
                      f":a server for testing")
            if target.channels:
                # Prefixed, so the prefix parsing is exercised rather than
                # assumed. Everyone here is an op as far as this server cares.
                channels = " ".join(f"@{c}" for c in sorted(target.channels))
                peer.send(f":{self.name} 319 {peer.nick} {target.nick} :{channels}")
            peer.send(f":{self.name} 317 {peer.nick} {target.nick} 42 1758000000 "
                      f":seconds idle, signon time")
            peer.send(f":{self.name} 330 {peer.nick} {target.nick} {target.nick} "
                      f":is authed as")
            peer.send(f":{self.name} 318 {peer.nick} {target.nick} :End of /WHOIS list.")
        elif cmd == "AWAY":
            # A bare AWAY (no trailing param at all) clears it; AWAY :text sets
            # it. `args` is empty for the former since there is nothing to fold
            # into a trailing parameter.
            peer.away = args[0] if args else None
            if peer.away:
                peer.send(f":{self.name} 306 {peer.nick} :You have been marked as being away")
            else:
                peer.send(f":{self.name} 305 {peer.nick} :You are no longer marked as being away")
        elif cmd == "INVITE":
            nick, channel = args[0], args[1]
            peer.send(f":{self.name} 341 {peer.nick} {nick} {channel}")
            for p in self.peers:
                if p.nick.lower() == nick.lower():
                    p.send(f":{peer.nick}!u@h INVITE {nick} :{channel}")
        elif cmd == "NAMES":
            channel = args[0]
            names = " ".join(p.nick for p in self.members(channel))
            peer.send(f":{self.name} 353 {peer.nick} = {channel} :{names}")
            peer.send(f":{self.name} 366 {peer.nick} {channel} :End of /NAMES list.")
        elif cmd == "QUIT":
            # Honour the reason, so a netsplit can be simulated by quitting with
            # one: ":nick!u@h QUIT :irc.a.net irc.b.net"
            peer.quit_reason = args[0] if args else "Client Quit"
            peer.writer.close()
        elif cmd == "LIST":
            # Every channel someone is in, with its population, plus whatever
            # a test planted with FAKECHANNELS -- enough for a channel browser.
            mask = args[0].lower().strip("*") if args else ""
            counts: dict[str, list] = {}
            for p in self.peers:
                for c in p.channels:
                    counts.setdefault(c.lower(), [c, 0])[1] += 1
            rows = [(c, n, "a topic for testing") for c, n in counts.values()] + self.fake_list
            peer.send(f":{self.name} 321 {peer.nick} Channel :Users  Name")
            for name, users, topic in rows:
                if not mask or mask in name.lower():
                    peer.send(f":{self.name} 322 {peer.nick} {name} {users} :{topic}")
            peer.send(f":{self.name} 323 {peer.nick} :End of /LIST")
        # --- control commands, for tests: a peer asks the server to act ---
        elif cmd == "RAWTO":
            # Send any line to one peer, as if the server had said it: an
            # error numeric, a WALLOPS, an INVITE from nowhere.
            for p in self.peers:
                if p.nick.lower() == args[0].lower():
                    p.send(args[1])
        elif cmd == "KILLPEER":
            # What a server does to a client it is throwing off: ERROR with
            # the reason, then close. "Excess Flood" is the one that matters.
            for p in list(self.peers):
                if p.nick.lower() == args[0].lower():
                    reason = args[1] if len(args) > 1 else "Killed"
                    p.send(f"ERROR :Closing Link: {p.nick}[127.0.0.1] ({reason})")
                    p.quit_reason = reason
                    p.writer.close()
        elif cmd == "FAKECHANNELS":
            count = int(args[0])
            self.fake_list = [(f"#fake{i}", (i * 37) % 500 + 1, f"topic {i}")
                              for i in range(count)]
        elif cmd == "FAKEKEY":
            # Give a channel a key (+k), or with no key take it away.
            if len(args) > 1 and args[1]:
                self.keys[args[0].lower()] = args[1]
            else:
                self.keys.pop(args[0].lower(), None)
        elif cmd == "BANLIST":
            # A reply made only of numerics nothing in the bouncer handles
            # (367, 368), for testing what becomes of the answer to a raw
            # line. Not an IRC command; real servers say this to MODE #c +b.
            channel = args[0]
            peer.send(f":{self.name} 367 {peer.nick} {channel} *!*@bad.example op 1758000000")
            peer.send(f":{self.name} 368 {peer.nick} {channel} :End of channel ban list")

    def _maybe_register(self, peer: Peer) -> None:
        if peer.registered or not (peer.nick and peer.user):
            return
        peer.registered = True
        peer.send(f":{self.name} 001 {peer.nick} :Welcome to the test network")
        peer.send(f":{self.name} 005 {peer.nick} CASEMAPPING=rfc1459 PREFIX=(ov)@+ "
                  f"CHANTYPES=# :are supported by this server")


async def _main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=6699)
    args = ap.parse_args()
    server = FakeIRCd(port=args.port)
    await server.start()
    print(f"fake ircd on 127.0.0.1:{args.port}")
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(_main())
