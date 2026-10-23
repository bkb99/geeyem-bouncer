#!/usr/bin/env python3
"""A terminal client for the bouncer. The reference implementation of the protocol.

This exists so the gateway can be exercised without Xcode in the loop. If this
works, the protocol works, and anything broken in the iOS app is in the iOS app.

    python tools/wsclient.py --token relay_xxx
    python tools/wsclient.py --token relay_xxx --url ws://127.0.0.1:8765/ws

Type a line to send it to the focused buffer. Commands:
    /buffers         list buffers
    /focus <id>      switch buffer
    /more            fetch another page of backlog
    /join #chan      join a channel
    /quit
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time

import aiohttp


RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"
YELLOW, CYAN, GREY = "\033[33m", "\033[36m", "\033[90m"


class TerminalClient:
    def __init__(self, url: str, token: str):
        self.url = url
        self.token = token
        self.buffers: dict[int, dict] = {}
        self.focused: int | None = None
        self.oldest_seen: dict[int, int] = {}
        self.ws: aiohttp.ClientWebSocketResponse | None = None
        self._req = 0

    def next_req(self) -> str:
        self._req += 1
        return f"r{self._req}"

    async def run(self) -> None:
        async with aiohttp.ClientSession() as http:
            async with http.ws_connect(
                self.url, headers={"Authorization": f"Bearer {self.token}"}, heartbeat=25
            ) as ws:
                self.ws = ws
                await asyncio.gather(self._read(), self._input(), self._keepalive())

    async def _keepalive(self) -> None:
        while True:
            await asyncio.sleep(30)
            await self.send({"type": "ping", "presence": "foreground",
                             "focused_buffer": self.focused})

    async def send(self, frame: dict) -> None:
        assert self.ws is not None
        await self.ws.send_str(json.dumps(frame))

    # --- output ------------------------------------------------------------

    def render(self, event: dict, *, history: bool = False) -> None:
        if self.focused is not None and event.get("buffer") != self.focused:
            return
        ts = time.strftime("%H:%M", time.localtime(event.get("ts", 0)))
        kind = event.get("kind")
        who = event.get("from") or ""
        text = event.get("text") or ""
        mark = f"{YELLOW}*{RESET}" if event.get("highlight") else " "
        prefix = f"{GREY}{ts}{RESET}{mark}"
        if kind == "message":
            colour = CYAN if event.get("self") else ""
            print(f"{prefix} {colour}<{who}>{RESET} {text}")
        elif kind == "action":
            print(f"{prefix} {DIM}* {who} {text}{RESET}")
        elif kind == "notice":
            print(f"{prefix} {DIM}-{who}- {text}{RESET}")
        elif kind in ("join", "part", "quit", "kick", "nick", "mode", "topic"):
            print(f"{prefix} {GREY}-- {who} {kind} {text}{RESET}")
        else:
            print(f"{prefix} {GREY}{text}{RESET}")

    async def _read(self) -> None:
        assert self.ws is not None
        async for msg in self.ws:
            if msg.type != aiohttp.WSMsgType.TEXT:
                continue
            frame = json.loads(msg.data)
            await self._handle(frame)

    async def _handle(self, frame: dict) -> None:
        t = frame.get("type")
        if t == "hello":
            print(f"{BOLD}connected{RESET} (protocol {frame['protocol']}, "
                  f"max_eid {frame['max_eid']})")
        elif t == "network":
            n = frame["network"]
            state = "connected" if n["registered"] else ("dialing" if n["connected"] else "offline")
            print(f"{GREY}[{n['name']}] {state} as {n['nick']}{RESET}")
        elif t == "buffers":
            for b in frame["buffers"]:
                self.buffers[b["id"]] = b
            self.print_buffers()
            # Focus the first joined channel so there is something to look at.
            for b in frame["buffers"]:
                if b["kind"] == "channel":
                    self.focused = b["id"]
                    break
        elif t == "buffer":
            self.buffers[frame["buffer"]["id"]] = frame["buffer"]
        elif t == "backlog":
            events = frame["events"]
            if events:
                self.oldest_seen[frame["buffer"]] = events[0]["eid"]
            if frame["buffer"] == self.focused:
                print(f"{GREY}--- {len(events)} lines of backlog"
                      f"{' (start of history)' if frame.get('complete') else ''} ---{RESET}")
            for e in events:
                self.render(e, history=True)
        elif t == "event":
            self.render(frame["event"])
        elif t == "members":
            if frame["buffer"] == self.focused:
                print(f"{GREY}({len(frame['members'])} members){RESET}")
        elif t == "unread":
            pass
        elif t == "error":
            print(f"{YELLOW}error: {frame.get('message')}{RESET}")
        elif t == "ok":
            pass

    def print_buffers(self) -> None:
        print(f"\n{BOLD}buffers{RESET}")
        for b in sorted(self.buffers.values(), key=lambda x: (x["kind"], x["name"])):
            star = "*" if b["id"] == self.focused else " "
            print(f" {star}{b['id']:>4}  {b['kind']:<8} {b['name']}")
        print()

    # --- input -------------------------------------------------------------

    async def _input(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                return
            line = line.rstrip("\n")
            if not line:
                continue
            if line == "/quit":
                await self.ws.close()
                return
            if line == "/buffers":
                self.print_buffers()
                continue
            if line.startswith("/focus "):
                self.focused = int(line.split()[1])
                print(f"{GREY}focused {self.buffers.get(self.focused, {}).get('name')}{RESET}")
                continue
            if line == "/more":
                if self.focused:
                    await self.send({"type": "backlog", "req": self.next_req(),
                                     "buffer": self.focused,
                                     "before_eid": self.oldest_seen.get(self.focused),
                                     "limit": 50})
                continue
            if line.startswith("/join "):
                await self.send({"type": "join", "req": self.next_req(),
                                 "channel": line.split(maxsplit=1)[1]})
                continue
            if self.focused is None:
                print("no buffer focused; /buffers then /focus <id>")
                continue
            await self.send({"type": "say", "req": self.next_req(),
                             "buffer": self.focused, "text": line})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="ws://127.0.0.1:8765/ws")
    ap.add_argument("--token", required=True)
    args = ap.parse_args()
    try:
        asyncio.run(TerminalClient(args.url, args.token).run())
    except (KeyboardInterrupt, aiohttp.ClientError) as exc:
        print(f"\n{exc or 'bye'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
