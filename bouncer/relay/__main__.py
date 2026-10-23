"""Command line: run the bouncer, or manage the tokens it authenticates with.

    python -m relay run
    python -m relay token new "Riley's iPhone"
    python -m relay token list
    python -m relay token revoke 3
    python -m relay buffers
    python -m relay epoch show
    python -m relay epoch new      # after restoring a database; see below

`epoch new` gives the database a new epoch: the id in `hello` that tells a
client the history behind the bouncer is not the one its cached lines came
from. Run it, with the bouncer stopped, after putting back a database that was
not restored through tools/backup.py -- a disk snapshot, a copied file -- or
clients go on merging what they cached with a history that reuses its eids. A
database restored from one of backup.py's own archives needs nothing: those are
saved without an epoch and are given a new one when first opened.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import logging
import sys

from .app import Relay
from .config import Config
from .store import Store


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)-14s %(message)s",
        datefmt="%H:%M:%S",
    )
    # aiohttp's access logging is off (see Gateway), but its other loggers are
    # chatty at DEBUG and drown out the IRC trace, which is the useful one.
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    # httpx logs every request at INFO with its full URL, and for APNs that URL
    # ends in the device token and for Web Push it IS the browser's push
    # endpoint -- both capabilities to reach a device, in the journal on every
    # notification until 2026-09-26. Failures still log at WARNING and above.
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _fmt_time(value: float | None) -> str:
    if not value:
        return "never"
    return dt.datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="relay")
    parser.add_argument("-c", "--config", help="path to config.json")
    parser.add_argument("-v", "--verbose", action="store_true", help="log every IRC line")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("run", help="run the bouncer")
    sub.add_parser("buffers", help="list stored buffers and their sizes")

    token = sub.add_parser("token", help="manage client tokens")
    token_sub = token.add_subparsers(dest="token_command", required=True)
    new = token_sub.add_parser("new", help="mint a token")
    new.add_argument("label", help="what device this is for")
    token_sub.add_parser("list", help="list tokens")
    revoke = token_sub.add_parser("revoke", help="revoke a token by id")
    revoke.add_argument("id", type=int)

    epoch = sub.add_parser("epoch", help="show the database's epoch, or give it a new one")
    epoch_sub = epoch.add_subparsers(dest="epoch_command", required=True)
    epoch_sub.add_parser("show", help="print the epoch")
    epoch_sub.add_parser("new", help="a new epoch: run after restoring a database by hand")

    args = parser.parse_args(argv)
    _setup_logging(args.verbose)
    config = Config.load(args.config)

    if args.command == "run":
        # No early refusal on an empty config.networks: a fresh install is
        # zero networks by definition, and the client onboarding flow (see
        # hello.has_networks / can_add_networks in docs/PROTOCOL.md) exists
        # precisely so someone can add one over the wire instead of editing a
        # file on a server they may not have open. Relay.run() prints its own
        # notice once it knows whether the store has anything the file did not.
        try:
            asyncio.run(Relay(config).run())
        except KeyboardInterrupt:
            pass
        return 0

    store = Store(config.db_path)

    if args.command == "token":
        if args.token_command == "new":
            value = store.create_token(args.label)
            # Printed once and never recoverable -- only the hash is stored. Say
            # so here rather than letting someone discover it later.
            print(value)
            print("\nThis is the only time this token is shown. Store it in the client now.",
                  file=sys.stderr)
        elif args.token_command == "list":
            rows = store.list_tokens()
            if not rows:
                print("no tokens")
            for r in rows:
                state = "REVOKED" if r["revoked"] else "active"
                print(f"{r['id']:>3}  {state:<8} {r['label']:<28} "
                      f"created {_fmt_time(r['created_at'])}  last used {_fmt_time(r['last_used_at'])}")
        elif args.token_command == "revoke":
            print("revoked" if store.revoke_token(args.id) else "no such token")
        return 0

    if args.command == "epoch":
        if args.epoch_command == "new":
            # Read by a running bouncer on the next attach, so it works with
            # the bouncer up too; stopped is still the time to do it, because
            # a restore is a file being replaced under whatever has it open.
            print(store.new_epoch())
            print("\nEvery client will drop the lines it had cached and fetch them again.",
                  file=sys.stderr)
        else:
            print(store.epoch)
        return 0

    if args.command == "buffers":
        for buf in store.buffers(include_archived=True):
            count = store.db.execute(
                "SELECT COUNT(*) AS c FROM events WHERE buffer_id=?", (buf.id,)
            ).fetchone()["c"]
            print(f"{buf.id:>4}  {buf.kind:<8} {buf.name:<24} {count:>7} events  "
                  f"{'joined' if buf.joined else ''}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
