#!/usr/bin/env python3
"""Nightly encrypted backup of every bouncer instance's database to R2.

geyem.db is every message, private message and read marker the bouncer has ever
kept, and it lives on exactly one disk. This snapshots it, encrypts it, and uploads
it, the same way the otherbot's state backup does (otherbot/backup_state.py).

EVERY INSTANCE (2026-09-26). The box runs more than one bouncer: Riley's in
/srv/geyem and Rowan's in /srv/geyem-rowan, each with its own
config.json and database. Only geyem.db was ever backed up, so Rowan's history
lived on one disk with no copy at all. Instances are this script's own
directory plus every sibling named <this directory>-* that holds a config.json
(so /srv/geyem-rowan), or exactly the directories listed in
GEYEM_BACKUP_DIRS (comma-separated, from .env or the environment). Each has its
own key prefix -- geyem-backups/ for this one, unchanged, and
geyem-backups-<name>/ for the rest -- so retention is counted per instance and
one instance's pruning can never delete another's backups. One instance failing
does not stop the others; the exit status says whether any did.

An instance's database is what the bouncer itself would open: RELAY_DB in its
own .env, else db_path in its config.json (relative to that file; relay.db if
it names none). With no config.json at all: geyem.db if present, else relay.db. A RELAY_DB set only in a systemd unit's Environment= is
invisible from cron: put it in the instance's .env, or db_path in config.json.

The snapshot is taken with SQLite's own backup API rather than by copying the file:
the database runs in WAL mode, so a plain copy of geyem.db can miss everything still
sitting in the -wal file, or catch it mid-write.

PRIVACY: the archive is encrypted (Fernet: AES-128-CBC + HMAC-SHA256) BEFORE it
leaves the box, because the bucket is served by the public domain
img.example.com. A 2026-08-29 audit of the otherbot backups found an
unauthenticated GET of a real key returning the file. The random path is only
defence in depth; the encryption is what protects the data. If the key is missing
this REFUSES to upload rather than falling back to plaintext.

Not backed up, on purpose: .env, the APNs .p8 (secrets), and the web assets (they
ship from the repo). config.json IS included: it holds no secrets.

KEY: GEYEM_BACKUP_KEY in /srv/geyem/.env (mode 600), one key for every
instance. It is not inside the archive it protects, so a restore needs the key
from somewhere else first. The daily VPS snapshot carries it, and a copy
belongs in a password manager. Lose it and every backup is unreadable.

Restore:
    venv/bin/python backup.py --list
    venv/bin/python backup.py --restore <key> [destdir]     # writes a .tar.gz
    tar xzf <that file>     # gives <the instance's db file> and config.json
    # stop the instance, put the db file in place (remove any -wal and -shm
    # left beside the old one), start it

THE EPOCH. Every database has an id, its epoch, which the bouncer sends in
`hello`; a client keeps the lines it has cached under it and throws them away
when it changes. A restored database must have a new one: it is last night's
history, and it will hand out again the event ids the lost database used today,
for different lines. So a snapshot is saved WITHOUT its epoch (see snapshot),
and the bouncer gives a database that has none a new one when it first opens
it. Restoring one of these archives therefore needs nothing more than the
steps above. A database put back any OTHER way -- the VPS disk snapshot,
a geyem.db copied by hand -- still carries its old epoch, and needs, once,
with the instance stopped:
    venv/bin/python -m relay epoch new
(with -c <its config.json>, or RELAY_DB set, for an instance that is not this
directory's). See docs/SELF-HOSTING.md, "Restoring".

Retention, per instance: everything from the last 30 days, then ONE backup per
calendar month kept indefinitely. Pruning only runs after a successful upload,
and refuses to prune down to nothing.

Deployed by deploy.sh to /srv/geyem/backup.py. Cron (ubuntu), unchanged:
    30 9 * * * cd /srv/geyem && /usr/bin/flock -n /tmp/geyem_backup.lock \
        venv/bin/python backup.py >> backup.log 2>&1
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

BASE = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(BASE, ".env")
DB = os.path.join(BASE, "geyem.db")
PREFIX = "geyem-backups/"
KEEP_DAYS = 30


@dataclass
class Instance:
    name: str        # "" for the instance this script lives in
    directory: str
    db: str

    @property
    def prefix(self) -> str:
        # The main instance keeps the prefix it always had, so its existing
        # backups stay under the same retention. The others get their own,
        # never a sub-prefix of it: listing "geyem-backups/" must not find
        # "geyem-backups/rowan/..." and prune it as if it were ours.
        return PREFIX if not self.name else f"geyem-backups-{self.name}/"

    @property
    def stem(self) -> str:
        return "geyem" if not self.name else f"geyem-{self.name}"

    @property
    def label(self) -> str:
        return self.name or "main"


def parse_env(path: str) -> dict[str, str]:
    env: dict[str, str] = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def load_env() -> dict[str, str]:
    return parse_env(ENV_FILE)


def client(env):
    import boto3
    return boto3.client(
        "s3",
        endpoint_url=env["GEYEM_S3_ENDPOINT"],
        aws_access_key_id=env["GEYEM_S3_ACCESS_KEY"],
        aws_secret_access_key=env["GEYEM_S3_SECRET_KEY"],
    ), env["GEYEM_S3_BUCKET"]


def fernet(env):
    from cryptography.fernet import Fernet
    key = env.get("GEYEM_BACKUP_KEY")
    if not key:
        sys.exit("[!] GEYEM_BACKUP_KEY missing from .env - refusing to upload an "
                 "unencrypted backup to a publicly-served bucket")
    return Fernet(key.encode())


def instance_db(directory: str) -> str:
    """Where an instance keeps its database; see the module note for the order."""
    env_file = os.path.join(directory, ".env")
    if os.path.exists(env_file):
        try:
            relay_db = parse_env(env_file).get("RELAY_DB")
        except OSError:
            relay_db = None
        if relay_db:
            return relay_db if os.path.isabs(relay_db) else os.path.join(directory, relay_db)
    cfg = os.path.join(directory, "config.json")
    if os.path.exists(cfg):
        try:
            # relay.db is relay.config.Config's own default: what the bouncer
            # opens when the file names none.
            db_path = json.load(open(cfg)).get("db_path") or "relay.db"
            return db_path if os.path.isabs(db_path) else os.path.join(directory, db_path)
        except (OSError, ValueError):
            pass
    legacy = os.path.join(directory, "geyem.db")
    return legacy if os.path.exists(legacy) else os.path.join(directory, "relay.db")


def discover_instances(base: str = BASE, env: dict[str, str] | None = None) -> list[Instance]:
    """This directory, then its <name>-* siblings with a config.json -- or the
    directories GEYEM_BACKUP_DIRS lists."""
    env = env or {}
    listed = os.environ.get("GEYEM_BACKUP_DIRS") or env.get("GEYEM_BACKUP_DIRS")
    stem = os.path.basename(os.path.normpath(base))
    if listed:
        dirs = [os.path.abspath(d.strip()) for d in listed.split(",") if d.strip()]
    else:
        parent = os.path.dirname(os.path.normpath(base))
        siblings = sorted(
            os.path.join(parent, d) for d in os.listdir(parent)
            if d.startswith(stem + "-") and os.path.isfile(os.path.join(parent, d, "config.json")))
        dirs = [os.path.normpath(base), *siblings]
    out = []
    for d in dirs:
        name = os.path.basename(d)
        if os.path.normpath(d) == os.path.normpath(base):
            name = ""
        elif name.startswith(stem + "-"):
            name = name[len(stem) + 1:]
        out.append(Instance(name=name, directory=d, db=instance_db(d)))
    return out


def snapshot(dest: str, db: str = DB) -> None:
    """A consistent copy of the live database, WAL included -- without its
    epoch.

    The epoch (meta row 'epoch'; see relay/store.py, Store.epoch) is the id a
    client keeps its cached lines under. A restored database hands out again
    the eids the live one used after this snapshot was taken, for different
    lines, so it must not answer to the same epoch or every client merges the
    two histories by number. Leaving the row out of the copy is what makes
    that automatic: a database with no epoch is given a new one the first time
    a bouncer opens it, so a restore is "untar, put the file in place, start",
    with no step to forget. The live database is not touched (it is opened
    read-only); only the copy loses the row.
    """
    src = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        out = sqlite3.connect(dest)
        try:
            src.backup(out)
            try:
                out.execute("DELETE FROM meta WHERE key = 'epoch'")
                out.commit()
            except sqlite3.Error as exc:
                # Never a reason to have no backup at all. The copy keeps its
                # epoch, and restoring it needs `python -m relay epoch new`.
                out.rollback()
                print(f"  [!] could not leave the epoch out of the snapshot ({exc}); "
                      "after restoring it, run: python -m relay epoch new")
        finally:
            out.close()
    finally:
        src.close()


def backup_instance(inst: Instance, cipher, s3, bucket) -> None:
    """Snapshot, check, encrypt, upload and prune one instance. Raises on failure."""
    if not os.path.exists(inst.db):
        raise FileNotFoundError(f"no database at {inst.db}")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    key = f"{inst.prefix}{secrets.token_hex(16)}/{inst.stem}-{stamp}.tar.gz.enc"
    db_name = os.path.basename(inst.db)

    with tempfile.TemporaryDirectory() as work:
        snap = os.path.join(work, db_name)
        snapshot(snap, inst.db)
        # A backup that cannot be opened is worse than none, so open it.
        check = sqlite3.connect(snap)
        try:
            if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError("snapshot failed integrity_check - not uploading")
            events = check.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        finally:
            check.close()

        tar_path = os.path.join(work, "backup.tar.gz")
        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(snap, arcname=db_name)
            cfg = os.path.join(inst.directory, "config.json")
            if os.path.exists(cfg):
                tar.add(cfg, arcname="config.json")

        enc_path = tar_path + ".enc"
        with open(tar_path, "rb") as fh, open(enc_path, "wb") as out:
            out.write(cipher.encrypt(fh.read()))
        size = os.path.getsize(enc_path)
        s3.upload_file(enc_path, bucket, key)

    print(f"[{datetime.now(timezone.utc).isoformat()}] {inst.label}: uploaded {key} "
          f"({size / 1e6:.2f}MB encrypted, {events} events)")
    prune(s3, bucket, inst.prefix)


def backup(base: str = BASE, env: dict[str, str] | None = None, s3=None, bucket=None) -> int:
    """Every instance; returns the number that failed (the exit status)."""
    env = env if env is not None else load_env()
    cipher = fernet(env)            # fail closed before doing any work
    if s3 is None:
        s3, bucket = client(env)
    failed = 0
    for inst in discover_instances(base, env):
        try:
            backup_instance(inst, cipher, s3, bucket)
        except Exception as exc:
            failed += 1
            print(f"[!] {inst.label} ({inst.directory}): backup FAILED: "
                  f"{type(exc).__name__}: {exc}")
    return failed


def list_all(s3, bucket, prefix: str = PREFIX):
    objs, token = [], None
    while True:
        kw = {"Bucket": bucket, "Prefix": prefix}
        if token:
            kw["ContinuationToken"] = token
        resp = s3.list_objects_v2(**kw)
        objs.extend(resp.get("Contents", []))
        if not resp.get("IsTruncated"):
            return objs
        token = resp.get("NextContinuationToken")
        if not token:
            return objs


def plan_prune(objs, now=None):
    """(keep, drop). Everything inside KEEP_DAYS, then the OLDEST backup of each
    older calendar month, kept forever."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=KEEP_DAYS)
    keep, older = [], []
    for o in objs:
        (keep if o["LastModified"] >= cutoff else older).append(o)
    by_month: dict[str, list] = {}
    for o in older:
        by_month.setdefault(o["LastModified"].strftime("%Y-%m"), []).append(o)
    drop = []
    for group in by_month.values():
        group.sort(key=lambda o: o["LastModified"])
        keep.append(group[0])
        drop.extend(group[1:])
    return keep, drop


def prune(s3, bucket, prefix: str = PREFIX) -> None:
    keep, drop = plan_prune(list_all(s3, bucket, prefix))
    if not keep:
        print(f"  [!] {prefix}: retention would keep NOTHING - refusing to prune")
        return
    for obj in drop:
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
        print(f"  pruned {obj['Key']} ({obj['LastModified']:%Y-%m-%d})")
    if not drop:
        print(f"  {prefix}: {len(keep)} backups kept, none expired")


def list_backups() -> None:
    env = load_env()
    s3, bucket = client(env)
    for inst in discover_instances(BASE, env):
        objs = sorted(list_all(s3, bucket, inst.prefix), key=lambda o: o["LastModified"])
        print(f"== {inst.label} ({inst.directory}, {inst.db})")
        for o in objs:
            print(f"{o['LastModified']:%Y-%m-%d %H:%M}  {o['Size'] / 1e6:6.2f}MB  {o['Key']}")
        if not objs:
            print("no backups found")


def restore(key: str, dest: str = ".") -> None:
    env = load_env()
    s3, bucket = client(env)
    local = os.path.join(dest, os.path.basename(key))
    s3.download_file(bucket, key, local)
    plain = local[:-4] if local.endswith(".enc") else local + ".dec"
    with open(local, "rb") as fh:
        data = fernet(env).decrypt(fh.read())
    with open(plain, "wb") as fh:
        fh.write(data)
    os.unlink(local)
    print(f"downloaded and decrypted {plain} - untar with: tar xzf {plain}")


if __name__ == "__main__":
    if "--list" in sys.argv:
        list_backups()
    elif "--restore" in sys.argv:
        i = sys.argv.index("--restore")
        restore(sys.argv[i + 1], sys.argv[i + 2] if len(sys.argv) > i + 2 else ".")
    else:
        sys.exit(1 if backup() else 0)
