-- The schema as deployed before waves 2 and 3: bouncer/relay/store.py SCHEMA
-- at main fec6c1e (SCHEMA_VERSION 6), comments stripped. Frozen here so
-- test_units.test_migration_from_v6 can build the live database's shape and
-- prove the current Store migrates it without losing anything.
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS networks (
    id         INTEGER PRIMARY KEY,
    slug       TEXT UNIQUE NOT NULL,
    name       TEXT NOT NULL,
    host       TEXT NOT NULL,
    port       INTEGER NOT NULL,
    tls        INTEGER NOT NULL DEFAULT 0,
    nick       TEXT NOT NULL,
    created_at REAL NOT NULL,
    username   TEXT NOT NULL DEFAULT '',
    realname   TEXT NOT NULL DEFAULT '',
    channels   TEXT NOT NULL DEFAULT '[]',
    enabled    INTEGER NOT NULL DEFAULT 1,
    source     TEXT NOT NULL DEFAULT 'client',
    config_channels TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS buffers (
    id            INTEGER PRIMARY KEY,
    network_id    INTEGER NOT NULL REFERENCES networks(id),
    name          TEXT NOT NULL,
    name_lower    TEXT NOT NULL,
    kind          TEXT NOT NULL,
    topic         TEXT,
    topic_by      TEXT,
    topic_at      REAL,
    joined        INTEGER NOT NULL DEFAULT 0,
    detached      INTEGER NOT NULL DEFAULT 0,
    created_at    REAL NOT NULL,
    last_seen_eid INTEGER NOT NULL DEFAULT 0,
    archived      INTEGER NOT NULL DEFAULT 0,
    UNIQUE (network_id, name_lower)
);
CREATE TABLE IF NOT EXISTS events (
    eid        INTEGER PRIMARY KEY AUTOINCREMENT,
    buffer_id  INTEGER NOT NULL REFERENCES buffers(id),
    network_id INTEGER NOT NULL,
    ts         REAL NOT NULL,
    kind       TEXT NOT NULL,
    sender     TEXT,
    sender_host TEXT,
    text       TEXT,
    self       INTEGER NOT NULL DEFAULT 0,
    highlight  INTEGER NOT NULL DEFAULT 0,
    extra      TEXT
);
CREATE INDEX IF NOT EXISTS events_buffer_eid ON events (buffer_id, eid DESC);
CREATE INDEX IF NOT EXISTS events_highlights ON events (eid DESC) WHERE highlight = 1;
CREATE TABLE IF NOT EXISTS members (
    buffer_id  INTEGER NOT NULL REFERENCES buffers(id),
    nick       TEXT NOT NULL,
    nick_lower TEXT NOT NULL,
    prefix     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (buffer_id, nick_lower)
);
CREATE TABLE IF NOT EXISTS tokens (
    id           INTEGER PRIMARY KEY,
    token_hash   TEXT UNIQUE NOT NULL,
    label        TEXT NOT NULL,
    created_at   REAL NOT NULL,
    last_used_at REAL,
    revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    text,
    sender,
    content='events',
    content_rowid='eid',
    tokenize="porter unicode61 remove_diacritics 2"
);
CREATE TRIGGER IF NOT EXISTS events_fts_insert AFTER INSERT ON events BEGIN
    INSERT INTO events_fts(rowid, text, sender)
    VALUES (new.eid, new.text, new.sender);
END;
CREATE TRIGGER IF NOT EXISTS events_fts_delete AFTER DELETE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, text, sender)
    VALUES ('delete', old.eid, old.text, old.sender);
END;
CREATE TABLE IF NOT EXISTS ignores (
    network_id INTEGER NOT NULL REFERENCES networks(id),
    nick_lower TEXT NOT NULL,
    nick       TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (network_id, nick_lower)
);
CREATE TABLE IF NOT EXISTS devices (
    id          INTEGER PRIMARY KEY,
    token_id    INTEGER REFERENCES tokens(id),
    apns_token  TEXT UNIQUE NOT NULL,
    platform    TEXT NOT NULL,
    environment TEXT NOT NULL,
    updated_at  REAL NOT NULL
);
