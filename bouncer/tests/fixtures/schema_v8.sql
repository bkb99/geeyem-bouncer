-- The schema as deployed before the October 2026 polish work:
-- bouncer/relay/store.py at polish-oct 1716d6d (SCHEMA_VERSION 8), as SQLite
-- holds it after that code has opened a database, comments stripped. Frozen
-- here so test_units.test_migration_from_v8 can build the live database's
-- shape and prove the current Store migrates it without losing anything.
-- The meta rows that code leaves behind are part of the shape: a migration
-- that keys on one of them must find it.
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE networks (
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
    config_channels TEXT NOT NULL DEFAULT '[]',
    highlight_words TEXT,
    away            TEXT,
    alt_nicks       TEXT NOT NULL DEFAULT '[]',
    q_username      TEXT,
    server_password TEXT,
    sasl_mechanism  TEXT,
    sasl_username   TEXT,
    sasl_password   TEXT,
    q_password      TEXT,
    edited          TEXT NOT NULL DEFAULT '[]',
    current_nick    TEXT
);
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE buffers (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
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
    notify        TEXT,
    pinned        INTEGER NOT NULL DEFAULT 0,
    UNIQUE (network_id, name_lower)
);
CREATE TABLE events (
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
CREATE INDEX events_buffer_eid ON events (buffer_id, eid DESC);
CREATE INDEX events_highlights ON events (eid DESC) WHERE highlight = 1;
CREATE TABLE members (
    buffer_id  INTEGER NOT NULL REFERENCES buffers(id),
    nick       TEXT NOT NULL,
    nick_lower TEXT NOT NULL,
    prefix     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (buffer_id, nick_lower)
);
CREATE TABLE tokens (
    id           INTEGER PRIMARY KEY,
    token_hash   TEXT UNIQUE NOT NULL,
    label        TEXT NOT NULL,
    created_at   REAL NOT NULL,
    last_used_at REAL,
    revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE VIRTUAL TABLE events_search USING fts5(
    text,
    content='events',
    content_rowid='eid',
    tokenize="unicode61 remove_diacritics 2"
);
CREATE TABLE ignores (
    network_id INTEGER NOT NULL REFERENCES networks(id),
    nick_lower TEXT NOT NULL,
    nick       TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (network_id, nick_lower)
);
CREATE TABLE devices (
    id          INTEGER PRIMARY KEY,
    token_id    INTEGER REFERENCES tokens(id),
    apns_token  TEXT UNIQUE NOT NULL,
    platform    TEXT NOT NULL,
    environment TEXT NOT NULL,
    updated_at  REAL NOT NULL
);
CREATE TABLE webpush_subscriptions (
    id         INTEGER PRIMARY KEY,
    token_id   INTEGER REFERENCES tokens(id),
    endpoint   TEXT UNIQUE NOT NULL,
    p256dh     TEXT NOT NULL,
    auth       TEXT NOT NULL,
    subject    TEXT,
    updated_at REAL NOT NULL
);
CREATE TABLE link_previews (
    url        TEXT PRIMARY KEY,
    fetched_at REAL NOT NULL,
    data       TEXT,
    error      TEXT
);
CREATE TABLE preview_images (
    hash       TEXT PRIMARY KEY,
    url        TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TRIGGER events_search_insert AFTER INSERT ON events
WHEN instr(COALESCE(new.extra, ''), '"redacted": true') = 0 BEGIN
    INSERT INTO events_search(rowid, text) VALUES (new.eid, new.text);
END;
CREATE TRIGGER events_search_delete AFTER DELETE ON events
WHEN instr(COALESCE(old.extra, ''), '"redacted": true') = 0 BEGIN
    INSERT INTO events_search(events_search, rowid, text)
    VALUES ('delete', old.eid, old.text);
END;
INSERT INTO meta (key, value) VALUES
    ('search_index', 'events_search'),
    ('search_triggers', '2'),
    ('quit_hosts', '1'),
    ('secret_scrub', '1'),
    ('schema_version', '8');
