# geeyem bouncer

The server for [geeyem](https://hg.hn/geeyem/), an IRC client for iPhone and iPad.

geeyem does not connect to IRC itself. It signs in to a bouncer: a small server
you run that stays connected to IRC for you, keeps your history, and hands
messages to the app as they arrive. This repository is that bouncer. It is free,
and anyone can run one.

Your messages and history stay on your machine. Nothing reaches the app's
developer.

You need a machine that stays on (a home server, a Raspberry Pi, or a small
VPS), Python 3.11 or newer, and about twenty minutes.

---

## 1. Install

```bash
git clone https://github.com/bkb99/geeyem-bouncer.git
cd geeyem-bouncer
./bootstrap.sh
```

This makes a Python environment in `bouncer/.venv` and creates
`bouncer/config.json` from the example.

## 2. Configure

The example config points at a bundled test server, not a real network. Either
edit `bouncer/config.json` and add your network under `networks`, or leave it
and set the network from the app after you sign in.

```json
{
  "slug": "libera",
  "name": "Libera.Chat",
  "host": "irc.libera.chat",
  "port": 6697,
  "tls": true,
  "nick": "yournick",
  "channels": ["#yourchannel"],
  "enabled": true
}
```

IRC shows every user's host to the channel. If you run the bouncer from home,
people in your channels can see your home IP. A VPS avoids that.

## 3. Make a token and start it

```bash
cd bouncer
.venv/bin/python -m relay token new "iPhone"    # copy the token; it is shown once
.venv/bin/python -m relay run
```

The bouncer listens on `127.0.0.1:8765`.

## 4. Reach it from your phone

Put something in front of the bouncer that provides HTTPS. Leave
`listen_host` at `127.0.0.1`.

**Cloudflare Tunnel** (no open ports):

```bash
cloudflared tunnel login
cloudflared tunnel create geeyem
cloudflared tunnel route dns geeyem irc.example.com
```

`/etc/cloudflared/config.yml`:

```yaml
tunnel: <tunnel id>
credentials-file: /etc/cloudflared/<tunnel id>.json
ingress:
  - hostname: irc.example.com
    service: http://127.0.0.1:8765
  - service: http_status:404
```

```bash
sudo cloudflared service install && sudo systemctl enable --now cloudflared
```

**Or nginx with Let's Encrypt.** Proxy everything to `127.0.0.1:8765`. For
`/ws`, pass the `Upgrade` and `Connection` headers, set `proxy_read_timeout`
above 90 seconds, and set `proxy_set_header Host $host;` and
`proxy_set_header X-Forwarded-Proto $scheme;`.

## 5. Sign in

In geeyem, enter your hostname (for example `irc.example.com`) and the token
from step 3. Tap Connect.

To add more devices, go to **Settings → Devices → Add a device** in the app.

The bouncer also serves a web client at your hostname.

---

## Keeping it running

To run it as a service, use `bouncer/geyem.service` as a starting point.
Change the paths and the user to match your machine.

## Backups

Your history is in `bouncer/relay.db`, which is plain SQLite and not encrypted.
To copy it while the bouncer is running, use:

```bash
sqlite3 relay.db ".backup copy.db"
```

If you restore a copy, run `.venv/bin/python -m relay epoch new` once before
starting the bouncer, so the apps reload their history.

## Tokens

```bash
.venv/bin/python -m relay token list
.venv/bin/python -m relay token revoke <id>
```

## Notifications

Push notifications to the App Store build are not available from your own
bouncer yet. Everything else works without them.

## Help

support@hg.hn

## License

MIT. See [LICENSE](LICENSE).
