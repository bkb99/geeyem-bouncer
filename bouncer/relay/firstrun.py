"""First run: a bouncer with no token yet sets itself up from a web page.

Minting the first token used to need a shell on the server (`python -m relay
token new`), and then moving 49 characters to a phone. On a hosting platform
(Fly.io, Railway, Render) there may be no shell anyone wants to open, and the
person setting it up may never have used one. So a bouncer that starts with no
active token serves /setup: a form for the IRC network and the first device's
name, which mints that device's token and shows it as a QR code and a
`geeyem://connect` link (docs/PROTOCOL.md, "First run").

What stops a stranger who finds the hostname first is a **setup code**,
printed to the bouncer's own log at startup and nowhere else. The log is the
one thing only the owner can read on every platform this runs on, and reading
it needs no shell: `fly logs`, Railway's and Render's log pages, `docker
compose logs`. The code is

  - twelve characters of the pairing alphabet (31^12, about 8e17), checked in
    constant time, behind the same failed-auth throttle as a token, before
    anything else in the form is looked at;
  - single use: the first token it mints closes /setup for good, and so does
    a token made any other way (the command line, a restore). The check is
    "is there an active token", made on every request, not a flag that could
    disagree with the database;
  - in memory only. A restart before setup is finished makes a new one and
    prints it; nothing about it is stored.

Nothing here reaches anyone but the owner: the page loads nothing from
anywhere else, the QR code is drawn on the bouncer (relay/qr.py), and the
token is in the one response to the one request that made it, marked
no-store.
"""

from __future__ import annotations

import hmac
import logging
import os
import secrets
import time
from html import escape
from urllib.parse import quote

from . import APP_NAME
from . import qr

log = logging.getLogger("relay.setup")

# The same alphabet as a pairing code (gateway.PAIR_ALPHABET): nothing that
# reads as something else off a log line. Twelve, not eight, because this one
# lives as long as the bouncer is unclaimed rather than five minutes.
SETUP_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
SETUP_CODE_LENGTH = 12
# How often opening /setup may print the code again (see announce).
ANNOUNCE_EVERY = 60.0

# What the form offers. A preset fills in the server; "other" takes the
# fields below it; "none" adds no network (the app can add one later).
PRESETS = {
    "libera": ("Libera.Chat", "irc.libera.chat", 6697, True),
    "oftc": ("OFTC", "irc.oftc.net", 6697, True),
    "quakenet": ("QuakeNet", "irc.quakenet.org", 6667, False),
    "efnet": ("EFnet", "irc.efnet.org", 6697, True),
}
FORM_FIELDS = ("code", "label", "network", "host", "port", "tls", "nick", "channels")


def clean_setup_code(value: object) -> str:
    """A code as someone copied it out of a log: upper case, without the
    dashes and spaces it is printed with. "" when it could not be one."""
    if not isinstance(value, str) or len(value) > 4 * SETUP_CODE_LENGTH:
        return ""
    code = "".join(ch for ch in value.upper() if ch not in " -\t")
    return code if len(code) == SETUP_CODE_LENGTH else ""


def format_code(code: str) -> str:
    """ABCDEFGHJKMN -> ABCD-EFGH-JKMN, for reading off a log."""
    return "-".join(code[i:i + 4] for i in range(0, len(code), 4))


def platform_url() -> str | None:
    """The bouncer's public address, when the platform it runs on says so in
    the environment. Only for the log line: the links the page makes come
    from the request, as the pairing links do."""
    if name := os.environ.get("FLY_APP_NAME"):
        return f"https://{name}.fly.dev"
    if domain := os.environ.get("RAILWAY_PUBLIC_DOMAIN"):
        return f"https://{domain}"
    if url := os.environ.get("RENDER_EXTERNAL_URL"):
        return url.rstrip("/")
    return None


class FirstRun:
    """The setup code, and whether /setup is open."""

    def __init__(self, store, code: str | None = None):
        self.store = store
        self.code = code or "".join(secrets.choice(SETUP_ALPHABET)
                                    for _ in range(SETUP_CODE_LENGTH))
        # A request that got past the code and is adding the network: a
        # second one meanwhile is told to wait rather than racing it.
        self.busy = False
        self._announced = float("-inf")

    @property
    def open(self) -> bool:
        return bool(self.code) and not self.store.active_token_ids()

    def check(self, attempt: str) -> bool:
        if not self.code:
            return False
        return hmac.compare_digest(self.code.encode(), clean_setup_code(attempt).encode())

    def finish(self) -> None:
        self.code = ""

    def announce(self, force: bool = False) -> None:
        """Print the code, and where to use it. At startup, and again when
        someone opens /setup (at most once a minute), so whoever is looking
        at the page finds the code at the bottom of the log, not scrolled
        away under an hour of IRC."""
        now = time.monotonic()
        if not self.open or (not force and now - self._announced < ANNOUNCE_EVERY):
            return
        self._announced = now
        where = platform_url()
        page = f"{where}/setup" if where else "/setup on this bouncer's address"
        log.warning("first run: no device is signed in yet. Open %s and enter "
                    "the setup code %s", page, format_code(self.code))


# --- the pages --------------------------------------------------------------

_STYLE = """
:root { color-scheme: light dark; --bg:#f6f5f2; --fg:#1d1c1a; --muted:#6b6862;
  --card:#fff; --line:#dcd9d2; --accent:#2f5d50; --bad:#a3342b; }
@media (prefers-color-scheme: dark) { :root { --bg:#161615; --fg:#ecebe7;
  --muted:#a09d96; --card:#201f1d; --line:#3a3936; --accent:#7fb8a6; --bad:#e8887f; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg);
  font:16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width:34rem; margin:0 auto; padding:24px 16px 48px; }
h1 { font-size:1.5rem; margin:0 0 4px; }
p.lede { color:var(--muted); margin:0 0 20px; }
form, section { background:var(--card); border:1px solid var(--line); border-radius:12px;
  padding:16px; margin-bottom:16px; }
label { display:block; font-weight:600; margin:12px 0 4px; }
label.check { font-weight:400; display:flex; gap:8px; align-items:center; }
small { display:block; color:var(--muted); font-weight:400; }
input, select { width:100%; font:inherit; padding:10px; border-radius:8px;
  border:1px solid var(--line); background:var(--bg); color:var(--fg); }
input[type=checkbox] { width:auto; }
fieldset { border:0; padding:0; margin:0; }
legend { font-weight:600; margin-top:12px; }
button { font:inherit; font-weight:600; padding:12px 16px; border:0; border-radius:8px;
  background:var(--accent); color:var(--bg); margin-top:16px; width:100%; cursor:pointer; }
.error { color:var(--bad); font-weight:600; }
.qr { display:block; width:min(260px, 75vw); margin:8px auto 16px; }
.qr svg { display:block; width:100%; height:auto; }
code, .mono { font-family:ui-monospace, Menlo, Consolas, monospace; }
.mono { word-break:break-all; }
.row { display:flex; gap:8px; } .row input { flex:1; min-width:0; } .row button { width:auto; margin:0; }
a { color:var(--accent); }
"""

# Copy buttons. The only script on either page; allowed by its hash.
_SCRIPT = """
for (const b of document.querySelectorAll("button[data-copy]")) {
  b.addEventListener("click", async () => {
    const field = document.getElementById(b.dataset.copy);
    try { await navigator.clipboard.writeText(field.value); b.textContent = "Copied"; }
    catch (e) { field.select(); }
  });
}
"""


def _page(title: str, body: str, script: bool = False) -> str:
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<meta name="robots" content="noindex">'
            f"<title>{escape(title)}</title><style>{_STYLE}</style></head>"
            f"<body><main>{body}</main>"
            + (f"<script>{_SCRIPT}</script>" if script else "")
            + "</body></html>")


def form_page(values: dict | None = None, error: str = "",
              networks: list[str] | None = None) -> str:
    """The setup form. `values` refills what was typed after a refusal,
    except the code."""
    v = {k: str((values or {}).get(k, "")) for k in FORM_FIELDS}
    networks = networks or []
    chosen = v["network"] or ("none" if networks else "libera")
    options = [(key, f"{name} ({host})") for key, (name, host, _, _) in PRESETS.items()]
    options += [("other", "Another server (below)"),
                ("none", "None now; I'll add one in the app")]
    option_html = "".join(
        f'<option value="{k}"{" selected" if k == chosen else ""}>{escape(t)}</option>'
        for k, t in options)
    have = ""
    if networks:
        have = (f"<small>Already set up on this bouncer: {escape(', '.join(networks))}."
                "</small>")
    tls_checked = " checked" if v["tls"] or not values else ""
    body = f"""
<h1>Set up your {APP_NAME} bouncer</h1>
<p class="lede">One time only. This makes the sign-in for your first device.</p>
<form method="post" action="/setup" autocomplete="off">
  {f'<p class="error" role="alert">{escape(error)}</p>' if error else ''}
  <label for="code">Setup code
    <small>It is in the bouncer's log, on the line that says "first run".</small></label>
  <input id="code" name="code" required autocapitalize="characters" spellcheck="false"
         placeholder="ABCD-EFGH-JKMN" class="mono">
  <label for="label">This device's name</label>
  <input id="label" name="label" value="{escape(v['label'] or 'iPhone')}" maxlength="64">
  <label for="network">IRC network</label>
  <select id="network" name="network">{option_html}</select>
  {have}
  <fieldset>
    <legend>Another server <small>Only if you picked "Another server".</small></legend>
    <label for="host">Server</label>
    <input id="host" name="host" value="{escape(v['host'])}" placeholder="irc.example.net"
           spellcheck="false" autocapitalize="none">
    <label for="port">Port <small>Leave empty for the usual one.</small></label>
    <input id="port" name="port" value="{escape(v['port'])}" inputmode="numeric">
    <label class="check"><input type="checkbox" name="tls" value="1"{tls_checked}>
      Encrypted (TLS)</label>
  </fieldset>
  <label for="nick">Your nickname</label>
  <input id="nick" name="nick" value="{escape(v['nick'])}" maxlength="32"
         spellcheck="false" autocapitalize="none">
  <label for="channels">Channels to join <small>Optional. For example: #geeyem #python</small></label>
  <input id="channels" name="channels" value="{escape(v['channels'])}"
         spellcheck="false" autocapitalize="none">
  <button type="submit">Finish setup</button>
</form>
"""
    return _page(f"Set up {APP_NAME}", body)


def connect_link(host: str, token: str, scheme: str = "https") -> str:
    """`geeyem://connect?host=…&token=…` (docs/PROTOCOL.md, "First run").
    `host` is bare for https, the way the app reads one, and the
    percent-encoded `http://host:port` for a bouncer reached over plain http
    on loopback, as in a pairing link."""
    where = host if scheme == "https" else quote(f"{scheme}://{host}", safe="")
    return f"{APP_NAME}://connect?host={where}&token={quote(token, safe='')}"


def done_page(*, host: str, token: str, label: str, link: str, web_url: str,
              network: str | None) -> str:
    code = qr.encode(link)
    picture = qr.svg(code, f"QR code to sign in {label}") if code else ""
    joined = (f"<p>It is connecting to {escape(network)} now.</p>" if network else
              "<p>No network yet: add one in the app once you are signed in.</p>")
    body = f"""
<h1>Your bouncer is ready</h1>
{joined}
<section>
  <h2>Sign in {escape(label)}</h2>
  <p>Scan this with the phone's camera to open {APP_NAME} and sign in.</p>
  <div class="qr">{picture}</div>
  <p>Or copy the link and open it on the phone:</p>
  <div class="row"><input id="link" class="mono" readonly value="{escape(link)}">
    <button type="button" data-copy="link">Copy</button></div>
  <p>Or type these into the app's sign-in screen:</p>
  <label for="host">Bouncer</label>
  <div class="row"><input id="host" class="mono" readonly value="{escape(host)}">
    <button type="button" data-copy="host">Copy</button></div>
  <label for="token">Access token</label>
  <div class="row"><input id="token" class="mono" readonly value="{escape(token)}">
    <button type="button" data-copy="token">Copy</button></div>
</section>
<section>
  <h2>Use it in this browser</h2>
  <p><a href="{escape(web_url)}">Open {APP_NAME} on the web</a>. That link signs in
  this browser as a device of its own, works once, and only for five minutes.</p>
</section>
<p><small>This page is shown once. The token is a password to your messages:
nobody else needs it, and it is not stored anywhere you can read it back. Lost it?
Sign in from another device and use Settings, Devices, Add a device; or run
<code>python -m relay token new</code> on the server. Other devices are added
from Settings, Devices in the app.</small></p>
"""
    return _page(f"{APP_NAME} is ready", body, script=True)


def closed_page() -> str:
    return _page(f"{APP_NAME}", f"""
<h1>This bouncer is already set up</h1>
<p>Sign in with your access token, or add a device from Settings, Devices in the
app on a device that is already signed in.</p>
<p><a href="/">Open {APP_NAME}</a></p>""")
