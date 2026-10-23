"""Link cards: a page's title, description and picture, fetched by the bouncer.

The phone never contacts the site. The bouncer fetches the page, reads its
OpenGraph and Twitter tags (or its <title>), and hands back a card whose picture
is a URL on the bouncer itself -- /p/<mac>/<hash> -- which the bouncer fetches
in turn when the phone asks for it. So pasting a link into a channel does not
tell the site where Riley's phone is, which was the reason the apps had no cards
at all (the audit's G71; The Lounge does the same through its server).

What it will fetch is narrow, because a URL someone else pasted is a URL chosen
by a stranger, fetched from a VPS:

  - http and https only; no credentials in the URL;
  - every address it connects to must be public, at every redirect hop
    (relay.netguard; the resolver that checks is the one that connects);
  - at most MAX_REDIRECTS redirects, TIMEOUT seconds in all, MAX_PAGE bytes of
    page and MAX_IMAGE bytes of picture read, whatever the server claims;
  - a picture is served back only if its first bytes are a PNG, JPEG, GIF or
    WebP -- never SVG, which is a document that can carry script, and would be
    running from the bouncer's own origin.

Parsed with the standard library's HTMLParser. No new dependency: a card needs
six meta tags and a title, not a DOM.

Cards are cached a day in SQLite (a failure for ten minutes); pictures are kept
in memory, a bounded amount, since they are cheap to fetch again and would bloat
the nightly backup of the database for nothing.
"""

from __future__ import annotations

import asyncio
import collections
import hashlib
import hmac
import logging
import re
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .netguard import BlockedAddress, PublicResolver, check_url

log = logging.getLogger("relay.previews")

MAX_REDIRECTS = 3
TIMEOUT = 5.0
MAX_PAGE = 1024 * 1024
MAX_IMAGE = 2 * 1024 * 1024
MAX_URL = 2048
CARD_TTL = 24 * 3600.0
ERROR_TTL = 600.0
# Pictures kept in memory, in bytes, oldest dropped first.
IMAGE_CACHE_BYTES = 32 * 1024 * 1024
# Fetches at once. A channel pasting ten links at the same moment is ten cards
# wanted, but not ten sockets open at the same moment from a 1-vCPU box.
CONCURRENCY = 4

# Honest about what it is, with the two tokens many sites look for before they
# will hand over their OpenGraph tags at all (the same trick The Lounge uses).
USER_AGENT = ("Mozilla/5.0 (compatible; geeyem link preview) "
              "facebookexternalhit/1.1 Twitterbot/1.0")

TITLE_MAX = 200
DESCRIPTION_MAX = 400
SITE_MAX = 100


# The most tags and runs of text read from one head. A real head is a few
# hundred of each; a hostile one is a quarter of a megabyte of "<x>" or of
# stray "<", each of which costs HTMLParser a Python call. Past this the card
# is made from what was read.
MAX_PARSE_EVENTS = 4000


class _Enough(Exception):
    """Raised from inside the parser to stop it mid-feed."""


class _CardParser(HTMLParser):
    """The meta tags and <title> of a page's head. Stops at </head>, <body>,
    or MAX_PARSE_EVENTS tags and runs of text, by raising _Enough."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, str] = {}
        self.title = ""
        self._in_title = False
        self._done = False
        self._events = 0

    def _count(self) -> None:
        self._events += 1
        if self._done or self._events > MAX_PARSE_EVENTS:
            raise _Enough

    def handle_starttag(self, tag, attrs):
        self._count()
        if tag == "meta":
            a = {k.lower(): (v or "") for k, v in attrs if k}
            key = (a.get("property") or a.get("name") or a.get("itemprop") or "").lower()
            content = a.get("content")
            if key and content and key not in self.meta:
                self.meta[key] = content
        elif tag == "title" and not self.title:
            self._in_title = True
        elif tag == "body":
            # Everything a card is made of lives in the head. A page that puts
            # its tags in the body is rare, and parsing a megabyte of body to
            # find out is not worth it.
            self._done = True

    def handle_endtag(self, tag):
        self._count()
        if tag == "title":
            self._in_title = False
        elif tag == "head":
            self._done = True

    def handle_data(self, data):
        self._count()
        if self._in_title:
            self.title += data


def _clean(text: str | None, limit: int) -> str | None:
    if not text:
        return None
    text = " ".join(text.split())
    if not text:
        return None
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


_META_CHARSET = re.compile(rb"""<meta[^>]+charset=["']?([A-Za-z0-9_\-]+)""", re.I)


def _decode(body: bytes, content_type: str) -> str:
    charset = None
    match = re.search(r"charset=([A-Za-z0-9_\-]+)", content_type or "", re.I)
    if match:
        charset = match.group(1)
    else:
        sniffed = _META_CHARSET.search(body[:4096])
        if sniffed:
            charset = sniffed.group(1).decode("ascii", "ignore")
    for candidate in (charset, "utf-8"):
        if not candidate:
            continue
        try:
            return body.decode(candidate, errors="replace")
        except LookupError:
            continue
    return body.decode("utf-8", errors="replace")


# Where a page's head ends. Everything a card is made of is in the head, and
# the parser used to be handed the whole megabyte and carry on through the body
# (it only stopped *recording* at </head>): a 1 MB page of "<" held the event
# loop for half a second. Cut here, before parsing.
_HEAD_END = re.compile(r"</head|<body", re.I)
# The most of a head that is parsed. Real heads with a lot of inline script
# and JSON-LD run to a few hundred KB; the tags a card wants come early in
# nearly all of them.
PARSE_MAX = 256 * 1024


def head_of(html: str) -> str:
    """The part of a page worth parsing for a card: up to </head> or <body>,
    and at most PARSE_MAX characters."""
    end = _HEAD_END.search(html, 0, PARSE_MAX)
    return html[: end.start() if end else PARSE_MAX]


def card_from_body(body: bytes, content_type: str, page_url: str) -> dict:
    """decode + cut to the head + parse. Run in a worker thread (it is plain
    CPU, and a hostile head can still take tens of milliseconds)."""
    # Decoding the first PARSE_MAX * 4 bytes is enough for PARSE_MAX
    # characters in any encoding, and skips decoding a megabyte of body.
    return parse_card(head_of(_decode(body[: PARSE_MAX * 4], content_type)), page_url)


def parse_card(html: str, page_url: str) -> dict:
    """{"title", "description", "site", "image"} from a page. `image` is the
    remote picture's absolute URL here; the caller swaps it for a /p/ one."""
    parser = _CardParser()
    try:
        parser.feed(html)
        parser.close()
    except _Enough:                    # the head ended, or was too much to read
        pass
    except Exception:                  # a page bad enough to break HTMLParser
        pass
    meta = parser.meta
    title = meta.get("og:title") or meta.get("twitter:title") or parser.title
    description = (meta.get("og:description") or meta.get("twitter:description")
                   or meta.get("description"))
    host = (urlsplit(page_url).hostname or "").lower()
    site = meta.get("og:site_name") or (host[4:] if host.startswith("www.") else host)
    image = (meta.get("og:image:secure_url") or meta.get("og:image")
             or meta.get("og:image:url") or meta.get("twitter:image")
             or meta.get("twitter:image:src"))
    if image:
        image = urljoin(page_url, image.strip())
        if urlsplit(image).scheme not in ("http", "https"):
            image = None
    return {
        "title": _clean(title, TITLE_MAX),
        "description": _clean(description, DESCRIPTION_MAX),
        "site": _clean(site, SITE_MAX),
        "image": image,
    }


def sniff_image(body: bytes) -> str | None:
    """The image type the bytes actually are, or None. Never trusts the
    server's Content-Type, and never answers SVG."""
    if body.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if body.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if body.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(body) >= 12 and body[:4] == b"RIFF" and body[8:12] == b"WEBP":
        return "image/webp"
    return None


class FetchError(ValueError):
    """A fetch that did not produce a page, said in a sentence."""


class LinkPreviews:
    def __init__(self, store, *, allow_private_hosts: bool = False):
        self.store = store
        self.allow_private_hosts = allow_private_hosts
        self._secret = store.secret("link-preview-images")
        self._session = None
        self._semaphore = asyncio.Semaphore(CONCURRENCY)
        # One fetch per URL at a time: ten clients asking for the same card at
        # once share the first one's answer.
        self._inflight: dict[str, asyncio.Future] = {}
        self._images: collections.OrderedDict[str, tuple[float, str, bytes]] = \
            collections.OrderedDict()
        self._image_bytes = 0
        self._saves = 0
        self.timeout = TIMEOUT
        store.prune_previews(CARD_TTL)

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    def _client(self):
        if self._session is None:
            import aiohttp

            connector = aiohttp.TCPConnector(
                resolver=PublicResolver(self.allow_private_hosts), limit=CONCURRENCY * 2)
            # trust_env=False: no proxy from the environment, so what is checked
            # is what is connected to.
            self._session = aiohttp.ClientSession(connector=connector, trust_env=False)
        return self._session

    # --- the card ------------------------------------------------------------

    async def preview(self, url: str) -> dict:
        """The card for a URL, or FetchError with a sentence for the person."""
        if not isinstance(url, str) or not url.strip():
            raise FetchError("That is not a link.")
        url = url.strip()
        if len(url) > MAX_URL:
            raise FetchError("That link is too long to preview.")
        check_url(url, allow_private=self.allow_private_hosts)
        cached = self.store.cached_preview(url, CARD_TTL, ERROR_TTL)
        if cached is not None:
            card, error = cached
            if error:
                raise FetchError(error)
            return card
        pending = self._inflight.get(url)
        if pending is None:
            pending = asyncio.get_running_loop().create_future()
            self._inflight[url] = pending
            task = asyncio.create_task(self._fetch_card(url))
            task.add_done_callback(lambda t, url=url, fut=pending: self._settle(url, fut, t))
        card, error = await asyncio.shield(pending)
        if error:
            raise FetchError(error)
        return card

    def _settle(self, url: str, future: asyncio.Future, task: asyncio.Task) -> None:
        self._inflight.pop(url, None)
        if future.done():
            return
        if task.cancelled():
            future.set_result((None, "The preview was cancelled."))
        elif task.exception() is not None:
            future.set_result((None, "That page could not be read."))
        else:
            future.set_result(task.result())

    async def _fetch_card(self, url: str) -> tuple[dict | None, str | None]:
        try:
            async with self._semaphore:
                final_url, content_type, body = await asyncio.wait_for(
                    self._fetch(url, MAX_PAGE), self.timeout)
            kind = content_type.split(";", 1)[0].strip().lower()
            if kind not in ("text/html", "application/xhtml+xml"):
                raise FetchError("That link is not a page.")
            # In a thread: the loop keeps serving every client and the IRC
            # links while a page is parsed (see head_of).
            card = await asyncio.to_thread(card_from_body, body, content_type, final_url)
            if not card["title"] and not card["description"]:
                raise FetchError("That page has no title to show.")
            if card["image"]:
                card["image"] = self.image_path(card["image"])
            card["url"] = url
            result: tuple[dict | None, str | None] = (card, None)
        except FetchError as exc:
            result = (None, str(exc))
        except asyncio.TimeoutError:
            result = (None, "That page took too long to answer.")
        except Exception as exc:
            log.info("preview of a link failed: %s: %s", type(exc).__name__, exc)
            result = (None, "That page could not be read.")
        self.store.save_preview(url, *result)
        # Expired cards are never read, only kept; clear them out now and then
        # rather than on every save.
        self._saves += 1
        if self._saves % 200 == 0:
            self.store.prune_previews(CARD_TTL)
        return result

    async def _fetch(self, url: str, limit: int) -> tuple[str, str, bytes]:
        """GET a URL through the public-only resolver, following at most
        MAX_REDIRECTS redirects by hand so each hop is checked, and reading at
        most `limit` bytes. Returns (final url, content type, body)."""
        import aiohttp

        session = self._client()
        for _hop in range(MAX_REDIRECTS + 1):
            try:
                check_url(url, allow_private=self.allow_private_hosts)
            except ValueError as exc:
                raise FetchError(str(exc))
            try:
                async with session.get(
                    url, allow_redirects=False,
                    headers={"User-Agent": USER_AGENT, "Accept-Language": "en",
                             "Accept": "text/html,application/xhtml+xml,image/*;q=0.8,*/*;q=0.5"},
                ) as resp:
                    if resp.status in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location")
                        if not location:
                            raise FetchError("That page redirects nowhere.")
                        url = urljoin(url, location)
                        continue
                    if resp.status != 200:
                        raise FetchError(f"That page answered {resp.status}.")
                    body = bytearray()
                    async for chunk in resp.content.iter_chunked(64 * 1024):
                        body.extend(chunk)
                        if len(body) >= limit:
                            del body[limit:]
                            break
                    return str(resp.url), resp.headers.get("Content-Type", ""), bytes(body)
            except aiohttp.ClientConnectorError as exc:
                if isinstance(getattr(exc, "os_error", None), BlockedAddress):
                    raise FetchError("That address is on a private network.")
                raise FetchError("That site could not be reached.")
            except BlockedAddress:
                raise FetchError("That address is on a private network.")
            except aiohttp.ClientError:
                raise FetchError("That site could not be reached.")
        raise FetchError("That link redirects too many times.")

    # --- the picture -----------------------------------------------------------

    def _mac(self, digest: str) -> str:
        return hmac.new(self._secret, digest.encode(), hashlib.sha256).hexdigest()[:32]

    def image_path(self, image_url: str) -> str:
        """The bouncer URL a card's picture is served from. The hash names the
        picture; the MAC over it makes the URL unguessable, so /p/ fetches
        nothing a card did not hand out."""
        digest = hashlib.sha256(image_url.encode()).hexdigest()[:32]
        self.store.save_preview_image(digest, image_url)
        return f"/p/{self._mac(digest)}/{digest}"

    async def image(self, mac: str, digest: str) -> tuple[str, bytes] | None:
        """(content type, bytes) for a /p/ URL, or None for anything not to be
        served: a bad MAC, an unknown hash, a fetch that failed, bytes that are
        not a picture."""
        if not (re.fullmatch(r"[0-9a-f]{32}", mac or "")
                and re.fullmatch(r"[0-9a-f]{32}", digest or "")):
            return None
        if not hmac.compare_digest(mac, self._mac(digest)):
            return None
        cached = self._images.get(digest)
        if cached is not None and time.time() - cached[0] < CARD_TTL:
            self._images.move_to_end(digest)
            return cached[1], cached[2]
        url = self.store.preview_image_url(digest)
        if url is None:
            return None
        try:
            async with self._semaphore:
                _final, _type, body = await asyncio.wait_for(
                    self._fetch(url, MAX_IMAGE + 1), self.timeout)
        except Exception as exc:
            log.info("preview image fetch failed: %s", exc)
            return None
        if len(body) > MAX_IMAGE:
            return None
        content_type = sniff_image(body)
        if content_type is None:
            return None
        self._keep_image(digest, content_type, body)
        return content_type, body

    def _keep_image(self, digest: str, content_type: str, body: bytes) -> None:
        old = self._images.pop(digest, None)
        if old is not None:
            self._image_bytes -= len(old[2])
        self._images[digest] = (time.time(), content_type, body)
        self._image_bytes += len(body)
        while self._image_bytes > IMAGE_CACHE_BYTES and self._images:
            _key, (_, _, dropped) = self._images.popitem(last=False)
            self._image_bytes -= len(dropped)
