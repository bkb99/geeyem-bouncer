/* geeyem's service worker. Served by the bouncer at /sw.js (with
   Service-Worker-Allowed: /) and registered by the page's wave 4 shell block.

   Two jobs, and a list of things it must never do.

   1. The shell. The page, its icons and its face are kept, so the app opens with no
      network (a train, a laptop just woken) and says it is offline, instead of
      the browser's own error page. Network first: a fresh copy whenever the
      bouncer answers within a few seconds, the kept one when it does not.
      Cache-first would open faster by a round trip and show a deploy only on
      the SECOND load after it, which is how "I deployed and nothing changed"
      happens. A bouncer answer that is an error (a proxy's 502 during a
      restart) is not the page either, and the kept one is shown instead.
      Icons asked for by version (?v=) never change and are answered from the
      cache; the face is answered from it and refreshed behind.

   2. Web push. The bouncer sends a push for the same things it pushes to the
      phone (PROTOCOL.md, `register_webpush`); this shows it, one notification
      per conversation, and pressing it opens that conversation at the line.

   Never: the websocket (a service worker cannot see one anyway), /health,
   /export, /p/ link-preview images, uploads, anything cross-origin, anything
   not a GET. Those are not in SHELL, so they are not answered here and go to
   the network exactly as if this file did not exist. The access token lives
   in the page and never passes through this file. */

"use strict";

// v2 (2026-09-23): Paper became the default icon, and v1 caches held the old one.
// v3 (2026-09-26): versioned icons and the face are kept by their full address
// and answered from the cache, and a proxy's error page no longer replaces the
// kept shell.
// v4 (2026-09-26): a larger gm. in every icon, and v3 caches held the old ones.
// (2026-10-05: cache writes are held open with waitUntil. No new cache name:
// what is kept has not changed shape, and the page offers a reload when the
// browser finds this file changed -- see "New version" in index.html.)
// v5 (2026-10-06): the ribbon replaced "gm." in every icon, and v4 caches
// held the old ones (the unversioned apple-touch-icon among them).
// v6 (2026-10-12): the two-bubble mark replaced the ribbon in every icon, and v5
// caches held the old ones.
// v7 (2026-10-18): the light mark became the default icon, and v6 caches
// held the navy one.
const SHELL_CACHE = "geeyem-shell-v7";
// Relative to this file, which is at the root of the scope.
// The face is in it because it is the default one: without it, an offline
// start is set in the fallback serif, which is not the app anyone chose.
const SHELL = ["./", "manifest.webmanifest", "icon-192.png", "icon-512.png", "icon-maskable-512.png",
               "newsreader.woff2"];
const NETWORK_GRACE_MS = 3000;
// The fallback tag, the same one the page gives its own notifications
// (maybeNotify). The page stops making its own once web push is on.
const APP = "geeyem";

const scopeURL = new URL(self.registration.scope);
const shellPaths = new Map(SHELL.map((p) => [new URL(p, scopeURL).pathname, p]));

self.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(SHELL_CACHE);
    // One at a time and forgiving: an older bouncer that does not serve the
    // maskable icon must not stop the page itself being kept.
    await Promise.allSettled(SHELL.map(async (path) => {
      const response = await fetch(new Request(path, { cache: "no-cache" }));
      if (response.ok) await cache.put(path, response);
    }));
    await self.skipWaiting();
  })());
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    for (const name of await caches.keys()) {
      if (name.startsWith("geeyem-shell-") && name !== SHELL_CACHE) await caches.delete(name);
    }
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== scopeURL.origin) return;
  // The page is asked for as a navigation, whatever query or fragment it
  // carries; the icons and manifest by their own paths. Nothing else.
  const key = request.mode === "navigate"
    ? (url.pathname === scopeURL.pathname ? "./" : null)
    : shellPaths.get(url.pathname) || null;
  if (!key) return;
  // An icon asked for with ?v=<its own hash> can never change (the bouncer
  // serves it immutable), so the network has nothing to add once it is kept.
  // The face is not versioned, but it is the same bytes for months and a
  // round trip for it on every start is the slowest part of an offline-first
  // open: it is answered from the cache and refreshed behind.
  if (request.mode !== "navigate" && url.searchParams.has("v")) {
    event.respondWith(cacheFirst(event, url));
    return;
  }
  if (key === FACE) {
    event.respondWith(staleWhileRevalidate(event, key));
    return;
  }
  event.respondWith(networkFirst(event, key));
});

/* Keep a copy, and keep this worker alive until it is kept. A write started
   after the response has been handed back is otherwise the browser's to
   abandon: it may stop a worker with nothing left to answer, and the fresh
   page it had just fetched was then never stored -- so the next start with no
   network opened the one before it. waitUntil holds the worker for the write.
   Failing (a full disk, a private window) is not worth more than that. */
function keep(event, written) {
  const done = Promise.resolve(written).catch(() => {});
  try { event.waitUntil(done); } catch (e) { /* the event is already over */ }
  return done;
}

const FACE = "newsreader.woff2";

/* Kept by its whole address, query and all: a new icon is a new ?v=, so it is
   a miss here and fetched, and the other versions of the same file go. */
async function cacheFirst(event, url) {
  const request = event.request;
  const cache = await caches.open(SHELL_CACHE);
  const kept = await cache.match(request);
  if (kept) return kept;
  let response;
  try { response = await fetch(request); }
  catch (e) {
    // Offline with this version not kept yet: the copy the install kept by
    // its bare name is the same picture, or nearly.
    const bare = await cache.match(shellPaths.get(url.pathname) || url.pathname);
    if (bare) return bare;
    throw e;
  }
  if (response.ok) {
    keep(event, cache.put(request, response.clone()).then(async () => {
      for (const old of await cache.keys()) {
        const o = new URL(old.url);
        if (o.pathname === url.pathname && o.search && o.search !== url.search) await cache.delete(old);
      }
    }));
  }
  return response;
}

async function staleWhileRevalidate(event, key) {
  const cache = await caches.open(SHELL_CACHE);
  const kept = await cache.match(key);
  const fresh = fetch(event.request, { cache: "no-cache" }).then((response) => {
    if (response.ok) keep(event, cache.put(key, response.clone()));
    return response;
  });
  // The refresh behind a kept answer outlives that answer, so it is held too.
  if (kept) { keep(event, fresh); return kept; }
  return fresh;
}

async function networkFirst(event, key) {
  const request = event.request;
  const cache = await caches.open(SHELL_CACHE);
  // no-cache, not no-store: always asked of the bouncer, but with the ETag
  // the browser kept, so an unchanged page is a 304 and the browser hands
  // this its copy as a whole 200. no-store sent no ETag, and every load
  // fetched the whole page again.
  const fresh = fetch(request, { cache: "no-cache" }).then((response) => {
    if (response.ok) keep(event, cache.put(key, response.clone()));
    return response;
  });
  // A bouncer slower than the grace period is answered for from the cache,
  // and its page, when it does arrive, is still worth keeping for next time.
  keep(event, fresh);
  const late = new Promise((resolve) => setTimeout(resolve, NETWORK_GRACE_MS, null));
  const first = await Promise.race([fresh.catch(() => null), late]);
  if (first && usable(first)) return first;
  const kept = await cache.match(key);
  // An answer that is an error -- Cloudflare's 502 or 530 while the bouncer
  // restarts, arriving well inside the grace period -- is not the page. The
  // kept one is, when there is one. With nothing kept, the error is still
  // better than nothing: it says what is wrong.
  if (kept) return kept;
  // Nothing kept yet: wait for the network however long it takes, and let
  // its failure be the browser's to show.
  return first || fresh;
}

/* A response worth showing in place of the kept copy. A navigation's redirect
   comes back opaque (status 0) and is the browser's to follow, so it counts. */
function usable(response) {
  return response.ok || response.status === 304 || response.type === "opaqueredirect";
}

/* ------------------------------------------------------------ web push */
/* The bouncer's payload is flat (relay/webpush.py, notification_payload):
   {title, body, buffer, eid, network, badge, quiet, tag, category}. The APNs
   shape, {aps: {alert}, relay: {buffer, eid}}, is read too, so the two ends
   never have to move in lockstep. */
/* A buffer or line id: a positive whole number, or null. These go into the
   URL a click opens, so a payload that carried "https://..." or "2/../x" in
   them must come out as nothing rather than as part of an address. */
function idOf(value) {
  const n = Number(value);
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

/* The words are other people's (a nick, a line from IRC) and a banner shows
   a few lines of them at most, so a hundred-thousand-character line is not
   handed to the system whole. */
const TITLE_MAX = 200;
const BODY_MAX = 1000;
/* The title is a name -- a channel, or the nick that wrote -- and is drawn the
   way the page draws names (nameText in index.html): a character that shows
   as nothing, or turns the text round, is shown as U+FFFD, so "Q" + U+200B is
   not a banner from Q. */
const HIDDEN_IN_NAMES = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}   -   　ᅟᅠㅤﾠ⠀]/gu;

function notificationFrom(data) {
  const aps = (data && data.aps) || {};
  const alert = typeof aps.alert === "object" && aps.alert ? aps.alert
    : { body: typeof aps.alert === "string" ? aps.alert : "" };
  const relay = (data && data.relay) || data || {};
  const buffer = idOf(relay.buffer);
  const eid = idOf(relay.eid);
  const title = String((data && data.title) || alert.title || APP)
    .replace(HIDDEN_IN_NAMES, "�").slice(0, TITLE_MAX);
  const body = String((data && data.body) || alert.body || "").slice(0, BODY_MAX);
  // A follow-up inside the bouncer's quiet window is passive on the phone:
  // no sound there, so none here either.
  const quiet = aps["interruption-level"] === "passive"
    || (data && (data.quiet === true || data.silent === true));
  return {
    title,
    options: {
      body,
      // One stack per conversation: the bouncer's tag, like APNs thread-id.
      tag: String((data && data.tag) || (buffer ? `${APP}-${buffer}` : APP)).slice(0, 128),
      renotify: !!buffer && !quiet,
      silent: quiet,
      icon: "icon-192.png",
      badge: "icon-192.png",
      data: { buffer, eid, network: typeof relay.network === "string" ? relay.network : null },
    },
  };
}

self.addEventListener("push", (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; }
  catch (e) { data = { body: event.data ? event.data.text() : "" }; }
  event.waitUntil(showPush(data));
});

async function showPush(data) {
  const { title, options } = notificationFrom(data);
  // The installed app's icon carries the same count the phone's does.
  const badge = Number(data && (data.badge ?? (data.aps && data.aps.badge)));
  if (Number.isFinite(badge) && self.navigator.setAppBadge) {
    (badge > 0 ? self.navigator.setAppBadge(badge) : self.navigator.clearAppBadge()).catch(() => {});
  }
  // Someone is at the app right now: the page itself shows what arrived, and
  // a banner on top of it would be the same line twice. The bouncer already
  // holds back the conversation on screen; this covers the others, and for
  // those the page in front raises the banner itself (maybeNotify in
  // index.html), so a mention elsewhere is still an alert.
  const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  if (windows.some((c) => c.focused && c.visibilityState === "visible")) return;
  await self.registration.showNotification(title, options);
}

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(openConversation(event.notification.data || {}));
});

/* To the conversation, at the line: an open window is brought forward and
   told where to go (the page's openFromPush), and with none open a new one
   starts at the line's permalink, #m/<buffer>/<eid>, which the page follows
   once its buffers arrive.
   Only ever this app's own page: the scope, plus a fragment made of two
   whole numbers. Nothing in a payload can make a click open anywhere else. */
async function openConversation(data) {
  const buffer = idOf(data && data.buffer);
  const eid = idOf(data && data.eid);
  const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  const ours = windows.filter((c) => new URL(c.url).origin === scopeURL.origin
    && c.url.startsWith(scopeURL.href));
  const target = ours.find((c) => c.focused) || ours[0];
  if (target) {
    try { await target.focus(); } catch (e) { /* focus is best effort */ }
    target.postMessage({ type: "open", buffer, eid });
    return target;
  }
  const hash = buffer && eid ? `#m/${buffer}/${eid}` : "";
  return self.clients.openWindow(scopeURL.href + hash);
}

/* The browser replaced this subscription (it expired, or the push service
   rotated it). Only a page can tell the bouncer, over its socket, so any open
   one is asked to register again; the next page to attach does it anyway. */
self.addEventListener("pushsubscriptionchange", (event) => {
  event.waitUntil((async () => {
    const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of windows) c.postMessage({ type: "resubscribe" });
  })());
});
