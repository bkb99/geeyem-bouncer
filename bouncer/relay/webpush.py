"""Web Push: notifications for the web client, installed as an app or not.

The browser hands over a subscription -- an endpoint URL at its push service
(Google's, Mozilla's, Apple's) and two keys -- and from then on a notification
is one encrypted POST to that endpoint. The push service cannot read it; only
the browser that subscribed can.

Hand-rolled for the same reason relay/apns.py is: it is a few dozen lines of
well-specified crypto on top of `cryptography` and one POST with httpx, both
already required, against a library that would hide the status codes that
matter. Two RFCs:

  RFC 8291 (message encryption): an ephemeral P-256 key agreed with the
    browser's p256dh key, mixed with its 16-byte auth secret through HKDF into
    an AES-128-GCM key and nonce; one record, "aes128gcm" content coding
    (RFC 8188), the header carrying the salt and the ephemeral public key.

  RFC 8292 (VAPID): the bouncer's own P-256 key pair, made on first start and
    kept in the database. Each request carries an ES256 JWT for the push
    service's origin, signed with it, plus the public key -- the same public key
    the browser subscribed with (`hello.webpush_key`), which is how the push
    service knows the sender is the one the browser agreed to.

What decides that a notification goes out is not here: it is exactly the APNs
decision (session._should_push, the hub's quiet window, push_preview), and the
hub hands the same Notification to both. See docs/PROTOCOL.md, "Web push".
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from urllib.parse import urlsplit

from .push import Notification

log = logging.getLogger("relay.webpush")

# How long a push service holds a notification for a browser that is offline.
# An hour, the same as apns-expiration: after that it is stale.
TTL = 3600
# A VAPID token may live at most 24 hours; a fresh one every 12 is well inside.
JWT_LIFETIME = 12 * 3600
# One record holds the whole payload. RFC 8291 allows up to 4096 bytes of
# ciphertext for a push service to accept, which leaves room for ~3.9 KB.
RECORD_SIZE = 4096
MAX_PAYLOAD = 3800


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    text = text.strip()
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 (RFC 5869), one block, which is all any of these need."""
    import hashlib
    import hmac

    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


def _public_bytes(public_key) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def encrypt(payload: bytes, p256dh: bytes, auth: bytes, *,
            salt: bytes | None = None, sender_key=None) -> bytes:
    """RFC 8291: the body of one Web Push request, "aes128gcm" coded.

    `salt` and `sender_key` are for tests; a real send makes both fresh every
    time, which is the whole of the scheme's forward secrecy.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(payload) > MAX_PAYLOAD:
        raise ValueError("web push payload too large")
    receiver = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), p256dh)
    sender_key = sender_key or ec.generate_private_key(ec.SECP256R1())
    sender_public = _public_bytes(sender_key.public_key())
    shared = sender_key.exchange(ec.ECDH(), receiver)
    salt = salt or os.urandom(16)

    # The auth secret and both public keys go into the key, so a payload made
    # for one subscription cannot be replayed at another.
    key_info = b"WebPush: info\x00" + p256dh + sender_public
    ikm = _hkdf(auth, shared, key_info, 32)
    cek = _hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = _hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12)

    # 0x02 marks the last (here, the only) record; no further padding.
    ciphertext = AESGCM(cek).encrypt(nonce, payload + b"\x02", None)
    header = salt + RECORD_SIZE.to_bytes(4, "big") + bytes([len(sender_public)]) + sender_public
    return header + ciphertext


class VapidKey:
    """The bouncer's application server key pair, made once and kept.

    In the `meta` table, as PEM. Losing it (a new database) means every browser
    has to subscribe again -- which the web client does on its own, seeing a
    different `webpush_key` in hello.
    """

    META_KEY = "vapid_private_key"

    def __init__(self, store):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        pem = store.meta_get(self.META_KEY)
        if pem is None:
            key = ec.generate_private_key(ec.SECP256R1())
            pem = key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()).decode("ascii")
            store.meta_set(self.META_KEY, pem)
            log.info("made a VAPID key pair for web push")
        self.private_key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
        self.public_bytes = _public_bytes(self.private_key.public_key())
        self.public_b64 = b64u(self.public_bytes)
        self._tokens: dict[tuple[str, str], tuple[str, float]] = {}

    def token(self, audience: str, subject: str, now: float | None = None) -> str:
        """The ES256 JWT for one push service origin, cached a while."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        now = time.time() if now is None else now
        cached = self._tokens.get((audience, subject))
        if cached and cached[1] - now > 3600:
            return cached[0]
        exp = int(now) + JWT_LIFETIME
        header = b64u(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
        claims = b64u(json.dumps({"aud": audience, "exp": exp, "sub": subject},
                                 separators=(",", ":")).encode())
        signing_input = f"{header}.{claims}"
        der = self.private_key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
        # Raw r||s, 32 bytes each, as JWS wants -- not the DER cryptography
        # returns. The same trap as the APNs provider token (relay/apns.py).
        r, s = decode_dss_signature(der)
        jwt = f"{signing_input}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"
        self._tokens[(audience, subject)] = (jwt, float(exp))
        return jwt


def notification_payload(notification: Notification) -> dict:
    """What the service worker receives, decrypted. Flat, and the same facts
    as the APNs payload: where (`buffer`, `eid`, `network`) and what to show."""
    return {
        "title": notification.title,
        "body": notification.body,
        "buffer": notification.buffer_id,
        "eid": notification.eid,
        "network": notification.network,
        "badge": notification.badge,
        # A follow-up inside the hub's quiet window: show it, but silently
        # (the service worker passes `silent: true` and keeps the same tag).
        "quiet": notification.quiet,
        # "none" is the person's choice of no sound at all; the browser plays
        # its own for anything else, as it cannot play the app's.
        "silent": notification.sound == "none",
        # One stack per conversation, like APNs thread-id.
        "tag": f"buffer-{notification.buffer_id}",
        "category": notification.category,
    }


class WebPushSender:
    """Delivers one Notification to every browser subscription."""

    def __init__(self, store, *, subject: str | None = None, transport=None,
                 allow_private_hosts: bool = False):
        self.store = store
        self.allow_private_hosts = allow_private_hosts
        self.key = VapidKey(store)
        self.default_subject = subject
        # `transport` is for tests: anything with an async post(url, headers,
        # body) -> (status, text). The real one is httpx, made on first use.
        self._transport = transport
        self._client = None

    @property
    def public_key(self) -> str:
        return self.key.public_b64

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _post(self, url: str, headers: dict, body: bytes) -> tuple[int, str]:
        if self._transport is not None:
            return await self._transport.post(url, headers, body)
        if self._client is None:
            import httpx

            # trust_env=False: no proxy from the environment.
            self._client = httpx.AsyncClient(timeout=10.0, trust_env=False)
        response = await self._client.post(url, headers=headers, content=body)
        return response.status_code, response.text[:200]

    def _subject(self, subscription: dict) -> str:
        # The web client's own origin (an https URL) is the best contact there
        # is, and Apple refuses a subject that is not a mailto: or https: URL.
        for candidate in (subscription.get("subject"), self.default_subject):
            if candidate and candidate.startswith(("https://", "mailto:")):
                return candidate
        return "https://localhost"

    async def send(self, notification: Notification, subscriptions: list[dict]) -> None:
        payload = json.dumps(notification_payload(notification),
                             separators=(",", ":")).encode()
        for sub in subscriptions:
            try:
                await self.send_one(payload, sub, quiet=notification.quiet)
            except Exception:
                # One broken browser must not stop the others, like APNs.
                log.exception("web push: send failed for a subscription")

    async def send_one(self, payload: bytes, sub: dict, *, quiet: bool = False) -> int:
        endpoint = sub["endpoint"]
        # Checked again at every send, not only when it was registered: a row
        # in the database is not proof it came through registration.
        from .netguard import check_push_endpoint

        try:
            check_push_endpoint(endpoint, allow_private=self.allow_private_hosts)
        except ValueError:
            log.warning("web push: refusing to post to an endpoint that is not a push service")
            return 0
        parts = urlsplit(endpoint)
        audience = f"{parts.scheme}://{parts.netloc}"
        body = encrypt(payload, unb64u(sub["p256dh"]), unb64u(sub["auth"]))
        headers = {
            "Authorization": f"vapid t={self.key.token(audience, self._subject(sub))},"
                             f" k={self.key.public_b64}",
            "Content-Encoding": "aes128gcm",
            "Content-Type": "application/octet-stream",
            "TTL": str(TTL),
            # "high" wakes a sleeping phone at once, like apns-priority 10; a
            # quiet follow-up can wait for the device's next wake.
            "Urgency": "normal" if quiet else "high",
        }
        status, text = await self._post(endpoint, headers, body)
        if status in (200, 201, 202):
            return status
        if status in (404, 410):
            # The browser unsubscribed or the subscription expired. Keeping it
            # means failing to it forever, as with a dead APNs token.
            log.info("web push: dropping a gone subscription (%s)", status)
            self.store.forget_webpush(endpoint)
            return status
        log.warning("web push: %s from the push service (%s)", status, text)
        return status
