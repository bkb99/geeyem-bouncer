"""APNs delivery over HTTP/2 with token (.p8) authentication.

Apple's provider API wants a short-lived ES256 JWT rather than a client
certificate, which is the better deal: one small file that does not expire
annually, and nothing to renew at 2am.

The transport is injected rather than constructed here. That is not ceremony --
it is the only way the interesting parts (the JWT, the payload, what to do with
a 410) can be tested without an Apple Developer account and a real device token,
neither of which a test suite can have.

WHAT IS VERIFIED, AND WHAT IS NOT. The alert push has been delivered by Apple
end to end: to a TestFlight build, on the production host, on 2026-09-20 (the
note in clients/RelayKit/.../PushRegistration.swift records it), and it has
been the way mentions reach the phone since. The tests here still cannot talk
to Apple -- the JWT is checked against its own public key, every response code
goes through a stub, the payloads are asserted field by field -- so anything
added after that date has only the stub's word for it until a device has
received one. As of this writing that is the background push (ReadReceipt:
`apns-push-type: background`, priority 5) and the retry on 429 and 5xx.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .push import Notification, ReadReceipt

log = logging.getLogger("relay.apns")

PRODUCTION_HOST = "https://api.push.apple.com"
SANDBOX_HOST = "https://api.sandbox.push.apple.com"

# Apple rejects a provider token younger than 20 minutes on refresh and older
# than 60. Refreshing at 45 sits clear of both edges without being chatty.
TOKEN_LIFETIME = 45 * 60

# How long to wait before each further attempt at a push Apple answered with
# 429 (too many requests for this device) or a 5xx (their side is unwell): two
# more tries, a second and then three seconds on. Both are Apple saying "not
# now", which a moment usually cures, and until 2026-10 the answer to either
# was to log it and lose the notification. Short on purpose: a mention that
# arrives a minute late has usually been read somewhere else, and the pushes
# behind this one are not held up -- each device is sent to on its own (see
# APNsClient.send), and none of it runs anywhere near the IRC read loop
# (Hub.push hands delivery to a task of its own).
RETRY_DELAYS = (1.0, 3.0)


def _b64(data: bytes) -> str:
    """base64url with the padding stripped, which is what JWT wants."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass
class APNsResult:
    """One device's outcome. `drop` means stop sending to this token, ever."""

    device_token: str
    status: int
    reason: str = ""
    drop: bool = False


class Transport(Protocol):
    async def post(self, url: str, headers: dict[str, str], body: bytes) -> tuple[int, dict]: ...


class HTTPXTransport:
    """The real one. HTTP/2 is mandatory -- APNs refuses HTTP/1.1."""

    def __init__(self) -> None:
        import httpx

        # trust_env=False: no proxy from the environment, as in webpush.py.
        # The provider token rides on every request, and an HTTPS_PROXY left
        # in the service's environment would be handed it.
        self._client = httpx.AsyncClient(http2=True, timeout=10.0, trust_env=False)

    async def post(self, url: str, headers: dict[str, str], body: bytes) -> tuple[int, dict]:
        response = await self._client.post(url, headers=headers, content=body)
        payload: dict = {}
        if response.content:
            try:
                payload = response.json()
            except Exception:
                payload = {"raw": response.text[:200]}
        return response.status_code, payload

    async def aclose(self) -> None:
        await self._client.aclose()


class ProviderToken:
    """The signed JWT, cached and refreshed on a clock.

    Signing on every push would be wasteful and, more to the point, Apple rate
    limits providers that mint a new token per request.
    """

    def __init__(self, key_path: str, key_id: str, team_id: str):
        self.key_path = key_path
        self.key_id = key_id
        self.team_id = team_id
        self._token: str | None = None
        self._issued_at: float = 0.0
        self._private_key = None

    def _load_key(self):
        if self._private_key is None:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            pem = Path(self.key_path).read_bytes()
            # A .p8 from Apple is already PEM; no passphrase.
            self._private_key = load_pem_private_key(pem, password=None)
        return self._private_key

    def value(self, now: float | None = None) -> str:
        now = now if now is not None else time.time()
        if self._token and (now - self._issued_at) < TOKEN_LIFETIME:
            return self._token
        self._token = self._sign(now)
        self._issued_at = now
        return self._token

    def _sign(self, issued_at: float) -> str:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        header = {"alg": "ES256", "kid": self.key_id}
        claims = {"iss": self.team_id, "iat": int(issued_at)}
        signing_input = f"{_b64(json.dumps(header, separators=(',', ':')).encode())}." \
                        f"{_b64(json.dumps(claims, separators=(',', ':')).encode())}"

        der = self._load_key().sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
        # `cryptography` returns a DER-encoded (r, s). JWS wants them raw and
        # fixed-width: 32 bytes each for P-256, big-endian, left-padded. Passing
        # the DER blob straight through is the classic way to produce a token
        # Apple rejects with no useful explanation.
        r, s = decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"{signing_input}.{_b64(signature)}"


class APNsClient:
    def __init__(
        self,
        *,
        key_path: str,
        key_id: str,
        team_id: str,
        topic: str,
        sandbox: bool = True,
        transport: Transport | None = None,
    ):
        self.topic = topic
        self.host = SANDBOX_HOST if sandbox else PRODUCTION_HOST
        self.token = ProviderToken(key_path, key_id, team_id)
        self._transport = transport
        self._own_transport = transport is None
        # An attribute, so a test can make the waits something it can sit out.
        self.retry_delays: tuple[float, ...] = RETRY_DELAYS

    @property
    def transport(self) -> Transport:
        if self._transport is None:
            self._transport = HTTPXTransport()
        return self._transport

    async def aclose(self) -> None:
        if self._own_transport and isinstance(self._transport, HTTPXTransport):
            await self._transport.aclose()

    def build_payload(self, notification: Notification | ReadReceipt) -> dict[str, Any]:
        if isinstance(notification, ReadReceipt):
            # Nothing to show, so nothing to group: no thread-id.
            return notification.to_apns_payload()
        return notification.to_apns_payload(thread_id=f"buffer-{notification.buffer_id}")

    def headers(self, notification: Notification | ReadReceipt) -> dict[str, str]:
        return {
            "authorization": f"bearer {self.token.value()}",
            "apns-topic": self.topic,
            # What is being sent says how it is to be treated: an alert is
            # "alert" at priority 10 (deliver immediately), a read receipt is
            # "background" at 5, which is the only pair Apple accepts for a
            # push that shows nothing. See push.Notification and ReadReceipt.
            "apns-push-type": notification.apns_push_type,
            "apns-priority": notification.apns_priority,
            # If it cannot be delivered within the hour it is stale -- the user
            # has almost certainly seen the message on another device by then.
            # The same hour for a read receipt: Apple keeps only the newest
            # background push for a device that is off, and a phone that comes
            # back later than that attaches and reads the markers for itself.
            "apns-expiration": str(int(time.time()) + 3600),
            # No apns-collapse-id. It was "b<buffer>", which made each
            # notification for a conversation replace the last one: alice's
            # mention erased bob's question, and a five-line PM left only its
            # last line. The payload's thread-id groups them into one stack
            # without losing any, and bursts are handled by sending follow-ups
            # quietly rather than by throwing them away (see Notification.quiet).
            "content-type": "application/json",
        }

    async def send_one(self, notification: Notification | ReadReceipt,
                       device_token: str) -> APNsResult:
        """One push to one device, tried again after a pause when Apple says
        "not now" (429, 5xx) and never when it says "not this" (see _attempt).

        The pause is an asyncio.sleep in the task that is delivering, so
        nothing else waits on it: not the event loop, not the IRC link, not
        the other devices this notification is going to.
        """
        result = await self._attempt(notification, device_token)
        for delay in self.retry_delays:
            if not (result.status == 429 or 500 <= result.status <= 599):
                break
            log.info("APNs: %s for a device (%s); trying again in %.0fs",
                     result.status, result.reason, delay)
            await asyncio.sleep(delay)
            result = await self._attempt(notification, device_token)
        if result.status != 200 and not result.drop:
            log.warning("APNs: %s for a device (%s)", result.status, result.reason)
        return result

    async def _attempt(self, notification: Notification | ReadReceipt,
                       device_token: str) -> APNsResult:
        url = f"{self.host}/3/device/{device_token}"
        body = json.dumps(self.build_payload(notification), separators=(",", ":")).encode()
        headers = self.headers(notification)
        status, payload = await self.transport.post(url, headers, body)
        reason = payload.get("reason", "") if isinstance(payload, dict) else ""

        if status == 200:
            return APNsResult(device_token, status)

        # 410 means the app was deleted; the 400s below mean the token was never
        # valid for us. Keeping any of them means retrying a dead device forever,
        # which is how a provider gets rate limited.
        if status == 410 or reason in ("Unregistered", "BadDeviceToken", "DeviceTokenNotForTopic"):
            log.info("APNs: dropping dead device token (%s)", reason or status)
            return APNsResult(device_token, status, reason, drop=True)

        if status == 403 or reason in ("ExpiredProviderToken", "InvalidProviderToken"):
            # The provider token is the one thing we can fix ourselves. Force a
            # re-sign and try once more; if it fails again the key or the ids are
            # wrong and retrying will not help.
            log.warning("APNs: provider token rejected (%s), re-signing and retrying", reason)
            # Only if the token Apple refused is still the one in hand. Devices
            # are sent to side by side, so several can be refused over the same
            # stale token at once, and each signing a new one would be several
            # new tokens in a second -- which Apple answers with
            # TooManyProviderTokenUpdates. The first re-signs; the rest use it.
            if headers["authorization"] == f"bearer {self.token.value()}":
                self.token._issued_at = 0.0
            status, payload = await self.transport.post(url, self.headers(notification), body)
            reason = payload.get("reason", "") if isinstance(payload, dict) else ""
            if status == 200:
                return APNsResult(device_token, status)

        # Everything else is reported as it is and left to send_one: a 429 or
        # a 5xx is worth another try, and any other 4xx (a payload too large,
        # a bad topic, a token for the wrong environment) is our mistake or
        # the device's, which trying again cannot fix.
        return APNsResult(device_token, status, reason)

    async def send(self, notification: Notification | ReadReceipt,
                   device_tokens: list[str]) -> list[APNsResult]:
        """Every device, each on its own: one device waiting out a retry does
        not hold up the push to the next one. HTTP/2 carries them side by side
        on the one connection. Results come back in the order asked."""
        async def one(token: str) -> APNsResult:
            try:
                return await self.send_one(notification, token)
            except Exception as exc:
                # One unreachable device must not stop the others. A push that
                # fails is a missed notification; an exception here would be a
                # missed notification for everyone.
                log.exception("APNs: send failed for a device")
                return APNsResult(token, 0, f"{type(exc).__name__}: {exc}")

        return list(await asyncio.gather(*(one(token) for token in device_tokens)))
