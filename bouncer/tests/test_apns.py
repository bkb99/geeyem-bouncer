#!/usr/bin/env python3
"""APNs: the JWT, the payload, and what to do with every response code.

No Apple Developer account is involved. The signing key is generated here and
the signature is verified against its own public key, so the ES256 work is
genuinely checked rather than assumed; the transport is a stub that records what
it was asked to send.

What this canNOT prove is that Apple accepts any of it. See the note at the top
of relay/apns.py.

    python tests/test_apns.py
"""

import asyncio
import base64
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from relay.apns import APNsClient, ProviderToken, RETRY_DELAYS, TOKEN_LIFETIME
from relay.push import (APNsPushProvider, Notification, NullPushProvider, ReadReceipt,
                        build_provider)

FAILED = []


def check(label, got, want):
    if got != want:
        FAILED.append(f"{label}: got {got!r}, want {want!r}")
        print(f"  FAIL {label}: got {got!r}, want {want!r}")
    else:
        print(f"  ok   {label}")


def make_key(directory):
    """A real P-256 key in the shape Apple hands out (PEM, no passphrase)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = os.path.join(directory, "AuthKey_TEST12345.p8")
    with open(path, "wb") as f:
        f.write(pem)
    return path, key.public_key()


def b64decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


class StubTransport:
    """Records requests and replays a scripted list of responses."""

    def __init__(self, responses=None):
        self.requests = []
        self.responses = list(responses or [])

    async def post(self, url, headers, body):
        self.requests.append({"url": url, "headers": headers, "body": json.loads(body)})
        if self.responses:
            return self.responses.pop(0)
        return 200, {}


def notification():
    return Notification(title="#hangout", body="morgan: riley you around?",
                        buffer_id=3, eid=91, network="quakenet", badge=2)


def test_jwt():
    print("provider token")
    with tempfile.TemporaryDirectory() as tmp:
        path, public_key = make_key(tmp)
        token = ProviderToken(path, "KEYID12345", "TEAMID6789")
        value = token.value(now=1_000_000)

        header_b64, claims_b64, signature_b64 = value.split(".")
        header = json.loads(b64decode(header_b64))
        claims = json.loads(b64decode(claims_b64))
        check("alg is ES256", header["alg"], "ES256")
        check("key id in header", header["kid"], "KEYID12345")
        check("team id is the issuer", claims["iss"], "TEAMID6789")
        check("issued-at is set", claims["iat"], 1_000_000)
        check("no padding in base64url", "=" in value, False)

        # The signature has to be raw r||s, not the DER that `cryptography`
        # returns. Getting this wrong yields a token Apple rejects with no
        # useful explanation, so verify it properly.
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        raw = b64decode(signature_b64)
        check("signature is 64 bytes (r||s for P-256)", len(raw), 64)
        r = int.from_bytes(raw[:32], "big")
        s = int.from_bytes(raw[32:], "big")
        signing_input = f"{header_b64}.{claims_b64}".encode()
        try:
            public_key.verify(encode_dss_signature(r, s), signing_input,
                              ec.ECDSA(hashes.SHA256()))
            check("signature verifies against its own public key", True, True)
        except Exception as exc:
            check("signature verifies against its own public key", f"failed: {exc}", True)

        # Cached, because Apple rate limits providers that mint one per push.
        check("token is cached", token.value(now=1_000_000 + 60), value)
        check("token refreshes after its lifetime",
              token.value(now=1_000_000 + TOKEN_LIFETIME + 1) != value, True)


def test_payload():
    print("payload and headers")
    with tempfile.TemporaryDirectory() as tmp:
        path, _ = make_key(tmp)
        stub = StubTransport()
        client = APNsClient(key_path=path, key_id="K", team_id="T",
                            topic="com.example.geyem", sandbox=True, transport=stub)

        asyncio.run(client.send_one(notification(), "DEVICETOKEN123"))
        request = stub.requests[0]

        check("sandbox host", request["url"].startswith("https://api.sandbox.push.apple.com"), True)
        check("device token in the path", request["url"].endswith("/3/device/DEVICETOKEN123"), True)
        check("bearer auth", request["headers"]["authorization"].startswith("bearer "), True)
        check("topic is the bundle id", request["headers"]["apns-topic"], "com.example.geyem")
        check("alert push type", request["headers"]["apns-push-type"], "alert")
        check("immediate priority", request["headers"]["apns-priority"], "10")
        # No collapse id: it made each mention REPLACE the last one from that
        # conversation, so alice's mention erased bob's question. thread-id
        # groups them without losing any.
        check("never collapses one notification into another",
              "apns-collapse-id" in request["headers"], False)

        aps = request["body"]["aps"]
        check("title is the channel", aps["alert"]["title"], "#hangout")
        check("body is the line", aps["alert"]["body"], "morgan: riley you around?")
        check("badge carried", aps["badge"], 2)
        check("thread groups by buffer", aps["thread-id"], "buffer-3")
        check("an ordinary notification makes a sound", aps.get("sound"), "default")
        check("an ordinary notification interrupts as usual", "interruption-level" in aps, False)
        # The app needs to wake and pre-fetch the surrounding backlog so that
        # opening the notification lands on a conversation already there.
        check("mutable-content set", aps["mutable-content"], 1)
        # Without the category iOS draws no Reply or Mark as Read on it.
        check("a message push names the message category", aps.get("category"), "message")

        extra = request["body"]["relay"]
        check("deep link carries the buffer", extra["buffer"], 3)
        check("deep link carries the eid", extra["eid"], 91)
        # Who said it, on its own, so the notification extension does not have
        # to parse "morgan: riley you around?" -- or, with previews off, cannot.
        check("no sender, no `from`", "from" in extra, False)
        named = notification()
        named.sender = "morgan"
        asyncio.run(client.send_one(named, "D"))
        check("relay.from is the nick", stub.requests[-1]["body"]["relay"],
              {"buffer": 3, "eid": 91, "network": "quakenet", "from": "morgan"})


def test_read_receipt():
    """The push that follows a read on another device: nothing to show, so
    Apple's rules for a background push -- its own type, priority 5."""
    print("read receipt (background push)")
    with tempfile.TemporaryDirectory() as tmp:
        path, _ = make_key(tmp)
        stub = StubTransport()
        client = APNsClient(key_path=path, key_id="K", team_id="T",
                            topic="com.example.geyem", sandbox=False, transport=stub)
        before = time.time()
        result = asyncio.run(client.send_one(ReadReceipt(3, 912, 3), "DEVICETOKEN123"))
        request = stub.requests[0]
        check("delivered", result.status, 200)
        check("to the device, on the production host",
              request["url"], "https://api.push.apple.com/3/device/DEVICETOKEN123")
        check("push type background", request["headers"]["apns-push-type"], "background")
        check("priority 5, the only one a background push may have",
              request["headers"]["apns-priority"], "5")
        check("the same topic", request["headers"]["apns-topic"], "com.example.geyem")
        expiry = int(request["headers"]["apns-expiration"])
        check("gone if not delivered within the hour",
              before + 3590 <= expiry <= time.time() + 3601, True)
        check("no collapse id here either", "apns-collapse-id" in request["headers"], False)
        check("the body is exactly the contract's", request["body"],
              {"aps": {"content-available": 1, "badge": 3},
               "relay": {"read": {"buffer": 3, "eid": 912}}})
        check("nothing in it would show or sound",
              [k for k in ("alert", "sound", "category", "thread-id", "mutable-content")
               if k in request["body"]["aps"]], [])

        asyncio.run(client.send_one(ReadReceipt(None, None, 0), "D"))
        check("everything read at once", stub.requests[-1]["body"],
              {"aps": {"content-available": 1, "badge": 0}, "relay": {"read": {"all": True}}})
        # An alert sent through the same client afterwards is still an alert.
        asyncio.run(client.send_one(notification(), "D"))
        check("an alert is unaffected",
              (stub.requests[-1]["headers"]["apns-push-type"],
               stub.requests[-1]["headers"]["apns-priority"]), ("alert", "10"))

        # The provider: the same split by environment, and a device Apple says
        # is gone is forgotten whichever kind of push found that out.
        forgotten = []
        provider = APNsPushProvider(path, "K", "T", "topic", True, forget_device=forgotten.append)
        sandbox = StubTransport([(200, {})])
        production = StubTransport([(410, {"reason": "Unregistered"})])
        provider._clients[True] = APNsClient(key_path=path, key_id="K", team_id="T", topic="t",
                                             sandbox=True, transport=sandbox)
        provider._clients[False] = APNsClient(key_path=path, key_id="K", team_id="T", topic="t",
                                              sandbox=False, transport=production)
        asyncio.run(provider.send_read(ReadReceipt(3, 912, 0), [
            {"apns_token": "S", "environment": "sandbox"},
            {"apns_token": "P", "environment": "production"}]))
        check("a receipt goes to each device's own environment",
              (len(sandbox.requests), len(production.requests)), (1, 1))
        check("  as a background push",
              sandbox.requests[0]["headers"]["apns-push-type"], "background")
        check("  and a dead device is forgotten", forgotten, ["P"])
        # With no APNs configured: logged at most, never an error.
        check("the no-op provider takes a receipt",
              asyncio.run(NullPushProvider().send_read(ReadReceipt(1, 2, 0), [{}])), None)


def test_retry():
    """429 and 5xx are Apple saying "not now": tried again, twice at most,
    after a pause that holds nothing else up. Anything else is not (B-R7)."""
    print("retry on 429 and 5xx (B-R7)")
    check("two more tries, a second and then three seconds on", RETRY_DELAYS, (1.0, 3.0))
    with tempfile.TemporaryDirectory() as tmp:
        path, _ = make_key(tmp)

        def run(responses, delays=(0.01, 0.02)):
            stub = StubTransport(responses)
            client = APNsClient(key_path=path, key_id="K", team_id="T", topic="t",
                                sandbox=True, transport=stub)
            client.retry_delays = delays
            started = time.monotonic()
            result = asyncio.run(client.send_one(notification(), "D"))
            return result, len(stub.requests), time.monotonic() - started

        result, sent, took = run([(429, {"reason": "TooManyRequests"}), (200, {})])
        check("429, then delivered on the second try", (result.status, sent), (200, 2))
        check("  after the pause", took >= 0.01, True)
        result, sent, took = run([(503, {"reason": "ServiceUnavailable"}),
                                  (500, {"reason": "InternalServerError"}), (200, {})])
        check("two 5xx, then delivered on the third try", (result.status, sent), (200, 3))
        check("  after both pauses", took >= 0.03, True)
        result, sent, _ = run([(503, {"reason": "ServiceUnavailable"})] * 5)
        check("it gives up after three tries in all",
              (result.status, result.reason, sent), (503, "ServiceUnavailable", 3))
        check("  and a device Apple could not take a push for is not dropped", result.drop, False)

        # Never for what trying again cannot fix.
        for status, reason, drop in ((400, "BadDeviceToken", True), (410, "Unregistered", True),
                                     (400, "DeviceTokenNotForTopic", True),
                                     (413, "PayloadTooLarge", False), (400, "BadTopic", False),
                                     (404, "BadPath", False)):
            result, sent, took = run([(status, {"reason": reason}), (200, {})], delays=(5.0, 5.0))
            check(f"{status} {reason} is not retried",
                  (result.status, sent, result.drop, took < 1.0), (status, 1, drop, True))

        # A background push is retried the same way.
        stub = StubTransport([(503, {}), (200, {})])
        client = APNsClient(key_path=path, key_id="K", team_id="T", topic="t",
                            sandbox=True, transport=stub)
        client.retry_delays = (0.01,)
        result = asyncio.run(client.send_one(ReadReceipt(1, 2, 0), "D"))
        check("a read receipt is retried too", (result.status, len(stub.requests)), (200, 2))

        # NEVER BLOCKING: one device being waited on holds up neither the
        # other devices of the same notification nor anything else on the loop.
        class OneSlow(StubTransport):
            def __init__(self):
                super().__init__()
                self.done, self.slow_tries = [], 0

            async def post(self, url, headers, body):
                self.requests.append(url)
                if url.endswith("/SLOW"):
                    self.slow_tries += 1
                    if self.slow_tries < 3:
                        return 503, {"reason": "ServiceUnavailable"}
                self.done.append((url.rsplit("/", 1)[1], time.monotonic()))
                return 200, {}

        async def fan_out():
            transport = OneSlow()
            client = APNsClient(key_path=path, key_id="K", team_id="T", topic="t",
                                sandbox=True, transport=transport)
            client.retry_delays = (0.15, 0.15)
            ticks = 0

            async def ticker():
                nonlocal ticks
                while True:
                    await asyncio.sleep(0.01)
                    ticks += 1

            tick = asyncio.create_task(ticker())
            started = time.monotonic()
            results = await client.send(notification(), ["SLOW", "FAST", "ALSO"])
            took = time.monotonic() - started
            tick.cancel()
            return transport, results, took, ticks, started

        transport, results, took, ticks, started = asyncio.run(fan_out())
        finished = {name: at - started for name, at in transport.done}
        check("every device is delivered to, in the order asked",
              [(r.device_token, r.status) for r in results],
              [("SLOW", 200), ("FAST", 200), ("ALSO", 200)])
        check("the others did not wait for the one being retried",
              (finished["FAST"] < 0.1, finished["ALSO"] < 0.1, finished["SLOW"] >= 0.3),
              (True, True, True))
        check("and the event loop ran all the while", ticks >= 15, True)

        # Sent side by side, several devices can be refused over one stale
        # provider token at once. One new token is signed, not one each.
        class Stale(StubTransport):
            async def post(self, url, headers, body):
                self.requests.append(headers["authorization"])
                first = self.requests[0]
                if headers["authorization"] == first:
                    return 403, {"reason": "ExpiredProviderToken"}
                return 200, {}

        stale = Stale()
        client = APNsClient(key_path=path, key_id="K", team_id="T", topic="t",
                            sandbox=True, transport=stale)
        results = asyncio.run(client.send(notification(), ["A", "B", "C"]))
        check("three devices refused over one expired token are all delivered",
              [r.status for r in results], [200, 200, 200])
        check("  with one new token between them, not three",
              len(set(stale.requests)), 2)


def test_quiet_payload():
    """A follow-up inside the quiet window is still delivered, and still listed,
    but says so to Apple the Apple way: no "sound" key at all, and a passive
    interruption level so the screen does not light up."""
    print("quiet follow-ups")
    with tempfile.TemporaryDirectory() as tmp:
        path, _ = make_key(tmp)
        stub = StubTransport()
        client = APNsClient(key_path=path, key_id="K", team_id="T", topic="t",
                            sandbox=True, transport=stub)
        quiet = notification()
        quiet.quiet = True
        asyncio.run(client.send_one(quiet, "D"))
        aps = stub.requests[0]["body"]["aps"]
        check("a quiet notification has no sound", "sound" in aps, False)
        check("a quiet notification is passive", aps.get("interruption-level"), "passive")
        check("a quiet notification still has its text", aps["alert"]["body"],
              "morgan: riley you around?")
        check("a quiet notification still stacks with its conversation",
              aps["thread-id"], "buffer-3")
        check("a quiet notification still sets the badge", aps["badge"], 2)
        check("a quiet notification keeps its Reply and Mark as Read",
              aps.get("category"), "message")
        check("and still wakes the extension", aps["mutable-content"], 1)


def test_category_from_the_session():
    """Every push the session makes -- a mention, a PM, a notify "all" line, an
    invite -- is a message push and carries the category iOS hangs the Reply
    and Mark as Read actions on."""
    print("push category from every kind of push")
    import os
    from relay.config import NetworkConfig
    from relay.ircproto import parse_line
    from relay.session import NetworkSession
    from relay.store import Store

    class Hub:
        def __init__(self):
            self.pushed, self.clients, self.sessions = [], set(), {}

        def publish(self, frame): pass

        async def broadcast(self, frame): pass

        def has_active_viewer(self, buffer_id): return False

        async def push(self, notification): self.pushed.append(notification)

    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "c.db"))
            hub = Hub()
            session = NetworkSession(NetworkConfig(slug="t", name="T", host="h", nick="me"),
                                     store, hub)
            session.conn.nick = "me"
            for line in (":me!u@h JOIN #c", ":bob!b@h PRIVMSG #c :me: mention",
                         ":bob!b@h PRIVMSG me :a pm", ":bob!b@h INVITE me :#secret"):
                await session._on_message(parse_line(line))
            chan = store.find_buffer(session.network_id, "#c")
            await session.set_buffer_settings(chan.id, notify="all")
            await session._on_message(parse_line(":bob!b@h PRIVMSG #c :just chatter"))
            payloads = [n.to_apns_payload("x")["aps"] for n in hub.pushed]
            check("four kinds of push, four pushes", len(payloads), 4)
            check("every one names the message category",
                  {aps.get("category") for aps in payloads}, {"message"})
            check("thread-id and mutable-content as before",
                  {(aps["thread-id"], aps["mutable-content"]) for aps in payloads}, {("x", 1)})
            store.close()

    asyncio.run(run())


def test_push_cooldown():
    """Twenty mentions in a burst: one sound, nineteen quiet deliveries.

    Measured from the last notification that made a sound, per conversation,
    so another conversation's first mention still makes its own sound.
    """
    print("push cooldown")
    from relay.hub import Hub

    class Devices:
        def devices(self):
            return [{"apns_token": "AA", "environment": "sandbox"}]

    class Recording:
        def __init__(self): self.sent = []
        async def send(self, notification, devices): self.sent.append(notification)

    async def run():
        provider = Recording()
        hub = Hub(Devices(), provider)
        for i in range(20):
            await hub.push(Notification(title="#busy", body=f"spam {i}", buffer_id=7,
                                        eid=i, network="n"))
        await hub.push(Notification(title="bob", body="a PM", buffer_id=8, eid=99,
                                    network="n"))
        await asyncio.sleep(0.05)
        return hub, provider.sent

    hub, sent = asyncio.run(run())
    busy = [n for n in sent if n.buffer_id == 7]
    check("every mention is still delivered", len(busy), 20)
    check("only the first one makes a sound", [n.quiet for n in busy].count(False), 1)
    check("the first one is the loud one", busy[0].quiet, False)
    check("another conversation gets its own sound",
          [n.quiet for n in sent if n.buffer_id == 8], [False])
    # After the window, the next one is loud again.
    check("inside the window is quiet", hub._quiet_for(7, now=time.monotonic() + 10), True)
    check("past the window is loud again",
          hub._quiet_for(7, now=time.monotonic() + hub.push_quiet_window + 1), False)


def test_production_host():
    print("environments")
    with tempfile.TemporaryDirectory() as tmp:
        path, _ = make_key(tmp)
        stub = StubTransport()
        client = APNsClient(key_path=path, key_id="K", team_id="T", topic="t",
                            sandbox=False, transport=stub)
        asyncio.run(client.send_one(notification(), "D"))
        check("production host", stub.requests[0]["url"].startswith("https://api.push.apple.com"),
              True)


def test_responses():
    print("response handling")
    with tempfile.TemporaryDirectory() as tmp:
        path, _ = make_key(tmp)

        def client_with(responses):
            client = APNsClient(key_path=path, key_id="K", team_id="T", topic="t",
                                sandbox=True, transport=StubTransport(responses))
            # One answer, one verdict: what each code MEANS is tested here,
            # and trying again after 429 and 5xx in test_retry.
            client.retry_delays = ()
            return client

        ok = asyncio.run(client_with([(200, {})]).send_one(notification(), "D"))
        check("200 is a success", (ok.status, ok.drop), (200, False))

        # A dead token kept forever is how a provider gets rate limited.
        gone = asyncio.run(client_with([(410, {"reason": "Unregistered"})])
                           .send_one(notification(), "D"))
        check("410 drops the device", gone.drop, True)

        bad = asyncio.run(client_with([(400, {"reason": "BadDeviceToken"})])
                          .send_one(notification(), "D"))
        check("BadDeviceToken drops the device", bad.drop, True)

        wrong_topic = asyncio.run(client_with([(400, {"reason": "DeviceTokenNotForTopic"})])
                                  .send_one(notification(), "D"))
        check("DeviceTokenNotForTopic drops the device", wrong_topic.drop, True)

        # A payload problem is OUR bug; dropping the device would hide it.
        too_big = asyncio.run(client_with([(413, {"reason": "PayloadTooLarge"})])
                              .send_one(notification(), "D"))
        check("PayloadTooLarge does not drop the device", too_big.drop, False)

        throttled = asyncio.run(client_with([(429, {"reason": "TooManyRequests"})])
                                .send_one(notification(), "D"))
        check("429 does not drop the device", throttled.drop, False)

        outage = asyncio.run(client_with([(503, {"reason": "ServiceUnavailable"})])
                             .send_one(notification(), "D"))
        check("503 does not drop the device", outage.drop, False)


def test_token_retry():
    print("expired provider token")
    with tempfile.TemporaryDirectory() as tmp:
        path, _ = make_key(tmp)
        # Rejected once, accepted after re-signing: the one failure we can fix
        # ourselves, so it is worth exactly one retry.
        stub = StubTransport([(403, {"reason": "ExpiredProviderToken"}), (200, {})])
        client = APNsClient(key_path=path, key_id="K", team_id="T", topic="t",
                            sandbox=True, transport=stub)
        result = asyncio.run(client.send_one(notification(), "D"))
        check("retried after re-signing", result.status, 200)
        check("sent exactly twice", len(stub.requests), 2)
        check("not dropped", result.drop, False)

        # And it gives up rather than looping if the key really is wrong.
        stub2 = StubTransport([(403, {"reason": "InvalidProviderToken"}),
                               (403, {"reason": "InvalidProviderToken"})])
        client2 = APNsClient(key_path=path, key_id="K", team_id="T", topic="t",
                             sandbox=True, transport=stub2)
        result2 = asyncio.run(client2.send_one(notification(), "D"))
        check("gives up after one retry", len(stub2.requests), 2)
        check("reports the failure", result2.status, 403)


def test_one_bad_device_does_not_stop_the_rest():
    print("fan-out")
    with tempfile.TemporaryDirectory() as tmp:
        path, _ = make_key(tmp)

        class Exploding(StubTransport):
            async def post(self, url, headers, body):
                if url.endswith("/BROKEN"):
                    raise ConnectionError("network went away")
                return await super().post(url, headers, body)

        client = APNsClient(key_path=path, key_id="K", team_id="T", topic="t",
                            sandbox=True, transport=Exploding())
        results = asyncio.run(client.send(notification(), ["A", "BROKEN", "C"]))
        check("every device got a result", len(results), 3)
        check("the good ones still succeeded",
              [r.status for r in results if r.device_token in ("A", "C")], [200, 200])
        check("the broken one is reported, not raised", results[1].status, 0)


def test_provider_routing():
    print("provider")
    with tempfile.TemporaryDirectory() as tmp:
        path, _ = make_key(tmp)
        forgotten = []
        provider = APNsPushProvider(path, "K", "T", "topic", True,
                                    forget_device=forgotten.append)

        sandbox_stub = StubTransport([(200, {})])
        production_stub = StubTransport([(410, {"reason": "Unregistered"})])
        from relay.apns import APNsClient as _C
        provider._clients[True] = _C(key_path=path, key_id="K", team_id="T", topic="t",
                                     sandbox=True, transport=sandbox_stub)
        provider._clients[False] = _C(key_path=path, key_id="K", team_id="T", topic="t",
                                      sandbox=False, transport=production_stub)

        asyncio.run(provider.send(notification(), [
            {"apns_token": "SANDBOXTOKEN", "environment": "sandbox"},
            {"apns_token": "PRODTOKEN", "environment": "production"},
        ]))
        # A sandbox token sent to the production host fails in a way that reads
        # like a bad token, which sends you looking in the wrong place.
        check("sandbox device used the sandbox client", len(sandbox_stub.requests), 1)
        check("production device used the production client", len(production_stub.requests), 1)
        check("a dead device is forgotten", forgotten, ["PRODTOKEN"])


def test_build_provider():
    print("configuration")

    class Config:
        apns_key_path = apns_key_id = apns_team_id = apns_topic = None
        apns_use_sandbox = True

    config = Config()
    check("no config means the no-op provider",
          isinstance(build_provider(config), NullPushProvider), True)

    # Partial configuration is a misconfiguration; it must not look configured.
    config.apns_key_path = "/tmp/key.p8"
    check("partial config falls back to the no-op",
          isinstance(build_provider(config), NullPushProvider), True)

    with tempfile.TemporaryDirectory() as tmp:
        path, _ = make_key(tmp)
        config.apns_key_path = path
        config.apns_key_id = "K"
        config.apns_team_id = "T"
        config.apns_topic = "com.example.geyem"
        check("complete config builds the real provider",
              isinstance(build_provider(config), APNsPushProvider), True)


def main():
    for fn in (test_jwt, test_payload, test_quiet_payload, test_category_from_the_session,
               test_push_cooldown,
               test_production_host, test_responses,
               test_token_retry, test_one_bad_device_does_not_stop_the_rest,
               test_provider_routing, test_build_provider,
               test_read_receipt, test_retry):
        fn()
    print()
    if FAILED:
        print(f"{len(FAILED)} FAILURE(S):")
        for f in FAILED:
            print(f"  - {f}")
        return 1
    print("all apns tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
