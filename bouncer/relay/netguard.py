"""Which addresses the bouncer may fetch from on its own.

The bouncer makes outbound requests that a client chose the target of: a link
preview fetches whatever URL was pasted into a channel, and Web Push posts to
whatever endpoint a browser handed over. Both run on a VPS, next to a cloud
metadata service (169.254.169.254) and whatever else listens on loopback or the
private network. So every address such a request would connect to must be a
public one, checked at EVERY hop -- a public page that redirects to
http://127.0.0.1:6379/ is the classic way around a check made only on the URL
that was pasted.

Checked where the connection is made, not beforehand: the resolver below is
what aiohttp connects with, so the address that was checked is the address that
is used. A check against a separate lookup could be answered differently by the
lookup the connection then does (DNS rebinding).

A local test rig, where every server is on 127.0.0.1, sets config
`allow_private_hosts: true`.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

from aiohttp.abc import AbstractResolver
from aiohttp.resolver import DefaultResolver


class BlockedAddress(OSError):
    """A connection that would have gone somewhere private."""


def address_is_public(address: str) -> bool:
    """True for an address anyone on the internet could reach, and nothing else.

    `is_global` already excludes loopback, the private ranges, link-local
    (the metadata service), CGNAT's 100.64/10 and the documentation ranges;
    multicast is excluded on top because it is "global" in the RFC's sense. An
    IPv6 address carrying an IPv4 one (::ffff:127.0.0.1) is judged by the IPv4
    address inside it, since that is where it connects.
    """
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]").split("%", 1)[0])
        return True
    except ValueError:
        return False


# The ports a fetch the bouncer makes on a client's behalf may use. A link
# preview is a web page; anything else on a public host (a mail server on 25, a
# Redis on 6379) is a service the bouncer has no business talking HTTP to.
WEB_PORTS = (80, 443)


def check_url(url: str, *, allow_private: bool, allow_http: bool = True) -> str:
    """Refuse a URL the bouncer must not fetch; return its hostname.

    Raises ValueError with a sentence. The hostname is resolved and checked by
    PublicResolver when the connection is made; an IP literal never reaches a
    resolver (aiohttp connects to it directly), so it is checked here -- in the
    form the HTTP client will actually connect to, not only as typed.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        raise ValueError("That is not a link.")
    scheme = parts.scheme.lower()
    if scheme not in (("http", "https") if allow_http else ("https",)):
        raise ValueError("Only http and https links have previews."
                         if allow_http else "That address must be https.")
    host = parts.hostname or ""
    if not host:
        raise ValueError("That link has no host.")
    try:
        parts.port
    except ValueError:
        raise ValueError("That link's port is not a number.")
    if parts.username or parts.password:
        raise ValueError("Links with a password in them are not fetched.")
    # yarl, which aiohttp parses every URL with, applies IDNA mapping to the
    # host: "①②⑦.0.0.1" becomes 127.0.0.1, an IP literal no resolver is ever
    # asked about. Checked only as typed, that link fetched from loopback
    # (security pass 2026-09-22, proof_ssrf_previews.py). Both forms are
    # checked, and the normalised one is what is returned.
    try:
        from yarl import URL

        normalised = URL(url).raw_host or ""
    except (ValueError, UnicodeError):
        raise ValueError("That is not a link.")
    if not allow_private:
        for candidate in {host, normalised}:
            if is_ip_literal(candidate) and not address_is_public(candidate.strip("[]")):
                raise ValueError("That address is on a private network.")
        port = parts.port or (443 if scheme == "https" else 80)
        if port not in WEB_PORTS:
            raise ValueError("Only links on the usual web ports are fetched.")
    return normalised or host


# The push services browsers subscribe with. A Web Push endpoint is a URL a
# browser hands over and the bouncer POSTs to; anything else is not a push
# service, whatever address it resolves to.
PUSH_SERVICE_SUFFIXES = (
    "fcm.googleapis.com",          # Chrome, Edge on Android, Brave, Opera, Samsung
    "push.services.mozilla.com",   # Firefox
    "push.apple.com",              # Safari (web.push.apple.com)
    "notify.windows.com",          # Edge on Windows
)


def check_push_endpoint(url: str, *, allow_private: bool) -> str:
    """Refuse a Web Push endpoint that is not a real push service over
    https on 443; return its host. A test rig (allow_private) may use its own
    fake endpoint on loopback."""
    host = check_url(url, allow_private=allow_private, allow_http=allow_private)
    if allow_private:
        return host
    if urlsplit(url).port not in (None, 443):
        raise ValueError("That is not a push service.")
    host = host.lower().rstrip(".")
    if not any(host == s or host.endswith("." + s) for s in PUSH_SERVICE_SUFFIXES):
        raise ValueError("That is not a push service.")
    return host


class PublicResolver(AbstractResolver):
    """aiohttp's resolver, refusing any name with a private address behind it.

    Every address a name resolves to must be public, not just one: a name with
    one public and one private address would otherwise connect to the private
    one whenever the connector happened to try it first.
    """

    def __init__(self, allow_private: bool = False):
        self.allow_private = allow_private
        self._inner = DefaultResolver()

    async def resolve(self, host: str, port: int = 0,
                      family: socket.AddressFamily = socket.AF_INET):
        results = await self._inner.resolve(host, port, family)
        if not self.allow_private:
            for result in results:
                if not address_is_public(result["host"]):
                    raise BlockedAddress(f"{host} resolves to a private address")
        return results

    async def close(self) -> None:
        await self._inner.close()


async def check_host_public(host: str, *, allow_private: bool) -> None:
    """Resolve a hostname once and refuse it if any address is private.

    For the one place a connection is not made through PublicResolver: a Web
    Push endpoint is checked when it is registered, and httpx has no resolver
    hook to check it again at send time.
    """
    if allow_private:
        return
    if is_ip_literal(host):
        if not address_is_public(host.strip("[]")):
            raise ValueError("That address is on a private network.")
        return
    import asyncio
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None)
    except OSError:
        raise ValueError(f"{host} could not be looked up.")
    if not infos or any(not address_is_public(info[4][0]) for info in infos):
        raise ValueError("That address is on a private network.")


async def resolve_public(host: str, port: int) -> list[str]:
    """Every address an IRC server's name resolves to, when all are public.

    For the one outbound connection that is not HTTP: the IRC link of a
    network whose server came from a client (add_network, edit_network). Its
    host is checked when it is given, with check_host_public, and resolved and
    checked again here on every connect, because a name can point somewhere
    else tomorrow. The connection then goes to an address returned here, with
    the name kept for TLS, so what was checked is what is dialled. Raises
    BlockedAddress, which the reconnect loop reports like any failed connect.
    """
    import asyncio

    if is_ip_literal(host):
        addresses = [host.strip("[]")]
    else:
        try:
            infos = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM),
                timeout=10)
        except (OSError, UnicodeError, asyncio.TimeoutError):
            raise BlockedAddress(f"{host} could not be looked up") from None
        addresses = list(dict.fromkeys(info[4][0] for info in infos))
    if not addresses or not all(address_is_public(a) for a in addresses):
        raise BlockedAddress(f"{host} resolves to a private address")
    return addresses
