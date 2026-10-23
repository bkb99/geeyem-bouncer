"""Presigned uploads to S3-compatible storage (Cloudflare R2, S3, MinIO…).

The client never sees the storage credentials. It asks the bouncer for a
short-lived presigned PUT, uploads the bytes straight to the bucket, and then
sends the resulting URL as an ordinary IRC message. The bouncer never handles
the file itself, which matters on a 1-vCPU box.

**Storage is per-bouncer and optional.** Geyem is bring-your-own-server, so the
bucket belongs to whoever runs the bouncer; there is no shared upload host and
no default. With nothing configured the feature is simply absent and the client
is told so, rather than failing at the moment someone picks a photo.

The settings are the same shape the otherbot already uses, so one R2 bucket can
serve both:

    GEYEM_S3_ENDPOINT      https://<account>.r2.cloudflarestorage.com
    GEYEM_S3_BUCKET        geyem-uploads
    GEYEM_S3_ACCESS_KEY    …
    GEYEM_S3_SECRET_KEY    …
    GEYEM_S3_PUBLIC_BASE   https://img.example.com   (the bucket's public domain)

and, optionally, one more:

    GEYEM_UPLOAD_PREFIX    morgan     (a folder for this bouncer's uploads:
                                      img.example.com/morgan/2026/10/<name>.png)

One bucket can serve several bouncers, and a prefix is how each one's files
stay together and say whose they are. It is public, in every link, so it names
a person: use one the person is happy to have shown. Unset, keys are the plain
`YYYY/MM/<name>` they have always been. Files already uploaded keep their
links and can still be deleted either way.
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

log =logging.getLogger("relay.uploads")

# What may be uploaded. An allow-list rather than a block-list: the bucket is
# served from a domain, and letting someone upload text/html to it would make it
# a hosting service for whatever they wanted to serve from that origin.
ALLOWED_TYPES = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/gif": "gif",
    "image/heic": "heic",
    "image/webp": "webp",
    "video/mp4": "mp4",
    "video/quicktime": "mov",
    "application/pdf": "pdf",
    "text/plain": "txt",
}

MAX_BYTES = 25 * 1024 * 1024
# How long a file may be asked to live: from five minutes (a picture for one
# conversation) to a year. Outside it is refused rather than clamped, so a
# client that sends "seconds" for "milliseconds" finds out.
MIN_TTL = 300
MAX_TTL = 365 * 24 * 3600
URL_TTL = 300  # seconds the presigned PUT stays valid


@dataclass
class UploadConfig:
    endpoint: str
    bucket: str
    access_key: str
    secret_key: str
    public_base: str
    # "" for none. Validated in from_env; a value that is not a plain folder
    # name is dropped with a warning rather than put in front of every key.
    prefix: str = ""
    # Folders this bouncer used to write to. Files in them are still its own
    # to delete and to expire; nothing new goes there. Set when a prefix is
    # renamed (GEYEM_UPLOAD_PREFIX_ALSO, comma separated).
    old_prefixes: tuple[str, ...] = ()

    @classmethod
    def from_env(cls) -> "UploadConfig | None":
        pieces = (
            os.environ.get("GEYEM_S3_ENDPOINT"),
            os.environ.get("GEYEM_S3_BUCKET"),
            os.environ.get("GEYEM_S3_ACCESS_KEY"),
            os.environ.get("GEYEM_S3_SECRET_KEY"),
            os.environ.get("GEYEM_S3_PUBLIC_BASE"),
        )
        if not all(pieces):
            if any(pieces):
                log.warning("Uploads are partly configured and will be OFF; all five of "
                            "GEYEM_S3_ENDPOINT/BUCKET/ACCESS_KEY/SECRET_KEY/PUBLIC_BASE "
                            "are required.")
            return None
        prefix = (os.environ.get("GEYEM_UPLOAD_PREFIX") or "").strip().strip("/")
        if prefix and not _PREFIX_RE.fullmatch(prefix):
            log.warning("GEYEM_UPLOAD_PREFIX %r is not a plain folder name "
                        "(a-z, 0-9, - and _, up to 32); uploads will have none.", prefix)
            prefix = ""
        old = tuple(
            name for name in (n.strip().strip("/")
                              for n in (os.environ.get("GEYEM_UPLOAD_PREFIX_ALSO") or "").split(","))
            if name and _PREFIX_RE.fullmatch(name) and name != prefix)
        return cls(*[p.rstrip("/") if p else p for p in pieces], prefix=prefix,
                   old_prefixes=old)


# The shape of a key this bouncer makes, and the ONLY shape `delete` will
# touch. The bucket may be shared with something else (the otherbot keeps its
# pictures and backups in one), and a delete that took any key under the public
# URL would let a link into that bucket remove it.
#
# Two forms, because the name used to be part of the key: `<token>-<name>` for
# files uploaded before 2026-10-11, and `<token>.<ext>` since. Both are
# `YYYY/MM/` then 22 characters of base64url (`secrets.token_urlsafe(16)`).
_PREFIX_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
_KEY_BODY = (
    r"\d{4}/\d{2}/[A-Za-z0-9_-]{22}"
    r"(?:\.(?:" + "|".join(sorted(set(ALLOWED_TYPES.values()))) + r")"
    r"|-[A-Za-z0-9._-]{1,64})"
)
_KEY_RE = re.compile(r"^" + _KEY_BODY + r"$")


def key_pattern(prefix: str = "", old: tuple[str, ...] = ()) -> "re.Pattern[str]":
    """The keys one bouncer may touch: its own prefix and the plain shape.

    Only the prefix it was configured with. Accepting any `<folder>/` would
    let a link to another folder's file (or anything that merely looks like a
    key) be deleted through this bouncer.
    """
    if not prefix and not old:
        return _KEY_RE
    folders = [re.escape(name) for name in (prefix, *old) if name]
    return re.compile(r"^(?:(?:" + "|".join(folders) + r")/)?" + _KEY_BODY + r"$")


# What a client is told when something goes wrong. Sentences for the person
# who picked the photo, never an exception's name: "storage error:
# ModuleNotFoundError" appeared twice on the phone when boto3 was missing, and
# the photo was thrown away with it.
# Set on every upload before its link goes out. Cloudflare serves the bucket's
# custom domain from its edge, and an object with no Cache-Control is cached
# there (and in browsers) for four hours: a file deleted from storage kept
# loading from its link, which is the opposite of what a delete is for. With
# no-store the edge goes to storage every time, so a delete takes effect on the
# next request, for everyone. Measured against the live bucket on 2026-10-11:
# without it `cf-cache-status: HIT` after delete; with it BYPASS, then 404.
CACHE_CONTROL = "no-store"

NOT_SET_UP = "Uploads aren't set up on this bouncer."
NOT_PREPARED = "The upload could not be started. Try again in a moment."
NOT_OURS = "That isn't a file this bouncer uploaded."
NOT_DELETED = "The file could not be deleted. Try again in a moment."
DELETE_DENIED = "The bouncer's storage key isn't allowed to delete files."


def boto3_installed() -> bool:
    """Is the S3 library there at all? Checked without importing it."""
    import importlib.util

    return importlib.util.find_spec("boto3") is not None


class Uploader:
    def __init__(self, config: UploadConfig):
        self.config = config
        self._key_re = key_pattern(config.prefix, config.old_prefixes)
        self._client = None
        # All five settings and no library is a bouncer that cannot upload:
        # hello.can_upload says so, rather than offering a button that fails
        # once a photo has been chosen.
        self.available = boto3_installed()
        if not self.available:
            log.warning("Uploads are configured but boto3 is not installed; "
                        "they stay OFF. Install it with: pip install boto3")

    @property
    def client(self):
        if self._client is None:
            import boto3
            from botocore.config import Config as BotoConfig

            self._client = boto3.client(
                "s3",
                endpoint_url=self.config.endpoint,
                aws_access_key_id=self.config.access_key,
                aws_secret_access_key=self.config.secret_key,
                # R2 requires SigV4 and has no regions. The timeouts matter
                # for `delete`, the one call here that really goes to the
                # network: boto's defaults are a minute each and several
                # tries, which would hold a person's "Delete" for minutes
                # when storage is unreachable.
                config=BotoConfig(signature_version="s3v4", region_name="auto",
                                  connect_timeout=5, read_timeout=15,
                                  retries={"max_attempts": 2}),
            )
        return self._client

    def presign(self, *, filename: str, content_type: str, size: int,
                ttl: int | None = None) -> dict:
        """A short-lived PUT URL, and the public URL the file will end up at.

        Refusals are ValueErrors with a sentence meant for the person; anything
        else that goes wrong is the gateway's to turn into NOT_PREPARED.
        """
        if not self.available:
            raise ValueError(NOT_SET_UP)
        if content_type not in ALLOWED_TYPES:
            raise ValueError("That kind of file can't be uploaded here.")
        if size <= 0:
            raise ValueError("That file is empty.")
        if size > MAX_BYTES:
            raise ValueError(f"That file is too big (max {MAX_BYTES // 1024 // 1024} MB).")
        if ttl is not None and not (MIN_TTL <= ttl <= MAX_TTL):
            raise ValueError("That is not a time a file can be kept for.")

        # Unguessable, and grouped by date so a bucket stays browsable. The
        # random component is the only thing protecting the file: anyone with
        # the URL can read it, which is what makes it shareable on IRC. That is
        # a deliberate trade and the client says so before uploading.
        #
        # Nothing of the person's filename goes in the key (`filename` is still
        # in the request, for older and newer clients alike, and is ignored): a
        # link in a channel is public, and "IMG_4021 - tax return.pdf" or
        # "scan-of-my-passport.jpg" is a thing to have told everyone who sees
        # it. The extension comes from the content type, which is on the
        # allow-list, so it is always one the client already draws inline
        # (.jpg, .png, ...) and never one the person typed.
        folder = f"{self.config.prefix}/" if self.config.prefix else ""
        key = (f"{folder}{datetime.utcnow():%Y/%m}/{secrets.token_urlsafe(16)}"
               f".{ALLOWED_TYPES[content_type]}")

        url = self.client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": self.config.bucket,
                "Key": key,
                "ContentType": content_type,
                # Signed in, so the upload cannot be larger than declared.
                "ContentLength": size,
            },
            ExpiresIn=URL_TTL,
        )
        now = time.time()
        return {
            "upload_url": url,
            "public_url": f"{self.config.public_base}/{key}",
            "content_type": content_type,
            "expires_in": URL_TTL,
            "max_bytes": MAX_BYTES,
            # When the bouncer will delete it, in epoch seconds, or null for a
            # file that stays. Counted from now, not from the PUT: a person
            # who picks "1 hour" means one hour from sending.
            "expires_at": (now + ttl) if ttl else None,
        }

    def key_for_url(self, url: str) -> str | None:
        """The storage key a public link points at, or None if it is not one
        of this bouncer's uploads.

        None for anything that is not exactly `<public_base>/<a key this
        bouncer makes>`: another host, another scheme or port, credentials in
        the address, a path that climbs, a percent-escape, another object in the
        same bucket. A query or fragment is ignored, so a link that was shared
        with `?x=1` on the end still names the file.
        """
        if not isinstance(url, str) or len(url) > 2048:
            return None
        try:
            given = urlsplit(url.strip())
            base = urlsplit(self.config.public_base)
            same_origin = (given.scheme.lower() == base.scheme.lower()
                           and given.netloc.lower() == base.netloc.lower())
        except ValueError:
            return None
        if not same_origin or not given.hostname:
            return None
        prefix = base.path.rstrip("/") + "/"
        if not given.path.startswith(prefix):
            return None
        key = given.path[len(prefix):]
        return key if self._key_re.fullmatch(key) else None

    def keys_in(self, text: str, limit: int = 3) -> list[str]:
        """The keys of this bouncer's uploads that a line of text links to."""
        if not isinstance(text, str) or self.config.public_base not in text:
            return []
        found: list[str] = []
        for match in re.finditer(r"https?://[^\s<>\"']+", text):
            key = self.key_for_url(match.group(0).rstrip(".,;:!?)]}"))
            if key and key not in found:
                found.append(key)
                if len(found) >= limit:
                    break
        return found

    def protect(self, key: str) -> bool:
        """Mark one uploaded object uncacheable. True if it was changed.

        Blocking (two calls to storage): the gateway runs it in a thread. The
        content type is carried over, because REPLACE drops every field it is
        not given and a picture that lost its type would stop displaying.
        """
        if not self._key_re.fullmatch(key):
            raise ValueError(NOT_OURS)
        head = self.client.head_object(Bucket=self.config.bucket, Key=key)
        if CACHE_CONTROL in (head.get("CacheControl") or ""):
            return False
        self.client.copy_object(
            Bucket=self.config.bucket, Key=key,
            CopySource={"Bucket": self.config.bucket, "Key": key},
            MetadataDirective="REPLACE",
            ContentType=head.get("ContentType") or "application/octet-stream",
            CacheControl=CACHE_CONTROL,
        )
        return True

    def delete(self, url: str) -> str:
        """Delete the file a public link points at. Returns its key.

        Blocking: a network call, so the gateway runs it in a thread. Refusals
        are ValueErrors with a sentence for the person, like `presign`.
        Deleting a file that is already gone succeeds (S3 and R2 both answer
        204), which is what a person wants: it is gone.
        """
        if not self.available:
            raise ValueError(NOT_SET_UP)
        key = self.key_for_url(url)
        if key is None:
            raise ValueError(NOT_OURS)
        try:
            self.client.delete_object(Bucket=self.config.bucket, Key=key)
        except Exception as exc:
            code = ""
            response = getattr(exc, "response", None)
            if isinstance(response, dict):
                code = str((response.get("Error") or {}).get("Code") or "")
            if code in ("AccessDenied", "403", "Forbidden"):
                log.warning("delete refused by storage (%s): the access key has no "
                            "delete permission on bucket %r", code, self.config.bucket)
                raise ValueError(DELETE_DENIED) from exc
            raise
        return key
