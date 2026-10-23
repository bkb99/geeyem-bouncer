"""The downstream wire protocol: what the bouncer and its clients say to each other.

One JSON object per websocket text frame. Every frame has a `type`. Frames the
client sends may carry a `req` (any string) and the server echoes it back on the
matching `ok` or `error`, which is how a client correlates a reply without
inventing a request-id scheme of its own.

The full reference, including every field of every frame, is docs/PROTOCOL.md.
This module is the single source of truth for the type names so a typo cannot
silently become a message nobody handles.
"""

from __future__ import annotations

import json
from typing import Any

PROTOCOL_VERSION = 1


# --- server -> client ------------------------------------------------------
HELLO = "hello"                 # session established; server + user info
NETWORK = "network"             # a network's connection state changed
BUFFER = "buffer"               # a buffer was created or its metadata changed
BUFFER_LIST = "buffers"         # the full buffer list, sent once after hello
MEMBERS = "members"             # full member list for a channel
MEMBER_ADD = "member_add"       # one person joined a channel
MEMBER_REMOVE = "member_remove" # one person left it (part, kick, quit)
MEMBER_UPDATE = "member_update" # one person's nick or prefix changed
EVENT = "event"                 # one live chat event
BACKLOG = "backlog"             # a page of history, oldest first
UNREAD = "unread"               # per-buffer unread + highlight counts
READ_MARKER = "read_marker"     # another device advanced the marker
OK = "ok"                       # a client request succeeded
ERROR = "error"                 # a client request failed
PONG = "pong"
IGNORES = "ignores"             # the block list for a network
SEARCH_RESULTS = "search_results"
UPLOADS = "uploads"            # a page of uploaded files, newest first
WHOIS = "whois"                 # one nick looked up, collected into one frame
SETTINGS = "settings"           # highlight words, push preview, auto away
MENTIONS = "mentions"           # a page of the mentions inbox, newest first
CHANNEL_LIST = "channel_list"   # the reply to `list`: channels on a network
BUFFER_REMOVED = "buffer_removed"  # a query merged into another on a nick change
BUFFER_CLEARED = "buffer_cleared"  # a buffer's history was deleted (clear_buffer)
LINK_PREVIEW = "link_preview"   # the reply to `link_preview`: one link's card
TYPING = "typing"               # someone is typing in a buffer, or stopped; never stored
TOKENS = "tokens"               # the reply to `tokens`: the devices that can attach
PAIR = "pair"                   # the reply to `pair`: a one-time code for a new device

# --- client -> server ------------------------------------------------------
C_BACKLOG = "backlog"           # request a page of history
C_SAY = "say"                   # send a line to a buffer
C_JOIN = "join"
C_PART = "part"
C_MARK_READ = "mark_read"
C_REGISTER_PUSH = "register_push"
C_UNREGISTER_PUSH = "unregister_push"   # sign-out: stop pushing to this device
C_PING = "ping"
C_MEMBERS = "members"           # request a member list refresh
C_BUFFERS = "buffers"           # re-send the buffer list (a client saw an unknown buffer)
C_NICK = "nick"                 # change nick on a network
C_TOPIC = "topic"               # set a channel topic
C_QUERY = "query"               # open (or find) a private query buffer
C_CLOSE = "close"               # archive a buffer; parts first if a channel
C_WHOIS = "whois"               # ask about a nick; answered with a `whois` frame
C_DETACH = "detach"             # mute a buffer without leaving it
C_ADD_NETWORK = "add_network"       # connect to an IRC network, from the client
C_REMOVE_NETWORK = "remove_network" # disconnect and forget one
C_EDIT_NETWORK = "edit_network"     # change a network's settings (nick, server, login...)
C_NETWORK_CONNECT = "network_connect"  # turn a network off, or connect it now
C_IGNORE = "ignore"                 # block or unblock someone
C_UPLOAD_URL = "upload_url"         # ask for a presigned PUT
C_DELETE_UPLOAD = "delete_upload"     # delete a file this bouncer uploaded, by its link
C_LIST_UPLOADS = "list_uploads"       # a page of the files this bouncer uploaded, newest first
C_SEARCH = "search"                 # full-text search over the backlog
C_CHANMODE = "chanmode"             # +o/-o, +v/-v, +b, +q on one person
C_KICK = "kick"                     # remove someone from a channel
C_AWAY = "away"                     # set or clear away status
C_INVITE = "invite"                 # invite a nick to a channel
C_NAMES = "names"                   # ask the server to refresh a channel's member list
C_BUFFER_SETTINGS = "buffer_settings"  # notify level and pin, per buffer
C_MARK_ALL_READ = "mark_all_read"   # every buffer (of one network) read to its newest
C_SET_SETTINGS = "set_settings"     # change highlight words, push preview, auto away
C_MENTIONS = "mentions"             # a page of every mention, across all buffers
C_RAW = "raw"                       # one IRC line as typed (/quote), within limits
C_LIST = "list"                     # the network's channel list (/list)
C_LINK_PREVIEW = "link_preview"     # fetch one link's title/description/image
C_EXPORT = "export"                 # a one-time download link for a buffer's history
C_CLEAR_BUFFER = "clear_buffer"     # delete a buffer's history
C_REGISTER_WEBPUSH = "register_webpush"      # a browser's push subscription
C_UNREGISTER_WEBPUSH = "unregister_webpush"  # ...and forgetting it
C_TYPING = "typing"                 # we are typing in a buffer, or stopped; no reply
C_TOKENS = "tokens"                 # list the access tokens (one per device)
C_REVOKE_TOKEN = "revoke_token"     # sign a device out: revoke its token
C_PAIR = "pair"                     # mint a one-time code a new device redeems at POST /pair


# Event kinds. These are the `kind` of a stored event and are what a client
# switches on to decide how to render a row.
KIND_MESSAGE = "message"        # PRIVMSG to a channel or query
KIND_ACTION = "action"          # CTCP ACTION, i.e. /me
KIND_NOTICE = "notice"
KIND_JOIN = "join"
KIND_PART = "part"
KIND_QUIT = "quit"
KIND_KICK = "kick"
KIND_NICK = "nick"
KIND_TOPIC = "topic"
KIND_MODE = "mode"
KIND_SERVER = "server"          # a server numeric / notice, lands in the status buffer
KIND_INVITE = "invite"          # someone invited you to a channel; status buffer


def frame(type_: str, **fields: Any) -> dict[str, Any]:
    return {"type": type_, **fields}


def dumps(obj: dict[str, Any]) -> str:
    # Compact separators because these frames go to a phone on a cell connection,
    # and there can be a few hundred of them in one backlog fetch.
    return json.dumps(obj, separators=(",", ":"))
