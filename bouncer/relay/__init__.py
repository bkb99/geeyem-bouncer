"""Geyem — an always-on IRC bouncer with a websocket gateway for thin clients.

The process holds the IRC connections. Clients (iOS, macOS, web) hold nothing but
a view of what this process tells them, so closing a client — or being killed by
iOS in the background — never drops a connection or loses a line.
"""

__version__ = "0.1.0"

# The product name, for anything the server says out loud: the `hello` frame's
# `server` field, and the CLI. THE PYTHON SIDE'S SPELLING IS THIS LINE.
#
# The package stays `relay` on purpose. It is a code identifier -- an import
# path, a systemd unit, a directory on the VPS -- and renaming the product
# should not mean rewriting every import and redeploying under a new name.
# See "Renaming" in README.md for the other surfaces' constants.
APP_NAME = "geeyem"
