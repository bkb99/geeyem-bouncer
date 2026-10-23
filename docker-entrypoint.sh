#!/bin/sh
# Give the bouncer's user its volume, then run as that user.
#
# A hosting platform's volume (Fly.io, Railway, Render) is mounted owned by
# root, over the /data the image made, so the unprivileged user could not
# write its database there. As root, take ownership of /data and drop to uid
# 10001 for good; as anyone else (a `user:` in compose, a cluster that will
# not run root), just run.
set -eu
if [ "$(id -u)" = "0" ]; then
  # Only when it is not already the bouncer's: root here has no
  # CAP_FOWNER, so it may change a directory it owns, not one it gave away.
  if [ "$(stat -c %u /data)" != "$(id -u geeyem)" ]; then
    chmod 700 /data
    chown geeyem:geeyem /data
  fi
  exec setpriv --reuid=geeyem --regid=geeyem --init-groups -- "$@"
fi
exec "$@"
