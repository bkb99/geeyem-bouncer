# The geeyem bouncer as a container. Build from the repository root:
#
#   docker build -t geeyem-bouncer .
#
# Everything it keeps -- the SQLite database and, if you add one, config.json
# -- lives in /data, which is a volume: replace the container and the history
# stays. It runs as an unprivileged user (uid 10001). It starts as root only
# for as long as it takes to give that user the volume, because the volumes
# Fly.io, Railway and Render mount are owned by root; see docker-entrypoint.sh.
#
# See docs/SELF-HOSTING.md (geeyem) or README.md (geeyem-bouncer).

FROM python:3.13-slim AS build
COPY bouncer/requirements.txt /tmp/requirements.txt
RUN python -m venv /venv \
 && /venv/bin/pip install --no-cache-dir --upgrade pip \
 && /venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt \
 && /venv/bin/pip uninstall --yes --quiet pip

FROM python:3.13-slim
ENV PATH=/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RELAY_LISTEN_HOST=0.0.0.0 \
    RELAY_LISTEN_PORT=8765 \
    RELAY_CONFIG=/data/config.json \
    RELAY_DB=/data/relay.db
RUN useradd --system --uid 10001 --user-group --home-dir /data --no-create-home geeyem \
 && mkdir /data && chown geeyem:geeyem /data && chmod 700 /data
COPY --from=build /venv /venv
# relay/ beside web/, the layout the gateway looks for (Gateway.__init__).
COPY bouncer/relay /app/relay
COPY web/index.html web/sw.js web/*.png web/*.woff2 /app/web/
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
WORKDIR /app
VOLUME /data
EXPOSE 8765
# The anonymous /health: up, and whether IRC is. Never with a token.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('RELAY_LISTEN_PORT', '8765'), timeout=4)"]
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["python", "-m", "relay", "run"]
