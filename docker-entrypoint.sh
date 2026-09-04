#!/bin/sh
# Starts as root only to fix ownership of a bind-mounted ./data supplied by the
# host user, then drops to the app uid. The app never runs as root. When the
# container is already unprivileged (--user, runAsNonRoot) go straight to it.
set -e

if [ "$(id -u)" = 0 ]; then
    chown -Rh kyrecovery:kyrecovery /app/data || \
        echo "data dir not chownable; continuing" >&2
    exec su-exec kyrecovery /app/kyrecovery "$@"
fi

exec /app/kyrecovery "$@"
