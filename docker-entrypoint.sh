#!/bin/sh
# Runs as root so a fresh bind-mounted ./data (owned by the host user) can be
# fixed up to match the fixed container uid, then drops to that uid before
# exec'ing the app. The app itself never runs as root.
set -e

chown -R kyrecovery:kyrecovery /app/data

exec su-exec kyrecovery /app/kyrecovery "$@"
