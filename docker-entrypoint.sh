#!/bin/sh
# Start as root just long enough to make /data writable, then run the scan
# as the unprivileged `subsonar` user. A bind-mounted volume is often owned
# by root, which that user would otherwise not be allowed to write.
set -eu

if [ "$(id -u)" = 0 ]; then
  mkdir -p /data/output /data/.subsonar_cache
  if ! chown -R subsonar:subsonar /data 2>/dev/null; then
    chmod -R a+rwX /data
  fi
  exec runuser -u subsonar -- subsonar "$@"
fi

exec subsonar "$@"
