#!/bin/sh
# ===========================================================
#  CodeArts Hub proxy - restart (LAN mode)
#
#  Stops every ca_proxy.py instance on this machine (from any
#  folder - that is what would otherwise refuse to start the
#  new copy with "already running"), then launches
#  start-codearts-hub-lan.sh so phones / other PCs can connect.
#
#  Usage: ./restart-codearts-hub.sh [port] [api-key]
#         (both optional, forwarded to the LAN launcher)
# ===========================================================

set -u

HERE=$(cd "$(dirname "$0")" && pwd)

echo "Stopping other ca_proxy instances ..."
pkill -f "python.*ca_proxy\.py" 2>/dev/null || true
sleep 1
if pgrep -f "python.*ca_proxy\.py" >/dev/null 2>&1; then
  echo "  [WARN] some ca_proxy processes are still alive;"
  echo "         they may still hold the port."
else
  echo "  all ca_proxy instances stopped."
fi

echo "Starting LAN mode ..."
exec "$HERE/start-codearts-hub-lan.sh" "$@"
