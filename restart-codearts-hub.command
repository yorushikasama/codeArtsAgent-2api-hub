#!/bin/bash
# ===========================================================
#  Double-clickable macOS wrapper for restart-codearts-hub.sh
#
#  Stops every ca_proxy.py instance on this machine, then
#  starts the proxy in LAN mode (reachable from phones and
#  other computers on the same network).
#
#  Right-click > Open the first time if Gatekeeper asks.
#  If double-clicking does nothing:
#      chmod +x restart-codearts-hub.command restart-codearts-hub.sh
# ===========================================================

set -u

cd "$(dirname "$0")" || exit 1
exec ./restart-codearts-hub.sh "$@"
