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

# 收尾预算：网关自己在 SIGTERM 后最多等 CODEARTS_SHUTDOWN_GRACE 秒（默认
# 25）。脚本必须等得比它久，否则「pkill 后 sleep 1 就启动」会撞上还在收尾
# 的旧进程 —— 端口还被占着，新进程绑定失败、直接退出，看起来就是「重启把
# 服务弄挂了」。
GRACE="${CODEARTS_SHUTDOWN_GRACE:-25}"
case "$GRACE" in
  ''|*[!0-9]*) GRACE=25 ;;
esac
WAIT=$((GRACE + 5))

echo "Stopping other ca_proxy instances ..."
PIDS=$(pgrep -f "python.*ca_proxy\.py" 2>/dev/null || true)
if [ -n "$PIDS" ]; then
  # SIGTERM 起手：网关会停止接新请求、把在跑的请求收尾（写账、发 idle），
  # 然后自己退出。SIGKILL 起手就没有这段收尾，账目和上游会话都会丢。
  kill -TERM $PIDS 2>/dev/null || true
  i=0
  while [ "$i" -lt "$WAIT" ]; do
    LEFT=$(pgrep -f "python.*ca_proxy\.py" 2>/dev/null || true)
    [ -z "$LEFT" ] && break
    sleep 1
    i=$((i + 1))
  done
  LEFT=$(pgrep -f "python.*ca_proxy\.py" 2>/dev/null || true)
  if [ -n "$LEFT" ]; then
    echo "  [WARN] still alive after ${WAIT}s, sending SIGKILL: $LEFT"
    kill -KILL $LEFT 2>/dev/null || true
    sleep 1
  fi
fi
if pgrep -f "python.*ca_proxy\.py" >/dev/null 2>&1; then
  echo "  [WARN] some ca_proxy processes are still alive;"
  echo "         they may still hold the port."
else
  echo "  all ca_proxy instances stopped."
fi

echo "Starting LAN mode ..."
exec "$HERE/start-codearts-hub-lan.sh" "$@"
