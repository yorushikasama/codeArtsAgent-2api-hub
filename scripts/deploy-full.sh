#!/usr/bin/env bash
# 全量同步部署：服务器目录 = 仓库当前提交的完整快照 + 旧目录里的运行时数据。
#
# 为什么必须全量（2026-10-25 教训）：增量 scp 只挑改过的文件，服务器很快漂移
# ——旧测试 + 新代码跑出 9 个假失败，排查半小时。本脚本每次都从 git 克隆
# 完整快照，不存在「哪个文件忘了传」；运行时数据按白名单从旧目录搬过来，
# 白名单之外的一切以仓库为准。
#
# 用法（在仓库根目录）：
#   scripts/deploy-full.sh
# 参数可用环境变量覆盖：WB_DEPLOY_DEST / WB_DEPLOY_KEY / WB_DEPLOY_DIR
#   / WB_DEPLOY_REPO / WB_DEPLOY_BRANCH
#
# 保留在服务器上的运行时数据（搬运白名单，改这里）：
#   accounts/ usage/ logs/ catalog/ _archive*/ quick-deploy.sh release/
#   restart-codearts-hub.* start-codearts-hub-lan.bat find_err.js
set -euo pipefail

DEST="${WB_DEPLOY_DEST:-ubuntu@155.248.163.15}"
KEY="${WB_DEPLOY_KEY:-$HOME/.ssh/ti.key}"
DIR="${WB_DEPLOY_DIR:-\$HOME/codearts-hub}"
REPO_URL="${WB_DEPLOY_REPO:-https://github.com/yorushikasama/codeArtsAgent-2api-hub.git}"
BRANCH="${WB_DEPLOY_BRANCH:-main}"

LOCAL_REV=$(git rev-parse --short HEAD)
echo "deploy-full: local HEAD = $LOCAL_REV, dest = $DEST"

ssh -i "$KEY" -o BatchMode=yes "$DEST" bash -s -- "$REPO_URL" "$BRANCH" "$DIR" <<'REMOTE'
set -euo pipefail
REPO_URL="$1"; BRANCH="$2"; DIR="$(eval echo "$3")"
STAMP=$(date +%Y%m%d-%H%M%S)
NEW="$DIR.new-$STAMP"
OLD="$DIR.old-$STAMP"

git clone -q --depth 1 -b "$BRANCH" "$REPO_URL" "$NEW"

# 运行时数据白名单搬运：只有这些从旧目录过来，其余一律以仓库为准。
if [ -d "$DIR" ]; then
  KEEP=""
  for item in accounts usage logs catalog quick-deploy.sh release \
              restart-codearts-hub.bat restart-codearts-hub.command \
              restart-codearts-hub.sh start-codearts-hub-lan.bat find_err.js; do
    [ -e "$DIR/$item" ] && KEEP="$KEEP $item"
  done
  for item in "$DIR"/_archive-*; do
    [ -e "$item" ] && KEEP="$KEEP $(basename "$item")"
  done
  if [ -n "${KEEP// /}" ]; then
    (cd "$DIR" && tar cf - $KEEP) | tar xf - -C "$NEW"
  fi
fi

# 部署前测试闸门：新克隆先在服务器上跑完全部套件，绿了才碰在跑的服务。
# 挂了就删掉新目录退出 —— 旧目录与在跑的网关毫发无损；这套 103 个套件
# 全程离线（~40s），应急可用 WB_DEPLOY_SKIP_TESTS=1 旁路（写明原因再绕）。
if [ "${WB_DEPLOY_SKIP_TESTS:-0}" != "1" ]; then
  echo "deploy-full: test gate — running the suite in the fresh clone..."
  GATE_LOG="$NEW/deploy-gate.log"
  if ! (cd "$NEW" && python3 tests/run_all.py 2>&1 | tee "$GATE_LOG"); then
    echo "deploy-full: TEST GATE FAILED in $NEW — nothing was touched," >&2
    echo "  the running service keeps the old revision. Fix, push, redeploy." >&2
    echo "  failing suites:" >&2
    grep "^  failed:" "$GATE_LOG" >&2 || tail -40 "$GATE_LOG" >&2
    rm -rf "$NEW"
    exit 1
  fi
  rm -f "$GATE_LOG"
fi

sudo systemctl stop codearts-hub || true
[ -d "$DIR" ] && mv "$DIR" "$OLD"
mv "$NEW" "$DIR"
sudo systemctl start codearts-hub
sleep 4
systemctl is-active codearts-hub
curl -fsS -m 5 localhost:9000/health && echo

# 回滚保险：保留最近 3 份旧目录；再旧的清掉。
ls -dt "$DIR".old-* 2>/dev/null | tail -n +4 | xargs -r rm -rf
echo "DEPLOYED $(git -C "$DIR" rev-parse --short HEAD) ($BRANCH)"
REMOTE
