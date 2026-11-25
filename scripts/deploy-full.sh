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
#   accounts/ usage/ logs/ _archive*/ quick-deploy.sh release/
#   restart-codearts-hub.* start-codearts-hub-lan.bat
#
# catalog/ 2026-11-03 起不再搬运：那是 WorkBuddy 时代 /v3/config 响应的落盘
# 副本，仓库里的代码从来没有读过它（README 原文就写「Nothing reads it back」）。
# 服务器上残留的旧目录会被留在上一个 .old-* 目录里，不影响运行。
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
  for item in accounts usage logs quick-deploy.sh release \
              restart-codearts-hub.bat restart-codearts-hub.command \
              restart-codearts-hub.sh start-codearts-hub-lan.bat; do
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

# systemd 单元以仓库为准（deploy/ 目录）：与服务器上的不一致就装上去并
# daemon-reload —— 内存护栏这类配置不能靠手工 remember 改。
#
# 路径必须走 $NEW：这段 remote 脚本跑在 ssh 的 `bash -s` 里，cwd 是登录目录
# 而不是刚 clone 出来的新副本。第一版写成相对路径 deploy/…，[ -f ] 找不到
# 文件就静默跳过，于是「同步成功」却 MemoryMax=infinity —— 护栏没生效而
# 部署看起来是绿的。部署脚本里任何「找不到就跳过」的分支都要喊出来。
UNIT_SRC="$NEW/deploy/codearts-hub.service"
UNIT_DST=/etc/systemd/system/codearts-hub.service
if [ -f "$UNIT_SRC" ]; then
  if ! sudo cmp -s "$UNIT_SRC" "$UNIT_DST"; then
    echo "deploy-full: systemd unit differs — installing $(dirname "$UNIT_SRC")/codearts-hub.service"
    sudo cp "$UNIT_SRC" "$UNIT_DST"
    sudo systemctl daemon-reload
    echo "deploy-full: unit installed + daemon-reload done"
  else
    echo "deploy-full: systemd unit already up to date"
  fi
else
  echo "deploy-full: WARNING no deploy/codearts-hub.service in $NEW — unit NOT synced" >&2
fi

sudo systemctl stop codearts-hub || true

# 等旧进程**真正退出**再搬账号文件。`systemctl stop` 返回时服务已停，但
# SIGTERM 收尾（等在跑的请求 drain，TimeoutStopSec=45）里如果正好有一次
# 续期在飞，它会把新 token 写盘 —— 那必须被下面这次同步看到。巡检线程自己
# 会看 shutting_down() 不再发新续期，所以只剩「已在飞的那一次」要等。
for _ in $(seq 1 20); do
  systemctl is-active --quiet codearts-hub || break
  sleep 1
done

# **停掉旧进程之后必须再同步一次 accounts**（2026-11-25 线上事故）。
#
# 为什么：refresh_token 是**一次性轮换**的，每次续期换一张、旧的当场作废
# （ca_codearts.refresh_session）。上面的白名单搬运发生在跑测试闸门**之前**，
# 闸门要 2-4 分钟；这段窗口里 STS 巡检（tick 30s，到期前 300s 就续）极可能
# 续一次，结果写进**旧目录**。旧进程一停，新进程拿的是闸门开始前那份 token，
# 而它在上游已经作废了 —— 于是每个请求都 503「no usable codearts account」，
# 手动续期报 STS5.1806，只能重新登录。
#
# 2026-11-25 100% 复现：accounts 复制于 10:52，10:55:04 旧进程续了一次期，
# 新进程 10:56:03 起来后立刻 1806，直到 11:00 用户手动重登录才恢复。
#
# 只重搬 accounts：logs/usage 此时也已完整落盘，但没必要整包重搬（慢，且
# 新进程马上要往里追加）。cp -a 保留 mtime，面板的「快照年龄」才不会错。
#
# **源必须是 $DIR（旧目录还在原位）**：$OLD 只是「待会儿要改成什么名字」的
# 路径变量，`mv $DIR $OLD` 在下面几行才执行。第一版写成 $OLD/accounts，
# `[ -d ]` 在那时为假 → 整个分支被静默跳过，修复看起来部署了其实没跑。
if [ -d "$DIR/accounts" ]; then
  rm -rf "$NEW/accounts"
  cp -a "$DIR/accounts" "$NEW/accounts"
  echo "deploy-full: accounts re-synced after stop (picks up the last STS renewal)"
else
  echo "deploy-full: WARNING no $DIR/accounts — accounts NOT re-synced after stop" >&2
fi

[ -d "$DIR" ] && mv "$DIR" "$OLD"
mv "$NEW" "$DIR"
sudo systemctl start codearts-hub
sleep 4
systemctl is-active codearts-hub
curl -fsS -m 5 localhost:9000/health && echo
# 内存护栏必须真的在位（MemoryMax 是硬闸）：上去了但没有生效就明说，别静默。
if command -v systemctl-show >/dev/null 2>&1 || true; then
  MM=$(systemctl show codearts-hub -p MemoryMax --value 2>/dev/null || echo "?")
  echo "deploy-full: MemoryMax=${MM} (expect 384M; infinity means the guard did not load)"
fi

# 回滚保险：保留最近 3 份旧目录；再旧的清掉。
ls -dt "$DIR".old-* 2>/dev/null | tail -n +4 | xargs -r rm -rf
echo "DEPLOYED $(git -C "$DIR" rev-parse --short HEAD) ($BRANCH)"
REMOTE
