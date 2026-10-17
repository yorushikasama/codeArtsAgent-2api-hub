"""wb_scheduler.py —— 后台定时调度器 (Scheduler)

负责常驻后台自动执行：
1. Token 保活 (Keepalive)：定期检查 Token 剩余寿命，不足 2 小时自动调用 Refresh Token。
2. 码道每日领取 (Daily Token Claim)：为 accounts/codearts/ 下的每个华为云会话
   领取当日推理额度（码道侧的「签到」），每日两次。
3. 对话活跃上报 (Activity Report)：每日定时为国内版账号上报轻量会话事件，点亮连登与热力墙。
4. 猫猫旅行与日常结算 (Cat Travel & Welfare)：自动派出猫猫旅行或领取归来奖励。
5. 状态持久化与看板展示：暴露状态、执行记录、支持手动立即触发与开关切换。
"""
import threading
import time
import wb_codearts
import wb_tasks
from wb_tasks import do_cat_travel


class Scheduler:
    def __init__(self, pool):
        self.pool = pool
        # 对齐 Sliverkiss/workbuddy2api 官方默认排程 (CST 24小时制)
        self.checkin_hours = [9, 21]     # 每日 09:00、21:00 领取当日额度
        self.travel_hours = [9, 21]      # 每日 09:00 派出、21:00 领奖闭环
        self.keepalive_hours = [22]      # 每日 22:00 集中 Token 保活检查
        self.cat_hours = [1]             # 每日 01:00 夜猫子专属任务
        self.accounts_dir = None         # 领取要走码道会话目录，由网关注入
        self.all_hours = sorted(list(set(self.checkin_hours + self.travel_hours + self.keepalive_hours + self.cat_hours)))
        self.enabled = True
        self._stop_event = threading.Event()
        self._thread = None
        self.last_run_time = None
        self.next_run_time = None
        self.logs = []
        # Guards against overlapping runs: trigger_now() spawns a thread per
        # click, and a manual trigger can also land on top of the hourly job.
        self._run_lock = threading.Lock()
        self._calc_next_fire()
        # Surface task-level failures (dead endpoints, upstream shape changes)
        # in the same log the panel shows.
        wb_tasks.set_logger(self.log)

    def log(self, msg, tag=None):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{ts}] {msg}"
        self.logs.append(entry)
        if len(self.logs) > 60:
            self.logs = self.logs[-60:]
        try:
            import wb_proxy
            # 任务/打卡/旅行类条目同时进入 tasks 模块日志，方便分类查看
            effective_tag = tag
            if not effective_tag:
                lower = str(msg).lower()
                if any(k in lower for k in ("签到", "打卡", "活跃", "猫猫", "连登", "夜猫", "抽奖", "兑换")):
                    effective_tag = "tasks"
                else:
                    effective_tag = "scheduler"
            wb_proxy.add_log_entry(f"[调度器] {msg}", tag=effective_tag)
        except Exception:
            pass

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self.log("后台定时调度器已启动")

    def stop(self):
        self._stop_event.set()
        self.log("后台定时调度器已暂停")

    def _run_loop(self):
        # 启动后先休眠 10 秒等待主服务就绪，然后执行初次检查
        time.sleep(10)
        try:
            self._execute_cycle("启动初次初始化巡检")
        except Exception as exc:
            self.log(f"初次巡检异常: {exc}")

        while not self._stop_event.is_set():
            self._calc_next_fire()
            # 每 30 秒检查一次当前整点
            now = time.localtime()
            cur_hour = now.tm_hour
            cur_min = now.tm_min
            if self.enabled:
                # 到达设定的整点前 1 分钟内触发
                if cur_min == 0 and cur_hour in self.all_hours:
                    reason = f"整点排程命中 ({cur_hour}:00)"
                    try:
                        self._execute_cycle(reason)
                    except Exception as exc:
                        self.log(f"排程执行异常: {exc}")
                    time.sleep(65) # 避开当前这一分钟重复触发
            self._stop_event.wait(30)

    def _calc_next_fire(self):
        now = time.localtime()
        cur_h = now.tm_hour
        next_h = None
        for h in self.all_hours:
            if h > cur_h or (h == cur_h and now.tm_min == 0 and now.tm_sec < 10):
                next_h = h
                break
        if next_h is not None:
            # 今天
            t_struct = time.struct_time((now.tm_year, now.tm_mon, now.tm_mday, next_h, 0, 0, 0, 0, -1))
        else:
            # 明天第一个小时
            t_tomorrow = time.time() + 86400
            now_tom = time.localtime(t_tomorrow)
            first_h = self.all_hours[0]
            t_struct = time.struct_time((now_tom.tm_year, now_tom.tm_mon, now_tom.tm_mday, first_h, 0, 0, 0, 0, -1))
        self.next_run_time = time.strftime("%Y-%m-%d %H:%M:%S", t_struct)

    def trigger_now(self):
        """手动立即触发一次调度检查。"""
        if self._run_lock.locked():
            return {"ok": False, "msg": "已有巡检正在执行，请稍候再试"}
        threading.Thread(target=self._execute_cycle, args=("手动立即触发",), daemon=True).start()
        return {"ok": True, "msg": "已触发后台调度执行"}

    def _execute_cycle(self, trigger_reason="周期巡检"):
        if not self._run_lock.acquire(blocking=False):
            self.log(f"跳过本次巡检 ({trigger_reason})：上一轮仍在执行")
            return
        try:
            self._run_cycle(trigger_reason)
        finally:
            self._run_lock.release()

    def claim_daily_tokens(self):
        """为每个码道会话领取当日推理额度（码道侧的「签到」）。

        与账号池完全独立：会话存在 accounts/codearts/，不走 /v1 调度，所以这里
        自己读目录、自己记账。领取接口幂等，额度已满时会被识别成跳过而不是一次
        成功的假领取 —— 每天固定两次正好覆盖「早上领了、晚上用完了再补一次」。
        """
        if not self.accounts_dir:
            return {"ok": False, "skipped": 0, "claimed": 0, "failed": 0,
                    "error": "scheduler has no accounts directory"}
        sessions = wb_codearts.load_sessions(self.accounts_dir)
        if not sessions:
            return {"ok": True, "skipped": 0, "claimed": 0, "failed": 0,
                    "logs": []}
        claimed = skipped = failed = 0
        logs = []
        for sess in sessions:
            acct = sess.get("account") or {}
            label = acct.get("label") or acct.get("id") or "码道账号"
            key = (sess.get("accessKey"), sess.get("secretKey"),
                   sess.get("securitytoken"))
            if not all(key):
                failed += 1
                logs.append("! %s 缺少 AK/SK 或令牌，已跳过（需重新登录）" % label)
                continue
            try:
                res = wb_codearts.claim_and_verify(*key, session=sess, trigger="scheduler")
            except Exception as exc:
                failed += 1
                logs.append("! %s 领取失败: %s" % (label, exc))
                continue
            if res.get("skipped"):
                skipped += 1
                logs.append("· %s %s" % (label, res.get("msg")))
            else:
                claimed += 1
                logs.append("✓ %s %s" % (label, res.get("msg")))
            time.sleep(0.5)
        return {"ok": True, "claimed": claimed, "skipped": skipped,
                "failed": failed, "logs": logs}

    def _run_cycle(self, trigger_reason="周期巡检"):
        self.last_run_time = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log(f"开始执行任务 ({trigger_reason})...")

        # 码道领取放在账号池之外：账号池空了也不该跳过它，那意味着用户只在用
        # 码道账号、没配 WorkBuddy 账号，此时领取恰恰是唯一该做的事。
        claim = self.claim_daily_tokens()
        for line in claim.get("logs") or []:
            self.log(f"🎁 码道 {line}")

        if not self.pool or not self.pool.accounts:
            self.log("暂无可用的活跃账号，跳过本次巡检")
            return

        refreshed_count = 0
        report_count = 0
        travel_count = 0

        for acc in list(self.pool.accounts):
            uid8 = acc.uid[:8] if acc.uid else "?"
            # 1. 检查 Token 剩余寿命 (小于 2 小时自动刷新保活)
            exp = acc.expires_at or 0
            if exp and (exp - time.time()) < 7200:
                self.log(f"账号 [{uid8}] Token 即将到期，执行主动保活刷新...")
                if acc.refresh():
                    refreshed_count += 1
                    self.log(f"✓ 账号 [{uid8}] Token 自动保活刷新成功")
                else:
                    self.log(f"! 账号 [{uid8}] Token 保活刷新失败: {acc.last_error}")

            # 2. 如果是国内版账号，检查猫猫旅行与连登
            if acc.realm == "cn":
                if acc.can_report_activity():
                    self.log(f"检测到国内版账号 [{uid8}] 今日尚未活跃上报，执行对话活跃上报...")
                    res = acc.report_activity()
                    if res.get("ok"):
                        report_count += 1
                        self.log(f"✓ 账号 [{uid8}] {res.get('msg')}")
                    else:
                        self.log(f"! 账号 [{uid8}] 对话活跃上报失败: {res.get('error') or res.get('msg')}")
                    time.sleep(1.0)

                # 检查猫猫旅行
                tr = do_cat_travel(acc)
                if tr.get("action") in ("claim", "depart"):
                    travel_count += 1
                    self.log(f"🐱 账号 [{uid8}] 猫猫日常处理: {tr.get('msg')}")
                time.sleep(1.0)

                # 连登管家闭环（补签保连登 -> 礼包/补偿 -> 连登兑换 -> 自动抽奖）
                bonus = wb_tasks.run_streak_bonus(acc)
                if bonus.get("logs"):
                    for l in bonus["logs"]:
                        self.log(f"★ 账号 [{uid8}] {l}")
                    time.sleep(1.0)

                # 01:00 夜猫子专属任务: black_cat 只在 23:00-08:00 上报计数,
                # 之前这个整点只是空转通用巡检, 从未真正上报过夜猫事件。
                if time.localtime().tm_hour in self.cat_hours:
                    night = wb_tasks.run_night_growth(acc)
                    for line in night.get("logs", []):
                        self.log(f"🌙 {line}")
                    time.sleep(1.0)


        self.log(f"巡检完成：Token保活 {refreshed_count} 个，码道领取 {claim.get('claimed', 0)} 个（跳过 {claim.get('skipped', 0)} · 失败 {claim.get('failed', 0)}），活跃上报 {report_count} 个，猫猫日常 {travel_count} 个")

    def status(self):
        return {
            "enabled": self.enabled,
            "mode": "整点排程 (09:00/21:00 码道领取 · 旅行 · 每日活跃上报 · 22:00 保活 · 01:00 夜猫)",
            "mode_cn": "整点排程 (09:00/21:00 码道领取 · 旅行 · 每日活跃上报 · 22:00 保活 · 01:00 夜猫)",
            "last_run_time": self.last_run_time or "尚未运行",
            "next_run_time": self.next_run_time or "待调度",
            "logs": self.logs[-20:],
        }
