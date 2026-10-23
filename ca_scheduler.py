"""ca_scheduler.py —— 后台定时调度器 (Scheduler)

WorkBuddy 账号池移除后（2026-10-23），这里只剩一件事：

码道每日领取 (Daily Token Claim)：为 accounts/codearts/ 下的每个华为云会话
领取当日推理额度（opengw benefit，不是活动页的「每日签到」积分），每日两次。

Token 保活、对话活跃上报、猫猫旅行与连登结算原本都是给 WorkBuddy 账号做的，
随账号池一起删除（那些调用点只存在于已删掉的 `ca_accounts.Account` 上）。
"""
import threading
import time
import ca_codearts


class Scheduler:
    def __init__(self):
        # 对齐 Sliverkiss/codearts2api 官方默认排程 (CST 24小时制)
        self.checkin_hours = [9, 21]     # 每日 09:00、21:00 领取当日额度
        self.accounts_dir = None         # 领取要走码道会话目录，由网关注入
        self.all_hours = sorted(set(self.checkin_hours))
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

    def log(self, msg, tag=None):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{ts}] {msg}"
        self.logs.append(entry)
        if len(self.logs) > 60:
            self.logs = self.logs[-60:]
        try:
            import ca_proxy
            ca_proxy.add_log_entry(f"[调度器] {msg}", tag=tag or "scheduler")
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
                    time.sleep(65)  # 避开当前这一分钟重复触发
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
            t_struct = time.struct_time(
                (now.tm_year, now.tm_mon, now.tm_mday, next_h, 0, 0, 0, 0, -1))
        else:
            # 明天第一个小时
            t_tomorrow = time.time() + 86400
            now_tom = time.localtime(t_tomorrow)
            first_h = self.all_hours[0]
            t_struct = time.struct_time(
                (now_tom.tm_year, now_tom.tm_mon, now_tom.tm_mday,
                 first_h, 0, 0, 0, 0, -1))
        self.next_run_time = time.strftime("%Y-%m-%d %H:%M:%S", t_struct)

    def trigger_now(self):
        """手动立即触发一次调度检查。"""
        if self._run_lock.locked():
            return {"ok": False, "msg": "已有巡检正在执行，请稍候再试"}
        threading.Thread(target=self._execute_cycle, args=("手动立即触发",),
                         daemon=True).start()
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
        """为每个码道会话领取当日推理额度（token 额度，不是积分签到）。

        会话存在 accounts/codearts/，不走 /v1 调度，所以这里自己读目录、自己
        记账。领取接口幂等，额度已满时会被识别成跳过而不是一次成功的假领取
        —— 每天固定两次正好覆盖「早上领了、晚上用完了再补一次」。
        """
        if not self.accounts_dir:
            return {"ok": False, "skipped": 0, "claimed": 0, "failed": 0,
                    "error": "scheduler has no accounts directory"}
        sessions = ca_codearts.load_sessions(self.accounts_dir)
        if not sessions:
            return {"ok": True, "skipped": 0, "claimed": 0, "failed": 0,
                    "logs": []}
        claimed = skipped = failed = 0
        logs = []
        for sess in sessions:
            acct = sess.get("account") or {}
            label = acct.get("label") or acct.get("id") or "码道账号"
            # STS 只有约 2 小时寿命，而调度是 09:00 / 21:00 各跑一次：不先在
            # 这里续期，闲置两小时后领取永远是 401，日志里天天「领取失败」。
            try:
                sess = ca_codearts.ensure_fresh_session(self.accounts_dir, sess)
                acct = sess.get("account") or acct
                label = acct.get("label") or acct.get("id") or label
            except Exception as exc:  # noqa: BLE001
                logs.append("! %s STS 续期失败: %s" % (label, exc))
            key = (sess.get("accessKey"), sess.get("secretKey"),
                   sess.get("securitytoken"))
            if not all(key):
                failed += 1
                logs.append("! %s 缺少 AK/SK 或令牌，已跳过（需重新登录）" % label)
                continue
            try:
                res = ca_codearts.claim_and_verify(*key, session=sess,
                                                   trigger="scheduler")
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
        claim = self.claim_daily_tokens()
        for line in claim.get("logs") or []:
            self.log(f"🎁 码道 {line}")
        self.log("巡检完成：码道领取 %d 个（跳过 %d · 失败 %d）"
                 % (claim.get("claimed", 0), claim.get("skipped", 0),
                    claim.get("failed", 0)))

    def status(self):
        return {
            "enabled": self.enabled,
            "mode": "整点排程 (09:00/21:00 码道领取)",
            "mode_cn": "整点排程 (09:00/21:00 码道领取)",
            "last_run_time": self.last_run_time or "尚未运行",
            "next_run_time": self.next_run_time or "待调度",
            "logs": self.logs[-20:],
        }
