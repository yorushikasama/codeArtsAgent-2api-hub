"""DOM-level mobile layout checks for dashboard.html.

Synthetic fixtures only (fake accounts, fake usage): never touches real
credentials. Starts the gateway on 127.0.0.1:18789 and drives it with
Playwright/Firefox at phone and desktop widths.

Usage:
    python3 _mobile_check.py            # run every check
    python3 _mobile_check.py account    # only checks whose name contains "account"

Screenshots are written to /tmp/mobile-shots for human review; the checks
themselves assert DOM properties (the reviewer model cannot see images).
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import time

FIX = "/tmp/mobile-fixtures"
SHOTS = "/tmp/mobile-shots"
PASSWORD = "testpass123"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the gateway lives one level up

PASS = FAIL = 0
PORT = 0
BASE = ""


def free_port():
    """Pick a free loopback port so we never collide with another service."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] %s" % name)
    else:
        FAIL += 1
        print("  [FAIL] %s  %s" % (name, extra))


def build_fixtures():
    if os.path.isdir(FIX):
        shutil.rmtree(FIX)
    acc = os.path.join(FIX, "accounts")
    use = os.path.join(FIX, "usage")
    os.makedirs(acc)
    os.makedirs(use)

    def account(uid, nick, realm, enabled=True, cooldown=0, err=""):
        return {
            "uid": uid,
            "nickname": nick,
            "domain": "www.workbuddy.ai" if realm == "intl" else "www.codebuddy.cn",
            "realm": realm,
            "platform": "CLI",
            "enterpriseId": "",
            "accessToken": "",
            "refreshToken": "",
            "expiresAt": int(time.time()) + 86400 * 30,
            "addedAt": time.time() - 3600,
            "source": "oauth",
            "enabled": enabled,
            "lastError": err,
            "cooldownUntil": cooldown,
            "credits": {"remain": 42, "used": 8, "size": 50, "packages": []},
            "lastActivityReport": None,
        }

    accounts = [
        account("11111111-1111-1111-1111-111111111111", "test-user-a", "intl"),
        account(
            "22222222-2222-2222-2222-222222222222",
            "test-user-b",
            "intl",
            enabled=False,
            err="HTTP 403",
        ),
        account("33333333-3333-3333-3333-333333333333", "test-user-cn", "cn"),
        account(
            "44444444-4444-4444-4444-444444444444",
            "test-user-d",
            "intl",
            cooldown=time.time() + 45,
            err="HTTP 429",
        ),
    ]
    for a in accounts:
        with open(os.path.join(acc, a["uid"] + ".json"), "w", encoding="utf-8") as fh:
            json.dump(a, fh, ensure_ascii=False, indent=2)

    with open(os.path.join(acc, "settings.json"), "w", encoding="utf-8") as fh:
        json.dump({}, fh, ensure_ascii=False, indent=2)

    now = time.time()
    with open(os.path.join(use, "usage.jsonl"), "w", encoding="utf-8") as fh:
        for i in range(40):
            ts = now - (40 - i) * 60
            row = {
                "at": ts,
                "iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts)),
                "model": "deepseek-v4.1-flash" if i % 3 else "glm-5.3",
                "stream": i % 2 == 0,
                "elapsed_ms": 4200 + i * 30,
                "ttft_ms": 1500 + i * 20,
                "gen_ms": 800,
                "prompt_tokens": 12000 + i * 50,
                "completion_tokens": 200 + i,
                "reasoning_tokens": i % 5,
                "cached_tokens": 9000 + i * 40,
                "total_tokens": 12200 + i * 51,
                "credit": 0,
                "cache_hit_pct": 75,
                "tokens_per_sec": 42.5,
                "account": "11111111-1111-1111-1111-111111111111"
                if i % 2
                else "33333333-3333-3333-3333-333333333333",
                "realm": "intl" if i % 2 else "cn",
            }
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def set_password():
    # Reuse the project's own hashing so the fixture matches production format.
    sys.path.insert(0, ROOT)
    import ca_settings

    ca_settings.set_panel_password(os.path.join(FIX, "accounts"), PASSWORD)


def wait_port(timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def wait_identity(timeout=20):
    """Wait until the port answers like our gateway, not some other service."""
    import urllib.request

    end = time.time() + timeout
    while time.time() < end:
        try:
            with urllib.request.urlopen(BASE + "/panel/status", timeout=2) as r:
                data = json.loads(r.read().decode())
                if "panel_password_required" in data:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


HOST_CANDIDATES = ("127.0.0.1", "::")


def start_server():
    """Start the gateway under test and wait for it to answer /health.

    The bind host is probed, not assumed: upstream binds IPv4 only, while a
    deployment that patched in a dual-stack listener only accepts IPv4
    connections on the wildcard socket. The first candidate that answers wins.
    """
    for host in HOST_CANDIDATES:
        proc = subprocess.Popen(
            [
                sys.executable,
                "ca_proxy.py",
                "--host",
                host,
                "--port",
                str(PORT),
                "--accounts-dir",
                os.path.join(FIX, "accounts"),
                "--usage-dir",
                os.path.join(FIX, "usage"),
                "--panel-password",
                PASSWORD,
            ],
            cwd=ROOT,
            env=dict(os.environ),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if wait_identity():
            return proc
        proc.kill()
        proc.wait()
    raise SystemExit("gateway did not answer on port %d" % PORT)


def login(page):
    page.goto(BASE + "/", timeout=20000)
    page.wait_for_timeout(1200)
    if page.locator("#panelPwdInput").count():
        page.fill("#panelPwdInput", PASSWORD)
        page.click("button:has-text('进入面板')")
        page.wait_for_timeout(1500)


def goto_tab(page, tab):
    btn = {
        "gateway": "#btnNavGateway",
        "analytics": "#btnNavAnalytics",
        "logs": "#btnNavLogs",
        "settings": "#btnNavSettings",
    }[tab]
    page.click(btn)
    page.wait_for_timeout(900)


def run_checks(filter_name):
    from playwright.sync_api import sync_playwright

    os.makedirs(SHOTS, exist_ok=True)

    with sync_playwright() as p:
        browser = p.firefox.launch(headless=True)

        # ---------- phone viewport ----------
        page = browser.new_page(viewport={"width": 390, "height": 844})
        login(page)
        page.screenshot(path=os.path.join(SHOTS, "phone-gateway.png"), full_page=True)

        if "nav" in filter_name or filter_name == "":
            # Tab 数由页面自己决定：设置里的「顶部页签显示」能把任意一页收起来，
            # 所以这里一个数量都不写死。要钉的是几何性质：
            # 标签不被截断、行内容不顶出导航条（摆不下就横向滚动，做法与
            # .page-nav 一致）、按钮填满整行不留空档。4 个 Tab 放得下时「等宽」
            # 是这三条的自然结果（issue #150 的属性仍在覆盖范围内）。
            nav = page.evaluate(
                """
                (() => {
                  const nav = document.querySelector('.main-nav');
                  const btns = Array.from(document.querySelectorAll('.main-nav-btn'));
                  const r = nav.getBoundingClientRect();
                  const hr = document.querySelector('header').getBoundingClientRect();
                  return {
                    count: btns.length,
                    widths: btns.map(b => Math.round(b.getBoundingClientRect().width)),
                    overflow: Math.round(nav.scrollWidth - nav.clientWidth),
                    scrollable: getComputedStyle(nav).overflowX !== 'visible',
                    right: Math.round(r.right),
                    headerRight: Math.round(hr.right),
                    clipped: btns.some(b => b.scrollWidth > b.clientWidth + 1),
                    filled: nav.scrollWidth >= nav.clientWidth - 2,
                  };
                })()
                """
            )
            widths = nav["widths"]
            check(
                "nav-labels-not-clipped",
                not nav["clipped"],
                nav,
            )
            check(
                "nav-stays-inside-the-header",
                nav["right"] <= nav["headerRight"] + 1,
                nav,
            )
            check(
                "nav-scrolls-instead-of-overflowing",
                nav["overflow"] <= 1 or nav["scrollable"],
                nav,
            )
            check(
                "nav-buttons-fill-the-bar",
                nav["filled"],
                (widths, nav["overflow"]),
            )
            nav_w = page.evaluate(
                "document.querySelector('.main-nav').getBoundingClientRect().width"
            )
            hdr_w = page.evaluate(
                "document.querySelector('header').getBoundingClientRect().width"
            )
            check("header-nav-full", nav_w >= hdr_w - 29, (nav_w, hdr_w))
            # The upstream GitHub link must share the title row and stay
            # inside the header box instead of wrapping onto its own line.
            gh = page.evaluate(
                """
                (() => {
                  const a = document.querySelector('.gh-link');
                  const h = document.querySelector('header');
                  const t = document.querySelector('header h1');
                  if(!a || !h || !t) return {ok: false, why: 'missing'};
                  const ar = a.getBoundingClientRect();
                  const hr = h.getBoundingClientRect();
                  const tr = t.getBoundingClientRect();
                  const sameRow = Math.abs(ar.top - tr.top) < 24;
                  return {
                    ok: ar.right <= hr.right + 1 && ar.left >= hr.left - 1 && sameRow,
                    right: Math.round(ar.right), hdrRight: Math.round(hr.right),
                    sameRow: sameRow,
                  };
                })()
                """
            )
            check("gh-link-header-row", gh["ok"], gh)

        if "models" in filter_name or filter_name == "":
            disp = page.evaluate(
                "document.querySelector('#modelsTable tbody tr') ? getComputedStyle(document.querySelector('#modelsTable tbody tr')).display : 'none'"
            )
            check("models-cards", disp == "grid", disp)

        if "account" in filter_name or filter_name == "":
            # 账号列表已重构成码道卡片（.ca-row，60-codearts.js 渲染）；旧
            # #accounts 表格整个没了。fixture 没有 codearts 账号（没有
            # accounts/codearts/ 目录），/accounts/codearts 返回空列表，页面
            # 停在空提示；这里手工注入一张与真实渲染同构的卡片，钉它在手机
            # 宽度下的几何：横向 flex 排布、不超出容器。
            page.evaluate(
                """
                (() => {
                  const box = document.querySelector('#codeartsPageList');
                  if(!box) return;
                  box.innerHTML = '<div class="ca-row"><div class="ca-main">'
                    + '<span class="ca-name">示例账号<span class="ca-badge ok">有效</span></span>'
                    + '<span class="ca-sub">STS 剩 3 小时 · 可续期</span></div>'
                    + '<div class="ca-actions"><button class="sec mini">积分签到</button>'
                    + '<button class="sec mini">删除</button></div></div>';
                })()
                """
            )
            row = page.evaluate(
                """
                (() => {
                  const row = document.querySelector('#codeartsPageList .ca-row');
                  if(!row) return {ok: false, why: 'missing'};
                  const r = row.getBoundingClientRect();
                  const b = row.parentElement.getBoundingClientRect();
                  return {
                    ok: getComputedStyle(row).display === 'flex'
                        && r.left >= b.left - 1 && r.right <= b.right + 1,
                    display: getComputedStyle(row).display,
                    left: Math.round(r.left), boxLeft: Math.round(b.left),
                    right: Math.round(r.right), boxRight: Math.round(b.right),
                  };
                })()
                """
            )
            check(
                "account-cards",
                row.get("ok"),
                row,
            )
            page.screenshot(
                path=os.path.join(SHOTS, "phone-accounts.png"), full_page=True
            )

        if "analytics" in filter_name or filter_name == "":
            goto_tab(page, "analytics")
            page.wait_for_timeout(1200)
            disp = page.evaluate(
                "document.querySelector('#recent tbody tr') ? getComputedStyle(document.querySelector('#recent tbody tr')).display : 'none'"
            )
            check("analytics-cards", disp == "grid", disp)
            page.screenshot(
                path=os.path.join(SHOTS, "phone-analytics.png"), full_page=True
            )

        if "limits" in filter_name or filter_name == "":
            # 旧的 table.limits-cards（每账号限额表）已随 UI 重构移除——限额
            # 现在是设置页里的内联数字输入框，不再是表格，卡片化断言随之失去
            # 对象。这里只钉剩下仍然成立的性质：设置页里非卡片化的普通表格
            #（更新检查 / 运行信息）在手机上保持原生 table 布局。
            goto_tab(page, "settings")
            page.wait_for_timeout(800)
            kv = page.evaluate(
                "getComputedStyle(document.querySelector('#pageSettings table:not(.data-cards)')).display"
            )
            check("kv-table-intact", kv == "table", kv)
            page.screenshot(
                path=os.path.join(SHOTS, "phone-settings.png"), full_page=True
            )

        if "log" in filter_name or filter_name == "":
            goto_tab(page, "logs")
            page.wait_for_timeout(800)
            h = page.evaluate(
                "document.querySelector('#logTerminalBody').getBoundingClientRect().height"
            )
            check("log-terminal-height", h <= 844 * 0.65 + 1, h)
            page.screenshot(path=os.path.join(SHOTS, "phone-logs.png"), full_page=True)

        if "modal" in filter_name or filter_name == "":
            # 面板已没有通用登录弹窗（openLoginModal/closeLogin 都删了）；
            # 现存唯一的对话框是码道账号弹窗 #codeartsLoginModal。不调
            # openCodeartsLogin()——那会真的发起 OAuth 授权——直接加 .show 类
            # 复现显示态，钉它在手机宽度下放得下。
            goto_tab(page, "gateway")
            page.evaluate(
                "document.getElementById('codeartsLoginModal').classList.add('show')"
            )
            page.wait_for_timeout(600)
            mw = page.evaluate(
                "document.querySelector('#codeartsLoginModal.show .modal').getBoundingClientRect().width"
            )
            check("modal-fits", mw >= 390 - 24, mw)
            page.screenshot(path=os.path.join(SHOTS, "phone-modal.png"))
            page.evaluate(
                "document.getElementById('codeartsLoginModal').classList.remove('show')"
            )

        if "overflow" in filter_name or filter_name == "":
            bad = []
            for tab in ("gateway", "analytics", "logs", "settings"):
                goto_tab(page, tab)
                page.wait_for_timeout(500)
                sw = page.evaluate("document.documentElement.scrollWidth")
                if sw > 391:
                    bad.append((tab, sw))
            check("no-h-overflow", not bad, bad)
        page.close()

        # ---------- desktop viewport (regression) ----------
        dpage = browser.new_page(viewport={"width": 1280, "height": 800})
        login(dpage)
        if "desktop" in filter_name or filter_name == "":
            # 旧断言看的是 #accounts 表格——那个容器已随账号页重构消失。改钉
            # 仍存在且被同一套 data-cards 规则覆盖的 #modelsTable：桌面宽度
            # 下必须还是原生表格（卡片化只发生在 ≤640px）。
            disp = dpage.evaluate(
                "getComputedStyle(document.querySelector('#modelsTable')).display"
            )
            row_disp = dpage.evaluate(
                "getComputedStyle(document.querySelector('#modelsTable tbody tr')).display"
            )
            check(
                "desktop-table",
                disp == "table" and row_disp == "table-row",
                (disp, row_disp),
            )
        dpage.screenshot(
            path=os.path.join(SHOTS, "desktop-gateway.png"), full_page=True
        )
        dpage.close()
        browser.close()


def main():
    global PORT, BASE
    filter_name = sys.argv[1] if len(sys.argv) > 1 else ""
    PORT = free_port()
    BASE = "http://127.0.0.1:%d" % PORT
    build_fixtures()
    set_password()
    proc = start_server()
    try:
        run_checks(filter_name)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    print()
    print("PASS=%d FAIL=%d" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
