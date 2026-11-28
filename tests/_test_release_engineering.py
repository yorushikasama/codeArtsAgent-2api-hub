"""Release engineering pins (M6 F1-F3).

The Dockerfile and compose file are text artifacts nothing else in the suite
executes; these assertions keep the release discipline from silently
disappearing (tag == source version, healthcheck, PUID/PGID). The last class
keeps merge leftovers (conflict markers) out of the tree.

GitHub Actions was removed from this repository (2026-10-22): there is no
`.github/workflows/` any more, so nothing here may read a workflow file.

Run with: python _test_release_engineering.py
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


class VersionStringTests(unittest.TestCase):
    def test_source_version_strings_agree(self):
        src = read("ca_proxy.py")
        overview = re.search(r'"version"\s*:\s*"([^"]+)"', src)
        server = re.search(r'server_version\s*=\s*"codearts-hub/([^"]+)"', src)
        self.assertIsNotNone(overview, "overview version string not found")
        self.assertIsNotNone(server, "server header version string not found")
        self.assertEqual(overview.group(1), server.group(1))


class DockerTests(unittest.TestCase):
    def test_healthcheck_probes_the_health_endpoint(self):
        text = read("Dockerfile")
        self.assertIn("HEALTHCHECK", text)
        self.assertIn("/health", text)

    def test_compose_supports_puid_pgid(self):
        text = read("docker-compose.yml")
        self.assertIn("${PUID:-", text)
        self.assertIn("${PGID:-", text)


class ReadmeTests(unittest.TestCase):
    def test_readme_suite_count_matches_the_tree(self):
        names = [n for n in os.listdir(os.path.join(ROOT, "tests"))
                 if n.startswith("_test_") and n.endswith((".py", ".js"))]
        py = len([n for n in names if n.endswith(".py")])
        js = len([n for n in names if n.endswith(".js")])
        expected = "%d 个套件：%d 个 Python + %d 个 JS" % (len(names), py, js)
        self.assertIn(expected, read("README.md"))


class SystemdUnitTests(unittest.TestCase):
    """内存护栏钉在仓库里的单元文件上。

    这台服务器只有 952MB 内存：没有 cgroup 上限时，一次泄漏（参考 2026-08-22
    ugrep 33GB 拖死整机）就是 Kernel-Power 41 重演。护栏必须同时在两处成立：
    仓库里的单元文件带上限（改它必须有意识），deploy 脚本负责把仓库版同步
    到服务器（漂移会被发现）。
    """

    def test_unit_defines_memory_guards(self):
        text = read("deploy", "codearts-hub.service")
        self.assertIn("MemoryHigh=", text)
        self.assertIn("MemoryMax=", text)
        self.assertIn("MemorySwapMax=", text)
        self.assertNotIn("MemoryMax=infinity", text)
        self.assertIn("Restart=always", text)
        self.assertIn("KillSignal=SIGTERM", text)

    def test_deploy_script_syncs_the_unit(self):
        text = read("scripts", "deploy-full.sh")
        self.assertIn("deploy/codearts-hub.service", text)
        self.assertIn("daemon-reload", text)
        self.assertIn("MemoryMax", text)


class DeploymentTests(unittest.TestCase):
    """Exercise the local script and its SSH payload without touching a real host."""

    STAMP = "20261128-120000"
    STUBS = r'''
record() { printf '%s\n' "$*" >> "$TEST_ROOT/calls"; }

ssh() {
    [[ $5 == deployment-test.invalid ]] || return 99
    shift 5
    record ssh
    "$@"
}

git() {
    case "$1" in
        rev-parse|-C) printf 'test-rev\n' ;;
        clone)
            local staged=${!#}
            [[ $staged == "$WB_DEPLOY_DIR.new-"* ]] || return 99
            mkdir -p "$staged/deploy"
            printf 'unit\n' > "$staged/deploy/codearts-hub.service"
            printf 'new\n' > "$staged/revision"
            ;;
        *) return 99 ;;
    esac
}

date() { printf '20261128-120000\n'; }
sleep() { record sleep; }
mv() {
    if [[ $TEST_MOVE_FAIL == 1 && ${!#} == "$WB_DEPLOY_DIR" ]]; then return 1; fi
    command mv "$@"
}
timeout() {
    case "$1:$2:$3" in
        60s:sudo:systemctl|30s:sudo:systemctl|2s:systemctl:*) shift; "$@" ;;
        *) return 99 ;;
    esac
}

sudo() {
    case "$1" in
        cmp) return 0 ;;
        systemctl) shift; systemctl "$@" ;;
        *) return 99 ;;
    esac
}

systemctl() {
    case "$*" in
        'stop codearts-hub') record stop; [[ $TEST_STOP != error ]] ;;
        'show codearts-hub -p ActiveState -p MainPID -p ControlPID')
            record stop-state
            local state=inactive main=0 control=0
            case "$TEST_STOP" in
                delayed)
                    if [[ ! -e "$TEST_ROOT/draining" ]]; then
                        : > "$TEST_ROOT/draining"
                        state=deactivating
                    else
                        printf 'last-renewal\n' > "$WB_DEPLOY_DIR/accounts/token"
                    fi ;;
                deactivating|failed) state=$TEST_STOP ;;
                main-pid) main=42 ;;
                control-pid) control=43 ;;
                query-error) return 1 ;;
            esac
            printf 'MainPID=%s\nControlPID=%s\nActiveState=%s\n' "$main" "$control" "$state"
            ;;
        'start codearts-hub') record start; [[ $TEST_START != error ]] ;;
        'is-active codearts-hub')
            record active-state
            printf '%s\n' "$TEST_ACTIVE"
            [[ $TEST_ACTIVE == active ]] ;;
        'show codearts-hub -p MemoryMax --value') printf '402653184\n' ;;
        *) return 99 ;;
    esac
}

curl() {
    record health
    [[ $* == *'--noproxy * --connect-timeout 1 --max-time 2 '* &&
       ${!#} == http://127.0.0.1:9000/health ]] || return 99
    printf '%s\n%s' "$TEST_BODY" "$TEST_STATUS"
    if [[ $TEST_RETRY == 1 && ! -e "$TEST_ROOT/probed" ]]; then
        : > "$TEST_ROOT/probed"
        return 28 # Even a complete-looking response cannot hide a curl failure.
    fi
}

python3() {
    if [[ $* == tests/run_all.py ]]; then
        printf '  failed: fixture\n'
        return 1
    fi
    "$TEST_PYTHON" "$@"
}
'''

    def deploy(self, *, install=False, stop="ok", start="ok", active="active",
               status="200", body='{"ok": true, "service": "codearts-hub"}',
               retry=False, gate_fails=False, move_fails=False):
        bash = shutil.which("bash")
        if os.name == "nt" and (not bash or "system32" in bash.lower()):
            git = shutil.which("git")
            candidate = Path(git).resolve().parents[1] / "bin" / "bash.exe" if git else None
            bash = str(candidate) if candidate and candidate.is_file() else None
        if not bash:
            self.skipTest("Bash is required for deployment script tests")

        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        live = root / "live"
        if not install:
            (live / "accounts").mkdir(parents=True)
            (live / "accounts" / "token").write_text("old\n", encoding="utf-8")
            (live / "revision").write_text("old\n", encoding="utf-8")
            for day in (25, 26, 27):
                (root / f"live.old-202611{day}-120000").mkdir()
        stubs = root / "stubs.sh"
        stubs.write_bytes(self.STUBS.encode("ascii"))
        env = dict(os.environ, BASH_ENV=stubs.as_posix(), TEST_ROOT=root.as_posix(),
                   TEST_PYTHON=Path(sys.executable).as_posix(), TEST_STOP=stop, TEST_START=start,
                   TEST_ACTIVE=active, TEST_STATUS=status, TEST_BODY=body, TEST_RETRY=str(int(retry)),
                   TEST_MOVE_FAIL=str(int(move_fails)),
                   WB_DEPLOY_DIR=live.as_posix(), WB_DEPLOY_DEST="deployment-test.invalid",
                   WB_DEPLOY_KEY="unused", WB_DEPLOY_REPO="https://deployment-test.invalid/repo",
                   WB_DEPLOY_BRANCH="test", WB_DEPLOY_SKIP_TESTS="0" if gate_fails else "1")
        result = subprocess.run(
            [bash, "-c", '[[ $(type -t ssh) == function ]] || exit 99; source "$1"',
             "deploy-test", (Path(ROOT) / "scripts" / "deploy-full.sh").as_posix()],
            cwd=root, env=env, capture_output=True, encoding="utf-8", timeout=30)
        calls_path = root / "calls"
        self.assertTrue(calls_path.is_file(), result.stdout + result.stderr)
        calls = calls_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(calls[0], "ssh")
        return result, calls, live, root / f"live.new-{self.STAMP}", root / f"live.old-{self.STAMP}"

    def assert_failed(self, result, message):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(message, result.stderr)
        self.assertNotIn("DEPLOYED", result.stdout)

    def assert_pre_swap(self, live, staged, backup):
        self.assertEqual((live / "revision").read_text(encoding="utf-8"), "old\n")
        self.assertEqual((staged / "revision").read_text(encoding="utf-8"), "new\n")
        self.assertFalse(backup.exists())

    def assert_post_swap_failure(self, calls, live, staged, backup):
        self.assertEqual((live / "revision").read_text(encoding="utf-8"), "new\n")
        self.assertEqual((backup / "revision").read_text(encoding="utf-8"), "old\n")
        self.assertFalse(staged.exists())
        self.assertEqual(len(list(live.parent.glob("live.old-*"))), 4)
        self.assertEqual(calls.count("stop"), 1)
        self.assertEqual(calls.count("start"), 1)

    def test_gate_failure_keeps_staging_and_does_not_stop(self):
        result, calls, live, staged, backup = self.deploy(gate_fails=True)
        self.assert_failed(result, "test gate failed")
        self.assert_pre_swap(live, staged, backup)
        self.assertTrue((staged / "deploy-gate.log").is_file())
        self.assertEqual(calls, ["ssh"])

    def test_stop_failure_keeps_live_and_staging(self):
        result, calls, live, staged, backup = self.deploy(stop="error")
        self.assert_failed(result, "systemctl stop failed")
        self.assert_pre_swap(live, staged, backup)
        self.assertEqual(calls, ["ssh", "stop"])

    def test_unconfirmed_stop_never_swaps_or_starts(self):
        for stop in ("deactivating", "failed", "main-pid", "control-pid", "query-error"):
            with self.subTest(stop=stop):
                result, calls, live, staged, backup = self.deploy(stop=stop)
                self.assert_failed(result, "could not confirm")
                self.assert_pre_swap(live, staged, backup)
                self.assertEqual(calls.count("stop-state"), 10)
                self.assertNotIn("start", calls)
                self.assertNotIn("health", calls)

    def test_staging_move_failure_keeps_staging_and_backup_without_rollback(self):
        result, calls, live, staged, backup = self.deploy(move_fails=True)
        self.assert_failed(result, "could not move staged directory into place")
        self.assertFalse(live.exists())
        self.assertEqual((staged / "revision").read_text(encoding="utf-8"), "new\n")
        self.assertEqual((backup / "revision").read_text(encoding="utf-8"), "old\n")
        self.assertEqual(calls, ["ssh", "stop", "stop-state"])

    def test_start_failure_keeps_both_revisions_without_rollback(self):
        result, calls, live, staged, backup = self.deploy(start="error")
        self.assert_failed(result, "systemctl start failed")
        self.assert_post_swap_failure(calls, live, staged, backup)
        self.assertNotIn("health", calls)

    def test_invalid_readiness_times_out_without_rollback_or_pruning(self):
        for overrides in (
            {"status": "204"},
            {"status": "302"},
            {"body": "not JSON"},
            {"body": '{"ok": 1, "service": "codearts-hub"}'},
            {"body": '{"ok": true, "service": "different"}'},
            {"body": '{"ok": true}'},
            {"active": "inactive"},
        ):
            with self.subTest(overrides=overrides):
                result, calls, live, staged, backup = self.deploy(**overrides)
                self.assert_failed(result, "readiness timed out")
                self.assert_post_swap_failure(calls, live, staged, backup)
                self.assertEqual(calls.count("health"), 10)

    def test_waits_for_exit_refreshes_accounts_and_retries_readiness(self):
        result, calls, live, staged, backup = self.deploy(stop="delayed", retry=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("DEPLOYED test-rev (test)", result.stdout)
        self.assertEqual(calls, ["ssh", "stop", "stop-state", "sleep", "stop-state",
                                 "start", "health", "sleep", "health", "active-state"])
        self.assertEqual((live / "accounts" / "token").read_text(encoding="utf-8"), "last-renewal\n")
        self.assertEqual((backup / "revision").read_text(encoding="utf-8"), "old\n")
        self.assertFalse(staged.exists())
        self.assertFalse((live.parent / "live.old-20261125-120000").exists())
        self.assertEqual(len(list(live.parent.glob("live.old-*"))), 3)

    def test_first_install_needs_no_backup_to_succeed(self):
        result, _, live, staged, backup = self.deploy(install=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("DEPLOYED test-rev (test)", result.stdout)
        self.assertTrue(live.is_dir())
        self.assertFalse(staged.exists())
        self.assertFalse(backup.exists())


class RepoHygieneTests(unittest.TestCase):
    """解冲突没解干净的残留（冲突标记）不许留在仓库里。

    main 上已经发生过三次：#131 专门清过一次 dashboard 的残留，README 又在
    #243/#245 那批合并里被提交进 12~15 行冲突标记。没有测试盯它的时候，
    Python 文件是直接 SyntaxError，HTML/JS 则是静默坏掉；回滚检查（revert
    guard）还会把「合并时顺手整理掉这些行」算成弄丢 main 的改动（见 #245）。
    """

    MARKER = re.compile(r"^(<{7}|>{7}|\|{7})(\s|$)")

    # 运行时数据与打包产物（.gitignore 里那些）：它们不是源码，不该被扫。
    SKIP_DIRS = (".git", "__pycache__", "node_modules", "accounts", "usage",
                 "logs", "suite-logs", "dist", "python", ".sdk-cache")

    def test_no_conflict_markers_in_the_tree(self):
        offenders = []
        for base, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
            for name in files:
                path = os.path.join(base, name)
                try:
                    if os.path.getsize(path) > 4 * 1024 * 1024:
                        continue
                    with open(path, "rb") as fh:
                        raw = fh.read()
                except OSError:
                    continue
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    continue                    # 二进制，跳过
                for line in text.splitlines():
                    if self.MARKER.match(line):
                        offenders.append("%s: %s"
                                         % (os.path.relpath(path, ROOT), line[:60]))
                        break
        self.assertEqual(
            offenders, [],
            "冲突标记残留（解冲突没解干净，两边都要留）：\n" + "\n".join(offenders))


if __name__ == "__main__":
    unittest.main()
