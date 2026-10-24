"""Runtime settings for the gateway: panel password and API key override.

Everything lives in `accounts/settings.json` so a change made from the web
panel survives a restart without editing the launcher .bat files. The panel
password is never stored in clear text - only a PBKDF2-SHA256 digest.

Only the Python standard library is required.
"""

import fnmatch
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time

DEFAULT_PANEL_PASSWORD = "admin"
PBKDF2_ROUNDS = 120_000
SESSION_TTL = 7 * 24 * 3600
# 价格估算体系已下线（2026-10-22）：pricing_refresh_minutes / pricing_variant_inherit /
# pricing_enabled 三个键连同读写函数一起删除。老 settings.json 里残留的键不读不写，
# 保存时原样留在文件里（load/save 不会丢未知键），回滚旧版本仍能读到它们。
# Panel window height cap, in pixels: a dashboard window (section) taller than
# this scrolls internally with its title row pinned, instead of stretching the
# whole page. 0 turns the cap off. The default sits just above the log
# terminal's own 620px so the terminal stays untouched until the user asks for
# something smaller.
SECTION_MAX_HEIGHT_KEY = "section_max_height"
DEFAULT_SECTION_MAX_HEIGHT = 640
MAX_SECTION_MAX_HEIGHT = 4000
# Whether the panel's account section is collapsed. Missing, or anything that is
# not the boolean true, reads as expanded: a fresh install and a value a hand
# edit or an older client left behind both keep the default view, and only an
# explicit true hides the accounts.
ACCOUNTS_COLLAPSED_KEY = "accounts_collapsed"
# Whether the panel's per-API-key table folds away its `(切换前)` row - the
# legacy tail of requests logged before the key field existed. Same
# normalisation as the disclosure above: only an explicit boolean true hides
# the row, so a hand edit or an older client cannot drop it by accident.
KEY_BEFORE_HIDDEN_KEY = "key_before_hidden"
# Which top-bar pages the panel keeps out of the nav, as a list of page keys
# ("tasks", "logs", ...). Deliberately not validated against a page registry:
# the pages live in dashboard.html, and the panel ignores a key it does not
# know, so adding or renaming a page upstream never needs a change here. A
# missing key, a hand-written string or any other malformed value reads as
# "nothing hidden" - the fail-safe direction for a display preference.
HIDDEN_PAGES_KEY = "hidden_pages"
# Page keys are the same lowercase identifiers switchMainTab() switches on.
PAGE_KEY_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
# The one page that is never hidden, whatever the request or the file says: it
# is where this switch itself lives, so hiding it would leave the panel with no
# way back. Dropped during normalisation, so the stored file cannot hold it
# either and no client of this API can lock itself out.
PAGE_KEEP_VISIBLE = "settings"
# Bound on the stored list. The panel sends at most one entry per page, so this
# only limits what a hand edit can put in the file.
MAX_HIDDEN_PAGES = 32
# Whether the panel's account sections get a main tab of their own instead of
# sharing the gateway page. Missing, or anything that is not the boolean true,
# reads as off: an install that predates the setting keeps the single
# "网关与账号" tab it has always had, and only an explicit true splits it into
# 网关 + 账号. Same `is True` normalisation as the two switches above, so a
# hand-edited "false", a 1 or an object cannot split the nav by accident.
ACCOUNTS_SEPARATE_TAB_KEY = "accounts_separate_tab"

# Instance-wide default UI language. The dashboard can override this per
# browser with localStorage; this key is the fallback when no override exists.
UI_LANGUAGE_KEY = "ui_language"
UI_LANGUAGE_DEFAULT = "zh"
UI_LANGUAGE_VALUES = ("zh", "zh-Hant", "en")

# Whether the gateway checks GitHub for a newer release once a day. Missing key
# reads as off - the opposite of the switches above - because turning it on
# makes the gateway send a request on its own schedule.
UPDATE_CHECK_ENABLED_KEY = "update_check_enabled"
# The last-check bookkeeping for that daily check. One small object, never a
# general update-state store: see update_check_state().
UPDATE_CHECK_STATE_KEY = "update_check"

# 出口级瞬时失败退避（issue #271）：传输类失败与 502/503/504 不再进账号级熔断
# 计数，改记在出口上、退避降到秒级（见 ca_egress）。缺失键读作关：它改变的是
# 派发路径上的失败归账与退避尺度，老安装保持原样（传输错误仍喂账号熔断）。
EGRESS_BACKOFF_ENABLED_KEY = "egress_backoff_enabled"

# 日志落库：把运行日志追加写进 usage/logs.sqlite3，重启后仍能回看，方便事后
# debug。缺失键读作关 —— 关着的时候日志只留在内存环形缓冲里，与上游一字不差；
# 只有显式 true 才建库、落盘。
LOG_DB_ENABLED_KEY = "log_db_enabled"
# 三条互相独立的保留上限，各自「留空 = 这一维不设限」：
#   * rows  —— 只留最新的 N 条（空 = 不限条数）
#   * days  —— 只留最近 N 天（空 = 不限天数；**默认 7 天**）
#   * bytes —— 库文件超过 N 字节就从最旧的删起，缩回 N 以内（空 = 不限大小）
# 天数给了 7 天默认值，是因为「无限增长的日志库」才是要防的那件事；条数与
# 字节数留空（不限），因为单独看任何一个都可能偏严或偏松，交给使用者按需填。
LOG_DB_MAX_ROWS_KEY = "log_db_max_rows"
LOG_DB_MAX_DAYS_KEY = "log_db_max_days"
LOG_DB_MAX_BYTES_KEY = "log_db_max_bytes"
DEFAULT_LOG_DB_MAX_DAYS = 7
# 上限只用来挡手滑：手编 settings.json 写个天文数字不该把裁剪循环拖死，也不该
# 让面板显示一个溢出成科学计数法的值。都远大于任何真实部署会用的量级。
MAX_LOG_DB_MAX_ROWS = 100_000_000
MAX_LOG_DB_MAX_DAYS = 36500
MAX_LOG_DB_MAX_BYTES = 100 * 1024 ** 3

_lock = threading.RLock()


def settings_path(accounts_dir):
    return os.path.join(accounts_dir, "settings.json")


def _digest(password, salt_hex, rounds=PBKDF2_ROUNDS):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), rounds
    ).hex()


# settings.json 的解析结果按 (path, mtime, size) 缓存：请求热路径上它被读约 10
# 次（prompt_config×2 / api_keys×2 / limits_data×3 /
# upstream_config×2），单次 156~273µs，合计 1.6~2.7ms/请求。所有写入都走 save()
# 的 os.replace 原子替换，mtime/size 必变，所以面板改动仍然即时生效；save() 里
# 再主动失效一次，连 mtime 精度粗（FAT 只有 2s）的同尺寸改写也不会读到旧值。
# 调用方拿到的是顶层浅拷贝：与原实现「每次重新解析、返回值随便改」的语义一致
# （现网所有 setter 都只改顶层键再 save()，嵌套值按约定只读），改返回值也不会
# 弄脏缓存。
_load_cache = {"key": None, "value": {}}
#: 上一次读盘是不是「文件在、但读不出来」。鉴权侧必须区分这两件事：
#: 全新安装（文件不存在）该当成没配置；而**文件损坏 / 读失败**绝不能当成
#: 「没配置」—— 那样一次磁盘抖动就把 API key 与面板密码一起关掉了。
_load_error = {"path": None, "message": "", "at": 0.0}


def last_load_error():
    """上一次 load() 的读失败信息（没有失败时返回 None）。

    鉴权路径用它决定「fail closed」而不是「当成空配置」：空配置意味着
    「不需要 key、密码是默认的 admin」—— 那是最危险的一种误解。
    """
    return dict(_load_error) if _load_error.get("path") else None


def _note_load_error(path, exc):
    _load_error.update({"path": path, "message": str(exc), "at": time.time()})


def _clear_load_error():
    _load_error.update({"path": None, "message": "", "at": 0.0})


def load(accounts_dir):
    """Return the persisted settings, or an empty dict on a fresh install.

    Cached on (path, mtime, size); the returned dict is a fresh top-level copy
    so callers keep the previous "mutate freely" semantics.

    **读失败不是空配置**：文件存在但解析不了（半截写入、被截断、权限）时
    返回空 dict 会让鉴权退化成「不需要 key + 密码是 admin」。这里仍然返回
    空 dict（调用方的类型契约不变），但把失败记进 ``_load_error``；鉴权侧
    用 ``last_load_error()`` 判「读不出来」并 fail closed。
    """
    path = settings_path(accounts_dir)
    try:
        info = os.stat(path)
        key = (path, info.st_mtime, info.st_size)
    except FileNotFoundError:
        # 全新安装：这**真的**是没有配置，不是读失败。
        _clear_load_error()
        with _lock:
            _load_cache.update({"key": (path, None, None), "value": {}})
        return {}
    except OSError as exc:
        # 目录不可读之类的系统错误：文件可能在，但我们看不见它。
        _note_load_error(path, exc)
        with _lock:
            _load_cache.update({"key": None, "value": {}})
        return {}
    with _lock:
        # 缓存命中也要先确认「上一次读是成功的」：坏文件的 (mtime, size) 没变，
        # 命中旧缓存就会把失败信号抹掉。
        cached_key = _load_cache["key"]
    if cached_key == key:
        if _load_error.get("path") and _load_error.get("path") == path:
            # 之前坏过、文件内容又没变（同一份坏文件）：继续按失败返回，
            # 但仍要重新读一次以更新 mtime/size —— 否则报错永远不消失。
            pass
        else:
            return dict(_load_cache["value"])
    data = {}
    failed = False
    try:
        with open(path, encoding="utf-8") as fh:
            parsed = json.load(fh)
        if isinstance(parsed, dict):
            data = parsed
            _clear_load_error()
        else:
            # 能被 json 解析但顶层不是对象：同样按「读不懂」处理。
            raise ValueError("settings.json is not a JSON object")
    except FileNotFoundError:
        # stat 之后、open 之前被删了：按全新安装处理。
        _clear_load_error()
    except Exception as exc:
        failed = True
        _note_load_error(path, exc)
    with _lock:
        # **坏结果不进缓存**：以前读失败也会把 {} 按 (mtime, size) 存下来，
        # 于是「文件坏了 → 鉴权关着」会一直保持，即便调用方后来做了 fail
        # closed 判断也拿不到失败信号（缓存直接返回空 dict）。
        if not failed:
            _load_cache.update({"key": key, "value": data})
        else:
            _load_cache.update({"key": None, "value": {}})
    return dict(data)


def save(accounts_dir, data):
    """Atomic write so a crash cannot leave a half-written settings file."""
    with _lock:
        os.makedirs(accounts_dir, exist_ok=True)
        path = settings_path(accounts_dir)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
        # 写完主动失效：不依赖文件系统 mtime 的精度（FAT 只有 2s），保证同尺寸
        # 改写的下一个 load() 一定重新读盘。
        _load_cache["key"] = None
        return path


def deep_merge(base, patch):
    """Recursively merge patch into base; unknown sibling keys survive.

    The panel form only submits the keys it manages. Replacing a whole group
    would silently drop hand-written or future keys, so nested objects merge
    key by key. Returns a new dict; the inputs are not mutated.
    """
    if not isinstance(base, dict) or not isinstance(patch, dict):
        return patch
    out = dict(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def panel_password_is_default(accounts_dir):
    data = load(accounts_dir)
    if last_load_error():
        # 配置读不出来：**不能**说「还是默认密码」——调用方（启动横幅、
        # 登录页提示）据此会认为「admin 还能进」，而 verify 那边已经拒绝。
        return False
    if not data.get("panel_password_hash"):
        return True
    return data.get("panel_password_default") is True


def verify_panel_password(accounts_dir, password):
    """True when `password` opens the web panel.

    **配置读不出来时一律拒绝**：空 dict 会让下面第一条分支判成「还没设过
    密码」并接受默认的 admin —— 一次文件损坏就等于面板门户洞开。
    """
    password = password or ""
    data = load(accounts_dir)
    if last_load_error():
        return False
    stored = data.get("panel_password_hash")
    if not stored:
        return password == DEFAULT_PANEL_PASSWORD
    if data.get("panel_password_default") is True:
        return password == DEFAULT_PANEL_PASSWORD
    salt = data.get("panel_password_salt")
    if not salt:
        return False
    rounds = int(data.get("panel_password_rounds") or PBKDF2_ROUNDS)
    try:
        given = _digest(password, salt, rounds)
    except Exception:
        return False
    return hmac.compare_digest(given, stored)


def set_panel_password(accounts_dir, password, source="launcher"):
    """改面板密码。``source`` 记「谁改的」，决定重启时听谁的。

    2026-10-21 的坑：systemd 的 ExecStart 带着 ``--panel-password
    "$PANEL_PASSWORD"``（来自 .credentials），而 main() 无条件执行本函数，
    于是**每次重启都把面板里改过的密码还原成 .credentials 的旧值**。
    用户表现为「我明明改过密码，现在登不进去 / 我改错了」——日志里
    "password set from --panel-password" 一天出现了 28 次，全是我部署时重启的。

    现在 source 存进 ``panel_password_source``，启动时只在这两件事都成立时
    才应用启动参数：密码还不是它、且面板没接管过。见 apply_launcher_password()。
    """
    with _lock:
        data = load(accounts_dir)
        if password == DEFAULT_PANEL_PASSWORD:
            data.pop("panel_password_salt", None)
            data.pop("panel_password_rounds", None)
            data["panel_password_hash"] = ""
            data["panel_password_default"] = True
            data["panel_password_source"] = ""
        else:
            salt = secrets.token_hex(16)
            data["panel_password_salt"] = salt
            data["panel_password_rounds"] = PBKDF2_ROUNDS
            data["panel_password_hash"] = _digest(password, salt)
            data["panel_password_default"] = False
            data["panel_password_source"] = source or ""
        save(accounts_dir, data)


def panel_password_source(accounts_dir):
    """'panel' = 用户在面板里设过；'' / 'launcher' = 来自启动参数。"""
    data = load(accounts_dir)
    return str(data.get("panel_password_source") or "")


def apply_launcher_password(accounts_dir, password, force=False):
    """启动时决定 ``--panel-password`` 要不要写进存档。返回动作名。

    三种结果：
      'same'    已经就是这个密码 —— 什么都不做（不重写 hash，免得每次启动
                都把 settings.json 的 mtime 改掉）
      'kept'    面板里设过密码，启动参数可能是过期值 —— **保留面板的**
      'applied' 首次部署 / 面板没设过 / 显式 force —— 应用启动参数

    为什么不能简单「启动参数永远赢」：.credentials 是部署时写的，用户之后在
    面板里改密码时它不会跟着变，于是每次重启都把用户的改动抹掉。
    也不能简单「面板永远赢」：运维改 .credentials 想重置密码时会静默失效。
    所以两边都要有明确出路 —— 面板改密码时会顺手同步 .credentials
    （sync_env_password），同步成功就谁都不会被覆盖；同步失败（文件只读）
    时按面板的来，并留 force 给运维强推。
    """
    if verify_panel_password(accounts_dir, password):
        return "same"
    if panel_password_source(accounts_dir) == "panel" and not force:
        return "kept"
    set_panel_password(accounts_dir, password, source="launcher")
    return "applied"


def env_password_path(project_dir=None):
    """启动脚本读密码的那个 env 文件。优先环境变量，其次项目根目录。"""
    explicit = os.environ.get("PANEL_PASSWORD_FILE")
    if explicit:
        return explicit
    base = project_dir or os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, ".credentials")


def sync_env_password(path, password):
    """把 PANEL_PASSWORD 写回 env 文件，其它行原样保留。成功返回 True。

    只替换 ``PANEL_PASSWORD=`` 那一行；没有该键则追加。走临时文件 +
    os.replace，避免写一半把服务起不来。**任何失败都只返回 False** ——
    调用方（改密码接口）不能因为同步失败就把改密码这件事判为失败。
    """
    try:
        rows, hit = [], False
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("PANEL_PASSWORD="):
                    rows.append("PANEL_PASSWORD=%s\n" % password)
                    hit = True
                else:
                    rows.append(line)
        if not hit:
            if rows and not rows[-1].endswith("\n"):
                rows[-1] += "\n"
            rows.append("PANEL_PASSWORD=%s\n" % password)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.writelines(rows)
        try:
            os.chmod(tmp, 0o600)      # 里面还有 API_KEY，不能给别人读
        except OSError:
            pass
        os.replace(tmp, path)
        return True
    except OSError:
        return False


def api_key_override(accounts_dir):
    """Return (key, is_set). `is_set` means the panel manages the key."""
    data = load(accounts_dir)
    if not data.get("api_key_set"):
        return None, False
    return str(data.get("api_key") or ""), True


def set_api_key(accounts_dir, key):
    with _lock:
        data = load(accounts_dir)
        data["api_key"] = key or ""
        data["api_key_set"] = True
        save(accounts_dir, data)


def ensure_launcher_key(accounts_dir):
    """Return the persisted LAN key, creating one on first use.

    LAN mode must never ship a well-known default: the gateway spends the
    account's own upstream quota, so anyone on the same network could drain it.
    The value is generated once and stored so clients keep working across
    restarts. Returns (key, created) so the caller can tell the user whether
    this run minted a fresh credential.
    """
    with _lock:
        data = load(accounts_dir)
        existing = str(data.get("launcher_key") or "").strip()
        if existing:
            return existing, False
        key = "wb-" + secrets.token_urlsafe(24)
        data["launcher_key"] = key
        save(accounts_dir, data)
        return key, True


# --------------------------------------------------------------- API keys


def _clean_model_patterns(value):
    """Normalize one key's model allow-list into a list of lowercase patterns.

    The panel posts a list; a hand-edited settings.json tends to hold a
    comma-separated string, so both shapes are accepted. Matching is done with
    fnmatch, which makes an exact name (`gpt-6-astra`) and a wildcard
    (`deepseek/*`) behave the same way. An empty result means "no restriction",
    which is what every key written before this field existed reads back as -
    an upgrade therefore keeps behaving exactly as before.
    """
    if isinstance(value, str):
        raw = [part for part in re.split(r"[,;\n]", value)]
    elif isinstance(value, (list, tuple, set)):
        raw = list(value)
    else:
        return []
    out = []
    for item in raw:
        pattern = str(item or "").strip().lower()
        if pattern and pattern not in out:
            out.append(pattern)
    return out


def key_allows_model(entry, model):
    """True when `entry` places no model restriction, or `model` matches it.

    A key with an empty list stays unrestricted, so nothing changes for
    installs that never touch this field. A restricted key that names no model
    is refused instead of waved through: nothing in the request says it is
    asking for something the key may use, and forwarding it only reaches the
    upstream carrying an empty model, spending an attempt on a call that cannot
    succeed.
    """
    patterns = _clean_model_patterns((entry or {}).get("models"))
    if not patterns:
        return True
    name = str(model or "").strip().lower()
    if not name:
        return False
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def _clean_key_entry(entry):
    """Normalize one stored key entry; returns None when unusable.

    A deleted entry keeps its row even though its secret is gone: the id is
    what the usage log records, so dropping the row would make every past
    request of that key unattributable. Deletion is one-way - the secret is
    never stored again and the entry can only ever be read, not re-enabled.
    """
    if not isinstance(entry, dict):
        return None
    key = str(entry.get("key") or "").strip()
    deleted_at = str(entry.get("deleted_at") or "").strip()
    if not key and not deleted_at:
        return None
    try:
        concurrency = int(entry.get("concurrency_limit") or entry.get("max_concurrency") or 0)
    except (TypeError, ValueError):
        concurrency = 0
    concurrency = max(0, concurrency)
    return {
        "id": str(entry.get("id") or secrets.token_hex(6)),
        "name": str(entry.get("name") or "").strip() or "未命名",
        "key": key,
        "models": _clean_model_patterns(entry.get("models")),
        "concurrency_limit": concurrency,
        "enabled": False if deleted_at else entry.get("enabled", True) is not False,
        "created_at": entry.get("created_at") or time.strftime("%Y/%m/%d %H:%M"),
        "deleted_at": deleted_at,
    }


def _unique_key_id(candidate, used):
    """Return `candidate`, or a variant that is not already in `used`.

    Ids used to be minted from the row's index in the submitted list, so a
    settings file written by an older build can hold two rows carrying the same
    id. `/settings/reveal` then answered with whichever row came first, which
    made the copy button on the other row hand out a different key. Later
    duplicates get a numeric suffix: the suffix is deterministic, so the id a
    `/settings` read just returned still resolves on the follow-up reveal.
    """
    candidate = str(candidate or "").strip()
    if candidate and candidate not in used:
        return candidate
    if candidate:
        suffix = 2
        while True:
            alt = "%s-%d" % (candidate, suffix)
            if alt not in used:
                return alt
            suffix += 1
    while True:
        alt = secrets.token_hex(6)
        if alt not in used:
            return alt


def api_keys(accounts_dir, include_deleted=False):
    """Every configured key, newest shape first.

    A settings file written by an older build only has the single
    `api_key`/`api_key_set` pair; that is surfaced as one unbound entry so
    upgrades keep working without a migration step. Ids are made unique here
    as well as on write, so a file that already holds a duplicate (and no
    longer has to be saved before it behaves) reads back as distinct rows.

    Deleted entries are hidden by default: they are gone as credentials, and
    match_api_key must never see them. Their rows stay on disk (and come back
    with include_deleted) because the usage log names a key by id, and an id
    with no name is not a table anyone can read.
    """
    data = load(accounts_dir)
    stored = data.get("api_keys")
    if isinstance(stored, list):
        out = []
        seen = set()
        seen_ids = set()
        for raw in stored:
            entry = _clean_key_entry(raw)
            if entry is None:
                continue
            # Deduplicate on the secret, and only when there is one: every
            # deleted entry has an empty key, and those are distinct rows.
            if entry["key"]:
                if entry["key"] in seen:
                    continue
                seen.add(entry["key"])
            entry["id"] = _unique_key_id(entry["id"], seen_ids)
            seen_ids.add(entry["id"])
            out.append(entry)
        if not include_deleted:
            out = [e for e in out if not e.get("deleted_at")]
        return out

    if data.get("api_key_set"):
        legacy = str(data.get("api_key") or "").strip()
        if legacy:
            return [{
                "id": "legacy",
                "name": "默认",
                "key": legacy,
                "models": [],
                "enabled": True,
                "created_at": "",
                "deleted_at": "",
            }]
    return []


def _retired_key_entry(old):
    """The soft-deleted form of a stored key: name and dates kept, secret gone."""
    return {
        "id": old["id"],
        "name": old["name"],
        "key": "",
        "models": old.get("models") or [],
        "enabled": False,
        "created_at": old.get("created_at") or "",
        "deleted_at": old.get("deleted_at") or time.strftime("%Y/%m/%d %H:%M"),
    }


def set_api_keys(accounts_dir, keys, delete_ids=None):
    """Save the key list. Returns the saved (live) list.

    Removal is a soft delete: the usage log attributes spend by id, so losing
    an id would dump a key's whole history into "(未知 key)", and the secret is
    wiped at the same moment so a deleted key can never authenticate again.

    Two modes decide which stored keys get soft-deleted:

    - `delete_ids is None`: replace semantics. Any stored key absent from
      `keys` is retired. This is what an older panel relies on - it deletes a
      row by leaving it out of the submission - so it stays the default.
    - `delete_ids` is a list: upsert semantics. Only those ids are retired; a
      stored key the submission does not mention is left untouched. The panel
      uses this because its submission is whatever its in-memory rows happen
      to be, and a list that is stale or incomplete (a second browser tab, a
      save that raced the post-save reload, a reload that failed) must not
      retire a key the user never removed.
    """
    with _lock:
        previous = api_keys(accounts_dir, include_deleted=True)
        upsert = delete_ids is not None
        drop = {str(entry_id) for entry_id in (delete_ids or [])}
        # Upsert mode: a stored live secret, so a submitted row that lost its id
        # (a stale panel resubmitting a key it already saved) can adopt the
        # stored id and update that key in place instead of minting a new one
        # and splitting its usage history in two.
        live_secret_id = {}
        if upsert:
            for old in previous:
                if old["key"] and not old.get("deleted_at"):
                    live_secret_id.setdefault(old["key"], old["id"])
        cleaned = []
        seen = set()
        seen_ids = set()
        for raw in keys or []:
            raw_id = str((raw or {}).get("id") or "").strip() if isinstance(raw, dict) else ""
            entry = _clean_key_entry(raw)
            if entry is None:
                continue
            if entry["key"]:
                if entry["key"] in seen:
                    continue
                seen.add(entry["key"])
            if upsert and entry["key"] and raw_id not in live_secret_id.values():
                entry["id"] = live_secret_id.get(entry["key"], entry["id"])
            entry["id"] = _unique_key_id(entry["id"], seen_ids)
            seen_ids.add(entry["id"])
            cleaned.append(entry)
        for old in previous:
            if old["id"] in seen_ids:
                continue
            seen_ids.add(old["id"])
            # Upsert mode keeps a stored key the submission never mentioned.
            # An already-deleted row is kept too: it is read-only history.
            if upsert and old["id"] not in drop:
                # A submitted row may already carry this exact secret (the
                # stale submission re-sent it under a fresh id). Two live rows
                # with one secret is the duplicate this mode exists to avoid,
                # so the stale stored copy is retired instead.
                if old["key"] and old["key"] in seen:
                    cleaned.append(_retired_key_entry(old))
                    continue
                if old["key"]:
                    seen.add(old["key"])
                cleaned.append(old)
                continue
            cleaned.append(_retired_key_entry(old))
        data = load(accounts_dir)
        data["api_keys"] = cleaned
        # The single-key fields are now derived; drop them so there is one
        # source of truth and the list survives a restart.
        data.pop("api_key", None)
        data.pop("api_key_set", None)
        save(accounts_dir, data)
        return [e for e in cleaned if not e.get("deleted_at")]


def match_api_key(accounts_dir, supplied, extra_keys=()):
    """Find which configured key a request presented, if any.

    Returns a copy of the entry (with a `source` field), or None when nothing
    matches.
    """
    supplied = (supplied or "").strip()
    if not supplied:
        return None
    for entry in api_keys(accounts_dir):
        # A deleted entry is already stored with enabled=False; the explicit
        # check keeps a hand-edited settings file from reviving one.
        if entry["enabled"] and not entry.get("deleted_at") \
                and hmac.compare_digest(supplied, entry["key"]):
            out = dict(entry)
            out["source"] = "panel"
            return out
    for candidate in extra_keys:
        candidate = (candidate or "").strip()
        if candidate and hmac.compare_digest(supplied, candidate):
            return {
                "id": "launcher",
                "name": "启动参数",
                "key": candidate,
                "models": [],
                "enabled": True,
                "source": "launcher",
            }
    return None


def auth_disabled(accounts_dir):
    """True when the operator switched API-key checking off entirely."""
    return load(accounts_dir).get("auth_disabled") is True


def set_auth_disabled(accounts_dir, disabled):
    with _lock:
        data = load(accounts_dir)
        data["auth_disabled"] = bool(disabled)
        save(accounts_dir, data)


# ------------------------------------------------------------------ limits
# Three daily guards, one global number each. They used to carry a per-realm
# override from the two-egress era; only one egress exists now, so the panel
# and the pool both read and write a single value per guard.
LIMIT_KEYS = ("daily_token_limit", "daily_credit_limit",
              "model_daily_token_limit")
LIMITS_KEY = "limits"
LIMIT_DEFAULTS = {}


def _default_global(key):
    """The global value an install reads before it ever saves one."""
    try:
        return max(0, int(LIMIT_DEFAULTS.get(key, 0)))
    except (TypeError, ValueError):
        return 0


def _empty_limit_entry(key=None):
    """One guard: just the global default."""
    return {"global": _default_global(key)}


def _coerce_global(value):
    """A global threshold. Junk and negatives collapse to 0 (off), which is
    also what every install predating the setting reads as."""
    try:
        number = int(value or 0)
    except (TypeError, ValueError):
        number = 0
    return max(0, number)


def _fold_legacy_limits(data):
    """Move the flat top-level guards into `limits`.

    Returns (changed, limits). The old keys are dropped as they are folded in,
    so a later rollback cannot resurrect a stale limit from beside the grouped
    copy.
    """
    limits = {}
    changed = False
    for key in LIMIT_KEYS:
        entry = _empty_limit_entry(key)
        if key in data:
            entry["global"] = _coerce_global(data.pop(key))
            changed = True
        limits[key] = entry
    return changed, limits


def _normalize_limits(raw):
    """A copy of the stored map with every key filled in, so a partial or
    hand-edited settings.json still reads as a complete shape."""
    limits = {}
    for key in LIMIT_KEYS:
        entry = raw.get(key)
        if not isinstance(entry, dict):
            entry = {}
        global_raw = entry.get("global")
        # A missing global reads as that guard's default; an explicit 0 is a
        # real "off" and is kept as one, so a saved "off" never silently comes
        # back on.
        global_value = (_default_global(key) if global_raw is None
                        else _coerce_global(global_raw))
        limits[key] = {"global": global_value}
    return limits


def limits_data(accounts_dir):
    """The grouped limits map, migrating a flat pre-grouping file on first read.

    Reading is what upgrades: the first look at an old settings.json folds the
    four flat keys into `limits` and rewrites the file, so the rest of the
    gateway only ever sees one shape.
    """
    with _lock:
        data = load(accounts_dir)
        raw = data.get(LIMITS_KEY)
        if isinstance(raw, dict):
            return _normalize_limits(raw)
        changed, limits = _fold_legacy_limits(data)
        if changed:
            data[LIMITS_KEY] = limits
            try:
                save(accounts_dir, data)
            except Exception:
                # A read-only accounts dir must not take the panel down; the
                # folded values are still returned and the next read retries.
                pass
        return limits


def limit_value(accounts_dir, key, realm=None):
    """One guard's global value.

    ``realm`` is accepted and ignored: the per-realm override belonged to the
    two-egress era. An unknown key reads as 0 (off), so a typo cannot wedge the
    request path.
    """
    entry = limits_data(accounts_dir).get(key) or _empty_limit_entry()
    return entry.get("global") or 0


def limit_values_many(accounts_dir, keys):
    """Several guards resolved once, off one settings read.

    limit_values() per key re-reads the file (cached by mtime/size, so a stat)
    and re-normalizes the whole grouped map every call; the daily guards all
    want the same map on the request path, so they share one read here. One
    implementation only: limit_values() is this with a single key.
    """
    grouped = limits_data(accounts_dir)
    out = {}
    for key in keys:
        entry = grouped.get(key) or _empty_limit_entry()
        out[key] = {"global": entry.get("global") or 0}
    return out


def limit_values(accounts_dir, key):
    """One guard resolved to {"global": g}. Kept for the pool's per-key view."""
    return limit_values_many(accounts_dir, (key,))[key]


def daily_token_limit(accounts_dir, realm=None):
    """Global daily guard: an account that already burned this many tokens
    today stays idle until local midnight.

    Zero disables the guard, which keeps installs that predate the setting
    behaving exactly as before.
    """
    return limit_value(accounts_dir, "daily_token_limit", realm)


def daily_credit_limit(accounts_dir, realm=None):
    """Daily credit guard: an account that already spent this many credits
    today serves free models only until local midnight, so a client that
    would keep burning credits on paid models rotates to another account
    instead of spending the whole balance.

    Zero disables the guard, which keeps installs that predate the setting
    behaving exactly as before.
    """
    return limit_value(accounts_dir, "daily_credit_limit", realm)


def model_daily_token_limit(accounts_dir, realm=None):
    """Per-model daily guard: an account that already burned this many
    tokens today on ONE model stops being handed out for that model until
    local midnight, while every other model keeps working.

    Zero disables the guard, which keeps installs that predate the setting
    behaving exactly as before.
    """
    return limit_value(accounts_dir, "model_daily_token_limit", realm)


def section_max_height(accounts_dir):
    """Panel window height cap in pixels; 0 means no limit.

    Anything that is not a whole number falls back to the default, so a
    hand-edited settings.json cannot leave the dashboard with windows a pixel
    tall; a value past MAX_SECTION_MAX_HEIGHT is clamped, not rejected. bool is
    checked first on purpose: it is an int subclass, and True would otherwise
    read as a 1px cap.
    """
    with _lock:
        raw = load(accounts_dir).get(SECTION_MAX_HEIGHT_KEY)
    if isinstance(raw, bool):
        return DEFAULT_SECTION_MAX_HEIGHT
    try:
        value = int(raw)
    except (TypeError, ValueError, OverflowError):
        # OverflowError is its own case: json.loads turns 1e400 into inf, and
        # int(inf) raises it - one broken line must not 500 the settings view.
        return DEFAULT_SECTION_MAX_HEIGHT
    if value < 0:
        return DEFAULT_SECTION_MAX_HEIGHT
    return min(value, MAX_SECTION_MAX_HEIGHT)


def set_section_max_height(accounts_dir, value):
    """Persist the cap. Returns the stored value."""
    if isinstance(value, bool):
        number = DEFAULT_SECTION_MAX_HEIGHT
    else:
        try:
            number = int(value)
        except (TypeError, ValueError, OverflowError):
            number = DEFAULT_SECTION_MAX_HEIGHT
    number = max(0, min(MAX_SECTION_MAX_HEIGHT, number))
    with _lock:
        data = load(accounts_dir)
        data[SECTION_MAX_HEIGHT_KEY] = number
        save(accounts_dir, data)
    return number


def ui_language(accounts_dir):
    """Instance-wide default UI language (zh / zh-Hant / en)."""
    value = load(accounts_dir).get(UI_LANGUAGE_KEY)
    if isinstance(value, str) and value in UI_LANGUAGE_VALUES:
        return value
    return UI_LANGUAGE_DEFAULT


def set_ui_language(accounts_dir, value):
    """Persist the instance-wide default UI language."""
    if not isinstance(value, str) or value not in UI_LANGUAGE_VALUES:
        raise ValueError("ui_language must be zh, zh-Hant or en")
    with _lock:
        data = load(accounts_dir)
        data[UI_LANGUAGE_KEY] = value
        save(accounts_dir, data)
    return value


UPSTREAM_DEFAULTS = {
    "header_timeout_seconds": 120,
    "idle_timeout_seconds": 300,
    "device_token": "",
    "device_token_file": "",
}


def validate_upstream_patch(raw):
    """Strict validation for a panel-saved upstream patch."""
    out = {}
    for key, value in (raw or {}).items():
        if key in ("header_timeout_seconds", "idle_timeout_seconds"):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError("%s must be a whole number of seconds" % key)
            if value < 1:
                raise ValueError("%s cannot be less than 1" % key)
            out[key] = value
        elif key in ("device_token", "device_token_file"):
            if not isinstance(value, str):
                raise ValueError("%s must be a string" % key)
            out[key] = value.strip()
        else:
            raise ValueError("unknown upstream setting %r" % key)
    return out


def upstream_config(accounts_dir):
    """Chat socket timeouts and the optional X-Device-Token source."""
    stored = load(accounts_dir).get("upstream")
    stored = stored if isinstance(stored, dict) else {}
    out = {}
    for key, default in UPSTREAM_DEFAULTS.items():
        value = stored.get(key, default)
        if key in ("header_timeout_seconds", "idle_timeout_seconds"):
            out[key] = (value if isinstance(value, int) and not isinstance(value, bool)
                        and value >= 1 else default)
        else:
            out[key] = value.strip() if isinstance(value, str) else default
    return out


CODEARTS_DEFAULTS = {
    "concurrency": 2,       # 每个账号同时在跑的请求数（上游给 3 个会话名额，留 1 个余量）
    "session_ping": 30,     # 流式期间 busy 续期间隔（秒）
    "busy_cooldown": 5,     # 撞 TM.00001041（并发会话满）后晾多久
    "tpm_cooldown": 20,     # 撞 ModelArts.811（TPM 限流）后晾多久
    # 流式读的心跳间隔与静默次数上限。这两个以前只读环境变量/模块常量，
    # 面板改了不生效 —— 实际静默上限永远是 15 s × 40 = 600 s。
    # 0 表示「关掉看门狗」，但 ca_codearts.IDLE_HARD_CEILING 仍有一道物理上限。
    "stream_idle": 15,
    "stream_max_idle": 40,
    # 模型健康降级链（学习官方 smart-router + flagship/fallback 标签制）：
    # 请求的模型连败进熔断时，按这条链换成第一个健康的模型。空串 = 关掉换模，
    # 只保留健康度展示。链里的段用逗号分隔，模型 id 必须能过 _FALLBACK_NAME_RE。
    "model_fallbacks": "glm-5.3,openpangu-2.0-flash,deepseek-v4.1-flash",
    "model_fallback_enabled": True,
}

#: 非数值型的 codearts 键：bool 与字符串各一张表，validate/config 分支用。
CODEARTS_BOOL_KEYS = {"model_fallback_enabled"}
CODEARTS_STR_KEYS = {"model_fallbacks"}
import re as _re
_FALLBACK_NAME_RE = _re.compile(r"^[A-Za-z0-9._-]+$")

#: 每个键对应的环境变量。**面板没设过这个键时**才用它。
#:
#: 以前 codearts_config() 直接拿 CODEARTS_DEFAULTS 兜底，环境变量只在
#: ca_proxy 的模块级常量里读了一次 —— 而 codearts_tuning() 读的永远是
#: settings（合并后必有一个值），于是 CODEARTS_CONCURRENCY 这类变量设了也不
#: 生效。现在把它们放进同一个合并顺序里：面板 > 环境变量 > 内置默认。
CODEARTS_ENV_KEYS = {
    "concurrency": "CODEARTS_CONCURRENCY",
    "session_ping": "CODEARTS_SESSION_PING",
    "busy_cooldown": "CODEARTS_BUSY_COOLDOWN",
    "tpm_cooldown": "CODEARTS_TPM_COOLDOWN",
    "stream_idle": "CODEARTS_STREAM_IDLE",
    "stream_max_idle": "CODEARTS_STREAM_MAX_IDLE",
}

#: 每个键的合法区间。面板可以调，但别让一次手滑把网关配成不可用。
#:
#: ``concurrency`` 上限是 **3**：上游每个账号只给 3 个会话名额，配到 4 以上
#: 必然撞 TM.00001041（以前面板允许 1~8，设 4 就等于每次都有一路在撞限流）。
CODEARTS_RANGES = {
    "concurrency": (1, 3),
    "session_ping": (5, 600),
    "busy_cooldown": (1, 300),
    "tpm_cooldown": (5, 3600),
    "stream_idle": (1, 300),
    "stream_max_idle": (0, 600),
}


def _codearts_env_default(key):
    """环境变量给的默认值；没设 / 坏值返回 None。"""
    import os as _os
    name = CODEARTS_ENV_KEYS.get(key)
    if not name:
        return None
    raw = _os.environ.get(name)
    if raw is None or raw == "":
        return None
    try:
        return int(float(raw))
    except (TypeError, ValueError):
        return None


def validate_codearts_patch(raw):
    """Strict validation for a panel-saved codearts tuning patch."""
    out = {}
    for key, value in (raw or {}).items():
        if key not in CODEARTS_DEFAULTS:
            raise ValueError("unknown codearts setting %r" % key)
        if key in CODEARTS_BOOL_KEYS:
            if not isinstance(value, bool):
                raise ValueError("%s must be a boolean" % key)
            out[key] = value
            continue
        if key in CODEARTS_STR_KEYS:
            text = str(value or "").strip()
            segs = []
            for seg in text.split(","):
                seg = seg.strip()
                if not seg:
                    continue
                if not _FALLBACK_NAME_RE.match(seg):
                    raise ValueError(
                        "%s contains an invalid model id %r" % (key, seg))
                segs.append(seg)
            out[key] = ",".join(segs)   # 规范化：去空白、去空段
            continue
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("%s must be a whole number" % key)
        low, high = CODEARTS_RANGES[key]
        if not low <= value <= high:
            raise ValueError("%s must be between %d and %d" % (key, low, high))
        out[key] = value
    return out


def codearts_config(accounts_dir):
    """码道并发 / 续期 / 冷却的可调项。

    优先级：**面板保存的值 > 环境变量 > 内置默认**。三者都过一遍区间校验，
    坏值一律退回下一级 —— 手改 settings.json 塞进 999 也不会把上游那 3 个
    会话名额一次打穿。
    """
    stored = load(accounts_dir).get("codearts")
    stored = stored if isinstance(stored, dict) else {}
    out = {}
    for key, default in CODEARTS_DEFAULTS.items():
        if key in CODEARTS_BOOL_KEYS:
            value = stored.get(key)
            out[key] = value if isinstance(value, bool) else default
            continue
        if key in CODEARTS_STR_KEYS:
            value = stored.get(key)
            out[key] = value if isinstance(value, str) else default
            continue
        low, high = CODEARTS_RANGES[key]
        value = stored.get(key)
        if not (isinstance(value, int) and not isinstance(value, bool)
                and low <= value <= high):
            value = _codearts_env_default(key)
        if not (isinstance(value, int) and not isinstance(value, bool)
                and low <= value <= high):
            value = default
        out[key] = value
    return out


def set_codearts_config(accounts_dir, cfg):
    """Persist the codearts tuning. Returns the stored config."""
    current = codearts_config(accounts_dir)
    if isinstance(cfg, dict):
        current.update({k: v for k, v in cfg.items() if k in CODEARTS_DEFAULTS})
    clean = validate_codearts_patch(current)
    with _lock:
        data = load(accounts_dir)
        data["codearts"] = deep_merge(data.get("codearts"), clean)
        save(accounts_dir, data)
    return clean


def set_upstream_config(accounts_dir, cfg):
    """Persist the upstream settings. Returns the stored config."""
    current = upstream_config(accounts_dir)
    if isinstance(cfg, dict):
        current.update({k: v for k, v in cfg.items() if k in UPSTREAM_DEFAULTS})
    clean = validate_upstream_patch(current)
    with _lock:
        data = load(accounts_dir)
        data["upstream"] = deep_merge(data.get("upstream"), clean)
        save(accounts_dir, data)
    return clean


USAGE_DEFAULTS = {
    "hour_keep_hours": 48,
    "day_keep_days": 32,
}

# 上限只是防手滑：面板输入框贴错位数会把 checkpoint 撑到几百 MB，而它每推进
# 一点就要整份重写——路由器上 flash 写入慢且费寿命。两周的小时层、一年的日桶
# 已经远超任何窗口够得到的范围。
USAGE_LIMITS = {
    "hour_keep_hours": 24 * 14,
    "day_keep_days": 366,
}

def validate_usage_patch(raw):
    """Strict validation for a panel-saved aggregate-retention patch."""
    out = {}
    for key, value in (raw or {}).items():
        if key not in USAGE_DEFAULTS:
            raise ValueError("unknown usage setting %r" % key)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("%s must be a whole number" % key)
        if value < 1:
            raise ValueError("%s cannot be less than 1" % key)
        if value > USAGE_LIMITS[key]:
            raise ValueError("%s cannot be more than %d" % (key, USAGE_LIMITS[key]))
        out[key] = value
    return out

def usage_config(accounts_dir):
    """聚合保留窗口（小时层 / 日桶）。面板没设过就是内置默认值。"""
    stored = load(accounts_dir).get("usage")
    stored = stored if isinstance(stored, dict) else {}
    out = {}
    for key, default in USAGE_DEFAULTS.items():
        value = stored.get(key, default)
        if (isinstance(value, bool) or not isinstance(value, int)
                or value < 1 or value > USAGE_LIMITS[key]):
            value = default
        out[key] = value
    return out

def set_usage_config(accounts_dir, patch):
    """Persist a validated aggregate-retention patch."""
    clean = validate_usage_patch(patch)
    with _lock:
        data = load(accounts_dir)
        data["usage"] = deep_merge(data.get("usage"), clean)
        save(accounts_dir, data)
    return clean

PROMPT_DEFAULTS = {
    "mode": "passthrough",
    "file": "",
}


def validate_prompt_patch(raw):
    """Strict validation for a panel-saved prompt patch."""
    out = {}
    for key, value in (raw or {}).items():
        if key == "mode":
            if not isinstance(value, str):
                raise ValueError("prompt mode must be a string")
            mode = value.strip().lower()
            if mode not in ("passthrough", "custom", "append"):
                raise ValueError("prompt mode must be passthrough, custom or append")
            out["mode"] = mode
        elif key == "file":
            if not isinstance(value, str):
                raise ValueError("prompt file must be a string")
            out["file"] = value.strip()
        else:
            raise ValueError("unknown prompt setting %r" % key)
    return out


def prompt_config(accounts_dir):
    """Gateway system-prompt mode (default passthrough = legacy behaviour)."""
    stored = load(accounts_dir).get("prompt")
    stored = stored if isinstance(stored, dict) else {}
    mode = stored.get("mode", PROMPT_DEFAULTS["mode"])
    if not isinstance(mode, str) or mode.strip().lower() not in (
            "passthrough", "custom", "append"):
        mode = PROMPT_DEFAULTS["mode"]
    else:
        mode = mode.strip().lower()
    file_path = stored.get("file", PROMPT_DEFAULTS["file"])
    if not isinstance(file_path, str):
        file_path = PROMPT_DEFAULTS["file"]
    return {"mode": mode, "file": file_path.strip()}


def set_prompt_config(accounts_dir, cfg):
    """Persist the prompt settings. Returns the stored config."""
    current = prompt_config(accounts_dir)
    if isinstance(cfg, dict):
        current.update({k: v for k, v in cfg.items() if k in PROMPT_DEFAULTS})
    clean = validate_prompt_patch(current)
    with _lock:
        data = load(accounts_dir)
        data["prompt"] = clean
        save(accounts_dir, data)
    return clean


def enable_anthropic_messages(accounts_dir):
    """Whether Anthropic Messages compatibility layer is enabled via panel settings."""
    return load(accounts_dir).get("enable_anthropic_messages") is True


def set_enable_anthropic_messages(accounts_dir, enabled):
    """Persist the Anthropic Messages toggle. Returns the stored boolean."""
    enabled = bool(enabled)
    with _lock:
        data = load(accounts_dir)
        data["enable_anthropic_messages"] = enabled
        save(accounts_dir, data)
    return enabled


def egress_backoff_enabled(accounts_dir):
    """Whether transient failures are accounted per egress instead of per account.

    Off unless the operator turns it on. Turning it on changes how a transport
    failure or a 502/503/504 is punished: it stops feeding the account breaker
    (30 minutes, doubling to 6h) and instead grows a seconds-level backoff on the
    outbound path the request actually used (see ca_egress). That is the fix for
    issue #271 - a few seconds of link flakiness used to park healthy accounts
    for half an hour - but it is a change to dispatch behaviour, so an install
    that predates the switch keeps the old accounting.
    """
    return load(accounts_dir).get(EGRESS_BACKOFF_ENABLED_KEY) is True


def set_egress_backoff_enabled(accounts_dir, enabled):
    """Persist the egress-level backoff switch. Returns the stored boolean."""
    enabled = bool(enabled)
    with _lock:
        data = load(accounts_dir)
        data[EGRESS_BACKOFF_ENABLED_KEY] = enabled
        save(accounts_dir, data)
    return enabled


def log_db_enabled(accounts_dir):
    """Whether runtime logs are also appended to usage/logs.sqlite3.

    Off unless the operator turns it on: with the switch off the log lives only
    in the in-memory ring, exactly as it does upstream, and no database file is
    created. Turning it on starts a durable copy so a crash, a restart or a
    slow-moving incident can still be read back afterwards.
    """
    return load(accounts_dir).get(LOG_DB_ENABLED_KEY) is True


def set_log_db_enabled(accounts_dir, enabled):
    """Persist the log-database switch. Returns the stored boolean."""
    enabled = bool(enabled)
    with _lock:
        data = load(accounts_dir)
        data[LOG_DB_ENABLED_KEY] = enabled
        save(accounts_dir, data)
    return enabled


def _positive_cap(raw, fallback, hard_max):
    """One retention cap read back: a positive whole number, clamped.

    Anything that is not a usable positive integer (a bool, text, 0, a negative,
    a hand-edited 1e400) falls back instead of raising - a broken settings.json
    must not take the log path down with it.
    """
    if isinstance(raw, bool):
        return fallback
    try:
        value = int(raw)
    except (TypeError, ValueError, OverflowError):
        return fallback
    if value <= 0:
        return fallback
    return min(value, hard_max)


def _clearable_cap(value, hard_max):
    """One retention cap on its way to disk: blank or nonsense means "no cap".

    The panel posts an empty string for a field the operator cleared, and 0 is
    the same intent typed out. Both land as None (JSON null), which is what the
    getters read back as "unlimited on this axis".
    """
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if number <= 0:
        return None
    return min(number, hard_max)


def log_db_max_rows(accounts_dir):
    """Newest-N row cap for the log database; None means no row cap.

    Absent key reads as None: a fresh install keeps every row until the days
    cap trims it, which is what "rows left blank" asks for.
    """
    data = load(accounts_dir)
    if LOG_DB_MAX_ROWS_KEY not in data:
        return None
    raw = data.get(LOG_DB_MAX_ROWS_KEY)
    if raw is None:
        return None
    return _positive_cap(raw, None, MAX_LOG_DB_MAX_ROWS)


def set_log_db_max_rows(accounts_dir, value):
    """Persist the row cap (blank clears it). Returns the stored value."""
    stored = _clearable_cap(value, MAX_LOG_DB_MAX_ROWS)
    with _lock:
        data = load(accounts_dir)
        data[LOG_DB_MAX_ROWS_KEY] = stored
        save(accounts_dir, data)
    return stored


def log_db_max_days(accounts_dir):
    """Age cap for the log database, in days; None means no age cap.

    Unlike the other two, an absent key reads as the 7-day default: an install
    that has never touched the setting still gets a bounded database. Clearing
    the field on purpose stores None and turns the cap off.
    """
    data = load(accounts_dir)
    if LOG_DB_MAX_DAYS_KEY not in data:
        return DEFAULT_LOG_DB_MAX_DAYS
    raw = data.get(LOG_DB_MAX_DAYS_KEY)
    if raw is None:
        return None
    return _positive_cap(raw, DEFAULT_LOG_DB_MAX_DAYS, MAX_LOG_DB_MAX_DAYS)


def set_log_db_max_days(accounts_dir, value):
    """Persist the age cap (blank clears it). Returns the stored value."""
    stored = _clearable_cap(value, MAX_LOG_DB_MAX_DAYS)
    with _lock:
        data = load(accounts_dir)
        data[LOG_DB_MAX_DAYS_KEY] = stored
        save(accounts_dir, data)
    return stored


def log_db_max_bytes(accounts_dir):
    """File-size cap for the log database, in bytes; None means no size cap.

    Absent key reads as None, like the row cap: the days default is what keeps
    a fresh install bounded, and the size cap is there for a deployment that
    wants a hard ceiling on the file itself.
    """
    data = load(accounts_dir)
    if LOG_DB_MAX_BYTES_KEY not in data:
        return None
    raw = data.get(LOG_DB_MAX_BYTES_KEY)
    if raw is None:
        return None
    return _positive_cap(raw, None, MAX_LOG_DB_MAX_BYTES)


def set_log_db_max_bytes(accounts_dir, value):
    """Persist the size cap (blank clears it). Returns the stored value."""
    stored = _clearable_cap(value, MAX_LOG_DB_MAX_BYTES)
    with _lock:
        data = load(accounts_dir)
        data[LOG_DB_MAX_BYTES_KEY] = stored
        save(accounts_dir, data)
    return stored


def accounts_collapsed(accounts_dir):
    """Whether the panel's account section is collapsed.

    Expanded unless the stored value is the boolean true. `is True` is the whole
    normalisation: a hand-edited "false", a 1, an object or a missing key all
    read as expanded, so none of them can hide the accounts by accident. The
    panel only ever writes a real boolean through set_accounts_collapsed.
    """
    return load(accounts_dir).get(ACCOUNTS_COLLAPSED_KEY) is True


def set_accounts_collapsed(accounts_dir, collapsed):
    """Persist the account-section disclosure state. Returns the stored boolean."""
    collapsed = bool(collapsed)
    with _lock:
        data = load(accounts_dir)
        data[ACCOUNTS_COLLAPSED_KEY] = collapsed
        save(accounts_dir, data)
    return collapsed


def key_before_hidden(accounts_dir):
    """Whether the per-API-key table folds away its `(切换前)` row.

    Shown unless the stored value is the boolean true, with the same `is True`
    normalisation as accounts_collapsed: the row is history worth seeing, so a
    hand-edited "false", a 1, an object or a missing key must all leave it
    visible rather than hide it by accident.
    """
    return load(accounts_dir).get(KEY_BEFORE_HIDDEN_KEY) is True


def set_key_before_hidden(accounts_dir, hidden):
    """Persist the `(切换前)` row disclosure state. Returns the stored boolean."""
    hidden = bool(hidden)
    with _lock:
        data = load(accounts_dir)
        data[KEY_BEFORE_HIDDEN_KEY] = hidden
        save(accounts_dir, data)
    return hidden


def _clean_page_keys(value):
    """Normalise a stored or patched page list into a clean list of keys.

    Anything that is not a list of well-formed keys is dropped rather than
    rejected, for the same reason the booleans above normalise instead of
    raising: the file is hand-editable, and the fail-safe direction for a
    display preference is "nothing hidden". Duplicates and over-long lists are
    collapsed so a hand edit cannot turn the panel's nav into a repeat of one
    entry.
    """
    if not isinstance(value, (list, tuple)):
        return []
    out = []
    for item in value:
        if not isinstance(item, str):
            continue
        key = item.strip()
        if not PAGE_KEY_RE.match(key) or key == PAGE_KEEP_VISIBLE or key in out:
            continue
        out.append(key)
        if len(out) >= MAX_HIDDEN_PAGES:
            break
    return out


def hidden_pages(accounts_dir):
    """The top-bar pages the panel hides. Empty on a fresh install.

    Normalised on every read, so a hand edit that puts a string, an unknown key
    or a duplicate in the file cannot hide a page twice or hide something the
    panel would then be unable to put back.
    """
    return _clean_page_keys(load(accounts_dir).get(HIDDEN_PAGES_KEY))


def set_hidden_pages(accounts_dir, pages):
    """Persist the hidden-page list. Returns the stored (normalised) list."""
    cleaned = _clean_page_keys(pages)
    with _lock:
        data = load(accounts_dir)
        data[HIDDEN_PAGES_KEY] = cleaned
        save(accounts_dir, data)
    return cleaned


def accounts_separate_tab(accounts_dir):
    """Whether the panel gives the account sections a main tab of their own.

    Off unless the stored value is the boolean true, with the same `is True`
    normalisation as the disclosures above: the merged "网关与账号" tab is what
    every install has always shown, so a hand-edited "false", a 1, an object or
    a missing key must all keep it rather than split the nav by accident.
    """
    return load(accounts_dir).get(ACCOUNTS_SEPARATE_TAB_KEY) is True


def set_accounts_separate_tab(accounts_dir, separate):
    """Persist the account-tab switch. Returns the stored boolean."""
    separate = bool(separate)
    with _lock:
        data = load(accounts_dir)
        data[ACCOUNTS_SEPARATE_TAB_KEY] = separate
        save(accounts_dir, data)
    return separate


def update_check_enabled(accounts_dir):
    """Whether the gateway checks for a newer release once a day.

    Off unless the operator turns it on, and off for an install that predates
    the key: this is the one setting here whose missing value means "no", since
    enabling it makes the gateway talk to GitHub on its own schedule. The manual
    check in the panel ignores this switch entirely.
    """
    return load(accounts_dir).get(UPDATE_CHECK_ENABLED_KEY) is True


def set_update_check_enabled(accounts_dir, enabled):
    """Persist the daily-check switch. Returns the stored boolean."""
    enabled = bool(enabled)
    with _lock:
        data = load(accounts_dir)
        data[UPDATE_CHECK_ENABLED_KEY] = enabled
        save(accounts_dir, data)
    return enabled


def update_check_state(accounts_dir):
    """The last-check bookkeeping: when it ran, and the version it saw.

    Deliberately three fields. The 24h cadence needs `last_attempt` to survive a
    restart, and `latest_version` is what lets the panel answer right after one;
    everything else about a check lives in memory. Nothing from the HTTP
    exchange - URL, headers, body - is ever stored here.
    """
    stored = load(accounts_dir).get(UPDATE_CHECK_STATE_KEY)
    stored = stored if isinstance(stored, dict) else {}
    out = {"last_attempt": 0.0, "last_success": 0.0, "latest_version": ""}
    for key in ("last_attempt", "last_success"):
        value = stored.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
            out[key] = float(value)
    version = stored.get("latest_version")
    if isinstance(version, str):
        out["latest_version"] = version.strip()[:32]
    return out


def record_update_check(accounts_dir, at=None, success=False, latest_version=""):
    """Write one check's outcome. Returns the stored state.

    One narrow write path on purpose: a checker that could write arbitrary keys
    into settings.json would turn it into an update-state database, which is
    what this is meant not to become.
    """
    stamp = float(at if at is not None else time.time())
    with _lock:
        data = load(accounts_dir)
        state = data.get(UPDATE_CHECK_STATE_KEY)
        state = dict(state) if isinstance(state, dict) else {}
        state["last_attempt"] = stamp
        if success:
            state["last_success"] = stamp
        version = str(latest_version or "").strip()[:32]
        if version:
            state["latest_version"] = version
        data[UPDATE_CHECK_STATE_KEY] = state
        save(accounts_dir, data)
    return update_check_state(accounts_dir)


class PanelSessions(object):
    """In-memory bearer tokens handed out after a successful panel login.

    Deliberately not persisted: restarting the gateway logs browsers out, which
    is the safer default for a LAN tool that people expose behind a port map.
    """

    def __init__(self, ttl=SESSION_TTL):
        self.ttl = ttl
        self._tokens = {}
        self._lock = threading.RLock()

    def create(self):
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._tokens[token] = time.time() + self.ttl
        return token

    def valid(self, token):
        if not token:
            return False
        with self._lock:
            expiry = self._tokens.get(token)
            if not expiry:
                return False
            if expiry < time.time():
                self._tokens.pop(token, None)
                return False
            return True

    def revoke(self, token):
        if not token:
            return
        with self._lock:
            self._tokens.pop(token, None)

    def revoke_all(self):
        with self._lock:
            self._tokens.clear()
