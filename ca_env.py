"""ca_env.py —— 数值型环境变量的统一读法（只依赖标准库）。

为什么需要一个单独的小模块：散在各处的 ``float(os.environ.get("X") or 30.0)``
有两个毛病，都是线上真实踩过的：

1. **设成非数字就启动即崩**。``CODEARTS_SLOT_WAIT=20s``（带单位）或一个手滑的
   空格，会让 ``ca_proxy`` 在 import 阶段抛 ``ValueError``，网关连端口都没开始
   监听 —— 报错栈指向一行常量，看不出是哪个环境变量。
2. **设成 "0" 悄悄关掉功能**。``os.environ.get("X") or 30.0`` 里 ``"0"`` 是
   非空字符串（真值），于是 ``float("0")`` 得 0 —— 一个「没打算改」的 0 变成了
   「关掉超时」。反过来，真的 0 也有它的语义（比如流式重开次数 0 = 不重开），
   所以不能一刀切。

这里的规则：**没设 / 空串 / 解析不出来 / 小于下限，一律回落到默认值**；只有
调用方显式声明 ``zero_ok=True`` 时 0 才是合法值。于是「0 关功能」只保留在那些
0 真的有意义的开关上，其余位置设 0 等于没设 —— 与运维的直觉一致。
"""
import os

_TRUE = ("1", "true", "yes", "on", "y")
_FALSE = ("0", "false", "no", "off", "n")


def text(name, default=""):
    """字符串型环境变量：没设或只有空白时用默认值。"""
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    return str(raw).strip()


def number(name, default, minimum=None, integer=False, zero_ok=False):
    """数值型环境变量；任何不可用的值都回落到默认值，绝不抛异常。

    ``minimum`` 是下限，``integer`` 决定返回 int 还是 float，``zero_ok``
    表示 0 本身是合法取值（默认不合法：0 秒超时、0 并发都没有意义）。
    """
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        value = int(str(raw).strip()) if integer else float(str(raw).strip())
    except (TypeError, ValueError):
        return default
    if not zero_ok and value == 0:
        return default
    if minimum is not None and value < minimum:
        return default
    return value


def flag(name, default):
    """布尔型开关：认 1/0、true/false、yes/no、on/off，认不出来用默认值。

    这里的 0 是「明确关闭」，不是「没设」—— 开关类变量的 0 本来就只有一个
    意思，和 ``number()`` 的语义不同。
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    text_value = str(raw).strip().lower()
    if text_value in _TRUE:
        return True
    if text_value in _FALSE:
        return False
    return default
