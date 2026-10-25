"""The isolated data root the suites were each building by hand.

Nine suites opened with the same six lines: a TemporaryDirectory, an atexit
cleanup, `accounts/` and `usage/` beneath it, and the two environment overrides
that point the gateway at them. That is the whole duplication this module
removes.

It is a function the suite calls at the top of its own file rather than an
import side effect, because the overrides have to land before the first module
that snapshots them is imported - and only the suite knows where that is.

It returns the TemporaryDirectory rather than the paths, so a caller keeps
writing `_TMP.name` for the suite-specific stores it puts next to `accounts/`
and `usage/`. Where a suite keeps its mutable state stays visible in the suite.

`patched_state` is the second shared shape: a suite swaps gateway globals for
the duration of one check. The hand-written save/restore pairs those swaps used
before come in two halves, and a suite that grows past its author's memory of
it restores only one - leaving the dirty value for every later check in the
same process. This closes the pair by construction.
"""
import atexit
import contextlib
import os
import tempfile


@contextlib.contextmanager
def patched_state(module, **overrides):
    """Swap module globals inside the with-block; restore them on any exit.

    Reads every attribute BEFORE the first write, so a typo'd name fails on
    entry instead of half-applying. Nested patches restore in reverse order
    naturally (inner block's saved values are the outer block's overrides).
    """
    saved = {name: getattr(module, name) for name in overrides}
    for name, value in overrides.items():
        setattr(module, name, value)
    try:
        yield
    finally:
        for name, value in saved.items():
            setattr(module, name, value)


def isolated_data_dirs(prefix):
    """An isolated ACCOUNTS_DIR + WB_PROXY_USAGE_DIR, removed at process exit.

    The two overrides are assignments, never `setdefault`: a value already in
    the environment belongs to whatever started this process, and inheriting it
    would put several suites back on one directory.
    """
    tmp = tempfile.TemporaryDirectory(prefix=prefix)
    atexit.register(tmp.cleanup)
    accounts = os.path.join(tmp.name, "accounts")
    usage = os.path.join(tmp.name, "usage")
    os.makedirs(accounts, exist_ok=True)
    os.makedirs(usage, exist_ok=True)
    os.environ["ACCOUNTS_DIR"] = accounts
    os.environ["WB_PROXY_USAGE_DIR"] = usage
    return tmp
