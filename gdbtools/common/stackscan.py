"""`stackscan` -- read the stack word by word and name what looks like a pointer."""
import gdb

from .runtime import *
from . import state
from .symbolize import resolve


class StackScan(gdb.Command):
    """stackscan [N] : read N machine words from $sp and name every value that
resolves to a symbol.

This is a scan of stack memory, not a frame unwind -- it is what is left when
`backtrace` cannot work, which in a kernel means early assembly before a frame
pointer exists, and in userspace means a corrupted or missing frame chain."""

    def __init__(self, name="stackscan"):
        super(StackScan, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        n = 32
        if arg.strip():
            try:
                n = int(arg.strip(), 0)
            except Exception:
                pass
        sp = reg("sp")
        if sp is None:
            print("[%s] no $sp on this target" % NAME)
            return
        if not sp:
            print("[%s] $sp is %s -- no stack has been set up yet." % (NAME, fmt(sp)))
            sess = state.session()
            if sess is not None and getattr(sess, "enabled", False):
                print("      Right now: %s." % sess.regime_phrase())
                arch = sess.ensure_arch()
                hint = getattr(arch, "stack_setup_hint", None)
                hint = hint() if hint else None
                if hint:
                    print("      %s" % hint)
                print("      `kearly regimes` shows where that is for this build.")
            return
        hits = 0
        for i in range(n):
            val = evi("*(unsigned long long *)0x%x" % ((sp + i * 8) & MASK))
            if val is None:
                continue
            res = resolve(val)
            if res and res[2]:
                print("  [sp+0x%03x] %s  %s  %s" % (i * 8, fmt(val), res[0], res[2]))
                hits += 1
        if hits == 0:
            print("[%s] no symbolizable pointers in %d words from $sp" % (NAME, n))


__all__ = ["StackScan"]
