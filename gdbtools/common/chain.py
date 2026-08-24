"""`chain` -- a depth-bounded pointer telescope, and the engine behind it.

Target-independent: it follows ordinary pointers through whatever memory gdb can
read.  The physical mode (`phys=True`) is only reachable when the kernel side is
loaded, and degrades to nothing when it is not.
"""
import gdb

from .runtime import *
from . import state
from .symbolize import resolve, short


def _read_phys_u64(pa):
    """Physical read, when the kernel side provides one.  None otherwise."""
    try:
        from ..linux_kernel.physmem import read_phys_u64
    except Exception:
        return None
    return read_phys_u64(pa)


@safe(default=None)
def safe_chain(addr, phys=False, hops=None):
    """A self-bounded pointer telescope that CANNOT overflow gdb's C stack.
    pwndbg's own `chain` is unusable on a page-table-base register: it does not
    know the value is a PGD, so it follows the descriptor words as if they were an
    ordinary pointer chain (0x41200000 -> 0x41201003 -> 0x41202003 -> ...) straight
    down the table tree until the process dies.  This telescope instead follows at
    most `hops` links, reading VIRTUAL (evi) or PHYSICAL (_read_phys_u64) memory,
    stopping on unreadable / zero / a repeated address (cycle), and symbolizes each
    hop -- giving the familiar 'a -> b -> c' look with a hard depth bound.  For a
    page-table base pass phys=True: each descriptor's flag bits are stripped so the
    walk follows the real next-table base (PGD -> PUD -> PMD ...).  The default hop
    count is the session's `chain_hops` (set live with `kearly chaindepth N`)."""
    if addr is None:
        return None
    if hops is None:
        hops = getattr(state.session(), "chain_hops", 6)
    hops = max(1, min(int(hops), 256))          # hard clamp: always finite
    if phys:
        rd = _read_phys_u64
        nxtf = lambda v: v & ((1 << 48) - 1) & ~0xFFF
    else:
        rd = lambda a: evi("*(unsigned long long *)0x%x" % (a & MASK))
        nxtf = lambda v: v & MASK
    out, seen, cur = [], set(), addr & MASK
    for _ in range(max(1, hops)):
        sym = ""
        res = resolve(cur)
        if res and res[2]:
            sym = " <%s>" % res[2].split(" in section")[0].strip()
        out.append("0x%x%s" % (cur, sym))
        if cur in seen:
            out.append("(cycle)")
            break
        seen.add(cur)
        val = rd(cur)
        if val is None:
            break
        nxt = nxtf(val)
        if nxt == 0:
            out.append("0x0")
            break
        cur = nxt
    return "  ->  ".join(out)


class Chain(gdb.Command):
    """chain [ADDR] [N] : telescope N machine words starting at ADDR (default $sp),
following each pointer and naming what it lands on.  Bounded and cycle-guarded,
so it is safe on a value that is not really a pointer chain.  With a kernel
session loaded the physical/virtual side of each hop is reported too."""

    def __init__(self, name="chain"):
        super(Chain, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        parts = (arg or "").split()
        addr = evi(parts[0]) if parts else None
        n = 8
        if len(parts) > 1:
            try:
                n = int(parts[1], 0)
            except Exception:
                pass
        if addr is None:
            addr = reg("sp")
        if addr is None:
            print("[%s] no address, and $sp is unavailable. usage: chain ADDR [N]" % NAME)
            return
        for i in range(max(1, min(n, 64))):
            slot = (addr + i * 8) & MASK
            val = evi("*(unsigned long long *)0x%x" % slot)
            if val is None:
                print("%02d:%04x  %s  <unreadable>" % (i, i * 8, fmt(slot)))
                continue
            res = resolve(val)
            sym = ""
            if res and res[2]:
                sym = "  %s %s" % (res[0], short(res[2]))
            print("%02d:%04x| %s%s" % (i, i * 8, safe_chain(val) or fmt(val), sym))


__all__ = ["safe_chain", "Chain"]
