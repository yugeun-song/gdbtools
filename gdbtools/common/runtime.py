"""part of gdbtools; see the package docstring."""
import json
import struct
import gdb
import os
import re

MASK = (1 << 64) - 1
NAME = "gdbtools"


# ----------------------------------------------------------------------------
# Safety layer: nothing here is allowed to throw into the gdb session.
# ----------------------------------------------------------------------------
class _Ring:
    def __init__(self, cap=300):
        self.buf, self.cap = [], cap

    def add(self, msg):
        self.buf.append(msg)
        if len(self.buf) > self.cap:
            self.buf = self.buf[-self.cap:]

    def dump(self, n=40):
        return "\n".join(self.buf[-n:]) if self.buf else "(empty)"


LOG = _Ring()


def safe(default=None):
    """Decorator: swallow every exception, log it, return `default`."""
    def deco(fn):
        def wrap(*a, **k):
            try:
                return fn(*a, **k)
            except Exception as e:                      # deliberately catch-all
                LOG.add("[%s] %s: %s" % (getattr(fn, "__name__", "?"),
                                         type(e).__name__, e))
                return default
        wrap.__name__ = getattr(fn, "__name__", "wrapped")
        return wrap
    return deco


@safe(default=None)
def ev(expr):
    """gdb.parse_and_eval(expr) -> gdb.Value, or None on any error."""
    return gdb.parse_and_eval(expr)


def evi(expr):
    """Evaluate -> python int masked to 64 bits, or None."""
    v = ev(expr)
    if v is None:
        return None
    try:
        return int(v) & MASK
    except Exception:
        u = ev("(unsigned long long)(%s)" % expr)
        try:
            return int(u) & MASK if u is not None else None
        except Exception:
            return None


@safe(default="")
def execstr(cmd):
    """gdb.execute(cmd, to_string=True) -> str ('' on failure)."""
    return gdb.execute(cmd, from_tty=False, to_string=True)


def exec_confirmless(cmd):
    """Run a command with `confirm` temporarily off, then restore it."""
    try:
        prev = gdb.parameter("confirm")
    except Exception:
        prev = None
    execstr("set confirm off")
    try:
        return execstr(cmd)
    finally:
        if prev is not None:
            execstr("set confirm %s" % ("on" if prev else "off"))


def reg(name):
    """Read a register / convenience var as a 64-bit int, or None."""
    return evi("$" + name)


def symval(name):
    """Address (&name) of a symbol as int, or None if the symbol is unknown."""
    return evi("(unsigned long long)&%s" % name)


def fmt(x):
    return ("0x%016x" % (x & MASK)) if isinstance(x, int) else str(x)


def _h(x):
    """Short hex for the compact context line, or '?' if the value is unreadable."""
    return ("0x%x" % (x & MASK)) if isinstance(x, int) else "?"


@safe(default=None)
def read_guest_bytes(pa, n):
    """Read `n` bytes of GUEST memory at physical/linear address `pa`.
    Works while the MMU is off (the gdbstub reads physical).  Host-side safe:
    this only reads, never writes."""
    if pa is None or n <= 0 or n > (16 << 20):
        return None
    inf = gdb.selected_inferior()
    return bytes(inf.read_memory(pa & MASK, n))


@safe(default=None)
def monitor_reg(name):
    """Best-effort: read a register the gdbstub hides, via QEMU monitor HMP.

    `monitor` tunnels to QEMU's human monitor through the gdbstub (qRcmd), so
    this works even when the register is absent from gdb's register set.  On a
    non-QEMU stub `monitor` simply fails and we degrade to None.
    """
    out = execstr("monitor info registers")
    if not out:
        return None
    pat = r"\b%s\b\s*[=:]?\s*(?:0x)?([0-9a-fA-F]{1,16})" % re.escape(name)
    m = re.search(pat, out, re.IGNORECASE)
    if not m:
        return None
    try:
        return int(m.group(1), 16) & MASK
    except Exception:
        return None


# Configuration reaches this package one way: a GDBTOOLS_-prefixed environment
# variable set by whoever launched gdb.  Nothing here searches for a value it was
# not given, and there is no second spelling to fall back to -- a name that is
# almost right must fail, not quietly resolve to something else.  Pass the bare
# suffix ("AUTO"); the prefix is added here.
_ENV_PREFIX = "GDBTOOLS_"


def _env(name):
    """An injected override, or None if it was not set."""
    v = os.environ.get(_ENV_PREFIX + name)
    return v if v else None


def _env_int(name):
    v = _env(name)
    if v is None:
        return None
    try:
        return int(v, 0) & MASK
    except Exception:
        return None


def _as_int(v):
    """Coerce a JSON scalar ('0x40000000' | int | '1073741824') to int, or None."""
    if v is None:
        return None
    if isinstance(v, int):
        return v & MASK
    try:
        return int(str(v), 0) & MASK
    except Exception:
        return None


# Underscore-prefixed helpers are part of this module's public surface for the
# rest of the package (`from .runtime import *`), which would otherwise skip them.
__all__ = ['MASK', 'NAME', '_Ring', 'LOG', 'safe', 'ev', 'evi', 'execstr', 'exec_confirmless', 'reg', 'symval', 'fmt', '_h', 'read_guest_bytes', 'monitor_reg', '_ENV_PREFIX', '_env', '_env_int', '_as_int']
