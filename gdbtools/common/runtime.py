"""part of gdbtools; see the package docstring."""
import json
import struct
import gdb
import re

from . import config
from .config import ConfigError

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


try:
    _DEBUG = bool(config.get("DEBUG"))
except config.ConfigError:
    _DEBUG = False                      # reported by bootstrap's validate pass
_BUG_TYPES = (NameError, AttributeError, TypeError)
_REPORTED = set()
_CONFIG_REPORTED = set()


def report_config_error(e, once=True):
    """Say on gdb's stderr that an injected value is invalid; once per message
    unless `once` is False."""
    msg = str(e)
    if once and msg in _CONFIG_REPORTED:
        return
    _CONFIG_REPORTED.add(msg)
    LOG.add("config: " + msg)
    try:
        gdb.write("[%s] %s\n" % (NAME, msg), gdb.STDERR)
    except Exception:
        pass


def _report(where, e):
    key = (where, type(e).__name__, str(e))
    if not _DEBUG:
        if not isinstance(e, _BUG_TYPES) or key in _REPORTED:
            return
        _REPORTED.add(key)
    try:
        gdb.write("[%s] %s: %s: %s\n" % (NAME, where, type(e).__name__, e), gdb.STDERR)
    except Exception:
        pass


def safe(default=None, boundary=None):
    """Decorator: swallow every exception, log it, return `default`.  A NameError,
    AttributeError or TypeError is also reported on gdb's stderr, once per site and
    message; with $GDBTOOLS_DEBUG set every swallowed exception is.

    ConfigError (an invalid injected value) is never swallowed on the way up: it
    passes through to the boundary, where boundary="command" turns it into the
    command's gdb error and boundary="hook" reports it once and returns `default`."""
    def deco(fn):
        def wrap(*a, **k):
            try:
                return fn(*a, **k)
            except ConfigError as e:
                if boundary == "command":
                    raise gdb.GdbError("[%s] %s" % (NAME, e))
                if boundary == "hook":
                    report_config_error(e)
                    return default
                raise
            except gdb.GdbError:
                if boundary == "hook":
                    return default
                raise                              # a command's own usage error
            except Exception as e:                      # deliberately catch-all
                LOG.add("[%s] %s: %s" % (getattr(fn, "__name__", "?"),
                                         type(e).__name__, e))
                _report(getattr(fn, "__name__", "?"), e)
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


def word():
    """(size, C type) of the target's pointer-sized word: 8 on the 64-bit kernels
    this package debugs, 4 on a 32-bit user program."""
    try:
        size = int(gdb.lookup_type("void").pointer().sizeof)
    except Exception:
        size = 8
    return (4, "unsigned int") if size == 4 else (8, "unsigned long long")


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


# Underscore-prefixed helpers are part of this module's public surface for the
# rest of the package (`from .runtime import *`), which would otherwise skip them.
__all__ = ['MASK', 'NAME', '_Ring', 'LOG', 'safe', 'ev', 'evi', 'execstr', 'exec_confirmless', 'reg', 'word', 'symval', 'fmt', '_h', 'read_guest_bytes', 'monitor_reg', 'config', 'ConfigError',
           'report_config_error']
