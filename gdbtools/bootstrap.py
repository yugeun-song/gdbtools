"""Command registration and conditional autostart."""
import gdb

from .common.runtime import *
from .common.cfgjson import CfgJson
from .common.cfgdis import CfgDis
from .common.chain import Chain
from .common.sym import Sym
from .common.stackscan import StackScan
from .common.enumvals import EnumVals
from .linux_kernel import arch as _kernel_arch     # registers the full arch classes
from .linux_kernel.session import SESSION
from .linux_kernel.commands import *
from .linux_kernel.fdt import KDtb
from .linux_kernel.pwndbg_glue import *

# Registered unconditionally, under explicit names: which command can answer
# depends on the target, not on which commands exist.  The names are spelled out
# rather than derived from the class, because the gdb name is a user-facing
# contract and a rename must be a visible edit here.
COMMON_COMMANDS = (
    (CfgJson, "cfgjson"), (CfgDis, "cfgdis"),
    (Sym, "sym"), (StackScan, "stackscan"), (Chain, "chain"),
    (EnumVals, "enumvals"),
)
KERNEL_COMMANDS = (
    (KEarly, "kearly"), (P2V, "kp2v"), (V2P, "kv2p"), (KB, "kb"), (KW, "kw"),
    (KSr, "ksr"), (KSregs, "ksregs"), (KFin, "kfin"), (KCensus, "kcensus"),
    (KPt, "kpt"), (KPgd, "kpgd"), (KPtHex, "kpthex"), (KOff, "koff"), (KX, "kx"),
    (KDtb, "kdtb"), (MmView, "mmview"), (MmView, "memlayout"),
)

# Names this package has already claimed in this gdb session.  It is kept on the
# `gdb` module because re-sourcing the loader drops every `gdbtools.*` module
# from sys.modules -- which is what makes edit-and-re-source work -- and a set
# stored here would be rebuilt empty each time, making our own commands look
# like someone else's on the second load.
_OURS = getattr(gdb, "_gdbtools_command_names", None)
if _OURS is None:
    _OURS = set()
    gdb._gdbtools_command_names = _OURS


@safe(default=None)
def _command_status(name):
    """What `name` means to gdb RIGHT NOW, without running it.

    Returns one of:
      "free"      nothing answers that word
      "command"   a real command answers it -- registering ours REPLACES it
      "prefix"    the word is only an ambiguous prefix; nothing usable is lost

    `help` is asked rather than `complete`, and the difference matters.
    `complete NAME` lists the words gdb would offer, and an exact-match test over
    that list is blind to the case that actually bites: a UNIQUE PREFIX
    ABBREVIATION of a builtin.  `sym` is not in gdb's command table -- it is how
    gdb spells `symbol-file` -- so `complete sym` never contains the line "sym",
    the exact test says free, and registering `sym` silently removes a working
    way to load a symbol table.  `help sym` says "Load symbol table from
    executable file FILE." and catches it.  No name list is hardcoded here; gdb
    is asked about the gdb that is actually running."""
    # gdb.execute directly, not execstr: "Undefined command" is the EXPECTED
    # answer for most names, and routing it through the @safe wrapper would file
    # one diagnostic-log entry per free command name on every load.  A log that is
    # mostly expected errors is a log nobody reads.
    try:
        out = (gdb.execute("help " + name, from_tty=False, to_string=True) or "").strip()
    except gdb.error as e:
        out = str(e).strip()
    if not out:
        return "free"
    low = out.lower()
    if "undefined command" in low or "undefined info command" in low:
        return "free"
    if "ambiguous command" in low:
        # Several commands share the prefix, so the word was not usable on its
        # own and taking it costs nothing.
        return "prefix"
    return "command"


def _command_exists(name):
    """Back-compatible boolean: does anything answer this word today?"""
    return _command_status(name) == "command"


@safe()
def _register():
    """Construct every command, announcing any name taken over from someone else.

    gdb lets a Python command silently replace an existing one, so a name added
    here later -- or one another extension already owns -- would remove a working
    command with no trace.  pwndbg owns `stack` and `telescope`, which is why
    neither is used here.  Report a collision rather than leaving the loser to be
    discovered by its absence.
    """
    taken = []
    for cls, name in COMMON_COMMANDS + KERNEL_COMMANDS:
        if name not in _OURS and _command_status(name) == "command":
            taken.append(name)
        cls(name)
        _OURS.add(name)
    if taken:
        print("[%s] took over existing gdb command(s): %s" % (NAME, ", ".join(sorted(set(taken)))))
        print("[%s]   the previous meaning is gone for this session; the full name "
              "still works where one exists (e.g. `symbol-file` for `sym`)" % NAME)


@safe()
def _autostart():
    # AUTO-enable (stop hook + shadow + banner + per-stop sysreg line) ONLY when
    # launched via the kernel runner, which sets $GDBTOOLS_AUTO.  A plain
    # `gdb vmlinux` must NOT auto-attach: the commands are still registered (type
    # `kearly on` to opt in), but nothing hooks the session and gdb stays stock.
    # This is a hard requirement -- never auto-attach outside the launcher.
    if not _env("AUTO"):
        LOG.add("not autostarting (no $GDBTOOLS_AUTO; plain gdb -> manual `kearly on`)")
        return
    a = SESSION.ensure_arch()
    if a is not None and SESSION.looks_like_kernel():
        SESSION.enable()
        SESSION.load_overrides()
        LOG.add("autostarted for arch=%s" % a.key)


def main():
    """Entry point for the gdbtools.py shim."""
    _register()
    _autostart()
    # The banner appears only when a kernel target is actually present, so a
    # global `source` from a gdb init file stays silent in ordinary sessions.
    # The common commands are registered either way.
    if SESSION.enabled:
        print("[%s] early-boot symbolizer loaded (kearly | kb | kw | kx | kp2v | kv2p | "
              "ksr | ksregs | kcensus | kpt | kpgd | kpthex | koff | mmview | kfin | kdtb)"
              % NAME)
