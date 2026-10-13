"""Command registration and conditional autostart."""
import gdb

from .common.runtime import *
from .common.cfgjson import CfgJson
from .common.cfgdis import CfgDis
from .common.chain import Chain
from .common.sym import Sym
from .common.stackscan import StackScan
from .common.enumvals import EnumVals
from .common.cmdinfo import CmdInfo
from .common.fz import Fz, bind_from_env
from .linux_kernel import arch as _kernel_arch     # registers the full arch classes
from .linux_kernel.session import SESSION
from .linux_kernel.commands import *
from .linux_kernel.fdt import KDtb
from .linux_kernel.memblock import KMemblock
from .linux_kernel.pwndbg_glue import *

# Registered unconditionally, under explicit names: which command can answer
# depends on the target, not on which commands exist.  The names are spelled out
# rather than derived from the class, because the gdb name is a user-facing
# contract and a rename must be a visible edit here.
COMMON_COMMANDS = (
    (CfgJson, "cfgjson"), (CfgDis, "cfgdis"),
    (Sym, "addr2sym"), (StackScan, "stackscan"), (Chain, "chain"),
    (EnumVals, "enumvals"), (CmdInfo, "cmdinfo"), (Fz, "fz"),
)
KERNEL_COMMANDS = (
    (KEarly, "kearly"), (P2V, "kp2v"), (V2P, "kv2p"), (KB, "kb"), (KW, "kw"),
    (KSr, "ksr"), (KSregs, "ksregs"), (KFin, "kfin"), (KCensus, "kcensus"),
    (KPt, "kpt"), (KPgd, "kpgd"), (KPtHex, "kpthex"), (KOff, "koff"), (KX, "kx"),
    (KDtb, "kdtb"), (MmView, "mmview"), (MmView, "memlayout"), (KBits, "kbits"),
    (KMemblock, "kmemblock"),
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


def _completions(word):
    try:
        out = gdb.execute("complete " + word, from_tty=False, to_string=True) or ""
    except gdb.error:
        return []
    return sorted({ln.strip() for ln in out.splitlines()
                   if ln.strip() and " " not in ln.strip()})


def _abbreviations(names):
    """{prefix: command} for each prefix of `names` that abbreviates exactly one
    command right now, e.g. `k` for `kill` in a gdb without pwndbg."""
    out = {}
    for name in names:
        for i in range(1, len(name)):
            p = name[:i]
            if p in out or p in _OURS or _command_status(p) != "command":
                continue
            c = _completions(p)
            if len(c) == 1 and c[0] != p and c[0] not in _OURS:
                out[p] = c[0]
    return out


@safe()
def _register():
    """Construct every command, announcing any name taken over from someone else.

    gdb lets a Python command silently replace an existing one, so a name added
    here later -- or one another extension already owns -- would remove a working
    command with no trace.  pwndbg owns `stack` and `telescope`, which is why
    neither is used here.  Report a collision rather than leaving the loser to be
    discovered by its absence.

    A new name also turns every abbreviation it shares into an ambiguous one:
    `kearly` makes `k` stop meaning `kill`, `kfin` makes `kf` stop meaning pwndbg's
    `kfile`.  Each abbreviation that resolved before registration and does not after
    gets an alias to the command it meant, so typing it does what it did before.
    """
    taken = []
    names = [n for _c, n in COMMON_COMMANDS + KERNEL_COMMANDS]
    before = _abbreviations(names)
    for cls, name in COMMON_COMMANDS + KERNEL_COMMANDS:
        if name not in _OURS and _command_status(name) == "command":
            taken.append(name)
        cls(name)
        _OURS.add(name)
    kept = []
    aliases = getattr(gdb, "_gdbtools_aliases", None)
    if aliases is None:
        aliases = gdb._gdbtools_aliases = {}
    for p, cmd in sorted(before.items()):
        if _command_status(p) != "prefix":
            continue
        try:
            gdb.execute("alias %s = %s" % (p, cmd), from_tty=False, to_string=True)
            kept.append("%s=%s" % (p, cmd))
            aliases[p] = cmd
        except gdb.error as e:
            LOG.add("abbreviation %s=%s not kept: %s" % (p, cmd, e))
    if kept:
        LOG.add("abbreviations kept as aliases: %s" % ", ".join(kept))
    if taken:
        print("[%s] took over existing gdb command(s): %s" % (NAME, ", ".join(sorted(set(taken)))))
        print("[%s]   the previous meaning is gone for this session; the full name "
              "still works where one exists" % NAME)


@safe(boundary="hook")
def _autostart():
    # AUTO-enable (stop hook + shadow + banner + per-stop sysreg line) ONLY when
    # $GDBTOOLS_AUTO says so.  A plain `gdb vmlinux` must NOT auto-attach: the
    # commands are still registered (`kearly on` opts in), but nothing hooks the
    # session and gdb stays stock.
    if not config.get("AUTO"):
        LOG.add("not autostarting (no $GDBTOOLS_AUTO; plain gdb -> manual `kearly on`)")
        return
    if not SESSION.try_autostart():
        # An init-file install runs before gdb reads the program named on its
        # command line; the session's new_objfile hook arms it when one appears.
        SESSION._autostart_pending = True
        LOG.add("autostart deferred until a kernel image is loaded")


def main():
    """Entry point for the gdbtools.py shim."""
    _register()
    for msg in config.validate_all():
        report_config_error(msg)
    SESSION.loaded_banner = ("[%s] early-boot symbolizer loaded (%s)"
                             % (NAME, " | ".join(n for _c, n in KERNEL_COMMANDS)))
    # Only when $GDBTOOLS_FZ_KEY says so; a debugger's keys are the user's.
    bind_from_env()
    _autostart()
    # The banner appears only when a kernel target is actually present, so a
    # global `source` from a gdb init file stays silent in ordinary sessions.
    # The common commands are registered either way.
    if SESSION.enabled:
        print(SESSION.loaded_banner)
