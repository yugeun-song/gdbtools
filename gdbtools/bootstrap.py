"""Command registration and conditional autostart."""
import gdb

from .common.runtime import *
from .common.cfgjson import CfgJson
from .common.cfgdis import CfgDis
from .common.chain import Chain
from .common.sym import Sym
from .common.stackscan import StackScan
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
def _command_exists(name):
    """True if `name` is already a gdb command.  `complete` reports what gdb
    would offer for that exact word, which is the only way to ask without
    running it."""
    for line in (execstr("complete " + name) or "").splitlines():
        if line.strip() == name:
            return True
    return False


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
        if name not in _OURS and _command_exists(name):
            taken.append(name)
        cls(name)
        _OURS.add(name)
    if taken:
        print("[%s] took over existing gdb command(s): %s"
              % (NAME, ", ".join(sorted(set(taken)))))
    # pwndbg probes the memory map by reading page-aligned addresses; one that
    # translates outside RAM crashes QEMU's debug-read path.  Wrap that funnel so
    # an unmapped probe fails the ordinary way instead of killing the VM.
    SAFEPROBE.install()
    # pwndbg's krelease() throws 'Linux version tuple not found' on the fragile early
    # start_kernel banner read and takes the whole context down with it -- make it
    # return None (unknown) instead, which pwndbg's own callers already handle.
    install_kernel_guards()


@safe()
def _autostart():
    a = SESSION.ensure_arch()
    # AUTO-enable (stop hook + shadow + banner + per-stop sysreg line) ONLY when
    # launched via the kernel runner, which sets $GDBTOOLS_AUTO.  A plain
    # `gdb vmlinux` must NOT auto-attach: the commands are still registered (type
    # `kearly on` to opt in), but nothing hooks the session and gdb stays stock.
    # This is a hard requirement -- never auto-attach outside the launcher.
    if not _env("AUTO"):
        LOG.add("not autostarting (no $GDBTOOLS_AUTO; plain gdb -> manual `kearly on`)")
        return
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
