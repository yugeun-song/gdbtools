"""Architecture registry.

`ARCHES` starts out holding the target-independent classes, which is all the
disassembly and control-flow views need.  Importing `gdbtools.linux_kernel.arch`
swaps in the richer subclasses that also know about page tables, system
registers and the phys<->virt map, so `detect_arch()` returns whichever half is
loaded without either side knowing about the other.

To add an architecture: subclass `ArchCommon` here with its branch regex, then
(optionally) subclass that plus `KernelArch` on the kernel side and call
`register()`.
"""
import gdb

from ..runtime import safe, LOG
from .base import ArchCommon
from .x86_64 import X86_64Common
from .arm64 import Arm64Common
from .riscv64 import Riscv64Common

ARCHES = [X86_64Common, Arm64Common, Riscv64Common]


def register(cls):
    """Install `cls` as the class used for its `key`, replacing any earlier one."""
    for i, c in enumerate(ARCHES):
        if c.key == cls.key:
            ARCHES[i] = cls
            return cls
    ARCHES.append(cls)
    return cls


@safe(default=None)
def _arch_name():
    return gdb.selected_inferior().architecture().name()


def detect_arch():
    """The registered class for gdb's current architecture, instantiated."""
    n = _arch_name()
    if not n:
        return None
    for cls in ARCHES:
        if cls.matches(n):
            return cls()
    LOG.add("unknown arch name: %s" % n)
    return None


__all__ = ["ARCHES", "ArchCommon", "register", "_arch_name", "detect_arch"]
