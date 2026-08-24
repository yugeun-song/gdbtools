"""part of gdbtools; see the package docstring."""
import os
import json
import gdb
import re
import struct
from ..common.runtime import *
from ..common import state
from ..common.chain import safe_chain
from .target import TARGET


# ----------------------------------------------------------------------------
# PHYSICAL memory access, independent of the MMU.
# Once the MMU is on, gdb's `x`/pwndbg `hexdump` and inf.read_memory() translate
# the address through the CURRENT page tables -- so reading a page-table page by
# its PHYSICAL address fails ("Cannot access memory at address 0x<pa>").  QEMU's
# HMP `xp` (examine physical) bypasses translation; we tunnel it through the
# gdbstub's monitor passthrough (qRcmd), so it works in every regime (MMU off,
# idmap, or full kernel map).  This is what makes the page-table walker able to
# read L0..L3 after the MMU comes on.  Degrades to inf.read_memory (valid as a
# physical read only while the MMU is off) when no monitor is available.
# ----------------------------------------------------------------------------
@safe(default=None)
def _mon_xp_words(pa, count):
    """`count` 64-bit words of PHYSICAL memory via QEMU HMP `xp/<count>gx`."""
    if pa is None or count <= 0 or count > 4096:
        return None
    if not _pa_in_ram(pa) or not _pa_in_ram((pa & MASK) + count * 8 - 1):
        return None
    out = execstr("monitor xp/%dgx 0x%x" % (count, pa & MASK))
    if not out or "Cannot access" in out or "not a valid" in out:
        return None
    vals = []
    for line in out.splitlines():
        if ":" not in line:                       # "<addr>: 0xWORD 0xWORD ..."
            continue
        for m in re.finditer(r"0x([0-9a-fA-F]+)", line.split(":", 1)[1]):
            vals.append(int(m.group(1), 16) & MASK)
    return vals if vals else None


@safe(default=True)
def _pa_in_ram(pa):
    """Whether `pa` is inside guest RAM.

    Reads outside it are the one thing that must never be issued.  QEMU serves a
    debug read of a non-RAM physical address by dispatching into the device model,
    and that path SEGVs -- taking the VM and the gdb session with it.  Reproduced
    deterministically: stopping in vfs_write on a KASLR kernel and rendering the
    panel killed QEMU 4/4, core stack gdb_read_byte -> cpu_memory_rw_debug ->
    memory_region_dispatch_read.  The panel gets there honestly: at that stop TTBR0
    holds the CURRENT USER PROCESS's page tables, and following their descriptors
    walks straight out of RAM.

    Defaults to True when the RAM map is unknown, so a machine we cannot describe
    keeps working exactly as before rather than going silently blind."""
    a = getattr(state.session(), "arch", None)
    pa &= MASK
    regs = [(b, sz) for b, sz in (TARGET.ram_regions(a) or []) if sz]
    if regs:
        return any(b <= pa < b + sz for b, sz in regs)
    # No DTB/profile described RAM -- the boot register that carries the DTB no
    # longer holds it this late.  Use the supplied physical window's floor instead:
    # everything below it is device space (arm64 virt keeps the GIC at 0x8000000
    # and the UART at 0x9000000), and those low addresses are exactly what a stray
    # page-table descriptor resolves to.  A floor with no ceiling stays permissive
    # for every legitimate kernel physical address.
    w = a.eff_phys_window() if a is not None else None
    if isinstance(w, tuple) and len(w) == 2 and w[0]:
        return pa >= w[0]
    # Nothing described this machine's RAM, so there is no floor to test against.
    # Declining to filter is not the same as guessing a floor: the read below will
    # fail on its own if the address is not really there.
    return True


@safe(default=False)
def _phys_fallback_ok():
    """Whether read_guest_bytes may stand in for a physical read.

    It may not once the MMU is on.  gdb reads through the LIVE page tables then, so
    a physical address handed to it is reinterpreted as a virtual one and translated
    to somewhere else entirely -- and if that somewhere is a device region, QEMU's
    debug-read path dispatches into a device model and SEGVs, taking the VM and the
    gdb session with it.  Reproduced deterministically: stopping in vfs_write on a
    KASLR kernel and rendering the panel killed QEMU 4/4 times, with the core stack
    gdb_read_byte -> cpu_memory_rw_debug -> memory_region_dispatch_read.  Returning
    None instead just leaves the field blank, which is what "unreadable" should look
    like."""
    a = getattr(state.session(), "arch", None)
    if a is None:
        return True
    return a.pc_is_virtual() is not True


@safe(default=None)
def read_phys_u64(pa):
    """One 64-bit little-endian word of PHYSICAL memory at `pa`, or None."""
    if pa is None:
        return None
    w = _mon_xp_words(pa, 1)
    if w:
        return w[0]
    if not _phys_fallback_ok():
        return None
    b = read_guest_bytes(pa, 8)                    # only physical while MMU off
    return struct.unpack("<Q", b)[0] if b and len(b) == 8 else None


@safe(default=None)
def read_phys_u32(pa):
    """One 32-bit little-endian word of PHYSICAL memory at `pa` -- e.g. a single
    fixed-width arm64/riscv instruction, for the KASLR MMU-crossing opcode scan."""
    if pa is None:
        return None
    base = pa & ~7
    v = read_phys_u64(base)
    if v is None:
        return None
    return (v >> (32 * ((pa >> 2) & 1))) & 0xFFFFFFFF


@safe(default=None)
def read_phys_words(pa, count):
    """`count` consecutive 64-bit PHYSICAL words at `pa` as a python list."""
    if pa is None or count <= 0:
        return None
    w = _mon_xp_words(pa, count)
    if w and len(w) >= count:
        return w[:count]
    if not _phys_fallback_ok():
        return w
    b = read_guest_bytes(pa, count * 8)
    if b and len(b) >= count * 8:
        return [struct.unpack_from("<Q", b, i * 8)[0] for i in range(count)]
    return w


# Underscore-prefixed helpers are part of this module's public surface for the
# rest of the package (`from .physmem import *`), which would otherwise skip them.
__all__ = ['_mon_xp_words', '_pa_in_ram', '_phys_fallback_ok', 'read_phys_u64', 'read_phys_u32', 'read_phys_words', 'safe_chain']
