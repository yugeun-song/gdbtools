"""x86_64: the kernel half.  See gdbtools.common.arch.x86_64 for the rest."""
import json
import struct
import gdb
import re
import os

from ...common.runtime import *
from ..physmem import *
from ...common.arch.x86_64 import X86_64Common
from .base import KernelArch




@safe(default=None)
def _x86_decomp_offsets(cv):
    """(self_reloc_jmp_off, lea_imm, extract_kernel_off) parsed from the x86 COMPRESSED
    vmlinux (arch/x86/boot/compressed/vmlinux) via nm/objdump -- version-tolerant, no
    hard-coded addresses.  The decompressor's startup_64 ends its self-relocation with
    `lea IMM(%rbx),%rax ; jmp *%rax` (IMM = moved-image internal offset); dividing that
    out of %rax at the jmp yields the moved base rbx, and extract_kernel = rbx + off.
    Returns None if the compressed vmlinux or the expected shape is absent."""
    import subprocess
    try:
        nm = subprocess.check_output(["nm", cv], stderr=subprocess.DEVNULL).decode("utf-8", "replace")
    except Exception:
        return None
    ek = None
    for line in nm.splitlines():
        p = line.split()
        if len(p) >= 3 and p[2] == "extract_kernel":
            ek = int(p[0], 16)
            break
    if ek is None:
        return None
    try:
        dis = subprocess.check_output(
            ["objdump", "-d", "--start-address=0x200", "--stop-address=0x400", cv],
            stderr=subprocess.DEVNULL).decode("utf-8", "replace")
    except Exception:
        return None
    jmp_off = lea_imm = last_lea = None
    for line in dis.splitlines():
        m = re.match(r"\s*([0-9a-f]+):", line)
        if not m:
            continue
        ml = re.search(r"lea\s+0x([0-9a-f]+)\(%rbx\),%rax", line)
        if ml:
            last_lea = int(ml.group(1), 16)
            continue
        if re.search(r"jmp\s+\*%rax", line):     # the self-relocation handoff
            jmp_off, lea_imm = int(m.group(1), 16), last_lea
            break
    if jmp_off is None or lea_imm is None:
        return None
    return (jmp_off, lea_imm, ek)


# --- the UEFI hand-off -------------------------------------------------------
#
# A firmware chain does not load a bzImage the way the boot protocol's direct path
# does.  OVMF loads it as a PE image and enters at efi_pe_entry, so startup_32, the
# self-relocation jmp and extract_kernel -- every stage the direct walk follows --
# are never executed.  What IS executed is the stub's own hand-off, enter_kernel()
# in drivers/firmware/efi/libstub/x86-stub.c:
#
#       asm("jmp *%0" :: "r"(kernel_addr), "S"(boot_params));
#
# an indirect jump through a register the COMPILER picks, with boot_params in %rsi.
# At that jump the register already holds the kernel's absolute physical entry, and
# the jump being the last thing the stub does is what makes it usable: the image has
# to be in RAM before its address can be found at all, and by then the earlier stages
# are behind us.
#
# Which register it is, is not a fact about the kernel.  gcc-13 inlined the hand-off
# as `add %rbx,%rax ; jmp *%rax`; gcc-16 emits `mov %rbp,%rsi ; jmp *%rbx`.  Matching
# either sequence matches the compiler, so what is matched instead is the shape the
# source guarantees -- see _x86_efi_handoff_off.
#
# The image's own base is stated nowhere.  The firmware's page allocator picks it and
# it moves between runs, so it is found the way arm64 and riscv find theirs: by the
# signatures the boot protocol fixes in the image.  'MZ' at +0, the boot flag 0xAA55
# at +0x1fe and 'HdrS' at +0x202 (arch/x86/boot/header.S, Documentation/arch/x86/
# boot.rst), on a page boundary because LoadImage allocates pages.
_HDRS_OFF = 0x202
_BOOT_FLAG_OFF = 0x1FE
_SETUP_SECTS_OFF = 0x1F1


@safe(default=None)
def _nm_value(cv, name):
    """Value of one symbol in an ELF, via nm.  None when the file or symbol is absent."""
    import subprocess
    try:
        out = subprocess.check_output(["nm", cv], stderr=subprocess.DEVNULL).decode("utf-8", "replace")
    except Exception:
        return None
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 3 and p[2] == name:
            return int(p[0], 16)
    return None


@safe(default=None)
def _nm_sym(cv, name):
    """(value, size) of one symbol, via `nm -S`.  size is 0 when the ELF records none,
    which is the caller's cue to fall back to a fixed window.  Knowing the size is what
    keeps a scan of one function from running on into the next one."""
    import subprocess
    try:
        out = subprocess.check_output(["nm", "-S", cv], stderr=subprocess.DEVNULL).decode("utf-8", "replace")
    except Exception:
        return None
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 4 and p[3] == name:        # value size type name
            return (int(p[0], 16), int(p[1], 16))
        if len(p) >= 3 and p[2] == name:        # value type name -- no size recorded
            return (int(p[0], 16), 0)
    return None


@safe(default=None)
def _x86_efi_handoff_off(cv):
    """(offset, register) of the stub's hand-off jump inside the COMPRESSED vmlinux,
    read from the build rather than stated here.  None when efi_stub_entry makes no
    such jump, which is how a kernel that hands over some other way reports itself.

    What identifies it is the shape the source guarantees, not the one a particular
    compiler emitted.  efi_stub_entry holds MORE than one register-indirect jump --
    gcc compiles a switch in it to a jump table, `movslq (%rbx,%r8,4),%r8 ; add
    %rbx,%r8 ; jmp *%r8` -- so "the indirect jump" is not a description of anything.
    What separates them is the other half of the same asm statement: boot_params is
    constrained to %rsi, so the hand-off is the register-indirect jump that has a
    write to %rsi just before it, and a jump table is exactly the one that does not.

    Both halves have to be read tolerantly.  The jump may carry a branch prefix
    (`notrack` under IBT, `bnd` under MPX), and the %rsi write may be rip-relative
    and so end in an objdump comment rather than in the register.  Keying on either
    of those spellings would be keying on the build again.

    The scan is bounded by the symbol's recorded size, so it cannot wander into the
    next function and match its jumps instead."""
    import subprocess
    sym = _nm_sym(cv, "efi_stub_entry")
    if sym is None:
        return None
    start, size = sym
    end = start + (size if size else 0x8000)
    try:
        dis = subprocess.check_output(
            ["objdump", "-d", "--start-address=0x%x" % start,
             "--stop-address=0x%x" % end, cv],
            stderr=subprocess.DEVNULL).decode("utf-8", "replace")
    except Exception:
        return None
    # How far back the %rsi write may sit.  It is the same asm statement, so it is
    # adjacent in the source; the compiler may still put a scheduled instruction or
    # two between them, and a jump table's own setup is longer than this window.
    RSI_WINDOW = 4
    cands = []
    recent = []
    for line in dis.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(\S.*)$", line)
        if not m:
            continue
        off = int(m.group(1), 16)
        insn = m.group(3).split("#", 1)[0].strip()      # drop objdump's comment
        jm = re.match(r"(?:notrack\s+|bnd\s+)*jmp\s+\*%(r[a-z0-9]+)\s*$", insn)
        if jm:
            near_rsi = any(re.search(r",\s*%rsi$", i) for i in recent)
            cands.append((off, jm.group(1), near_rsi))
        recent.append(insn)
        if len(recent) > RSI_WINDOW:
            recent.pop(0)
    if not cands:
        return None
    pref = [c for c in cands if c[2]]
    if len(pref) == 1:
        return (pref[0][0], pref[0][1])
    if len(cands) == 1:
        return (cands[0][0], cands[0][1])
    print("[%s] UEFI: efi_stub_entry has %d register-indirect jumps and %d of them "
          "load %%rsi first, so the hand-off cannot be told from a jump table here; "
          "taking the last, and it may be wrong."
          % (NAME, len(cands), len(pref)))
    return (cands[-1][0], cands[-1][1])


@safe(default=None)
def _x86_image_head(cv, n=8):
    """The decompressor's first `n` bytes (startup_32) straight out of the compressed
    vmlinux, for confirming that an address really holds the image before running the
    guest at it.  Read through objdump, which the offset parser above already needs."""
    import subprocess
    try:
        dis = subprocess.check_output(
            ["objdump", "-d", "--start-address=0x0", "--stop-address=0x%x" % (n + 16), cv],
            stderr=subprocess.DEVNULL).decode("utf-8", "replace")
    except Exception:
        return None
    out = bytearray()
    for line in dis.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)", line)
        if not m or int(m.group(1), 16) != len(out):
            continue
        out += bytes(int(b, 16) for b in m.group(2).split())
        if len(out) >= n:
            break
    return bytes(out[:n]) if len(out) >= n else None


@safe(default=None)
def _qemu_ram_window():
    """(lo, hi) of guest RAM as QEMU itself describes it.  Read from the machine's
    flat view rather than probed: a read outside RAM is the one thing physmem warns
    must never be issued, so the bound has to come from the model.  Flash and ROM
    regions are excluded by name -- they are backed like RAM but hold no guest image."""
    out = execstr("monitor info mtree -f")
    if not out:
        return None
    best = None
    for m in re.finditer(r"^\s*([0-9a-f]{16})-([0-9a-f]{16}) \(prio [-\d]+, ram\): (\S+)",
                         out, re.M):
        name = m.group(3).lower()
        if "ram" not in name or "flash" in name or "rom" in name:
            continue
        a, b = int(m.group(1), 16), int(m.group(2), 16) + 1
        # The largest single region, not the union: a machine scatters small aliases
        # of the same backing RAM around the low megabyte, and the gaps between them
        # are device space that must never be read.
        if b > a and (best is None or (b - a) > (best[1] - best[0])):
            best = (a, b)
    return best


@safe(default=False)
def _qemu_advance(ms):
    """Let the guest run for `ms` milliseconds without gdb resuming it: QEMU's own
    monitor starts and stops the machine, so gdb sees no execution state change and
    neither do its stop hooks nor a DAP client's state machine.  gdb cannot READ the
    guest afterwards -- its view is of the last real stop -- which is why everything
    the search touches goes through the monitor instead.  QEMU-only: a target without
    a monitor gets False."""
    import time
    # execstr is @safe(default=""), so a target with no monitor answers with an EMPTY
    # string rather than raising.  Empty is therefore the only evidence that the
    # command did not land, and it has to be treated as "no monitor", not as "stopped".
    status = (execstr("monitor info status") or "").strip()
    if not status or "unning" in status:
        return False                                  # no monitor here, or not ours to drive
    out = execstr("monitor cont")
    if out and ("Undefined" in out or "unknown" in out.lower()):
        return False
    try:
        time.sleep(max(0.0, ms / 1000.0))
    finally:
        # However this ends, the machine goes back to the state gdb still believes it
        # is in.  Leaving it running would desynchronise everything after.
        execstr("monitor stop")
    return True


@safe(default=None)
def _phys_bytes(pa, n):
    """`n` bytes of PHYSICAL memory, through the QEMU monitor.  Every read in the
    search below is physical on purpose: it runs while the firmware still owns the
    page tables, and at the reset vector the CPU is not even in long mode."""
    words = _mon_xp_words(pa & ~7, (n + (pa & 7) + 7) // 8)
    if not words:
        return None
    buf = bytearray()
    for w in words:
        buf += int(w).to_bytes(8, "little")
    off = pa & 7
    return bytes(buf[off:off + n]) if len(buf) >= off + n else None


def _image_at(page, pa, head, buf=None, off=None):
    """setup_size when the loaded bzImage starts at `pa`, None when it does not.  Four
    readings have to agree: 'MZ', the boot flag and 'HdrS' where arch/x86/boot/header.S
    puts them, and the decompressor's own first bytes at the end of the setup image.
    The last one is taken from the same dump when it reaches that far, and read from
    the guest when it does not."""
    if len(page) < 0x210 or page[0:2] != b"MZ":
        return None
    if page[_BOOT_FLAG_OFF:_BOOT_FLAG_OFF + 2] != b"\x55\xaa":
        return None
    if page[_HDRS_OFF:_HDRS_OFF + 4] != b"HdrS":
        return None
    setup_size = ((page[_SETUP_SECTS_OFF] or 4) + 1) * 512      # boot.rst: 0 means 4
    if head:
        there = None
        if buf is not None and off is not None and off + setup_size + len(head) <= len(buf):
            there = bytes(buf[off + setup_size:off + setup_size + len(head)])
        if there is None:
            there = _phys_bytes(pa + setup_size, len(head))
        if there != head:
            return None
    return setup_size


@safe(default=False)
def _qemu_pmemsave(pa, size, path):
    """Write `size` bytes of guest PHYSICAL memory at `pa` to a file on the host, using
    QEMU's own monitor.  This is the only fast way to read physical memory here: gdb
    reads VIRTUAL addresses, and once the guest leaves the firmware's identity map a
    low physical address is not mapped anywhere it can reach.  The path is quoted
    because the monitor parses an unquoted argument as an expression, in which `/` is
    division.  QEMU writes the file, so this only works while QEMU runs beside us."""
    out = execstr('monitor pmemsave 0x%x 0x%x "%s"' % (pa & MASK, size, path))
    if out and out.strip():
        LOG.add("pmemsave: %s" % out.strip()[:120])
        return False
    return True


@safe(default=None)
def _x86_scan_for_image(lo, hi, head):
    """Every page between `lo` and `hi` that starts a loaded bzImage, as a list of
    (base, setup_size).

    All of them, not the first one found.  Under UEFI the firmware holds TWO copies at
    once -- the file the loader read off the ESP, and the separate image LoadImage
    allocated from it -- and their headers are byte-identical, so no reading of the
    contents can tell them apart.  Only the second is ever executed.  Taking the
    topmost match picked the loader's buffer on every measured boot, and a breakpoint
    there is never reached.

    Searched in the dump rather than in the guest: a window of physical memory goes to
    a host file in one monitor command and is then scanned at native speed.  Only page
    starts are examined, because LoadImage allocates pages, and each candidate is
    confirmed by the four things the boot protocol fixes in a bzImage."""
    import tempfile
    lo = max(0, lo) & ~0xFFF
    hi &= ~0xFFF
    if hi <= lo:
        return []
    fd, path = tempfile.mkstemp(prefix="gdbtools-pmem-", suffix=".bin")
    os.close(fd)
    hits = []
    try:
        top = hi
        while top > lo:
            bot = max(lo, top - _SCAN_WINDOW)
            if not _qemu_pmemsave(bot, top - bot, path):
                return hits
            with open(path, "rb") as fh:
                buf = fh.read()
            for off in range(len(buf) - 0x1000, -1, -0x1000):
                if buf[off:off + 2] != b"MZ":
                    continue
                setup_size = _image_at(buf[off:off + 0x1000], bot + off, head, buf, off)
                if setup_size:
                    hits.append((bot + off, setup_size))
            top = bot
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return hits


# How much memory one dump covers.  A bound on the work, not a measurement: every
# megabyte is bytes written by QEMU and read back here.  Measured on this machine, one
# 64MB window costs 19ms and a whole 1GB of RAM 0.53s, so the whole of RAM is scanned
# every round rather than a band near the top -- where the firmware puts the image is
# the allocator's business, and a band that guesses wrong finds nothing at all.
_SCAN_WINDOW = 64 << 20

# Guest milliseconds, advanced through the monitor with the guest frozen in between, so
# a scan's own cost never races the firmware.  Coarse until something shows up, then
# fine until the set of copies stops growing: measured on QEMU/OVMF the loader's copy of
# the file lands around 1300ms and LoadImage's executable copy about 75ms after it, and
# breaking on only the first of the two never reaches the kernel.
_EFI_SETTLE_MS = 500
_EFI_COARSE_MS = 100
_EFI_FINE_MS = 25
_EFI_MAX_MS = 6000
# Rounds of _EFI_FINE_MS with no new copy before the set is called settled.  It has to
# outlast the gap between the two copies -- measured at about 75ms -- or the loop stops
# having seen only the loader's buffer and arms a breakpoint that is never reached.
# 6 x 25ms = 150ms, twice the measured gap, and still inside _EFI_MAX_MS.
_EFI_SETTLE_ROUNDS = 6

# x86 has four debug registers, and only a HARDWARE breakpoint can be placed on these
# addresses: they are reached before the firmware has mapped anything gdb could write
# a byte into, so there is no software breakpoint to fall back on.
_EFI_MAX_ANCHORS = 4


@safe(default=None)
def _x86_find_bzimages(sess):
    """Every loaded copy of the bzImage in guest RAM, as (base, setup_size).

    At reset nothing is loaded, so the guest is let run for a moment and then polled
    with it frozen: coarsely until the first copy appears, finely until no new copy has
    appeared for a couple of rounds.  Both copies are returned because nothing in their
    contents says which one the firmware will execute.  Returns [] rather than a guess."""
    win = _qemu_ram_window()
    if win is None:
        print("[%s] UEFI: QEMU did not describe its RAM, so there is no bounded place "
              "to look for the loaded image." % NAME)
        return []
    ram_lo, ram_hi = win
    cv = sess._compressed_vmlinux()
    head = _x86_image_head(cv) if cv else None
    if not _qemu_advance(_EFI_SETTLE_MS):
        print("[%s] UEFI: cannot step the guest -- no QEMU monitor behind this target, "
              "so the loaded image cannot be looked for." % NAME)
        return []
    ms = _EFI_SETTLE_MS
    hits, stable = [], 0
    while ms < _EFI_MAX_MS:
        now = _x86_scan_for_image(ram_lo, ram_hi, head) or []
        stable = stable + 1 if now and len(now) == len(hits) else 0
        if now:
            hits = now
        if hits and stable >= _EFI_SETTLE_ROUNDS:
            break
        step = _EFI_FINE_MS if hits else _EFI_COARSE_MS
        if not _qemu_advance(step):
            break
        ms += step
    if not hits:
        print("[%s] UEFI: no loaded bzImage in guest RAM after %d ms of firmware time."
              % (NAME, ms))
    else:
        print("[%s] UEFI: bzImage at %s after %d ms of firmware time."
              % (NAME, ", ".join(fmt(b) for b, _ss in hits), ms))
    return hits


class X86_64(X86_64Common, KernelArch):
    entry_symbol = "startup_64"
    # x86 KASLR randomizes the PHYSICAL base, not just the virtual one: the
    # decompressor picks a slot anywhere in usable RAM, and measured boots have
    # landed hundreds of megabytes apart.  Whoever supplies $GDBTOOLS_PHYS_WINDOW
    # for this machine has to allow for that -- a window sized for a fixed base,
    # as arm64 and riscv can use, fails every sanity check here under KASLR.
    entry_break_kind = "hw"             # the decompressor relocates vmlinux over the entry
    KBASE = 0xFFFFFFFF80000000          # __START_KERNEL_map (config-stable)
    def _is_va(self, addr):
        return (addr >> 63) & 1 == 1     # high half == kernel map

    def detect_kaslr_slide(self, sess):
        # x86_64: physical and virtual KASLR are INDEPENDENT (phys_base = output -
        # virt_addr, arch/x86/kernel/head64.c), so no invariant scalar equals the
        # virtual slide.  Instead walk from CR3 down to the kernel-text PMD table
        # (level2_kernel_pgt): __startup_64 shifts only [_text.._end], so the index
        # i0 of the first present kernel-text PMD entry gives the slide:
        #   i0 = (LOAD_PHYSICAL_ADDR + slide) >> 21 = 8 + (slide >> 21)
        #   slide = (i0 - 8) << 21     (8 = 0x1000000 >> 21)
        # A pure chained physical-read walk seeded by CR3 -> non-circular; the
        # kernel-half PGD entries are shared across init_top_pgt / per-mm /
        # PTI-shadow, so it resolves under KPTI whatever CR3 is live.
        KBASE = self.KBASE
        cr3 = evi("$cr3")
        if cr3 is None:
            cr3 = monitor_reg("CR3")
        if cr3 is None:
            return None
        tbl = cr3 & 0x000FFFFFFFFFF000
        cr4 = evi("$cr4")
        la57 = bool(cr4 is not None and ((cr4 >> 12) & 1))
        for sh in ((48, 39, 30) if la57 else (39, 30)):   # descend PGD..PUD, stop above PMD
            i = (KBASE >> sh) & 0x1FF
            d = read_phys_u64((tbl + i * 8) & MASK)
            if d is None or not (d & 1) or (d & (1 << 7)):  # absent, or a 1G huge page
                return None
            tbl = d & 0x000FFFFFFFFFF000
        words = read_phys_words(tbl, 512)                  # the kernel-text PMD table
        if not words:
            return None
        for i0 in range(512):
            if words[i0] and (words[i0] & 1):
                return ((i0 - 8) << 21) & MASK
        return None

    def find_mmu_enable(self, sess):
        """x86_64 long mode is never unpaged, so there is no "enable" instruction in
        the arm64 sense.  The meaningful equivalent is the CR3 load in startup_64
        that installs early_top_pgt -- the point at which the kernel's own high
        mapping becomes live while the PC is still physical.  `mov %rXX,%cr3` is
        0f 22 d8|d9|... (ModRM reg field 3), so scan the entry for the 0f 22 d? pair
        rather than fixing an offset that moves between builds."""
        if sess.offset is None:
            return None
        ent = symval(self.entry_symbol)
        if ent is None:
            return None
        link = sess._link_va(ent)
        if link is None:
            return None
        base = (link + sess.offset) & MASK
        blob = read_guest_bytes(base, 0x100)
        if not blob:
            return None
        for i in range(len(blob) - 2):
            if blob[i] == 0x0F and blob[i + 1] == 0x22 and (blob[i + 2] & 0xF8) == 0xD8:
                return {"pa": (base + i) & MASK, "link": (link + i) & MASK,
                        "desc": "startup_64+0x%x: mov %%r%d,%%cr3  (installs early_top_pgt)"
                                % (i, blob[i + 2] & 0x07)}
        return None

    def find_crossing(self, sess):
        # startup_64 loads CR3=early_top_pgt ('mov %rax,%cr3') then crosses to the
        # kernel high VA with 'jmp *0f(%rip)', where 0f = .quad common_startup_64 (a
        # decompressor-virt-relocated quad).  The jmp runs identity-mapped (VA==PA);
        # single-stepping it lands $pc on common_startup_64's RUNTIME VA, giving the
        # VIRTUAL slide (independent of phys_base).  Fallback: detect_kaslr_slide
        # (CR3 already = kernel tables here).  head_64.S:126-134.
        if sess.offset is None:
            return None
        su = symval("startup_64")
        if su is None:
            return None
        link_su = sess._link_va(su)
        if link_su is None:
            return None
        pa0 = (link_su + sess.offset) & MASK
        out = execstr("disassemble 0x%x, 0x%x" % (pa0, (pa0 + 0x200) & MASK))
        pa = None
        ptr = None
        for line in (out or "").splitlines():
            # the memory-indirect kernel-VA crossing, matched in EITHER disassembly
            # flavour: AT&T `jmp *0x..(%rip)` or Intel `jmp QWORD PTR [rip+0x..]`.
            if re.search(r"\bjmp\b.*(?:\*[^,]*\(%rip\)|\[rip\s*[+\-])", line):
                m = re.search(r"(0x[0-9a-fA-F]+)", line)
                if m:
                    pa = int(m.group(1), 16) & MASK
                    # gdb annotates the rip-relative operand with the absolute address
                    # it resolves to ("# 0x...").  Since we disassembled the PHYSICAL
                    # range, that is the physical address of the `.quad common_startup_64`
                    # slot -- reading it gives the landing's runtime VA with NO stepi,
                    # so the slide can be read without ever moving the CPU.
                    c = re.search(r"#\s*(?:0x)?([0-9a-fA-F]+)\b", line)
                    if c:
                        ptr = int(c.group(1), 16) & MASK
                    break
        if pa is None:
            return None
        land = "common_startup_64"
        lva = symval(land)
        tl = sess._link_va(lva) if lva is not None else None
        return {"pa": pa, "reg": None, "ptr": ptr,
                "stepi": tl is not None and ptr is None,
                "target_link": tl, "land": land, "detect_fallback": True,
                "desc": "startup_64: jmp *0f -> common_startup_64 (virtual slide)"}

    def recover_kaslr_base_efi(self, sess):
        """The UEFI counterpart of recover_kaslr_base.  Finds every loaded copy of the
        bzImage by its own signatures, breaks on the stub's hand-off jump in all of them
        at once, and reads the kernel's absolute physical entry straight out of whichever
        register that jump goes through.  Returns that PA, or None.

        All the copies, because the firmware keeps the loader's buffer alongside the
        image it executes and they are identical to read.  Whichever breakpoint the
        guest stops at is the executed one, which is the only way to tell."""
        cv = sess._compressed_vmlinux()
        if cv is None:
            print("[%s] UEFI: no compressed vmlinux ($GDBTOOLS_X86_DECOMP_VMLINUX)." % NAME)
            return None
        ho = _x86_efi_handoff_off(cv)
        if ho is None:
            print("[%s] UEFI: efi_stub_entry makes no register-indirect jump, so it has "
                  "no hand-off to break on; this kernel hands over some other way." % NAME)
            return None
        jmp_off, jmp_reg = ho
        found = _x86_find_bzimages(sess)
        if not found:
            return None
        anchors = sorted((base + setup_size + jmp_off) & MASK for base, setup_size in found)
        if len(anchors) > _EFI_MAX_ANCHORS:
            print("[%s] UEFI: %d copies of the image but only %d debug registers; "
                  "breaking on the lowest %d, and the hand-off will be missed if the "
                  "executed copy is not among them."
                  % (NAME, len(anchors), _EFI_MAX_ANCHORS, _EFI_MAX_ANCHORS))
            anchors = anchors[:_EFI_MAX_ANCHORS]
        print("[%s] UEFI: stub hand-off (jmp *%%%s) at %s; running there ..."
              % (NAME, jmp_reg, ", ".join(fmt(a) for a in anchors)))
        if not sess._hbreak_any(anchors):
            print("[%s] UEFI: none of the hand-offs was reached." % NAME)
            return None
        entry = reg(jmp_reg)
        if entry is None:
            print("[%s] UEFI: stopped at the hand-off but %%%s could not be read."
                  % (NAME, jmp_reg))
            return None
        entry &= MASK
        print("[%s] UEFI: kernel entry PA %s, handed over by the EFI stub." % (NAME, fmt(entry)))
        return entry

    def recover_kaslr_base(self, sess):
        # x86_64 COLD-FROZEN KASLR: unlike arm64/riscv (fixed physical load, only the
        # VIRTUAL address randomizes), x86's bzImage decompressor relocates the kernel
        # to a RANDOM physical base, so the nominal entry PA is wrong and bootbreak
        # misses.  Recover the real base from the decompressor, which loads at a FIXED
        # low PA (0x100000):
        #   1. break at the decompressor entry (startup_32, $GDBTOOLS_X86_DECOMP_PA);
        #   2. break at startup_64's self-relocation `jmp *%rax` -- %rax = moved_base +
        #      IMM, so moved_base rbx = %rax - IMM;
        #   3. break at extract_kernel (rbx + off), then `finish` -> %rax = the
        #      decompressed main-kernel physical entry (2MB-aligned, KASLR base).
        # Returns that PA, or None (no compressed vmlinux / unexpected shape -> caller
        # falls back to the nominal entry or --entry-pa).  head_64.S (compressed):
        # startup_64 self-reloc + `.Lrelocated: call extract_kernel; jmp *%rax`.
        cv = sess._compressed_vmlinux()
        if cv is None:
            return None
        # Which walk applies is the launcher's to state, not this package's to guess:
        # $GDBTOOLS_X86_DECOMP_PA is where a DIRECT boot's decompressor is loaded, and
        # only a direct boot has one.  It cannot be decided by looking either -- with
        # `-kernel` the option ROM copies the image there during boot, so at the reset
        # vector the address is legitimately empty and the breakpoint is what waits
        # for it.
        load = _env_int("X86_DECOMP_PA")
        if load is None:
            return self.recover_kaslr_base_efi(sess)
        offs = _x86_decomp_offsets(cv)
        if offs is None:
            return None
        jmp_off, lea_imm, ek_off = offs
        if not sess._hbreak_to(load):                       # decompressor entry (fixed)
            return None
        if not sess._hbreak_to((load + jmp_off) & MASK):    # self-relocation jmp *%rax
            return None
        rax = evi("$rax")
        if rax is None:
            return None
        rbx = (rax - lea_imm) & MASK                        # moved decompressor base
        if not sess._hbreak_to((rbx + ek_off) & MASK):      # extract_kernel
            return None
        print("[%s] x86 KASLR: extract_kernel reached; decompressing kernel (finish) ..." % NAME)
        execstr("finish")
        base = evi("$rax")                                  # main-kernel physical entry
        if base is None:
            return None
        base &= MASK
        LOG.add("x86 KASLR: recovered main-kernel phys base 0x%x via decompressor" % base)
        return base

    # This kernel's own top-level tables.  early_top_pgt is what head_64.S builds
    # and loads; init_top_pgt is the one the kernel proper runs on.
    pt_root_symbols = ("early_top_pgt", "init_top_pgt", "early_level4_pgt",
                       "init_level4_pgt")

    def _translation_probe(self):
        # Paging is on when CR0.PG (bit 31) is set.  That it is FOUR- or
        # five-level 64-bit paging additionally needs EFER.LMA (bit 10) and
        # CR4.PAE (bit 5); without both, CR3 points at a 32-bit or PAE structure
        # that pt_decode() would misread.
        #
        # CR3 keeps its value across a paging-off transition, so it is evidence of
        # nothing on its own.  The previous rule here -- "long mode requires
        # paging, so assume on when pc is readable" -- is true only once kernel
        # code is running, and this tool is used from the reset vector onward,
        # where it is false.  There is no inference left, so an unreadable CR0 is
        # reported as unknown.
        cr0, src0 = self.read_ctrl("cr0")
        if cr0 is None:
            return ("unknown", "none", None,
                    "cr0 did not answer (no gdb register, no QEMU monitor)")
        if not ((cr0 >> 31) & 1):
            return ("off", src0, None, "cr0=0x%x -> PG(bit31)=0" % cr0)
        efer, _ = self.read_ctrl("efer")
        cr4, _ = self.read_ctrl("cr4")
        if efer is None or cr4 is None:
            self._ia32e = None
            return ("on", src0, "CR3 (paging structure unconfirmed)",
                    "cr0=0x%x -> PG=1, but EFER.LMA / CR4.PAE did not answer, so "
                    "the paging structure's shape is unconfirmed" % cr0)
        lma, pae = (efer >> 10) & 1, (cr4 >> 5) & 1
        if not (lma and pae):
            self._ia32e = False
            return ("on", src0, "CR3 (32-bit or PAE paging)",
                    "cr0 PG=1 but EFER.LMA=%d CR4.PAE=%d -- not 64-bit paging"
                    % (lma, pae))
        la57 = (cr4 >> 12) & 1
        self._ia32e = True
        return ("on", src0, "CR3 IA-32e (%d-level)" % (5 if la57 else 4),
                "cr0=0x%x PG=1, EFER=0x%x LMA=1, CR4=0x%x PAE=1 LA57=%d"
                % (cr0, efer, cr4, la57))

    def auto_calibrate(self, sess):
        # Kernel-text window: VA = PA - phys_base + KBASE  =>  PA-VA = phys_base-KBASE.
        # Under nokaslr phys_base==0 -> offset == -KBASE.  Refine if readable.
        pb = 0
        if self.pc_is_virtual():
            v = evi("phys_base")
            if v is not None:
                pb = v
        return (pb - self.KBASE) & MASK
        # No sysreg override: ksr falls through to gdb ($cr0 etc., which QEMU 11
        # exposes as flag registers) then the QEMU monitor -- with an honest source
        # label instead of an opaque "[via arch]".

    def return_addr(self):
        # x86 has no link register; a freshly-called function's return address is
        # at the top of stack (before the prologue pushes).  Best-effort.
        sp = reg("sp")
        return None if sp is None else evi("*(unsigned long long *)0x%x" % sp)

    ctx_sysregs = ("cr0", "cr2", "cr3", "cr4", "efer", "gs_base", "fs_base")
    ctx_inline_sysregs = ("cr0", "cr3", "cr4", "efer")

    def context_summary(self, sess):
        cr0, cr3, cr4 = evi("$cr0"), evi("$cr3"), evi("$cr4")
        pg = "?" if cr0 is None else ("on" if (cr0 >> 31) & 1 else "off")
        return "paging=%s  cr0=%s cr3=%s cr4=%s efer=%s" % (
            pg, _h(cr0), _h(cr3), _h(cr4), _h(evi("$efer")))

    # cr3 = page-table base (phys), cr2 = fault addr, *_base = segment bases.
    addr_sysregs = frozenset(("cr2", "cr3", "gs_base", "fs_base"))

    def decode_sysreg(self, name, value):
        n = name.lower()
        if n == "cr0":
            pg = (value >> 31) & 1
            return "PG=%d (paging %s)  WP=%d PE=%d" % (
                pg, "on" if pg else "off", (value >> 16) & 1, value & 1)
        if n == "cr4":
            la57 = (value >> 12) & 1
            return "PAE=%d  LA57=%d (%s)  SMEP=%d SMAP=%d" % (
                (value >> 5) & 1, la57, "5-level" if la57 else "4-level",
                (value >> 20) & 1, (value >> 21) & 1)
        if n == "efer":
            lma = (value >> 10) & 1
            return "LME=%d  LMA=%d (long mode %s)  NXE=%d" % (
                (value >> 8) & 1, lma, "active" if lma else "off", (value >> 11) & 1)
        return None

    # --- page-table walk (IA-32e: PML4->PDPT->PD->PT, or 5-level with LA57) ---
    pagewalk_supported = True
    _PA_MASK = 0x000FFFFFFFFFF000
    _4LVL = ["PML4", "PDPT", "PD", "PT"]
    _5LVL = ["PML5", "PML4", "PDPT", "PD", "PT"]

    def pt_config_probe(self):
        """Level count from CR4.LA57, with no table root needed.  A failure clears
        the recorded shape rather than leaving a previous call's behind."""
        cr4, _ = self.read_ctrl("cr4")
        if cr4 is None:
            self._ptcfg = {}
            return False
        la57 = bool((cr4 >> 12) & 1)
        self._ptcfg = {"la57": la57, "nlevels": 5 if la57 else 4,
                       "top_shift": 48 if la57 else 39, "probed": True}
        return True

    def pt_base_raw(self, va):
        """CR3 as it reads right now, WITHOUT the translation gate.  See the
        arm64 note: for the refusal message only, never presented as live."""
        cr3, _ = self.read_ctrl("cr3")
        if cr3 is None:
            return None
        base = cr3 & self._PA_MASK
        return None if base == 0 else ("CR3", base)

    def pt_base(self, va):
        # The gate comes first.  CR3 keeps its value across a paging-off
        # transition, so a readable CR3 says nothing about whether translation is
        # active; CR0.PG does, and _translation_probe() also confirms EFER.LMA and
        # CR4.PAE so the structure is known to be the 64-bit one pt_decode reads.
        ts = self.translation_state()
        if not ts or ts.get("state") != "on":
            return None
        # Paging on is not enough: pt_decode() reads 64-bit IA-32e descriptors, and
        # a 32-bit or PAE structure has neither the same entry width nor the same
        # level shape.
        #
        # Decided on a FLAG that _translation_probe sets, not on whether the
        # human-readable regime string contains "IA-32e".  That substring test was
        # the bug it was meant to be the fix for: the negative case spelled itself
        # "CR3 (not IA-32e)", which contains the token, so the gate passed exactly
        # the case it existed to stop -- and a 32-bit page directory was decoded as
        # a PML4, printing tables and blocks and attribute flags for bytes that
        # were kernel code.  A gate keyed on prose breaks the next time the prose
        # is reworded.
        if getattr(self, "_ia32e", None) is not True:
            LOG.add("x86 pt_base: refusing -- paging is on but not confirmed IA-32e "
                    "(regime %r)" % (ts.get("regime") or ""))
            return None
        cr3, _ = self.read_ctrl("cr3")
        if cr3 is None:
            return None
        if not self.pt_config_probe():
            # Paging is on but CR4 did not answer: the table exists and its level
            # count does not.  Four levels is the overwhelmingly common shape, so
            # it is what gets decoded -- but it is recorded as assumed, and
            # pt_config_desc() says so rather than presenting it as read.
            self._ptcfg = {"la57": False, "nlevels": 4, "top_shift": 39,
                           "probed": False}
        base = cr3 & self._PA_MASK
        if base == 0:
            return None
        c = self._ptcfg
        return ("CR3 (%d-level)" % c["nlevels"], base)

    def pt_levels(self):
        c = getattr(self, "_ptcfg", None) or {"la57": False}
        return list(self._5LVL if c.get("la57") else self._4LVL)

    def pt_index(self, va, level):
        c = self._ptcfg
        shift = c["top_shift"] - level * 9
        return ((va >> shift) & 0x1FF, shift)

    def pt_decode(self, desc, level, shift, nlevels):
        if not (desc & 1):                                # P=0
            return ("invalid", None, None, "")
        rw, us, a, d = (desc >> 1) & 1, (desc >> 2) & 1, (desc >> 5) & 1, (desc >> 6) & 1
        g, nx = (desc >> 8) & 1, (desc >> 63) & 1
        ps = (desc >> 7) & 1
        last = (level == nlevels - 1)
        huge = ps and not last                            # 1G at PDPT / 2M at PD
        attrs = "%s %s%s%s%s%s" % ("W" if rw else "R", "U" if us else "S",
                                   " A" if a else "", " D" if d else "",
                                   " G" if g else "", " NX" if nx else "")
        if not last and not huge:
            return ("table", desc & self._PA_MASK, None, "")
        leaf_base = desc & self._PA_MASK & ~((1 << shift) - 1)
        return (("page" if last else "block"), None, leaf_base, attrs)

    def pt_config_desc(self):
        c = getattr(self, "_ptcfg", None)
        if not c:
            return "paging shape not probed (CR4 unread)"
        tag = "" if c.get("probed") else "  [ASSUMED -- CR4 unreadable]"
        return "%d-level paging (%s)%s" % (
            c["nlevels"], "LA57 5-level" if c["la57"] else "4-level", tag)

    # --- mmview support (single CR3 root; VA is sign-extended, not prefixed) ---
    def pt_make_va(self, low, prefix):
        c = getattr(self, "_ptcfg", {}) or {}
        signbit = 56 if c.get("la57") else 47
        if low & (1 << signbit):
            low |= (~((1 << (signbit + 1)) - 1)) & MASK
        return low & MASK

    def pt_dump_roots(self):
        rep = symval("_text") or self.KBASE
        return [("kernel+user  CR3", rep, 0)]

    def kernel_va_floor(self):
        c = getattr(self, "_ptcfg", {}) or {}
        return 0xFF00000000000000 if c.get("la57") else 0xFFFF800000000000

    va_landmarks = (
        ("_text", "kernel image start"),
        ("_stext", ".text start"),
        ("_etext", ".text end"),
        ("__init_begin", "__init start"),
        ("__init_end", "__init end (freed)"),
        ("_edata", ".data end"),
        ("__bss_start", ".bss start"),
        ("_end", "kernel image end"),
        ("init_top_pgt", "init top-level PGD (CR3)"),
        ("early_top_pgt", "early top-level PGD"),
        ("init_task", "init task_struct"),
    )

    # Map census names to a cheap gdb register where one exists; MSRs by number
    # are not gdb registers -> None (shown '?'; kcensus can try the monitor).
    _CENSUS_REG = {"CR0": "cr0", "CR2": "cr2", "CR3": "cr3", "CR4": "cr4",
                   "MSR_EFER": "efer", "RFLAGS": "eflags", "CS": "cs", "DS": "ds",
                   "ES": "es", "SS": "ss", "FS": "fs", "GS": "gs",
                   "MSR_GS_BASE": "gs_base", "MSR_FS_BASE": "fs_base"}

    def census_read(self, name):
        r = self._CENSUS_REG.get(name)
        return evi("$" + r) if r else None

    census = (
        # control-reg
        ("CR0", "W", "control-reg", "enable PE + PG + WP (protected mode + paging + write-protect)"),
        ("CR2", "R", "control-reg", "faulting linear address on early #PF (build missing PMD)"),
        ("CR4", "RW", "control-reg", "PAE/LA57/PSE/PGE (paging mode + global TLB)"),
        # paging
        ("CR3", "W", "paging", "load top-level page table (early_top_pgt -> init_top_pgt)"),
        # msr
        ("MSR_EFER", "RW", "msr", "SCE (syscall) + NX enable; LME/LMA long mode"),
        ("MSR_GS_BASE", "W", "msr", "GS base = fixed_percpu_data (stack-protector canary)"),
        ("MSR_IA32_MISC_ENABLE", "RW", "msr", "Intel: clear XD_DISABLE so NX is usable"),
        ("MSR_K7_HWCR", "RW", "msr", "AMD: clear bit15 to force-enable SSE"),
        ("MSR_IA32_APICBASE", "RW", "msr", "test/force X2APIC mode (parallel AP boot)"),
        ("APIC_X2APIC_ID_MSR", "R", "msr", "read local APIC ID in X2APIC mode"),
        ("MSR_AMD64_SEV", "R", "msr", "SEV/SME/SNP status -> sev_status/sme_me_mask"),
        ("MSR_AMD64_SYSCFG", "R", "msr", "MEM_ENCRYPT bit (firmware SME enabled?)"),
        # segment
        ("CS", "W", "segment", "reload __KERNEL_CS via lretq so IRET is reliable"),
        ("DS", "W", "segment", "drop stale realmode selector, reload __KERNEL_DS"),
        ("ES", "W", "segment", "drop stale realmode selector, reload __KERNEL_DS"),
        ("SS", "W", "segment", "drop stale realmode selector, reload __KERNEL_DS"),
        ("FS", "W", "segment", "zero stale realmode selector (FS base left unchanged)"),
        ("GS", "W", "segment", "zero stale realmode selector (GS base set via MSR)"),
        # descriptor-table
        ("GDTR", "W", "descriptor-table", "lgdt loads the kernel GDT (gdt_page)"),
        ("IDTR", "W", "descriptor-table", "lidt loads the bringup IDT (early exception/#VC)"),
        # misc
        ("RFLAGS", "RW", "misc", "save/clear dangerous flags; cld/cli in early handlers"),
    )
