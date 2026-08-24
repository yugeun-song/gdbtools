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
        offs = _x86_decomp_offsets(cv)
        if offs is None:
            return None
        jmp_off, lea_imm, ek_off = offs
        load = _env_int("X86_DECOMP_PA")
        if load is None:
            LOG.add("x86 decompressor recovery needs $GDBTOOLS_X86_DECOMP_PA")
            return None
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

    def mmu_translation_on(self):
        # 64-bit long mode requires paging, so CR0.PG is effectively always on once
        # kernel code runs.  Prefer the real bit when the stub exposes $cr0; else fall
        # back to "pc readable -> paging on".
        cr0 = evi("$cr0")
        if cr0 is not None:
            return bool((cr0 >> 31) & 1)
        v = self.pc_is_virtual()
        return None if v is None else True

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

    def pt_base(self, va):
        cr3 = evi("$cr3")
        if cr3 is None:
            cr3 = monitor_reg("cr3")
        if cr3 is None:
            return None
        cr4 = evi("$cr4")
        la57 = bool(((cr4 >> 12) & 1)) if cr4 is not None else False
        self._ptcfg = {"la57": la57, "nlevels": 5 if la57 else 4,
                       "top_shift": 48 if la57 else 39}
        base = cr3 & self._PA_MASK
        if base == 0:
            return None
        return ("CR3 (%d-level)" % (5 if la57 else 4), base)

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
        return ("%d-level paging (%s)" % (c["nlevels"], "LA57 5-level" if c["la57"]
                else "4-level")) if c else "4-level paging"

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
