"""Kernel-side architecture knowledge: address-space classification,
calibration, KASLR, system registers and page-table walking.

Mixed into the concrete arch classes alongside the generic half from
`gdbtools.common.arch`.
"""
import os
import json
import struct
import gdb
import re

from ...common.runtime import *
from ..physmem import *
from ...common.chain import safe_chain
from ..pwndbg_glue import PWN
from ..target import TARGET


class KernelArch:
    entry_symbol = None          # symbol whose PA == $pc at the first frozen stop
    entry_break_kind = "hw"      # "sw": entry not overwritten -> sw bp ok; "hw":
                                 # entry gets relocated over, so a sw bp is clobbered
    entry_magic = None           # (word, offset_from_text): scan RAM for the Image
    dtb_pointer_reg = None       # reg holding the DTB PA at entry (arm64 x0/riscv a1)
    return_reg = None            # reg holding a just-called fn's return addr (lr/ra)
    post_mmu_symbols = ()        # virtual landing(s) reached just after the MMU is on

    def stack_setup_hint(self):
        """Where this architecture's head code first establishes a stack, or None.

        Printed when a stack scan is asked for and $sp is still zero: the useful
        answer there is not "nothing found" but "nothing exists yet, and here is
        where it starts existing"."""
        return None


    # --- address space ---
    def _is_va(self, addr):
        """True if `addr` is a kernel virtual address (vs a physical one)."""
        raise NotImplementedError

    def pc_is_virtual(self):
        pc = reg("pc")
        return None if pc is None else self._is_va(pc)

    def return_addr(self):
        """Return address of the current (just-entered) function, for a CFI-less
        'finish' in early asm.  Default: the arch link register if it has one."""
        return reg(self.return_reg) if self.return_reg else None

    def eff_phys_window(self):
        """The physical range the kernel image may plausibly sit in, or None.

        Supplied, never assumed: $GDBTOOLS_PHYS_WINDOW ("lo:hi") or the machine
        profile.  With neither, the sanity check that uses this has nothing to
        check against and the caller skips it rather than testing against a range
        that describes some other board."""
        pw = _env("PHYS_WINDOW")
        if pw and ":" in pw:
            try:
                lo, hi = pw.split(":", 1)
                return (int(lo, 0) & MASK, int(hi, 0) & MASK)
            except Exception:
                pass
        return TARGET.phys_window(self)

    # --- locate the kernel entry PA (scan the Image magic, else the hint) ---
    def _scan_ranges(self):
        """Candidate (start,end) physical ranges to scan for the Image magic.

        Every range is supplied: $GDBTOOLS_SCAN 'lo:hi', $GDBTOOLS_RAM_BASE, the
        JSON profile, or RAM regions read out of a DTB.  Empty when nothing was
        supplied, which makes the scan find nothing rather than sweep a range that
        belongs to a different board."""
        out = []
        sc = _env("SCAN")
        if sc and ":" in sc:
            try:
                lo, hi = sc.split(":", 1)
                out.append((int(lo, 0) & MASK, int(hi, 0) & MASK))
            except Exception:
                pass
        rb = _env_int("RAM_BASE")
        if rb is not None:
            out.append((rb, (rb + 0x8000000) & MASK))   # ram_base .. +128 MiB
        # profile / DTB supplied machine RAM (non-QEMU boards)
        out.extend(TARGET.scan_ranges())
        for base, size in TARGET.ram_regions(self):
            span = size if (size and size < 0x8000000) else 0x8000000
            out.append((base, (base + span) & MASK))
        return out

    def discover_load_pa(self):
        """Ask QEMU where it ACTUALLY loaded the kernel image -- fully dynamic,
        no magic and no hardcoded address (works when -kernel is loaded in place,
        i.e. arm64/riscv).  Parses 'monitor info roms': the kernel is the rom whose
        name matches the image, else the largest mem=ram rom that is not the
        bootloader / dtb / fw rom.  On a non-QEMU stub this yields None and the
        caller falls back to the DTB/profile-driven scan."""
        out = execstr("monitor info roms")
        if not out:
            return None
        best, best_sz = None, -1
        for line in out.splitlines():
            m = re.search(r"addr=([0-9a-fA-F]+)\s+size=(0x[0-9a-fA-F]+)\s+"
                          r"mem=ram\s+name=\"([^\"]*)\"", line)
            if not m:
                continue
            addr, sz, name = int(m.group(1), 16) & MASK, int(m.group(2), 16), m.group(3)
            if any(k in name for k in ("Image", "bzImage", "vmlinux")):
                LOG.add("load PA %s from 'info roms' name=%s" % (fmt(addr), name))
                return addr
            low = name.lower()
            if sz > best_sz and not any(k in low for k in ("bootloader", "dtb", "rom@", "fw")):
                best, best_sz = addr, sz
        if best is not None:
            LOG.add("load PA %s from 'info roms' (largest ram rom)" % fmt(best))
        return best

    def find_entry_pa(self):
        # 0. machine descriptor (JSON profile) pins the image-base PA -- highest
        #    precedence among the auto sources (env $GDBTOOLS_ENTRY_PA still wins above).
        pe = TARGET.entry_pa()
        if pe is not None:
            LOG.add("entry PA %s from profile" % fmt(pe))
            return pe
        if self.entry_magic is None:
            # x86: the decompressor relocates the image, so there is no magic in
            # guest memory to find it by.  The entry PA has to be stated.
            return None
        # 1. DYNAMIC: QEMU reports the actual load address (no scan, no hardcode)
        pa = self.discover_load_pa()
        if pa is not None:
            return pa
        # 2. fallback: scan guest RAM (profile/DTB ranges included) for the magic
        word, off = self.entry_magic
        for start, end in self._scan_ranges():
            out = execstr("find /w 0x%x, 0x%x, 0x%x" % (start, end, word))
            m = re.search(r"0x([0-9a-fA-F]{6,16})", out or "")
            if m:
                return (int(m.group(1), 16) - off) & MASK
        # Nothing in the target answered.  Say so; do not invent a plausible one.
        return None

    # --- MMU state (architectural flag, if cheaply available; else None) ---
    def mmu_translation_on(self):
        return None

    # --- calibration: return offset (PA - VA) mod 2^64, or None ---
    def auto_calibrate(self, sess):
        pc = reg("pc")
        if pc is None:
            return None
        if not self._is_va(pc):
            va = symval(self.entry_symbol) if self.entry_symbol else None
            return None if va is None else (pc - va) & MASK
        # pc is already a VA (attached post-MMU, e.g. at start_kernel): subclasses
        # may recover the image offset from a kernel variable; base class cannot.
        return None

    def detect_kaslr_slide(self, sess):
        """KASLR virtual slide = runtimeVA(_text) - linkVA(_text), read from an
        arch-specific anchor at the CURRENT phase without circularity.  The base
        class has no anchor -> returns None; each arch overrides.  None means the
        tool keeps slide 0 and tells the user how to set it (kearly kaslr <hex>)."""
        return None

    def find_mmu_enable(self, sess):
        """Locate the instruction that TURNS TRANSLATION ON for the primary CPU --
        the SCTLR_EL1.M write on arm64, the satp write on riscv, the CR3 load on
        x86.  Found by scanning the idmap routine's physical bytes for the opcode,
        so nothing is hard-coded per kernel version.

        Returns {"pa", "link", "desc"} or None.  This is the boundary between
        "MMU off" and "MMU on, PC still physical" -- the regime a user analysing
        head.S most often wants to stop at and cannot otherwise locate without
        disassembling the kernel by hand in another terminal."""
        return None

    def find_crossing(self, sess):
        """Locate this arch's PRIMARY-CPU physical->high-VA control transfer -- the
        instruction that, in a COLD FROZEN boot, executes AFTER KASLR relocation but
        BEFORE start_kernel, while still running at VA==PA (idmap/identity) or MMU-off,
        so a hardware breakpoint placed at its PHYSICAL address fires without knowing
        the slide.  Returns a dict, or None when no such anchor exists here:

          {"pa":   physical address to hardware-break at (linkVA+offset),
           "reg":  register holding the landing's RUNTIME VA at that instant, or None,
           "stepi": True to single-step the crossing once, then read $pc as the
                    landing's runtime VA (for a memory-indirect branch with no reg),
           "target_link": link VA of the landing symbol (slide = runtime - this),
           "land": landing symbol name (for messages),
           "detect_fallback": True to fall back to detect_kaslr_slide() after landing
                    (for arches whose slide is a post-crossing global readable here),
           "desc": short human description}

        The base class has no anchor -> None; each arch overrides.  Used only by the
        frozen-boot slide path (_advance_to_crossing); never on a live/attached kernel."""
        return None

    def recover_kaslr_base(self, sess):
        """Recover the RANDOM physical load base of the kernel image when the arch's
        boot relocates it physically (x86 bzImage decompressor).  arm64/riscv load at a
        FIXED physical address (only the VIRTUAL address randomizes), so the base class
        -- and those arches -- return None (the nominal entry PA is already correct)."""
        return None

    # --- system-register read hook (arch specials); default: none ---
    def sysreg(self, name):
        return None

    # --- key system/control registers to surface in early boot ---
    ctx_sysregs = ()             # full set dumped by `ksregs`
    ctx_inline_sysregs = ()      # compact set shown in the per-stop context badge
    def context_summary(self, sess):
        """One compact line: MMU state + the registers that actually change or
        gate behaviour in head.S.  Default empty; each arch fills it in."""
        return ""

    def inline_sysreg_names(self):
        """Register names for the per-stop context badge; overridable so an arch
        can pick the set that actually exists at the current exception level."""
        return list(self.ctx_inline_sysregs or self.ctx_sysregs)

    # --- value rendering --------------------------------------------------
    # A sysreg value is NOT automatically a pointer just because it is a hex
    # number: CurrentEL/SCTLR/DAIF/satp are packed bitfields, not addresses.
    # So telescope ONLY the registers that genuinely hold an address
    # (addr_sysregs); decode the bitfield/status ones; show the rest as plain
    # hex.  This keeps the context panel from "dereferencing" a status word.
    addr_sysregs = frozenset()

    def _sysreg_is_addr(self, name):
        return name.lower() in self.addr_sysregs

    def decode_sysreg(self, name, value):
        """Human-readable decode of a bitfield/status register, or None when no
        arch-specific decoder applies (caller then shows the plain value)."""
        return None

    def render_sysreg(self, name, value):
        """Format a sysreg value for the context panel / ksregs: a telescope
        chain for address registers, a field decode for status registers,
        otherwise plain hex.  Uses the self-bounded safe_chain (never pwndbg's
        unbounded chain) so an address register can never crash the session."""
        if self._sysreg_is_addr(name):
            return safe_chain(value) or ("0x%x" % value)
        hexv = PWN.color("yellow", "0x%x" % value) or ("0x%x" % value)
        dec = self.decode_sysreg(name, value)
        return ("%s   %s" % (hexv, dec)) if dec else hexv

    # --- early-boot register census -------------------------------------
    # Every SYSTEM/CONTROL register that head.S AND the files it transitively
    # calls read or write at least once (the general-purpose x0..x30 / rax.. are
    # already in pwndbg's REGISTERS panel; this is the set that panel omits).
    # A list of (name, acc, category, purpose); each arch fills it in.  `kcensus`
    # dumps it with live values + decode; the context panel shows it compactly.
    census = ()

    def census_read(self, name):
        """Cheap value read for the census/panel: gdb-exposed register only
        (no monitor round-trip), so per-stop rendering stays fast.  None if the
        stub does not expose it at the current EL."""
        return evi("$" + name)

    def census_categories(self):
        """Ordered list of category keys present in this arch's census."""
        seen = []
        for _n, _a, cat, _p in self.census:
            if cat not in seen:
                seen.append(cat)
        return seen

    # --- hardware page-table walk ---------------------------------------
    # A radix walk driven by per-arch hooks.  Reads the actual page-table pages
    # from PHYSICAL memory (read_phys_u64), so it reports what the HARDWARE would
    # translate -- L0..L3 (arm64) / PML4..PT (x86) / Sv39-57 (riscv) -- including
    # "not mapped" for freed __init text or unmapped image head pages.
    pagewalk_supported = False
    pt_entry_size = 8

    def pt_base(self, va):
        """(regime_name, top_level_table_PA) for VA, or None if unreadable."""
        return None

    def pt_levels(self):
        """Ordered level names top->bottom, e.g. ['L0/PGD',...,'L3/PTE']."""
        return []

    def pt_index(self, va, level):
        """(index, va_shift) for `level` (0 == top)."""
        return (0, 0)

    def pt_decode(self, desc, level, shift, nlevels):
        """(kind, next_pa, leaf_base, attrs_str);
        kind in {'table','block','page','invalid'}."""
        return ("invalid", None, None, "")

    def pt_config_desc(self):
        """One-line human description of the active paging config."""
        return ""

    @safe(default=None)
    def pagewalk(self, va):
        if not self.pagewalk_supported or va is None:
            return None
        rb = self.pt_base(va)
        if rb is None:
            return None
        regime, base = rb
        if base is None:
            return None
        names = self.pt_levels()
        nlevels = len(names)
        tbl, leaf_pa, levels = base, None, []
        for i in range(nlevels):
            idx, shift = self.pt_index(va, i)
            ent_pa = (tbl + idx * self.pt_entry_size) & MASK
            desc = read_phys_u64(ent_pa)
            rec = {"name": names[i], "index": idx, "entry_pa": ent_pa,
                   "desc": desc, "shift": shift}
            if desc is None:
                rec["kind"] = "unreadable"
                levels.append(rec)
                break
            kind, next_pa, leaf_base, attrs = self.pt_decode(desc, i, shift, nlevels)
            rec.update(kind=kind, next_pa=next_pa, attrs=attrs)
            levels.append(rec)
            if kind == "table":
                tbl = next_pa
                continue
            if kind in ("block", "page") and leaf_base is not None:
                leaf_pa = (leaf_base | (va & ((1 << shift) - 1))) & MASK
            break
        return {"regime": regime, "va": va & MASK, "base": base,
                "levels": levels, "leaf_pa": leaf_pa, "config": self.pt_config_desc()}

    # --- memory-map (ptdump) enumeration, for mmview/memlayout ------------
    # Landmark symbols to always resolve (VA + PA) so the layout is meaningful
    # even BEFORE the MMU is on (symbols + calibration need no live mapping).
    va_landmarks = ()

    def pt_dump_roots(self):
        """[(label, representative_va, high_prefix), ...] top-level tables to
        enumerate.  representative_va picks the regime via pt_base (which also
        sets the paging config); high_prefix is OR-ed onto the walked low bits by
        pt_make_va to rebuild the canonical VA."""
        return []

    def kernel_va_floor(self):
        """Lowest kernel-space VA.  On a unified root (x86 CR3 / riscv satp holds
        BOTH user and kernel), mmview hides mappings below this by default so the
        output is the KERNEL layout, not whatever user process happens to be
        current.  arm64's kernel root (TTBR1) is already all high, so the default
        is a no-op there; the idmap root is never floored."""
        return 0xFFFF000000000000

    def pt_make_va(self, low, prefix):
        """Rebuild a canonical VA from the low (index) bits + regime prefix.
        Split-regime arches (arm64) OR a fixed prefix; single-root arches (x86,
        riscv) sign-extend and override this."""
        return (prefix | low) & MASK

    @safe(default=[])
    def enumerate_regions(self, base, prefix, cap_leaves=20000, cap_nodes=60000):
        """Recursively walk the table at `base`, returning leaf mappings
        [(va, pa, size, attrs, kind), ...] sorted by VA.  Reads whole 512-entry
        tables from PHYSICAL memory (one monitor read per node), so it works with
        the MMU on OR off.  Bounded by cap_* against a pathological/looping tree."""
        names = self.pt_levels()
        nlevels = len(names)
        if not nlevels:
            return []
        shifts = [self.pt_index(0, lv)[1] for lv in range(nlevels)]
        leaves = []
        state = {"nodes": 0}

        def rec(tbl, level, acc):
            if state["nodes"] >= cap_nodes or len(leaves) >= cap_leaves:
                return
            state["nodes"] += 1
            words = read_phys_words(tbl, 512)
            if not words:
                return
            shift = shifts[level]
            for i, desc in enumerate(words):
                if not desc:
                    continue
                kind, next_pa, leaf_base, attrs = self.pt_decode(desc, level, shift, nlevels)
                acc2 = acc | (i << shift)
                if kind == "table" and next_pa is not None and level + 1 < nlevels:
                    rec(next_pa, level + 1, acc2)
                elif kind in ("block", "page") and leaf_base is not None:
                    leaves.append((self.pt_make_va(acc2, prefix), leaf_base,
                                   1 << shift, attrs, kind))
                    if len(leaves) >= cap_leaves:
                        return
        rec(base, 0, 0)
        leaves.sort(key=lambda r: r[0])
        return leaves
