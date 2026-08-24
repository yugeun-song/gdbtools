"""arm64: the kernel half.  See gdbtools.common.arch.arm64 for the rest."""
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
from ...common.arch.arm64 import Arm64Common
from .base import KernelArch


class Arm64(Arm64Common, KernelArch):
    entry_symbol = "_text"
    entry_break_kind = "sw"              # entry executes in place; sw bp is reliable
    entry_magic = (0x644D5241, 0x38)     # arm64 Image magic "ARM\x64" at _text+0x38
    dtb_pointer_reg = "x0"               # bootloader leaves the DTB PA in x0 at _text
    return_reg = "lr"                    # x30; head.S calls via bl, so lr = ret addr
    # first virtual code after __enable_mmu: primary via __primary_switch ->
    # br __primary_switched; secondary via secondary_startup -> br __secondary_switched.
    # (C entries kept as fallbacks in case the LOCAL asm labels are absent.)
    post_mmu_symbols = ("__primary_switched", "__secondary_switched",
                        "start_kernel", "secondary_start_kernel")

    # PSTATE (exposed as $pstate/$cpsr) carries fields that the hidden EL1
    # sysregs duplicate.  CurrentEL is literally PSTATE.EL in bits[3:2].
    PSTATE_DERIVED = {
        "currentel": lambda ps: ps & 0xC,
        "spsel":     lambda ps: ps & 0x1,
        "daif":      lambda ps: (ps >> 6) & 0xF,
        "nzcv":      lambda ps: (ps >> 28) & 0xF,
    }

    def stack_setup_hint(self):
        return ("arm64 head.S establishes sp only in __primary_switch\n"
                "      (`adrp x1, early_init_stack`); before that there is nothing to scan.")

    def _is_va(self, addr):
        # TTBR1 (kernel) high half for 48-bit AND 52-bit VA: 48-bit -> top 16 bits
        # 0xFFFF, 52-bit (ARMv8.2 LVA) -> top 12 bits 0xFFF.  `(addr >> 52) == 0xFFF`
        # matches both (0xFFFF8.. >>52 == 0xFFF, 0xFFF0.. >>52 == 0xFFF); phys is far below.
        return (addr >> 52) == 0xFFF

    def mmu_translation_on(self):
        v = evi("$SCTLR_EL1")             # usually absent on the QEMU gdbstub
        if v is None:
            h = TARGET.mmu_hint()         # profile may name a readable MMU reg
            if h and h.get("reg"):
                v = evi("$" + str(h["reg"]))
                if v is not None:
                    return bool(v & (1 << int(h.get("bit", 0))))
            return None
        return bool(v & 1)

    def auto_calibrate(self, sess):
        pc = reg("pc")
        if pc is not None and not self._is_va(pc):
            va = symval(self.entry_symbol)
            return None if va is None else (pc - va) & MASK
        # Attached post-MMU (pc is a VA): kimage_voffset = VA - PA for the image,
        # so PA-VA = -kimage_voffset.  Set by the time start_kernel runs.
        kv = evi("kimage_voffset")
        return None if kv is None else (-kv) & MASK

    def detect_kaslr_slide(self, sess):
        # arm64: slide = kimage_voffset + offset, where
        #   kimage_voffset = runtimeVA(_text) - PA(_text)   (arch/arm64/mm/mmu.c; set in head.S)
        #   offset         = PA(_text) - linkVA(_text)       (sess.offset, from calibration)
        # Read kimage_voffset's VALUE at its INVARIANT physical address via `monitor xp`
        # -- valid in every regime and, unlike evi(), needs no mapped (slid) link VA.
        lk = symval("kimage_voffset")
        if lk is None or sess.offset is None:
            return None
        lk = (lk - sess.kaslr_slide) & MASK
        v = read_phys_u64((lk + sess.offset) & MASK)
        if not v:                       # 0 => not written yet (before __primary_switched sets it)
            return None
        return (v + sess.offset) & MASK

    def find_mmu_enable(self, sess):
        """`msr sctlr_el1, xN` inside __enable_mmu -- the write whose bit 0 (M) turns
        the MMU on.  Encoding is 0xD5181000 | Rt, so a masked word compare finds it
        without knowing the register or the kernel version.  __enable_mmu exists in
        both 6.12 and 4.6; the 4.6 KASLR build runs its tail twice, and the FIRST
        match is the one that first enables translation."""
        if sess.offset is None:
            return None
        MSR_SCTLR_EL1, RT = 0xD5181000, 0xFFFFFFE0
        for fn in ("__enable_mmu", "__primary_switch"):
            fva = symval(fn)
            if fva is None:
                continue
            link = sess._link_va(fva)
            if link is None:
                continue
            base = (link + sess.offset) & MASK
            for k in range(64):
                w = read_phys_u32((base + 4 * k) & MASK)
                if w is None:
                    break
                if (w & RT) == MSR_SCTLR_EL1:
                    return {"pa": (base + 4 * k) & MASK,
                            "link": (link + 4 * k) & MASK,
                            "desc": "%s+0x%x: msr sctlr_el1, x%d  (M=1 turns the MMU on)"
                                    % (fn, 4 * k, w & 0x1F)}
        return None

    def find_crossing(self, sess):
        # Primary CPU's phys->high-VA transfer: the terminal `br xN` that jumps to
        # the first virtual landing.  6.12: `br x8` -> __primary_switched at the tail
        # of __primary_switch, after `bl __pi_early_map_kernel` mapped+relocated
        # (head.S:515-519).  4.6: `br x27` -> __mmap_switched at the tail of
        # __enable_mmu, x27 = link + x23(=kaslr displacement) (head.S:809-811).  It
        # runs idmapped (VA==PA -- proven by the adjacent `adrp x0, KERNEL_START //
        # __pa`), so a HW bp at PA(br)=linkVA(br)+offset fires; xN then holds the
        # landing's RUNTIME VA => slide = xN - linkVA(landing).  Reading the register
        # (not a global) works even under nokaslr, where the slide is pa_base % 2M,
        # not necessarily 0.  Scanned from the crossing function's phys bytes so no
        # per-version address is hard-coded.
        if sess.offset is None:
            return None
        land = next((s for s in ("__primary_switched", "__mmap_switched")
                     if symval(s) is not None), None)
        if land is None:
            return None
        tl = sess._link_va(symval(land))
        if tl is None:
            return None
        BR, RET, MASKI = 0xD61F0000, 0xD65F0000, 0xFFFFFC1F   # br / ret opcode masks
        for fn in ("__primary_switch", "__enable_mmu"):
            fva = symval(fn)
            if fva is None:
                continue
            link_fva = sess._link_va(fva)
            if link_fva is None:
                continue
            base_pa = (link_fva + sess.offset) & MASK
            for k in range(48):                    # these idmap routines are short
                w = read_phys_u32((base_pa + 4 * k) & MASK)
                if w is None:
                    break
                if (w & MASKI) == RET:             # function end reached, no crossing
                    break
                if (w & MASKI) == BR:              # br xN -- the primary crossing
                    return {"pa": (base_pa + 4 * k) & MASK,
                            "reg": "x%d" % ((w >> 5) & 0x1F), "stepi": False,
                            "target_link": tl, "land": land, "detect_fallback": True,
                            "desc": "%s: br -> %s" % (fn, land)}
        return None

    def sysreg(self, name):
        n = name.lower()
        if n in self.PSTATE_DERIVED:
            ps = reg("pstate")
            if ps is None:
                ps = reg("cpsr")
            if ps is not None:
                return self.PSTATE_DERIVED[n](ps)
        v = evi("$" + name)              # exposed sysreg (rare) ?
        if v is not None:
            return v
        return monitor_reg(name)         # QEMU monitor fallback

    ctx_sysregs = ("CurrentEL", "SCTLR_EL1", "TTBR0_EL1", "TTBR1_EL1", "TCR_EL1",
                   "MAIR_EL1", "VBAR_EL1", "SP_EL0", "ELR_EL1", "SPSR_EL1",
                   "ESR_EL1", "FAR_EL1", "DAIF", "NZCV")
    ctx_inline_sysregs = ("CurrentEL", "SCTLR_EL1", "TTBR0_EL1", "TTBR1_EL1", "DAIF")

    def _cur_el(self):
        el = self.sysreg("CurrentEL")
        return ((el >> 2) & 3) if el is not None else None

    def inline_sysreg_names(self):
        # Show the registers of the regime we are ACTUALLY in: SCTLR/TTBR are
        # banked per EL (TTBR0_EL1+TTBR1_EL1 for the kernel's EL1&0 regime;
        # _EL2 under VHE; EL3 has TTBR0_EL3 only -- no TTBR1).
        el = self._cur_el() or 1
        names = ["CurrentEL", "SCTLR_EL%d" % el, "TTBR0_EL%d" % el]
        if el != 3:
            names.append("TTBR1_EL%d" % el)
        names.append("DAIF")
        return names

    def context_summary(self, sess):
        el = self._cur_el()
        eltxt = ("EL%d" % el) if el is not None else "EL?"
        n = el or 1
        sctlr = self.sysreg("SCTLR_EL%d" % n)
        mmu = "?" if sctlr is None else ("on" if (sctlr & 1) else "off")
        daif = self.sysreg("DAIF")
        bits = ["MMU=%s %s" % (mmu, eltxt),
                "SCTLR_EL%d=%s" % (n, _h(sctlr)),
                "TTBR0_EL%d=%s" % (n, _h(self.sysreg("TTBR0_EL%d" % n)))]
        if n != 3:
            bits.append("TTBR1_EL%d=%s" % (n, _h(self.sysreg("TTBR1_EL%d" % n))))
        bits.append("PSTATE.DAIF=%s" % (_h(daif) if daif is not None else "?"))
        return "  ".join(bits)

    # TTBR0/1 (page-table base), VBAR (vector base), ELR/FAR (addresses),
    # SP_ELx hold addresses -> telescope.  EL is banked, so match the family
    # (TTBR0_EL1, TTBR0_EL2, ...) by stripping the _ELn suffix.
    def _sysreg_is_addr(self, name):
        base = re.sub(r"_el[0123]$", "", name.lower())
        return base in ("ttbr0", "ttbr1", "vbar", "elr", "far", "sp")

    def render_sysreg(self, name, value):
        # TTBR keeps its telescope (it is the heart of arm64 MMU debugging), but
        # the RAW register carries the ASID in bits[63:48], making it a
        # non-canonical pointer that would crash pwndbg's telescope.  So show the
        # raw value AND telescope the ASID-stripped page-table base (the thing
        # worth following) -- more correct, and safe.
        n = re.sub(r"_el[0123]$", "", name.lower())
        if n in ("ttbr0", "ttbr1"):
            base = value & ((1 << 48) - 1) & ~0xFFF
            asid = (value >> 48) & 0xFFFF
            hexv = PWN.color("yellow", "0x%x" % value) or ("0x%x" % value)
            # telescope the page-table base via PHYSICAL reads (TTBR holds a phys
            # PGD address): PGD -> PUD -> PMD ... -- the heart of arm64 MMU
            # debugging -- but with safe_chain's hard depth bound (kearly chaindepth),
            # never pwndbg's unbounded chain (which walks the whole tree until gdb dies).
            chain = safe_chain(base, phys=True)
            tail = "  PTbase %s" % (chain if chain else "0x%x" % base)
            if asid:
                tail += "  ASID 0x%x" % asid
            return hexv + tail
        return Arch.render_sysreg(self, name, value)

    def decode_sysreg(self, name, value):
        n = re.sub(r"_el[0123]$", "", name.lower())
        if n == "currentel":
            return "EL%d" % ((value >> 2) & 3)
        if n == "sctlr":
            m = value & 1
            return "M=%d (MMU %s)  C=%d I=%d A=%d SA=%d WXN=%d" % (
                m, "on" if m else "off", (value >> 2) & 1, (value >> 12) & 1,
                (value >> 1) & 1, (value >> 3) & 1, (value >> 19) & 1)
        if n in ("daif", "nzcv"):
            # sysreg() returns the field already shifted to bits[3:0]; a raw
            # register read leaves DAIF at [9:6] / NZCV at [31:28] -> normalise.
            v = value
            if n == "daif" and (v & ~0xF):
                v = (v >> 6) & 0xF
            if n == "nzcv" and (v & ~0xF):
                v = (v >> 28) & 0xF
            order = ((3, "D"), (2, "A"), (1, "I"), (0, "F")) if n == "daif" \
                else ((3, "N"), (2, "Z"), (1, "C"), (0, "V"))
            letters = [ch if (v >> b) & 1 else ch.lower() for b, ch in order]
            if n == "daif":
                note = "all masked" if v == 0xF else ("none masked" if v == 0 else "partial")
                return "[%s]  (%s)" % (" ".join(letters), note)
            return "[%s]" % " ".join(letters)
        if n == "tcr":
            t0, t1 = value & 0x3F, (value >> 16) & 0x3F
            return "T0SZ=%d (VA %d-bit)  T1SZ=%d (VA %d-bit)" % (
                t0, 64 - t0, t1, 64 - t1)
        return None

    # --- page-table walk (4KB granule / up to 4 levels, TCR-driven) -------
    pagewalk_supported = True
    _ARM_LVL = {0: "L0/PGD", 1: "L1/PUD", 2: "L2/PMD", 3: "L3/PTE"}

    def _regime_for(self, va):
        el = self._cur_el() or 1
        if self._is_va(va):
            return ("TTBR1_EL%d" % el, "TTBR1_EL%d (kernel/high)" % el, True)
        return ("TTBR0_EL%d" % el, "TTBR0_EL%d (idmap/low)" % el, False)

    def pt_base(self, va):
        regname, label, is_ttbr1 = self._regime_for(va)
        ttbr = self.sysreg(regname)
        if ttbr is None:
            return None
        base = ttbr & ((1 << 48) - 1) & ~0xFFF            # strip ASID + align
        if base == 0:                                     # TTBR unset -> paging not up
            return None
        page_shift, nlevels, stride = 12, 4, 9
        tcr = self.sysreg("TCR_EL%d" % (self._cur_el() or 1))
        if tcr is not None:
            tsz = ((tcr >> 16) & 0x3F) if is_ttbr1 else (tcr & 0x3F)
            tg = ((tcr >> 30) & 3) if is_ttbr1 else ((tcr >> 14) & 3)
            page_shift = ({1: 14, 2: 12, 3: 16}.get(tg, 12) if is_ttbr1
                          else {0: 12, 1: 16, 2: 14}.get(tg, 12))
            stride = page_shift - 3
            va_bits = 64 - tsz if 1 <= tsz <= 47 else 48
            addr_bits = max(va_bits - page_shift, stride)
            nlevels = (addr_bits + stride - 1) // stride
        top_shift = page_shift + (nlevels - 1) * stride
        self._ptcfg = {"page_shift": page_shift, "nlevels": nlevels,
                       "stride": stride, "top_shift": top_shift,
                       "start": 4 - nlevels}
        return (label, base)

    def pt_levels(self):
        c = getattr(self, "_ptcfg", None) or {"nlevels": 4, "start": 0, "page_shift": 12}
        if c["page_shift"] != 12:
            return ["Lvl%d" % i for i in range(c["nlevels"])]
        return [self._ARM_LVL.get(c["start"] + i, "L%d" % (c["start"] + i))
                for i in range(c["nlevels"])]

    def pt_index(self, va, level):
        c = self._ptcfg
        shift = c["top_shift"] - level * c["stride"]
        return ((va >> shift) & ((1 << c["stride"]) - 1), shift)

    @staticmethod
    def _leaf_attrs(desc):
        af, ap, sh, ai = (desc >> 10) & 1, (desc >> 6) & 3, (desc >> 8) & 3, (desc >> 2) & 7
        pxn, uxn, ng, con = (desc >> 53) & 1, (desc >> 54) & 1, (desc >> 11) & 1, (desc >> 52) & 1
        apn = {0: "RW-", 1: "RWEL0", 2: "RO-", 3: "ROEL0"}[ap]
        shn = {0: "NS", 1: "?", 2: "OSh", 3: "ISh"}[sh]
        return "AF=%d %s AttrIdx=%d %s%s%s%s%s" % (
            af, apn, ai, shn, " PXN" if pxn else "", " UXN" if uxn else "",
            " nG" if ng else "", " Cont" if con else "")

    def pt_decode(self, desc, level, shift, nlevels):
        if not (desc & 1):
            return ("invalid", None, None, "")
        table_bit = (desc >> 1) & 1
        last = (level == nlevels - 1)
        oa = desc & ((1 << 48) - 1) & ~0xFFF               # bits[47:12]
        if not last and table_bit:
            return ("table", oa, None, "")
        if last and not table_bit:
            return ("invalid", None, None, "reserved@last")
        leaf_base = desc & ((1 << 48) - 1) & ~((1 << shift) - 1)
        return (("page" if last else "block"), None, leaf_base, self._leaf_attrs(desc))

    def pt_config_desc(self):
        c = getattr(self, "_ptcfg", None)
        if not c:
            return "4KB granule, 48-bit VA, 4-level (assumed)"
        return "%dKB granule, %d-level (L%d..L3), %d-bit index/level" % (
            1 << (c["page_shift"] - 10), c["nlevels"], c["start"], c["stride"])

    # --- mmview support -------------------------------------------------
    def _hi_prefix(self):
        """High canonical VA prefix (bits above the active VA size) for TTBR1."""
        tcr = self.sysreg("TCR_EL%d" % (self._cur_el() or 1))
        vb = 48
        if tcr is not None:
            t1 = (tcr >> 16) & 0x3F
            if 1 <= t1 <= 47:
                vb = 64 - t1
        return (~((1 << vb) - 1)) & MASK

    def pt_dump_roots(self):
        el = self._cur_el() or 1
        hi = symval("_text") or (self._hi_prefix() | 0x80000)
        return [("kernel  TTBR1_EL%d" % el, hi, self._hi_prefix()),
                ("idmap   TTBR0_EL%d" % el, 0, 0)]

    va_landmarks = (
        ("_text", "kernel image start (.head.text)"),
        ("_stext", ".text start"),
        ("_etext", ".text / rodata boundary"),
        ("__init_begin", "__init start"),
        ("__init_end", "__init end (freed after boot)"),
        ("_edata", ".data end"),
        ("__bss_start", ".bss start"),
        ("_end", "kernel image end"),
        ("swapper_pg_dir", "kernel PGD (TTBR1)"),
        ("idmap_pg_dir", "identity-map PGD (TTBR0)"),
        ("init_task", "init task_struct"),
        ("vectors", "EL1 exception vectors (VBAR)"),
    )

    def census_read(self, name):
        # cheap path for the per-stop panel: PSTATE-derived fields + gdb-exposed
        # sysregs only (no monitor round-trip).  kcensus does the full lookup.
        n = name.lower()
        if n in self.PSTATE_DERIVED:
            ps = reg("pstate")
            if ps is None:
                ps = reg("cpsr")
            if ps is not None:
                return self.PSTATE_DERIVED[n](ps)
        return evi("$" + name)

    # --- early-boot register census (union of 4.6 + 6.12 head.S call chain) ---
    census = (
        # translation
        ("TTBR0_EL1", "RW", "translation", "idmap/user page-table base (MMU enable, switch_mm, resume)"),
        ("TTBR1_EL1", "RW", "translation", "kernel/swapper page-table base (KPTI, replace-ttbr1)"),
        ("TCR_EL1", "RW", "translation", "granule + T0SZ/T1SZ + IPS + cacheability/shareability"),
        ("TCR2_EL1", "RW", "translation", "extended translation control (S1PIE/PIE enable) [6.12]"),
        ("VTTBR_EL2", "W", "translation", "clear stage-2 base (no guest)"),
        ("TTBR0_EL12", "R", "translation", "VHE alias: read EL1 TTBR0 during MM transfer [6.12]"),
        ("TTBR1_EL12", "R", "translation", "VHE alias: read EL1 TTBR1 during MM transfer [6.12]"),
        ("TCR_EL12", "R", "translation", "VHE alias: read EL1 TCR during MM transfer [6.12]"),
        # memory-attr
        ("MAIR_EL1", "RW", "memory-attr", "memory attribute indirection (Device/Normal/NC/WT encodings)"),
        ("PIR_EL1", "W", "memory-attr", "permission indirection (S1PIE) [6.12]"),
        ("PIRE0_EL1", "W", "memory-attr", "permission indirection EL0 (S1PIE) [6.12]"),
        ("LORC_EL1", "W", "memory-attr", "clear LORegion control [6.12]"),
        ("MAIR_EL12", "R", "memory-attr", "VHE alias: read EL1 MAIR [6.12]"),
        ("PIR_EL12", "R", "memory-attr", "VHE alias: read EL1 PIR [6.12]"),
        ("PIRE0_EL12", "R", "memory-attr", "VHE alias: read EL1 PIRE0 [6.12]"),
        # system-control
        ("SCTLR_EL1", "RW", "system-control", "MMU(M) + caches(C/I) + endianness + alignment"),
        ("SCTLR_EL2", "RW", "system-control", "EL2 system control (EE, MMU-off init, ENTP2)"),
        ("SCTLR_EL12", "RW", "system-control", "VHE alias: set/enable EL1 SCTLR [6.12]"),
        ("CPACR_EL1", "RW", "system-control", "FP/ASIMD/SVE/SME EL0/EL1 access enable"),
        ("CPTR_EL2", "RW", "system-control", "coprocessor trap control to EL2 (disable FP/SVE/SME traps)"),
        ("HCR_EL2", "RW", "system-control", "hyp config: RW(64-bit EL1), E2H/TGE (VHE), host flags"),
        ("HCRX_EL2", "W", "system-control", "extended hyp config [6.12]"),
        ("HSTR_EL2", "W", "system-control", "disable CP15 (AArch32) traps to EL2"),
        ("ICC_SRE_EL2", "RW", "system-control", "GICv3 sysreg interface enable (+read-back check)"),
        ("ICH_HCR_EL2", "W", "system-control", "reset GICv3 hyp control to defaults"),
        ("HFGRTR_EL2", "W", "system-control", "disable fine-grained read traps [6.12]"),
        ("HFGWTR_EL2", "W", "system-control", "disable fine-grained write traps [6.12]"),
        ("HFGITR_EL2", "W", "system-control", "disable fine-grained insn traps [6.12]"),
        ("HFGRTR2_EL2", "W", "system-control", "disable FGT2 read traps [6.12]"),
        ("HFGWTR2_EL2", "W", "system-control", "disable FGT2 write traps [6.12]"),
        ("HFGITR2_EL2", "W", "system-control", "disable FGT2 insn traps [6.12]"),
        ("ZCR_EL2", "W", "system-control", "SVE vector length (max) for EL1 [6.12]"),
        ("SMCR_EL2", "W", "system-control", "SME vector length / FA64 / EZT0 [6.12]"),
        ("SMPRIMAP_EL2", "W", "system-control", "SME priority mapping [6.12]"),
        ("CPACR_EL12", "R", "system-control", "VHE alias: read EL1 CPACR [6.12]"),
        ("DAIF", "RW", "system-control", "mask/restore D,A,I,F (irq/SError/debug)"),
        # el-transition
        ("CurrentEL", "R", "el-transition", "determine entry EL (EL2 vs EL1) to pick setup path"),
        ("SPSR_EL2", "W", "el-transition", "saved PSTATE for EL2->EL1 drop eret (EL1h, DAIF masked)"),
        ("ELR_EL2", "W", "el-transition", "exception link for EL2->EL1 drop eret"),
        ("SPSR_EL1", "RW", "el-transition", "saved PSTATE for EL1 eret; rewritten on VHE upgrade"),
        ("ELR_EL1", "W", "el-transition", "exception link for EL1->EL1 clean-state eret [6.12]"),
        ("SP_EL0", "W", "el-transition", "install task/thread_info stack pointer"),
        ("SP_EL1", "R", "el-transition", "reuse EL1 stack after VHE upgrade [6.12]"),
        # exception-vectors
        ("VBAR_EL1", "RW", "exception-vectors", "install EL1 exception vector base (vectors)"),
        ("VBAR_EL2", "RW", "exception-vectors", "install EL2 hyp-stub vector base"),
        ("VBAR_EL12", "R", "exception-vectors", "VHE alias: read EL1 VBAR [6.12]"),
        ("ESR_EL2", "R", "exception-vectors", "decode HVC syndrome in hyp-stub sync handler [4.6]"),
        # feature-id
        ("MIDR_EL1", "R", "feature-id", "main ID -> VPIDR_EL2 mirror; errata checks"),
        ("MPIDR_EL1", "R", "feature-id", "CPU affinity: secondary pen match, VMPIDR mirror"),
        ("CTR_EL0", "R", "feature-id", "cache type: D/I line size for maintenance loops"),
        ("ID_AA64MMFR0_EL1", "R", "feature-id", "TGRAN granule support + PARange for TCR.IPS"),
        ("ID_AA64MMFR1_EL1", "R", "feature-id", "HAFDBS, VHE(VH), HCX, LO fields"),
        ("ID_AA64MMFR2_EL1", "R", "feature-id", "VARange (52-bit VA) support [6.12]"),
        ("ID_AA64MMFR3_EL1", "R", "feature-id", "S1PIE/S1POE/TCRX presence [6.12]"),
        ("ID_AA64MMFR4_EL1", "R", "feature-id", "E2H0 -> detect VHE-only CPUs [6.12]"),
        ("ID_AA64PFR0_EL1", "R", "feature-id", "GIC sysreg iface / SVE / AMU presence"),
        ("ID_AA64PFR1_EL1", "R", "feature-id", "SME presence (FGT + SME enable) [6.12]"),
        ("ID_AA64DFR0_EL1", "R", "feature-id", "PMUVer/PMSVer/TraceBuffer -> gate PMU/SPE/TRBE"),
        ("ID_AA64SMFR0_EL1", "R", "feature-id", "SME features (FA64, SMEver/ZT0) [6.12]"),
        ("PMBIDR_EL1", "R", "feature-id", "SPE profiling buffer ID (EL2 ownership) [6.12]"),
        ("TRBIDR_EL1", "R", "feature-id", "trace buffer ID (EL2 ownership) [6.12]"),
        ("SMIDR_EL1", "R", "feature-id", "SME ID: priority-mapping supported? [6.12]"),
        ("VMPIDR_EL2", "W", "feature-id", "virtual MPIDR for EL1 (mirror of MPIDR_EL1)"),
        ("VPIDR_EL2", "W", "feature-id", "virtual PIDR for EL1 (mirror of MIDR_EL1)"),
        # timer
        ("CNTHCTL_EL2", "RW", "timer", "enable EL1/EL0 physical timer & counter access"),
        ("CNTVOFF_EL2", "W", "timer", "clear virtual counter offset (=0)"),
        # debug
        ("MDSCR_EL1", "RW", "debug", "monitor debug system control: reset, disable DCC/EL0, step"),
        ("MDCR_EL2", "RW", "debug", "debug/monitor config: PMU to EL1, SPE/TRBE ownership"),
        ("OSLAR_EL1", "W", "debug", "OS lock access (restore OS-lock on resume)"),
        ("OSLSR_EL1", "R", "debug", "OS lock status (saved during suspend)"),
        ("OSDLR_EL1", "RW", "debug", "OS double-lock (suspend/resume) [6.12]"),
        ("PMCR_EL0", "R", "debug", "read PMU counter count (N) to program MDCR_EL2"),
        ("PMUSERENR_EL0", "W", "debug", "disable PMU access from EL0"),
        ("PMSCR_EL2", "W", "debug", "SPE profiling control [6.12]"),
        ("HDFGRTR_EL2", "W", "debug", "disable debug FGT read traps (SPE etc.) [6.12]"),
        ("HDFGWTR_EL2", "W", "debug", "disable debug FGT write traps [6.12]"),
        ("HDFGRTR2_EL2", "W", "debug", "disable debug FGT2 read traps [6.12]"),
        ("HDFGWTR2_EL2", "W", "debug", "disable debug FGT2 write traps [6.12]"),
        ("HAFGRTR_EL2", "W", "debug", "disable AMU FGT read traps [6.12]"),
        ("AMUSERENR_EL0", "W", "debug", "disable AMU counter access from EL0 [6.12]"),
        ("DISR_EL1", "W", "debug", "clear deferred SError/RAS on resume [6.12]"),
        # misc
        ("CONTEXTIDR_EL1", "RW", "misc", "context ID (saved/restored across suspend/resume)"),
        ("TPIDR_EL1", "RW", "misc", "per-CPU offset base (non-VHE)"),
        ("TPIDR_EL2", "RW", "misc", "per-CPU offset base under VHE [6.12]"),
        ("TPIDR_EL0", "RW", "misc", "user thread pointer (suspend/resume)"),
        ("TPIDRRO_EL0", "RW", "misc", "user read-only thread pointer (suspend/resume)"),
        ("FAR_EL1", "RW", "misc", "scratch: write+readback to probe HCR_EL2.E2H (VHE detect) [6.12]"),
        ("FAR_EL2", "W", "misc", "scratch: probe FAR remapping for VHE detect [6.12]"),
    )
