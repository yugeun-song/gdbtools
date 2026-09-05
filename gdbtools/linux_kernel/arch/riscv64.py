"""riscv64: the kernel half.  See gdbtools.common.arch.riscv64 for the rest."""
import os
import json
import struct
import gdb
import re

from ...common.runtime import *
from ..physmem import *
from ...common.arch.riscv64 import Riscv64Common
from .base import KernelArch




class Riscv64(Riscv64Common, KernelArch):
    entry_symbol = "_start"
    entry_break_kind = "sw"              # entry executes in place; sw bp is reliable
    entry_magic = (0x05435352, 0x38)     # RISCV_IMAGE_MAGIC2 "RSC\x05" at _start+0x38
    dtb_pointer_reg = "a1"               # SBI leaves the DTB PA in a1 at _start
    return_reg = "ra"                    # x1; head calls via jal, so ra = ret addr

    def _is_va(self, addr):
        # Kernel high half for ANY satp mode (Sv39 >=0xFFFFFFC0.., Sv48 >=0xFFFF8000..,
        # Sv57 >=0xFF000000..).  All sit at/above -2^56; guest physical is far below,
        # so this single threshold classifies every mode without catching a phys addr.
        return addr >= 0xFF00000000000000

    def detect_kaslr_slide(self, sess):
        # riscv64: the global `struct kernel_mapping kernel_map` (.data) holds
        #   kernel_map.virt_addr = runtimeVA(_start)      (arch/riscv/mm/init.c)
        # so slide = virt_addr - linkVA(_start).  Read virt_addr's VALUE at its
        # INVARIANT physical address (kernel_map is .data: PA = linkVA + offset),
        # via `monitor xp` -- non-circular.  Field offset from DWARF so it survives
        # struct-layout changes; fallback +8 (asm-offsets KERNEL_MAP_VIRT_ADDR).
        km = symval("kernel_map")
        link_start = sess.link_entry_va()        # robust image-base link VA (ET_DYN/PIE-safe)
        if km is None or link_start is None or sess.offset is None:
            return None
        foff = evi("(unsigned long long)&((struct kernel_mapping*)0)->virt_addr")
        if foff is None:
            foff = 8
        link_km = (km - sess.kaslr_slide) & MASK
        va = read_phys_u64((link_km + sess.offset + foff) & MASK)
        if va is None or not self._is_va(va):
            return None
        return (va - link_start) & MASK

    def find_mmu_enable(self, sess):
        """`csrw satp, rsN` inside relocate_enable_mmu -- writing satp.MODE is what
        turns translation on.  Encoding is csrrw x0, satp(0x180), rs1 =
        0x18001073 | (rs1 << 15), so a masked compare finds it regardless of which
        register the compiler picked.  The FIRST match is the trampoline switch --
        the instruction after which the next fetch traps to stvec."""
        if sess.offset is None:
            return None
        CSRW_SATP, RS1 = 0x18001073, 0xFFF07FFF
        rem = symval("relocate_enable_mmu")
        if rem is None:
            return None
        link = sess._link_va(rem)
        if link is None:
            return None
        base = (link + sess.offset) & MASK
        for k in range(48):
            w = read_phys_u32((base + 4 * k) & MASK)
            if w is None:
                break
            if (w & RS1) == CSRW_SATP:
                return {"pa": (base + 4 * k) & MASK,
                        "link": (link + 4 * k) & MASK,
                        "desc": "relocate_enable_mmu+0x%x: csrw satp  (next fetch traps to stvec)"
                                % (4 * k)}
        return None

    def find_crossing(self, sess):
        # riscv's crossing is trap-mediated (csrw satp loads trampoline_pg_dir, which
        # maps only the high VA, trapping to stvec=virt(1f)) -- awkward to anchor on
        # directly.  But head.S does `call setup_vm` (head.S:311) BEFORE `call
        # relocate_enable_mmu` (head.S:315), and setup_vm writes kernel_map.virt_addr
        # to its FINAL value (mm/init.c:1129).  So at relocate_enable_mmu's entry the
        # primary is still MMU-off (physical) yet the slide is already readable via
        # detect_kaslr_slide (kernel_map.virt_addr).  Break there; let detect read it.
        if sess.offset is None:
            return None
        rem = symval("relocate_enable_mmu")
        if rem is None:
            return None
        link_rem = sess._link_va(rem)
        if link_rem is None:
            return None
        return {"pa": (link_rem + sess.offset) & MASK, "reg": None, "stepi": False,
                "target_link": None, "land": "relocate_enable_mmu",
                "detect_fallback": True,
                "desc": "relocate_enable_mmu entry (post setup_vm, MMU-off)"}

    # This kernel's own top-level tables across the setup_vm / relocate window.
    pt_root_symbols = ("swapper_pg_dir", "trampoline_pg_dir", "early_pg_dir")

    def _translation_probe(self):
        # satp.MODE (bits 63:60) is both the enable bit and the shape selector:
        # 0 is Bare, meaning no translation at all.  Unlike arm64 and x86 there is
        # no separate enable flag to fall out of step with the base register, so
        # the gate and the root come from the same read.
        #
        # Read through the shared chain rather than evi() alone: a stub that hides
        # satp from the register set but answers `monitor info registers` would
        # otherwise leave the gate unknown while pt_base() reads the value fine.
        satp, src = self.read_ctrl("satp")
        if satp is None:
            return ("unknown", "none", None,
                    "satp did not answer (no gdb register, no QEMU monitor)")
        mode = (satp >> 60) & 0xF
        if mode == 0:
            return ("off", src, "Bare",
                    "satp=0x%x -> MODE=0 (Bare: no address translation)" % satp)
        info = self._SATP_MODE.get(mode)
        if info is None:
            return ("unknown", src, None,
                    "satp=0x%x -> MODE=%d, which is not a mode this build decodes"
                    % (satp, mode))
        return ("on", src, info[0],
                "satp=0x%x -> MODE=%d (%s)" % (satp, mode, info[0]))

    def auto_calibrate(self, sess):
        pc = reg("pc")
        if pc is not None and not self._is_va(pc):
            va = symval(self.entry_symbol)
            return None if va is None else (pc - va) & MASK
        # Attached post-MMU (pc is a VA): kernel_map.va_kernel_pa_offset = VA - PA
        # for the kernel image, so PA-VA = -that.  (riscv linear map uses
        # va_pa_offset; for symbolizing image code the kernel offset is correct.)
        for sym in ("kernel_map.va_kernel_pa_offset", "va_kernel_pa_offset"):
            v = evi(sym)
            if v is not None:
                return (-v) & MASK
        return None

    def sysreg(self, name):
        v = evi("$" + name)
        if v is not None:
            return v
        return monitor_reg(name)

    ctx_sysregs = ("satp", "sstatus", "stvec", "sepc", "scause", "stval",
                   "sie", "sip", "sscratch")
    ctx_inline_sysregs = ("satp", "sstatus", "stvec", "sepc")

    def context_summary(self, sess):
        s = evi("$satp")
        mode = (s >> 60) & 0xF if s is not None else None
        mmu = "?" if s is None else (("on(mode=%d)" % mode) if mode else "off")
        return "MMU=%s  satp=%s sstatus=%s stvec=%s sepc=%s" % (
            mmu, _h(s), _h(evi("$sstatus")), _h(evi("$stvec")), _h(evi("$sepc")))

    # stvec (trap vector), sepc (exception PC), sscratch (kernel ptr), stval
    # (faulting addr) hold addresses -> telescope.  satp is NOT an address (top
    # nibble is MODE) -> decode and surface the page-table base it encodes.
    addr_sysregs = frozenset(("stvec", "sepc", "sscratch", "stval"))

    def decode_sysreg(self, name, value):
        n = name.lower()
        if n == "satp":
            mode = (value >> 60) & 0xF
            modes = {0: "Bare(off)", 8: "Sv39", 9: "Sv48", 10: "Sv57", 11: "Sv64"}
            ppn = value & ((1 << 44) - 1)
            return "MODE=%d (%s)  PPN=0x%x  (PT@0x%x)" % (
                mode, modes.get(mode, "?"), ppn, ppn << 12)
        if n == "sstatus":
            spp = (value >> 8) & 1
            return "SIE=%d SPIE=%d  SPP=%d (%s)  SUM=%d MXR=%d" % (
                (value >> 1) & 1, (value >> 5) & 1, spp, "S" if spp else "U",
                (value >> 18) & 1, (value >> 19) & 1)
        return None

    # --- page-table walk (Sv39 / Sv48 / Sv57, 4KB pages, 9-bit stride) ----
    pagewalk_supported = True
    _SATP_MODE = {8: ("Sv39", 3, 30), 9: ("Sv48", 4, 39), 10: ("Sv57", 5, 48)}

    def pt_config_probe(self):
        """Shape from satp.MODE, with no table root needed.  On riscv the mode
        field carries both facts, so this succeeds exactly when translation is
        on -- there is no separate enable bit that could disagree."""
        satp, _ = self.read_ctrl("satp")
        if satp is None:
            self._ptcfg = {}
            return False
        info = self._SATP_MODE.get((satp >> 60) & 0xF)
        if info is None:
            self._ptcfg = {}
            return False
        name, nlevels, top_shift = info
        self._ptcfg = {"name": name, "nlevels": nlevels, "top_shift": top_shift,
                       "probed": True}
        return True

    def pt_base_raw(self, va):
        """satp's PPN as it reads right now.  On riscv MODE==0 already means
        "no translation", so a raw read here is only ever informational."""
        satp, _ = self.read_ctrl("satp")
        if satp is None:
            return None
        ppn = satp & ((1 << 44) - 1)
        return None if ppn == 0 else ("satp PPN 0x%x" % ppn, ppn << 12)

    def pt_base(self, va):
        ts = self.translation_state()
        if not ts or ts.get("state") != "on":
            return None
        satp, _ = self.read_ctrl("satp")
        if satp is None or not self.pt_config_probe():
            return None
        ppn = satp & ((1 << 44) - 1)
        return ("satp %s (PPN 0x%x)" % (self._ptcfg["name"], ppn), ppn << 12)

    def pt_levels(self):
        c = getattr(self, "_ptcfg", None) or {"nlevels": 3}
        n = c["nlevels"]
        return ["L%d" % (n - 1 - i) for i in range(n)]

    def pt_index(self, va, level):
        c = self._ptcfg
        shift = c["top_shift"] - level * 9
        return ((va >> shift) & 0x1FF, shift)

    def pt_decode(self, pte, level, shift, nlevels):
        if not (pte & 1):                                 # V=0
            return ("invalid", None, None, "")
        r, w, x = (pte >> 1) & 1, (pte >> 2) & 1, (pte >> 3) & 1
        u, g, a, d = (pte >> 4) & 1, (pte >> 5) & 1, (pte >> 6) & 1, (pte >> 7) & 1
        ppn = (pte >> 10) & ((1 << 44) - 1)
        phys = ppn << 12
        if not (r or x):                                  # pointer PTE -> next table
            return ("table", phys, None, "")
        perm = "".join(c if b else "-" for c, b in (("R", r), ("W", w), ("X", x)))
        attrs = "%s %s%s%s%s" % (perm, "U" if u else "S", " G" if g else "",
                                 " A" if a else "", " D" if d else "")
        leaf_base = phys & ~((1 << shift) - 1)
        return (("page" if level == nlevels - 1 else "block"), None, leaf_base, attrs)

    def pt_config_desc(self):
        c = getattr(self, "_ptcfg", None)
        if not c:
            return "paging shape not probed (satp unread)"
        return "%s, %d-level, 4KB pages" % (c["name"], c["nlevels"])

    # --- mmview support (single satp root; VA sign-extended per satp MODE) ---
    def pt_make_va(self, low, prefix):
        c = getattr(self, "_ptcfg", {}) or {}
        signbit = c.get("top_shift", 30) + 8       # Sv39->38, Sv48->47, Sv57->56
        if low & (1 << signbit):
            low |= (~((1 << (signbit + 1)) - 1)) & MASK
        return low & MASK

    def pt_dump_roots(self):
        rep = symval("_start_kernel") or symval("_start") or symval("_stext") or 0
        return [("kernel  satp", rep, 0)]

    def kernel_va_floor(self):
        c = getattr(self, "_ptcfg", {}) or {}
        vb = c.get("top_shift", 30) + 9        # Sv39->39, Sv48->48, Sv57->57
        return (~((1 << (vb - 1)) - 1)) & MASK

    va_landmarks = (
        ("_start", "image entry (_start)"),
        ("_start_kernel", "S-mode kernel entry"),
        ("_stext", ".text start"),
        ("_etext", ".text end"),
        ("__init_begin", "__init start"),
        ("__init_end", "__init end (freed)"),
        ("_end", "kernel image end"),
        ("swapper_pg_dir", "kernel PGD (satp)"),
        ("trampoline_pg_dir", "trampoline PGD"),
        ("init_task", "init task_struct"),
    )

    census = (
        ("satp", "W", "translation", "enable/switch Sv39/48/57 paging (root PPN + MODE)"),
        ("stvec", "W", "trap-setup", "early trap vector (post-satp landing, spin, handle_exception)"),
        ("sepc", "RW", "trap-setup", "trap PC (saved on entry, written on return)"),
        ("scause", "R", "trap-setup", "trap cause (irq vs exception dispatch)"),
        ("stval", "R", "trap-setup", "trap value / faulting address"),
        ("sstatus", "RW", "status-control", "clear FS/VS to trap FPU/Vector; SUM/SIE on trap"),
        ("fcsr", "W", "status-control", "zero FP control/status after clearing f0-f31"),
        ("vcsr", "RW", "status-control", "reset vector control/status"),
        ("sie", "W", "interrupt", "mask all interrupts on boot entry"),
        ("sip", "W", "interrupt", "clear all pending interrupts on boot entry"),
        ("sscratch", "RW", "misc", "kernel/user tp save slot (0 = in-kernel marker)"),
        ("misa", "R", "feature-id", "probe F/D (FPU) and V (Vector) ISA bits [M-mode]"),
        ("mhartid", "R", "feature-id", "this hart's ID (M-mode, no SBI) [M-mode]"),
        ("pmpaddr0", "W", "misc", "PMP entry-0 address = all memory (NAPOT) [M-mode]"),
        ("pmpcfg0", "W", "misc", "PMP entry-0 config = RWX NAPOT [M-mode]"),
    )
