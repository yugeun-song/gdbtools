"""part of gdbtools; see the package docstring."""
import os
import json
import struct
import gdb
import re
from ..common.runtime import *
from .physmem import *
from ..common.chain import safe_chain
from .target import TARGET
from ..common.arch import ARCHES, detect_arch, _arch_name
from .presets import PRESETS
from .session import SESSION
from .pwndbg_glue import SAFEPROBE


# ----------------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------------
class KEarly(gdb.Command):
    """kearly: early-boot symbolization control.

Everyday: `kearly on`, `kearly bootbreak`, `kearly calibrate` -- or set
$GDBTOOLS_AUTO=1 before gdb starts and all three happen on attach.
The rest are HAND CONTROLS -- every automatic decision is overridable mid-session.

Subcommands:
  kearly safemem [on|off|auto|status]   guard pwndbg's memory-map probing: ask QEMU
                           whether a page is mapped before reading it, so an unmapped
                           probe fails normally instead of crashing the VM (default auto:
                           on only for a kernel target once translation is live)
  kearly where             ONE-LINER ORIENTATION: regime badge, pc + symbol + its phys/virt
                           twin, offset, KASLR slide, boot phase, and the command that most
                           likely moves you forward.  Read-only -- never resumes the CPU.
  kearly regimes [walk|stop NAME]  this build's early-boot MMU stop points (entry / MMU-enable /
                           phys->virt transfer / first virtual instruction / start_kernel), each
                           as symbol+offset, link VA and PA.  'walk' arms all of them so plain
                           `continue` steps through the transition; 'stop NAME' runs to one.
  kearly status            arch / offset / map / MMU / preset / anchor / target / vmlinux
  kearly on | off          enable/disable the auto stop hook + shadow symbols
  kearly bootbreak [arm]   run past QEMU reset/firmware to the kernel entry, calibrate.
                           'arm' only arms the entry breakpoint and does NOT resume, for a
                           front end (VS Code) that has to issue the continue itself
  kearly calibrate [SYM]   compute the phys<->virt offset (auto, or $pc-at-anchor SYM)
  kearly mmu               report MMU on/off + which map + control register
  kearly overmmu [SYM]     cross the MMU-enable boundary via a temp hw-break at the
                           virtual landing + continue (never single-step across
                           __enable_mmu -- QEMU can drop the step there); SYM overrides
  kearly preset [list|NAME] list boot-combination presets, or apply one
  -- machine descriptors (non-QEMU boards: RPi / Broadcom / Qualcomm / ...) --
  kearly profile <path|show>  load a JSON machine profile (ram_base/entry_pa/...)
  kearly dtb <path|guest|show> load a DTB (file, or auto-read from guest RAM)
  -- manual overrides (also settable as $GDBTOOLS_* before gdb starts) --
  kearly offset <hex|->    force the phys<->virt offset by hand ('-' clears it)
  kearly entry <pa|auto>   pin the image-base entry PA (or auto-rescan)
  kearly anchor <sym|->    set the break/calibration anchor symbol (or default)
  kearly break <sw|hw|->   force the entry breakpoint kind (or arch default)
  kearly shadow <on|off>   load/unload just the shadow symbol file
  kearly arch <key|auto>   force the architecture if auto-detect is wrong
  kearly verbose on|off    per-stop pc annotation line
  kearly sysregs on|off    per-stop compact MMU + key-sysreg line (on by default)
  kearly census off|compact|full  per-stop head.S register census in the panel: every
                           system/control register head.S + its call chain touch
                           (off by default; 'full' = annotated, same as `kcensus`)
  kearly chaindepth N      telescope hop depth for the panel's TTBR/addr chains,
                           ksregs and chain (safe_chain: always bounded; default 8)
  kearly steplock on|off|auto  gdb scheduler-locking (default OFF -- untouched): opt in
                           with 'on' (or 'auto'=while-MMU-off) to freeze the other
                           cores during a single-step; restored automatically after
                           (kills the "thread 1 PC keeps jumping" noise); auto-off on MMU
  kearly log [N]           show the internal degrade/diagnostic log
  kearly saferender <warn|on|off|auto>   pwndbg emulated-disasm crash guard on arm64
                           (default 'auto' = 'set emulate off' on arm64, restored on 'kearly off';
                            'off' restores emulation now, 'warn' only prints a heads-up)
  kearly bpfix <on|off>    optional cleanup for dual native(VA)+shadow(PA) breakpoints: the
                           virtual location is ALWAYS kept enabled (it is the one that fires
                           for MMU-on code such as start_kernel); only the dormant physical
                           location is dropped while the MMU is on.  Default OFF -- gdb's
                           native dual-location breakpoint already hits.
  kearly kaslr [auto|off|status|<hex>]   detect the KASLR slide and relocate gdb's symbols
                           to runtime VAs so `b SYM` hits.  'auto': if the slide is not yet
                           readable (cold frozen boot), advance the PRIMARY CPU to the arch's
                           phys->high-VA MMU-crossing -- post-relocation, still idmap/MMU-off,
                           BEFORE start_kernel (arm64 `br x8`->__primary_switched; x86
                           `jmp *0f`->common_startup_64; riscv relocate_enable_mmu entry) --
                           via a temp HW breakpoint at its invariant physical address, read the
                           slide from the branch register/landing/global, then symbol-file -o it.
                           Because it stops BEFORE start_kernel, a following `b start_kernel;
                           continue` lands.  $GDBTOOLS_X86_KASLR=1 runs this on attach.
                           'off' reverts symbols to link addresses; <hex> applies an explicit slide.
                           Only 'auto' ever resumes the CPU.  Bare `kearly kaslr` prints this
                           usage plus the current slide and moves nothing.  'auto' is re-entrant
                           while already stopped ON the crossing: it reads the slide in place
                           rather than continuing into a free-run with nothing left to catch it.
  (see also: ksregs -- full system-register dump; kcensus -- head.S register census;
   kpt [VA] [hex] -- walk the hardware page tables (L0..L3) for VA; kpgd -- dump the top
   table; kpthex -- byte-level hex of a page-table page; mmview / memlayout -- layout + ptdump)
"""

    def __init__(self, name="kearly"):
        super(KEarly, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        args = (arg or "").split()
        sub = args[0].lower() if args else "status"
        if sub == "on":
            SESSION.enable()
            print("[%s] enabled" % NAME)
        elif sub == "off":
            SESSION.disable()
            print("[%s] disabled" % NAME)
        elif sub in ("bootbreak", "boot"):
            SESSION.bootbreak(arm_only=(len(args) > 1 and args[1].lower() in ("arm", "armonly", "noresume")))
        elif sub in ("calibrate", "cal", "recal"):
            SESSION.calibrate(anchor=args[1] if len(args) > 1 else None)
        elif sub == "mmu":
            self._mmu()
        elif sub == "preset":
            if len(args) > 1 and args[1].lower() != "list":
                SESSION.apply_preset(args[1])
            else:
                self._preset_list()
        elif sub == "profile":
            self._profile(args[1] if len(args) > 1 else "show")
        elif sub == "dtb":
            self._dtb(args[1] if len(args) > 1 else "show")
        elif sub == "offset":
            if len(args) > 1 and args[1].lower() not in ("-", "clear", "none"):
                v = evi(args[1])
                if v is not None:
                    SESSION.set_offset(v)
                else:
                    print("usage: kearly offset <hex>   ('kearly offset -' clears)")
            else:
                SESSION.clear_calibration()
        elif sub == "entry":
            if len(args) > 1 and args[1].lower() not in ("-", "auto"):
                SESSION.entry_pa = evi(args[1])
                print("[%s] entry (image-base) PA = %s" % (NAME, fmt(SESSION.entry_pa)))
            else:
                SESSION.entry_pa = None
                print("[%s] entry PA = auto (will re-scan)" % NAME)
        elif sub == "anchor":
            SESSION.anchor = (args[1] if len(args) > 1 and
                              args[1].lower() not in ("-", "none", "auto") else None)
            print("[%s] anchor = %s" % (NAME, SESSION.current_anchor() or "?"))
        elif sub in ("break", "bp", "breakkind"):
            SESSION.break_kind = args[1] if (len(args) > 1 and args[1] in ("sw", "hw")) else None
            print("[%s] break kind = %s" % (NAME, SESSION.current_break_kind()))
        elif sub == "shadow":
            SESSION.set_shadow(len(args) > 1 and args[1].lower() in ("on", "1", "true"))
        elif sub == "arch":
            SESSION.force_arch(args[1] if len(args) > 1 else "auto")
        elif sub == "verbose":
            SESSION.verbose = (len(args) > 1 and args[1].lower() in ("on", "1", "true"))
            print("[%s] verbose=%s" % (NAME, SESSION.verbose))
        elif sub == "sysregs":
            SESSION.show_sysregs = not (len(args) > 1 and
                                        args[1].lower() in ("off", "0", "false", "no"))
            print("[%s] per-stop sysreg/MMU line = %s "
                  "(full dump: ksregs)" % (NAME, SESSION.show_sysregs))
        elif sub in ("census", "regs"):
            SESSION.set_census(args[1] if len(args) > 1 else "compact")
        elif sub in ("chaindepth", "chain", "depth", "telescope", "hops"):
            if len(args) > 1:
                SESSION.set_chain_hops(args[1])
            else:
                print("[%s] telescope depth = %d hops  (kearly chaindepth <N>)"
                      % (NAME, SESSION.chain_hops))
        elif sub in ("steplock", "lock"):
            SESSION.set_steplock(args[1] if len(args) > 1 else "auto")
        elif sub in ("saferender", "safe", "emulate", "emu"):
            SESSION.set_saferender(args[1] if len(args) > 1 else "status")
        elif sub in ("bpfix", "regimebp"):
            SESSION.set_bpfix(args[1] if len(args) > 1 else "on")
        elif sub == "adopt":
            SESSION.adopt = not (len(args) > 1 and args[1].lower() in ("off", "0", "false", "no"))
            print("[%s] adopt=%s  (plain `b SYM` auto-gains PA(S)+IMG(S) regime-aware siblings)"
                  % (NAME, SESSION.adopt))
        elif sub in ("kaslr", "slide"):
            SESSION.set_kaslr(args[1] if len(args) > 1 else "")
        elif sub in ("overmmu", "mmuon", "over", "crossmmu"):
            SESSION.over_mmu(args[1] if len(args) > 1 else None)
        elif sub in ("safemem", "safeprobe"):
            m = (args[1].lower() if len(args) > 1 else "status")
            if m in ("on", "off", "auto"):
                SAFEPROBE.mode = m
                if m != "off":
                    SAFEPROBE.install()
                print("[%s] safemem = %s (%s)"
                      % (NAME, m, "wrapped" if SAFEPROBE.installed else "pwndbg absent"))
            else:
                print("[%s] safemem = %s  installed=%s  blocked=%d unmapped probe(s)  "
                      "rescued=%d phys read(s) via monitor"
                      % (NAME, SAFEPROBE.mode, SAFEPROBE.installed,
                         SAFEPROBE.blocked, SAFEPROBE.rescued))
        elif sub in ("where", "situation"):
            for ln in (SESSION.where_lines() or []):
                print(ln)
        elif sub in ("regimes", "regime"):
            SESSION.regimes(args[1] if len(args) > 1 else None,
                            args[2] if len(args) > 2 else None)
        elif sub == "log":
            print(LOG.dump(int(args[1]) if len(args) > 1 else 40))
        else:
            self._status()

    @safe()
    def _status(self):
        a = SESSION.ensure_arch()
        SESSION.load_overrides()
        st, src = SESSION.mmu_state()
        print("[%s] arch=%s  enabled=%s  offset(PA-VA)=%s\n"
              "      map=%s  MMU=%s [%s]  steplock=%s  census=%s  chaindepth=%d\n"
              "      preset=%s  anchor=%s  break=%s\n"
              "      target=%s\n"
              "      vmlinux=%s  shadow=%s" % (
                  NAME, a.key if a else "?", SESSION.enabled,
                  fmt(SESSION.offset) if SESSION.offset is not None else "(uncalibrated)",
                  SESSION.which_map(), st, src, SESSION.steplock, SESSION.census_mode,
                  SESSION.chain_hops,
                  SESSION.preset or "(default)",
                  SESSION.current_anchor() or "?", SESSION.current_break_kind(),
                  TARGET.describe(),
                  SESSION.vmlinux_path(),
                  fmt(SESSION.shadow_addr) if SESSION.shadow_addr is not None else "off"))

    @safe()
    def _mmu(self):
        a = SESSION.ensure_arch()
        if a is None:
            print("[%s] no arch" % NAME)
            return
        st, src = SESSION.mmu_state()
        pc = reg("pc")
        line = "[%s] MMU=%s [%s]  map=%s  pc=%s" % (
            NAME, st, src, SESSION.which_map(), fmt(pc) if pc is not None else "?")
        # show the raw control register where we can read it
        if a.key == "arm64":
            v = evi("$SCTLR_EL1")
            if v is None:
                v = a.sysreg("SCTLR_EL1")
            line += "  SCTLR_EL1.M=%s" % ("?" if v is None else (v & 1))
        elif a.key == "riscv64":
            v = evi("$satp")
            line += "  satp.MODE=%s" % ("?" if v is None else ((v >> 60) & 0xF))
        elif a.key == "x86_64":
            v = evi("$cr0")
            line += "  cr0.PG=%s" % ("?" if v is None else ((v >> 31) & 1))
        print(line)
        if st == "off":
            print("      pre-MMU: $pc/pointers are PHYSICAL; shadow symbols active.")
        elif st == "on":
            print("      MMU on: kernel VAs resolve natively; kp2v/kv2p translate either way.")

    @safe()
    def _profile(self, arg):
        if arg == "show":
            self._show_target()
            return
        if TARGET.set_profile(arg):
            SESSION.entry_pa = None          # force re-resolve with the new descriptor
            SESSION.load_overrides()

    @safe()
    def _dtb(self, arg):
        if arg == "show":
            self._show_target()
        elif arg in ("guest", "auto"):
            TARGET.try_guest_dtb(SESSION.ensure_arch())
            SESSION.entry_pa = None          # a freshly-read DTB can change the scan
            self._show_target()
        else:
            if TARGET.set_dtb(arg):
                SESSION.entry_pa = None
                self._show_target()

    @safe()
    def _show_target(self):
        a = SESSION.ensure_arch()
        print("[%s] target descriptor: %s" % (NAME, TARGET.describe()))
        if a is not None:
            print("      ram regions: %s" %
                  (", ".join("%s+%s" % (fmt(b), fmt(s)) for b, s in TARGET.ram_regions(a)) or "(none)"))
            print("      scan ranges: %s" %
                  (", ".join("%s..%s" % (fmt(lo), fmt(hi)) for lo, hi in a._scan_ranges()) or "(none)"))
            pe = TARGET.entry_pa()
            if pe is not None:
                print("      profile entry_pa: %s" % fmt(pe))

    @safe()
    def _preset_list(self):
        a = SESSION.ensure_arch()
        print("[%s] presets (* = matches current arch %s; active=%s):" %
              (NAME, a.key if a else "?", SESSION.preset or "default"))
        for name, p in PRESETS.items():
            mark = "*" if (a and p["arch"] == a.key) else " "
            v = "verified" if p["verified"] else "designed"
            print("  %s %-15s [%-8s] %s" % (mark, name, v, p["desc"]))
        print("  overrides: $GDBTOOLS_PRESET/_ANCHOR/_BREAK_KIND/_ENTRY_PA/_RAM_BASE/_SCAN")
        print("  machines : $GDBTOOLS_PROFILE=FILE.json | $GDBTOOLS_DTB=FILE.dtb, or `kearly profile|dtb FILE`")


class P2V(gdb.Command):
    """kp2v ADDR : physical -> virtual (and symbol).  ADDR may be an expression."""

    def __init__(self, name="kp2v"):
        super(P2V, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        pa = evi(arg)
        if pa is None:
            print("usage: kp2v ADDR")
            return
        a = SESSION.arch
        if a is not None and a._is_va(pa):
            print("[%s] kp2v: %s is already a kernel VIRTUAL address, not a physical one.\n"
                  "      Right now: %s.\n"
                  "      Use `kv2p` for this direction, or `sym` which accepts either."
                  % (NAME, fmt(pa), SESSION.regime_phrase()))
            return
        va = SESSION.p2v(pa)
        if va is None:
            print("[%s] uncalibrated -- run: kearly calibrate" % NAME)
            return
        print("PA %s -> VA %s  %s" % (fmt(pa), fmt(va), SESSION.info_symbol(va) or ""))


class V2P(gdb.Command):
    """kv2p ADDR : virtual -> physical.  ADDR may be an expression."""

    def __init__(self, name="kv2p"):
        super(V2P, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        va = evi(arg)
        if va is None:
            print("usage: kv2p ADDR")
            return
        a = SESSION.arch
        if a is not None and not a._is_va(va):
            # Refuse instead of answering.  Applying the VA->PA arithmetic to an
            # address that is already physical produces a plausible-looking number
            # that means nothing -- in head.S, where $pc IS physical, `kv2p $pc` used
            # to return exactly such a value.
            print("[%s] kv2p: %s is not a kernel virtual address -- it looks PHYSICAL.\n"
                  "      Right now: %s.\n"
                  "      Use `kp2v` for this direction, or `sym` which accepts either."
                  % (NAME, fmt(va), SESSION.regime_phrase()))
            return
        pa = SESSION.v2p(va)
        if pa is None:
            print("[%s] uncalibrated -- run: kearly calibrate" % NAME)
            return
        print("VA %s -> PA %s" % (fmt(va), fmt(pa)))
class KB(gdb.Command):
    """kb LOC : regime-aware kernel breakpoint (whitelist-free).

Arms LOC at BOTH its invariant physical address PA(S)=linkVA+offset AND its
runtime kernel VA IMG(S)=linkVA+slide, as hardware breakpoints.  When the code
runs MMU-off / under the idmap (head.S, pi/, secondary-CPU bring-up, cpu_resume)
the PA location fires; once it runs from the high kernel map (start_kernel and all
steady-state code) the IMG location fires.  Whichever regime the CPU is in when
that code executes, the matching location fires and the other never matches.
PA(S) is pure arithmetic and both are HW breakpoints, so neither needs the page
mapped in the live tables -- there is no per-function/section list anywhere.

Usage:  kb SYMBOL  |  kb *ADDR  |  kb FILE:LINE       (remove with `delete`)"""

    def __init__(self, name="kb"):
        super(KB, self).__init__(name, gdb.COMMAND_BREAKPOINTS)

    @safe()
    def invoke(self, arg, from_tty):
        SESSION.kb(arg)


class KW(gdb.Command):
    """kw [-r|-a] LOC [SIZE] : regime-aware kernel WATCHPOINT (the data twin of `kb`).

A kernel global is written through its PHYSICAL address while the MMU is off or
the CPU is running on the idmap (head.S touching __bss, boot args, kernel_map,
the page tables it is building), and through its runtime kernel VA linkVA+slide
once the high map is live.  A plain `watch SYM` only ever covers the single
address the symbol resolves to at the moment you typed it, so it goes blind on
the other side of the MMU crossing.  `kw` arms BOTH -- PA(S)=linkVA+offset and
IMG(S)=linkVA+slide -- and re-points the IMG side automatically the moment the
KASLR slide becomes known, exactly like `kb`.

  kw SYMBOL          write watchpoint, size taken from the symbol's type
  kw -r SYMBOL       read watchpoint (rwatch)
  kw -a SYMBOL       access watchpoint (awatch)
  kw *ADDR [SIZE]    raw address; SIZE in {1,2,4,8} bytes (default 8)

Each kw consumes TWO hardware watchpoint slots, and targets are limited (arm64
cores typically expose 4).  Remove them with `delete` like any watchpoint."""

    def __init__(self, name="kw"):
        super(KW, self).__init__(name, gdb.COMMAND_BREAKPOINTS)

    @safe()
    def invoke(self, arg, from_tty):
        SESSION.kw(arg)
class KSr(gdb.Command):
    """ksr NAME : read a system register, trying (1) arch derivation from pstate,
(2) gdb's exposed register, (3) QEMU monitor passthrough.  Degrades to a clear
'unavailable' note instead of erroring.  Example: ksr CurrentEL"""

    def __init__(self, name="ksr"):
        super(KSr, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        name = arg.strip()
        if not name:
            print("usage: ksr NAME   (e.g. ksr CurrentEL, ksr SCTLR_EL1, ksr satp)")
            return
        a = SESSION.ensure_arch()
        if a is None:
            print("[%s] no arch" % NAME)
            return
        v = a.sysreg(name)
        src = "arch"
        if v is None:
            v = evi("$" + name)
            src = "gdb"
        if v is None:
            v = monitor_reg(name)
            src = "monitor"
        if v is None:
            print("[%s] %s: unavailable via gdbstub/monitor. "
                  "If the next insn is `mrs Xn, %s`, single-step it and read Xn."
                  % (NAME, name, name))
        else:
            print("%s = %s (%d)   [via %s]" % (name, fmt(v), v, src))


class KSregs(gdb.Command):
    """ksregs : dump the key system/control registers for the current arch --
arm64: CurrentEL/SCTLR/TTBR0/TTBR1/TCR/MAIR/VBAR/SP_EL0/ELR/SPSR/ESR/FAR + PSTATE
DAIF/NZCV; riscv: satp/sstatus/stvec/sepc/scause/stval/...; x86: cr0-4/efer.
Same fallback chain as ksr (pstate-derived -> exposed reg -> QEMU monitor); a
register the stub/monitor cannot supply shows '?' with the single-step hint."""

    def __init__(self, name="ksregs"):
        super(KSregs, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        a = SESSION.ensure_arch()
        if a is None:
            print("[%s] no arch" % NAME)
            return
        st, src = SESSION.mmu_state()
        print("[%s] %s   [MMU=%s %s]" % (NAME, a.context_summary(SESSION), st, src))
        miss = []
        for nm in getattr(a, "ctx_sysregs", ()):
            v = a.sysreg(nm)
            if v is None:
                v = evi("$" + nm)
            if v is None:
                miss.append(nm)
                print("  %-12s ?" % nm)
            else:
                dec = a.decode_sysreg(nm, v)
                print("  %-12s %s  (%d)%s" % (nm, fmt(v), v, ("   " + dec) if dec else ""))
        if miss:
            print("  [%s] unreadable via gdbstub/monitor: %s -- if the next insn is "
                  "`mrs Xn, <reg>`, single-step it and read Xn." % (NAME, ", ".join(miss)))


class KFin(gdb.Command):
    """kfin : a 'finish' that works in early asm (head.S) where there is no CFI
unwind info, so gdb's own `finish`/`backtrace` give up ("outermost frame").
Runs to the current function's return address taken straight from the link
register (arm64 $lr / riscv $ra) or the top of stack (x86 *$rsp).  Most reliable
AT or just after a `bl`/`call` target's entry, before a nested call overwrites
the link register.  `kfin ADDR` runs to an explicit return address instead."""

    def __init__(self, name="kfin"):
        super(KFin, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        a = SESSION.ensure_arch()
        if a is None:
            print("[%s] no arch" % NAME)
            return
        ra = evi(arg) if arg.strip() else a.return_addr()
        if ra is None:
            print("[%s] no return address (lr/ra/stack). Pass one explicitly: "
                  "kfin <addr>, or set a breakpoint at the caller." % NAME)
            return
        if not arg.strip() and not ra:
            # At the kernel entry no `bl`/`call` has run, so the link register is
            # still zero.  Running to 0 would take the guest away for no reason --
            # say why instead, and leave the CPU exactly where it is.
            print("[%s] kfin: the return address is %s -- nothing has called into here yet.\n"
                  "      Right now: %s.\n"
                  "      head.S sets the link register only at its first `bl`; until then\n"
                  "      there is no caller to finish back to.  Use `kfin ADDR` for an\n"
                  "      explicit target, or step to a `bl` first." % (NAME, fmt(ra), SESSION.regime_phrase()))
            return
        res = SESSION.symbolize(ra)
        sym = (res[2] if res else None) or ""
        print("[%s] kfin -> return %s %s" % (NAME, fmt(ra), sym))
        execstr("tbreak *0x%x" % (ra & MASK))
        execstr("continue")
class KCensus(gdb.Command):
    """kcensus [full] : dump the head.S early-boot register census -- every
system/control register that head.S AND the files it transitively calls read or
write at least once, with the current value + field decode + purpose, grouped by
category.  These are exactly the registers pwndbg's REGISTERS panel does NOT show.
Use `kearly census compact|full` to render a live version inside the context panel
on every stop."""

    def __init__(self, name="kcensus"):
        super(KCensus, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        a = SESSION.ensure_arch()
        if a is None:
            print("[%s] no arch" % NAME)
            return
        st, src = SESSION.mmu_state()
        print("[%s] head.S early-boot register census -- %s   [MMU=%s %s]   "
              "(%d registers)" % (NAME, a.key, st, src, len(getattr(a, "census", ()))))
        for ln in (SESSION.census_lines(full=True) or []):
            print(ln)
        print("  legend: acc = how head.S uses it (R/W/RW); '?' = not exposed by the "
              "gdbstub/monitor at this EL/moment; tags [6.12]/[4.6]/[M-mode] mark "
              "version- or mode-specific registers.")


class KPt(gdb.Command):
    """kpt [VA] : walk the HARDWARE page tables for VA (default $pc), showing every
level -- L0/PGD..L3/PTE (arm64), PML4..PT (x86_64), or Sv39/48/57 (riscv) -- with
the raw descriptor read from PHYSICAL memory, its type (table/block/page/invalid),
the next-table or output PA (+symbol), and leaf attributes.  This is the reliable
way to inspect the tables AFTER the MMU is on: gdb's `x`/pwndbg `hexdump` on a
physical page-table address fail there, because they translate the address through
the very tables you are trying to read.  VA may be an expression (e.g. &_stext).
Add 'hex' to also print each level's raw descriptor as little-endian bytes."""

    def __init__(self, name="kpt"):
        super(KPt, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        parts = (arg or "").split()
        hexbytes = any(p.lower() in ("hex", "bytes", "raw") for p in parts)
        parts = [p for p in parts if p.lower() not in ("hex", "bytes", "raw")]
        va = evi(" ".join(parts)) if parts else reg("pc")
        if va is None:
            print("usage: kpt VA [hex]    ($pc unavailable -- pass an address/expression)")
            return
        for ln in (SESSION.walk_lines(va, hexbytes=hexbytes) or []):
            print(ln)


class KPgd(gdb.Command):
    """kpgd [TABLE_PA] [MAXROWS] : dump the non-zero entries of a page-table page.
Default: the TOP-level table (arm64 L0/PGD, x86 PML4, riscv satp root) for $pc's
regime.  Each row shows the index, raw descriptor, type, output PA (+symbol) and
attributes.  Pass an explicit TABLE_PA (e.g. a 'table -> 0x...' PA printed by kpt)
to dump a specific lower level."""

    def __init__(self, name="kpgd"):
        super(KPgd, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        parts = (arg or "").split()
        table_pa = evi(parts[0]) if parts else None
        maxrows = 80
        if len(parts) > 1:
            try:
                maxrows = int(parts[1], 0)
            except Exception:
                pass
        for ln in (SESSION.pgd_dump_lines(va=reg("pc"), table_pa=table_pa,
                                          maxrows=maxrows) or []):
            print(ln)


class KPtHex(gdb.Command):
    """kpthex [TABLE_PA] [N | full] : byte-level HEX view of a page-table page --
each raw descriptor split into its 8 little-endian bytes exactly as they sit in
physical RAM, next to the reconstructed 64-bit value and a short decode.  Default:
the TOP-level table for $pc's regime (arm64 L0/PGD, x86 PML4, riscv satp root),
first N non-zero entries (N=64 default).  Pass 'full' to hexdump the whole 4KB page
(16 bytes/row, xxd-style).  Reads PHYSICAL memory via the QEMU monitor, so it works
AFTER the MMU is on (where gdb's x / pwndbg hexdump on a physical page-table address
fail).  TABLE_PA may be a 'table -> 0x...' PA printed by kpt."""

    def __init__(self, name="kpthex"):
        super(KPtHex, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        parts = (arg or "").split()
        full = any(p.lower() in ("full", "all", "page") for p in parts)
        parts = [p for p in parts if p.lower() not in ("full", "all", "page")]
        table_pa = evi(parts[0]) if parts else None
        count = None
        if len(parts) > 1:
            try:
                count = int(parts[1], 0)
            except Exception:
                count = None
        for ln in (SESSION.pt_hex_lines(va=reg("pc"), table_pa=table_pa,
                                        count=count, full=full) or []):
            print(ln)


class KOff(gdb.Command):
    """koff [SYMBOL] : why a runtime address differs from the vmlinux ELF
(nm/readelf) symbol value.  Prints the CPU flags/control-registers/mem values
that ARE the reason -- SCTLR_EL1.M / TTBR / kimage_voffset (arm64), CR0.PG /
CR3 / phys_base (x86), satp.MODE / satp.PPN (riscv), plus the cmdline KASLR
marker -- split by MMU on/off, then the ELF-value-vs-runtime offset.  SYMBOL
defaults to the image base (_text / _start / startup_64)."""

    def __init__(self, name="koff"):
        super(KOff, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        parts = (arg or "").strip().split()
        for ln in (SESSION.koff_lines(parts[0] if parts else None) or []):
            print(ln)


class KX(gdb.Command):
    """kx [/NFU] ADDR : examine PHYSICAL memory, the way `x` examines virtual.

There are early-boot moments where $pc holds a physical address while translation
is already on -- riscv lands exactly there, because `csrw satp` makes the very next
fetch trap to stvec, so the CPU reports a PC that is no longer a valid VA.  gdb's
`x` translates through the live page tables and answers "Cannot access memory at
address 0x...", leaving no way to see the instruction you just stopped on.  `kx`
reads through QEMU's HMP `xp` instead, which bypasses translation entirely and
therefore works in every regime: MMU off, idmap, mid-switch, or fully virtual.

Syntax follows `x` closely enough to be muscle-memory:  kx/16xb $pc,  kx/8gx 0x...
N = count, U = unit (b/h/w/g), F = format (x hex, d decimal, i is not supported --
use cfgdis).  Default /16xb.  A kernel VA argument is converted to its physical
address first (and the conversion is printed), so `kx $pc` is right in either
regime.  gdb's own `x` is untouched."""

    _UNIT = {"b": 1, "h": 2, "w": 4, "g": 8}

    def __init__(self, name="kx"):
        super(KX, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        spec, expr = "", (arg or "").strip()
        if expr.startswith("/"):
            spec, _, expr = expr[1:].partition(" ")
        count, unit, form = 16, 1, "x"
        num = "".join(c for c in spec if c.isdigit())
        if num:
            count = max(1, min(int(num), 4096))
        for c in spec:
            if c in self._UNIT:
                unit = self._UNIT[c]
            elif c in "xdu":
                form = c
        expr = expr.strip() or "$pc"
        addr = evi(expr)
        if addr is None:
            print("[%s] kx: cannot evaluate '%s'" % (NAME, expr))
            return

        pa, note = addr & MASK, ""
        a = SESSION.arch
        if a is not None and a._is_va(pa):
            conv = SESSION.v2p(pa)
            if conv is not None:
                note = "  (VA %s -> PA %s)" % (fmt(pa), fmt(conv))
                pa = conv
        nbytes = count * unit
        words = read_phys_words(pa & ~7, (nbytes + (pa & 7) + 7) // 8)
        if not words:
            print("[%s] kx: cannot read physical memory at %s -- no QEMU monitor "
                  "passthrough on this target?" % (NAME, fmt(pa)))
            return
        raw = b"".join(struct.pack("<Q", w) for w in words)[pa & 7:][:nbytes]
        if len(raw) < nbytes:
            print("[%s] kx: short read (%d of %d bytes)" % (NAME, len(raw), nbytes))
        if note:
            print("[%s] kx%s" % (NAME, note))
        per = max(1, 16 // unit)
        for i in range(0, len(raw) // unit, per):
            vals = []
            for j in range(i, min(i + per, len(raw) // unit)):
                v = int.from_bytes(raw[j * unit:(j + 1) * unit], "little")
                vals.append(("0x%0*x" % (unit * 2, v)) if form == "x" else str(v))
            print("0x%016x:\t%s" % ((pa + i * unit) & MASK, "\t".join(vals)))


class MmView(gdb.Command):
    """mmview | memlayout [noidmap] : kernel MEMORY LAYOUT (a vmmap for the kernel
-- pwndbg's own vmmap cannot read a kernel target).  Two halves, useful in EVERY
regime including the pre-MMU physical phase:
  (1) kernel image + key symbols (VA -> PA) -- straight from the symbol table +
      calibration, so it works even before the MMU is on (on physical addresses);
  (2) live mappings -- a ptdump of the hardware page tables (arm64 TTBR1 kernel +
      TTBR0 idmap / x86 CR3 / riscv satp), coalesced into contiguous regions with
      permissions.  While the MMU is still OFF there are no VA mappings yet, so it
      prints the kernel's PHYSICAL placement + RAM and asks you to re-run after
      MMU-enable.  Options: 'all' (also show the user/low-half of a unified x86
      CR3 / riscv satp), 'noidmap' (skip the arm64 TTBR0 dump).  Alias: memlayout."""

    def __init__(self, name):
        super(MmView, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        a = (arg or "").lower()
        want_idmap = "noidmap" not in a
        show_all = any(k in a for k in ("all", "user", "full"))
        for ln in (SESSION.mmview_lines(want_idmap=want_idmap, show_all=show_all) or []):
            print(ln)
__all__ = ['KEarly', 'P2V', 'V2P', 'KB', 'KW', 'KSr', 'KSregs', 'KFin', 'KCensus', 'KPt', 'KPgd', 'KPtHex', 'KOff', 'KX', 'MmView']
