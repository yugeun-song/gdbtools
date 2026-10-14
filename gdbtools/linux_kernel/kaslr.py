"""part of gdbtools; see the package docstring."""
import gdb
import re
from ..common.runtime import *
from .physmem import *
from .target import TARGET


# ----------------------------------------------------------------------------
# KASLR: the evidence board, reading the slide, the crossing catcher, applying it.
# Mixed into Session (session.py), which holds the state these methods use.
# ----------------------------------------------------------------------------
class KaslrMixin:
    @safe(default=None)
    def _slide_via_pc_pa(self):
        # Virtual-regime KASLR anchor that needs no kernel global populated yet
        # (unlike kimage_voffset / kernel_map.virt_addr, which are 0 just after the
        # crossing).  Translate the live $pc to its true physical address with a
        # hardware page-table walk (slide-independent, NEVER resumes the CPU), then
        # use the fixed-load identity PA(byte)=linkVA(byte)+offset to close the loop
        # non-circularly:  slide = pc - linkVA(pc) = pc - (PA(pc) - offset).
        # Fixed physical load only (arm64/riscv); x86 never reaches here -- its
        # detect resolves first, and its base recovery runs while pc is physical.
        a = self.ensure_arch()
        if a is None or self.offset is None:
            return None
        pc = reg("pc")
        if pc is None or not a._is_va(pc):          # high-VA regime only
            return None
        pw = a.pagewalk(pc)                          # monitor-xp walk; no CPU resume
        if not pw or pw.get("leaf_pa") is None:
            return None
        pa = pw["leaf_pa"] & MASK
        sym = self.symbolize(pa)                     # pa -> link VA (slide 0) -> symbol
        if not sym or sym[2] is None:                # not in-image -> defer, no guess
            return None
        return (pc - pa + self.offset) & MASK

    @safe(default=False)
    def _kaslr_disabled(self):
        """True when the kernel was told not to randomise.

        Read from the DTB's /chosen/bootargs when there is one -- QEMU hands the
        cmdline to arm64/riscv that way, so this is answerable at the reset vector,
        long before the kernel has parsed anything.  Falls back to the parsed kernel
        globals, which only become valid once start_kernel runs."""
        # The guest DTB is read lazily, and at the reset vector nothing has needed it
        # yet -- so ask for it here rather than reporting "unknown" when the answer is
        # sitting in guest RAM.  Harmless when there is no DTB (x86) or the boot
        # register no longer holds it: try_guest_dtb just returns.
        TARGET.try_guest_dtb(self.arch)
        d = getattr(TARGET, "_dtb", None)
        ba = (d or {}).get("bootargs") if isinstance(d, dict) else None
        if ba:
            return "nokaslr" in ba.split()
        cl = self._cmdline()
        return bool(cl) and "nokaslr" in cl.split()

    @safe(default="? (err)")
    def _kaslr_field(self):
        """The KASLR slide for the status panel.

        Always a NUMBER when one is knowable, because that is what the panel is read
        for: a real slide of 0 is information, not an absence, and `nokaslr` on the
        cmdline settles it as exactly 0 even before the MMU is on.  Only the case
        that is genuinely undecided until the crossing shows a `?`, and it says what
        it is waiting for."""
        disabled = self._kaslr_disabled()
        tag = "  (KASLR disabled)" if disabled else ""
        if self.kaslr_slide:
            return "0x%x%s" % (self.kaslr_slide, tag)
        if disabled:
            return "0%s" % tag
        if self.offset is None:
            return "? (uncalibrated)"
        if self.which_map() != "virtual":
            # Undecided, not zero -- and "still physical" is not the same as "MMU off":
            # x86 runs this whole window with paging ON.
            st, _ = self.mmu_state()
            return "? (undecided until the crossing -- still physical, MMU %s)" % st
        s = self.detect_kaslr_slide()
        if s is None:
            return "? (anchor unreadable)"
        if s == 0:
            return "0"
        return "0x%x (detected; run 'kearly kaslr')" % s

    # --- koff: evidence board for ELF-symbol vs runtime-address offset -------
    @safe(default=None)
    def _cmdline(self):
        """Fully-formed kernel cmdline, or None if not parsed yet.  Rejects the
        zero/garbage these globals hold in head.S / __primary_switched (parsed
        only once start_kernel runs), so early reads don't fake a KASLR verdict."""
        for s in ("saved_command_line", "boot_command_line"):
            try:
                out = execstr('printf "%s", ' + s).strip()
            except Exception:
                out = ""
            if out and "=" in out and ("root=" in out or "console=" in out
                                       or "rw" in out.split() or "ro" in out.split()):
                return out
        return None

    def _nokaslr_clue(self):
        cl = self._cmdline()
        if cl is None:
            return ("cmdline", "(unparsed)", "set at start_kernel; KASLR unknown until then")
        no = "nokaslr" in cl.split()
        return ("cmdline kaslr", "off (nokaslr)" if no else "on",
                "runtime VA == linked VA" if no else "VAs may be slid")

    @safe(default=[])
    def _koff_clues(self, a, st):
        """(name, value, why) markers of the CPU flags/registers/mem that pin down
        the current translation regime -- per arch."""
        c = []
        if a.key == "arm64":
            sctlr = evi("$SCTLR_EL1")
            if sctlr is None:
                sctlr = a.sysreg("SCTLR_EL1")
            m = None if sctlr is None else (sctlr & 1)
            c.append(("SCTLR_EL1.M", "?" if m is None else str(m),
                      "MMU %s -> ptrs %s" % (("on", "VIRTUAL") if m else ("off", "PHYSICAL"))))
            ttbr1 = evi("$TTBR1_EL1")
            if ttbr1 is None:
                ttbr1 = a.sysreg("TTBR1_EL1")
            c.append(("TTBR1_EL1", _h(ttbr1),
                      "kernel page-table base" if ttbr1 else "kernel tables not installed"))
            if st == "on":
                kv = evi("kimage_voffset")
                if kv:
                    c.append(("kimage_voffset", _h(kv), "image VA - PA"))
                elif kv == 0:
                    c.append(("kimage_voffset", "0", "unset until setup_arch (early)"))
        elif a.key == "x86_64":
            cr0 = evi("$cr0")
            pg = None if cr0 is None else ((cr0 >> 31) & 1)
            c.append(("CR0.PG", "?" if pg is None else str(pg),
                      "paging %s -> ptrs %s" % (("on", "VIRTUAL") if pg else ("off", "PHYSICAL"))))
            c.append(("CR3", _h(evi("$cr3")), "top-level page-table base"))
            cr4 = evi("$cr4")
            if cr4 is not None:
                c.append(("CR4.PAE", str((cr4 >> 5) & 1), "phys-addr extension"))
            efer = evi("$efer")
            if efer is not None:
                c.append(("EFER.LMA", str((efer >> 10) & 1), "long mode active"))
            pb = evi("phys_base")
            if pb is not None:
                c.append(("phys_base", _h(pb), "KASLR phys slide (0 = nokaslr)"))
        elif a.key == "riscv64":
            satp = evi("$satp")
            mode = None if satp is None else ((satp >> 60) & 0xF)
            mn = {0: "Bare(off)", 8: "Sv39", 9: "Sv48", 10: "Sv57"}.get(mode, str(mode))
            c.append(("satp.MODE", "?" if mode is None else ("%s (%s)" % (mode, mn)),
                      "MMU %s -> ptrs %s" % (("off", "PHYSICAL") if mode == 0 else ("on", "VIRTUAL"))))
            if satp is not None:
                ppn = (satp & ((1 << 44) - 1)) << 12
                c.append(("satp.PPN<<12", _h(ppn),
                          "page-table base" if mode else "unused (Bare)"))
        k = self._nokaslr_clue()
        if k:
            c.append(k)
        return c

    @safe(default=[])
    def koff_lines(self, sym=None):
        """Evidence board -- why a runtime address differs from the vmlinux ELF
        (nm/readelf) symbol value, split by MMU regime.  Shows the CPU flags,
        control registers, and key values that ARE the reason (markers, not
        prose).  SYMBOL defaults to the image base (_text/_start/startup_64)."""
        a = self.ensure_arch()
        if a is None:
            return ["[%s] koff: no supported arch on this target" % NAME]
        if self.offset is None:
            self.calibrate(quiet=True)           # runtime attach: derive PA-VA if we can
        st, src = self.mmu_state()
        mapping = self.which_map()               # 'physical' / 'virtual' / 'unknown'
        pc = reg("pc")
        sym = sym or getattr(a, "entry_symbol", None) or "_text"
        elf_va = symval(sym)
        if mapping == "virtual":
            regime = "pc VIRTUAL (high-half map live)"
        elif mapping == "physical" and st == "on":
            regime = "pc PHYSICAL (paging ON but identity/low map -- high-half not live yet)"
        elif mapping == "physical":
            regime = "pc PHYSICAL (MMU off)"
        else:
            regime = "regime unknown"
        out = ["[%s] koff  arch=%s  %s   [MMU=%s %s]" % (NAME, a.key, regime, st, src),
               "  clues (CPU flag / register / mem  ->  what it pins down):"]
        clues = []
        if pc is not None:
            clues.append(("$pc", _h(pc),
                          "high-half VA" if mapping == "virtual" else "physical / low (identity)"))
        clues += self._koff_clues(a, st)
        w = max((len(k) for k, _v, _t in clues), default=1)
        for k, v, t in clues:
            out.append("    %-*s = %-18s %s" % (w, k, v, ("-> " + t) if t else ""))
        out.append("  ELF symbol &%s  vs  its address right now:" % sym)
        applied = self.kaslr_slide & MASK
        linked_va = ((elf_va - applied) & MASK) if elf_va is not None else None
        elf_s = fmt(linked_va) if linked_va is not None else "?"
        off_s = fmt(self.offset) if self.offset is not None else "(uncalibrated)"
        out.append("    ELF value (linked VA) = %s   (vmlinux symtab / nm / readelf)" % elf_s)
        if mapping == "virtual":
            now_s = fmt(elf_va) if elf_va is not None else "?"
            out.append("    address now (VA)      = %s   (linked VA + KASLR slide)" % now_s)
            if applied:
                slide = ("0x%x  (applied via 'kearly kaslr'; symbols relocated to runtime VAs)"
                         % applied)
            else:
                cl = self._cmdline()
                if cl is None:
                    slide = "unknown (cmdline unparsed; run 'kearly kaslr' to detect + apply)"
                elif "nokaslr" in cl.split():
                    slide = "0  (nokaslr in cmdline -> VA == ELF, confirmed)"
                else:
                    slide = "not applied (no nokaslr; run 'kearly kaslr' to measure the slide)"
            out.append("    KASLR slide           = %s" % slide)
            out.append("    offset(PA-VA)         = %s   (VA + offset = PHYS; page-walk/aliases)" % off_s)
        elif mapping == "physical":
            pa = self.v2p(linked_va) if (linked_va is not None and self.offset is not None) else None
            out.append("    address now (PA)      = %s   (QEMU loaded the image here)"
                       % (fmt(pa) if pa is not None else "?"))
            out.append("    why differ: %s" %
                       ("paging ON but identity-mapped -> pc runs at PHYSICAL/low addrs"
                        if st == "on" else "MMU off -> addresses are PHYSICAL"))
            out.append("    offset(PA-VA)         = %s   (ELF VA + offset = its PHYS)" % off_s)
        else:
            out.append("    (regime unknown -- stop in the kernel and retry)")
        return out

    @safe(default=None)
    def detect_kaslr_slide(self):
        """Per-arch KASLR slide = runtimeVA(_text) - linkVA(_text).  Dispatches to
        arch.detect_kaslr_slide(), which reads that arch's clean anchor at the
        current phase (an invariant physical read or a register) -- never circular.
        Returns None when this arch/phase has no reliable anchor."""
        a = self.ensure_arch()
        if a is None or self.offset is None:
            return None
        return a.detect_kaslr_slide(self)

    @safe(default=None)
    def _advance_to_crossing(self):
        """Frozen-boot KASLR slide reader.  Advance the PRIMARY CPU to the arch's
        physical->high-VA MMU-crossing (post-relocation, still idmap/MMU-off, BEFORE
        start_kernel) via a temporary HARDWARE breakpoint at the crossing's invariant
        physical address, then read the slide from the branch register (arm64) / a
        single-step landing (x86) / a now-valid global (riscv).  Returns the slide
        (int, possibly 0) or None to defer.  Unlike the old secondary_startup probe,
        this does NOT overshoot start_kernel -- the crossing precedes it on the
        primary path -- so a following `b start_kernel; continue` lands correctly."""
        a = self.ensure_arch()
        if a is None or self.offset is None:
            return None
        if a.pc_is_virtual() is True:            # already relocated -> detect handles it
            return None
        cr = a.find_crossing(self)
        if not cr or cr.get("pa") is None:
            return None
        pa = cr["pa"] & MASK
        pc0 = reg("pc")
        # Already parked ON the crossing?  ($GDBTOOLS_X86_KASLR leaves the CPU exactly
        # there, and so does a previous `kearly kaslr auto`.)  Continuing would resume a
        # target whose only catcher is a breakpoint at an address it has already reached,
        # so nothing would ever stop it and gdb would block forever.  Read the slide where
        # we stand instead -- the crossing branch has not executed yet, so the register /
        # stepi / global sources below are all still valid.
        at_crossing = pc0 is not None and (pc0 & MASK) == pa
        bpnum = None
        if at_crossing:
            LOG.add("kaslr: already stopped on the crossing (phys 0x%x) -- reading in place" % pa)
            print("[%s] kaslr: already stopped ON the MMU-crossing (%s, phys 0x%x) -- "
                  "reading the slide in place (not continuing)."
                  % (NAME, cr.get("land") or "crossing", pa))
        else:
            out = exec_confirmless("thbreak *0x%x" % pa)   # HW bp fires MMU-off/idmap
            m = re.search(r"[Bb]reakpoint\s+(\d+)", out or "")
            if not m:
                out = exec_confirmless("tbreak *0x%x" % pa)   # sw temp fallback
                m = re.search(r"[Bb]reakpoint\s+(\d+)", out or "")
            bpnum = m.group(1) if m else None
            LOG.add("kaslr: advancing to MMU-crossing %s (phys 0x%x)" % (cr.get("desc", ""), pa))
            print("[%s] kaslr: continuing to the MMU-crossing (%s, phys 0x%x, primary CPU, "
                  "post-relocation, pre-start_kernel) to read the slide ..."
                  % (NAME, cr.get("land") or "crossing", pa))
        self._in_advance = True
        try:
            if not at_crossing:
                execstr("continue")
                pc = reg("pc")
                landed = pc is not None and (pc & MASK) == pa
                if not landed:
                    LOG.add("kaslr crossing: landed at %s, expected 0x%x -- arming catcher"
                            % (fmt(pc), pa))
                    self._arm_crossing_catcher(cr, pa, bpnum)
                    return None
            slide = self._read_slide_at_crossing(cr, a)
        finally:
            self._in_advance = False
        return slide

    @safe(default=None)
    def _read_slide_at_crossing(self, cr, a=None):
        """Read the KASLR slide with the CPU stopped ON the crossing instruction.
        Split out of _advance_to_crossing so the persistent catcher can reuse it
        from the stop hook."""
        a = a or self.ensure_arch()
        if a is None or not cr:
            return None
        slide = None
        tl = cr.get("target_link")
        prev = self._in_advance
        self._in_advance = True
        try:
            if cr.get("ptr") is not None and tl is not None:
                # Read the landing's runtime VA straight out of the indirect-jump slot.
                # Physical read, so it is valid in every regime and moves nothing.
                tv = read_phys_u64(cr["ptr"])
                if tv is not None and a._is_va(tv):
                    slide = (tv - tl) & MASK
            if slide is None and cr.get("stepi") and tl is not None:
                execstr("stepi")                            # execute the crossing branch
                npc = reg("pc")
                if npc is not None and a._is_va(npc):
                    slide = (npc - tl) & MASK
            elif cr.get("reg") and tl is not None:
                rv = evi("$" + cr["reg"])                   # register holds landing runtime VA
                if rv is not None and a._is_va(rv):
                    slide = (rv - tl) & MASK
            if slide is None and cr.get("detect_fallback", True):
                slide = self.detect_kaslr_slide()
        finally:
            self._in_advance = prev
        if slide is not None:
            LOG.add("kaslr: slide 0x%x read at crossing (%s)" % (slide, cr.get("desc", "")))
        return slide

    @safe()
    def _arm_crossing_catcher(self, cr, pa, tempnum=None):
        """Another stop beat us to the crossing.  Do not give up and do not silently
        resume past the user's stop: leave a PERSISTENT breakpoint on the crossing so
        the slide gets read and applied automatically whenever execution finally
        reaches it -- however many of the user's own breakpoints/watchpoints fire in
        between.  This is what makes `kearly kaslr auto` robust against arbitrary
        breakpoints armed anywhere in head.S."""
        if tempnum:
            exec_confirmless("delete %s" % tempnum)     # drop the spent one-shot
        if self._kaslr_pending and self._kaslr_pending.get("pa") == pa:
            bp = self._kaslr_pending.get("bp")
        else:
            out = exec_confirmless("hbreak *0x%x" % pa)
            m = re.search(r"[Bb]reakpoint\s+(\d+)", out or "")
            if not m:
                out = exec_confirmless("break *0x%x" % pa)
                m = re.search(r"[Bb]reakpoint\s+(\d+)", out or "")
            bp = m.group(1) if m else None
            self._kaslr_pending = {"pa": pa, "bp": bp, "cr": cr}
        LOG.add("kaslr: persistent crossing catcher armed at 0x%x (bp %s)" % (pa, bp))
        print("[%s] kaslr: another breakpoint stopped first (pc=%s) -- left a PERSISTENT "
              "catcher%s on the crossing (phys 0x%x).  Keep debugging: the slide is read and "
              "applied automatically the moment execution reaches it."
              % (NAME, fmt(reg("pc")), ("  [bp %s]" % bp) if bp else "", pa))

    @safe()
    def _warn_unslid_literal(self, bp, n):
        """`b *0xLINKVA` means "exactly this address" -- so under KASLR it names a byte the
        relocated kernel never executes.  Moving the user's literal would be wrong, so the
        literal stays put and _adopt_plain_bp arms the regime-aware siblings alongside it;
        this just explains which location is the one that will actually fire."""
        a = self.arch
        if a is None or self.offset is None:
            return
        loc = (getattr(bp, "location", None) or "").strip()
        if not loc.startswith("*"):
            return                                  # only literal-address probes
        addr = evi(loc[1:].strip())
        if addr is None or not a._is_va(addr):
            return
        slide = self.kaslr_slide
        if slide:
            # The old guard asked whether (addr - slide) still looked like a kernel VA.  On
            # every arch here that is true for a LINK address as well, so this returned
            # early every time and the useful branch below was dead code.  Ask the real
            # question instead: does gdb's (relocated) symbol table know this address?  If it
            # does, the user typed a runtime address and there is nothing to warn about.
            if self.info_symbol(addr):
                return
            adopted = " -- armed there for you as a sibling location" if n in self._adopted else ""
            print("[%s] note: %s is a LINK address; this kernel runs at slide 0x%x, so that "
                  "byte is never executed.  The live one is *0x%x%s (`b SYM` follows the "
                  "slide by itself)."
                  % (NAME, fmt(addr), slide, (addr + slide) & MASK, adopted))
        elif self._kaslr_pending:
            adopted = ("  Its physical twin has been armed alongside, so a probe here still "
                       "fires while the MMU is off." if n in self._adopted else "")
            print("[%s] note: %s is a LINK address and this kernel is KASLR-relocated, so that "
                  "exact byte will not be executed once the slide is known.%s"
                  % (NAME, fmt(addr), adopted))

    @safe()
    def _service_catch_wanted(self):
        """Arm a deferred catcher from a context where creating a breakpoint is safe --
        a gdb prompt, a stop, or one of our own commands.  Never from inside gdb's own
        breakpoint create/delete callbacks."""
        if not self._catch_wanted or self.kaslr_slide or self._kaslr_pending \
                or not self._flag("CROSSING"):
            self._catch_wanted = False
            return
        self._catch_wanted = False
        # A stop hook or a gdb prompt is a safe context, so use the internal python
        # catcher here too -- the CLI one is deletable and would be lost to a `delete`.
        self._ensure_crossing_catcher("a probe armed earlier", use_python=True)

    @safe()
    def _retire_catcher(self, why):
        """Take the crossing catcher away, so reaching the crossing applies nothing.
        Command context only."""
        pend, self._kaslr_pending = self._kaslr_pending, None
        self._catch_wanted = False
        if not pend:
            return
        obj = pend.get("obj")
        if obj is not None:
            try:
                obj.delete()
            except Exception:
                pass
            self._catcher_obj = None
        elif pend.get("bp"):
            exec_confirmless("delete %s" % pend["bp"])
        LOG.add("catcher: retired (%s)" % why)

    @safe()
    def _maybe_catch_for(self, bp, n):
        """Any new breakpoint that targets a kernel high VA while the KASLR slide is
        still unknown needs the crossing catcher, or it will never fire.  Hooked on
        breakpoint creation so it covers stock `b SYM` regardless of whether the
        adopt path applied (the shadow alone already yields two locations)."""
        if self.kaslr_slide or self._in_catcher:
            return
        if not self.enabled or not self._flag("CROSSING"):
            return
        # Deliberately do NOT try to work out whether this probe targets a high VA.
        # The previous attempt keyed off _bp_locations(), whose regex only matches the
        # `N.M  y  0xADDR` rows of a MULTI-location breakpoint -- so a single-location
        # `b *ADDR` and every watchpoint (which has no address column at all) silently
        # got no catcher and then never fired.  Any probe at all is reason enough: the
        # catcher costs one breakpoint and retires itself at the crossing.
        #
        # We are inside gdb's breakpoint-created event, so gdb is part-way through building
        # a breakpoint.  Constructing a PYTHON gdb.Breakpoint here made gdb abort with an
        # internal-error assertion and dump core when the probe was a watchpoint.  Creating
        # one through the CLI is safe -- _adopt_plain_bp has been doing exactly that from
        # this same callback all along -- so ask for the plain-CLI catcher here.  (Deferring
        # with gdb.post_event does not work: in a scripted -ex session gdb never returns to
        # its event loop between commands, so the catcher would never be armed at all.)
        # gdb asserts in watch_command_1 that the breakpoint chain still ends with the
        # watchpoint it is building (breakpoint.c: "&breakpoint_chain.back () ==
        # watchpoint_ptr").  Creating ANY breakpoint from this callback while a watchpoint
        # is being made violates that and gdb dies with an internal error + core dump --
        # it is not specific to the python Breakpoint object, which was the earlier wrong
        # diagnosis.  So: arm now only for ordinary breakpoints, and for watchpoints just
        # record that one is wanted; the safe points below pick it up.
        # Only a WATCHPOINT is unsafe here: gdb's watch_command_1 asserts that the
        # breakpoint chain still ends with the watchpoint it is building, so creating
        # anything from this callback during it kills gdb.  Testing "not BP_BREAKPOINT"
        # was wrong -- a hardware breakpoint is not BP_BREAKPOINT either, so every hbreak
        # the tool makes for itself was misread as a watchpoint and deferred the catcher
        # onto the unsafe CLI path, where a later `delete` could remove it.
        _WP = tuple(getattr(gdb, _n) for _n in
                    ("BP_WATCHPOINT", "BP_HARDWARE_WATCHPOINT",
                     "BP_READ_WATCHPOINT", "BP_ACCESS_WATCHPOINT")
                    if hasattr(gdb, _n))
        if _WP and getattr(bp, "type", None) in _WP:
            self._catch_wanted = True
            LOG.add("catcher: deferred (a watchpoint is being created -- unsafe here)")
            return
        # Safe to build the internal python catcher here: we have already returned above
        # if a WATCHPOINT is being created, and that is the only case gdb asserts on.  It
        # must be the internal one -- a CLI catcher is deletable, and a later bare `delete`
        # would silently take it away and the slide would never be applied.
        self._ensure_crossing_catcher("that probe", use_python=True)

    @safe(default=False)
    def _catcher_alive(self):
        """Is the breakpoint backing the pending catcher still registered with gdb?
        `delete` takes it out silently, and a stale pending record would block every
        future re-arm."""
        pend = self._kaslr_pending
        if not pend:
            return False
        num = pend.get("bp")
        if num is None:
            return False
        try:
            want = int(num)
        except Exception:
            return False
        obj = pend.get("obj")
        if obj is not None:                     # internal catcher: gdb.breakpoints() hides
            try:                                # it, so ask the object itself
                return bool(obj.is_valid())
            except Exception:
                return False
        for bp in (gdb.breakpoints() or []):
            if getattr(bp, "number", None) == want:
                return True
        return False

    @safe()
    def _ensure_crossing_catcher(self, why="", use_python=True):
        """Arm the crossing catcher PRE-EMPTIVELY when the user puts a breakpoint or
        watchpoint on a high-VA location while the KASLR slide is still unknown.

        Without this, `b start_kernel` typed at the head.S entry silently misses: the
        kernel has not computed its randomized virtual base yet, so the address gdb
        armed is the link VA, which the relocated kernel never executes -- the guest
        just boots away with no stop and no diagnostic.  Arming the catcher here means
        the slide is read and applied automatically before that VA is ever reached, so
        the user's breakpoint resolves to the right runtime address on its own.  Costs
        one breakpoint, and it retires itself the moment it fires."""
        if self._in_catcher or self.kaslr_slide:
            return
        if self._kaslr_pending and not self._catcher_alive():
            # A bare `delete` removes our catcher along with the user's breakpoints, but
            # the pending record survived and suppressed every future re-arm -- so the
            # slide was never applied again for the rest of the session.  Forget it and
            # fall through to arm a fresh one.
            LOG.add("catcher: previous catcher was deleted -- re-arming")
            self._kaslr_pending = None
        if self._kaslr_pending:
            return
        a = self.ensure_arch()
        if a is None:
            LOG.add("catcher: skipped (no arch)")
            return
        if self.offset is None:
            # On x86 the main kernel is not in RAM until the decompressor has run, so
            # calibrating from the reset vector produces the NOMINAL 0x1000000 offset and
            # loads a shadow at it -- the very stale state that then poisons everything.
            # Leave it uncalibrated and say what to run instead.
            if getattr(a, "key", None) == "x86_64" and self._compressed_vmlinux():
                _pc = reg("pc")
                _dpa = self.x86_decomp_pa()
                # X86_DECOMP_PA is stated only for a DIRECT boot, so it cannot carry
                # this guard on its own any more: under a firmware chain there is no
                # decompressor address to compare against, and the pre-kernel pc would
                # sail past and calibrate the nominal offset anyway.  KASLR being on is
                # the same evidence -- the base is not knowable until bootbreak has
                # measured it -- but only while it is still UNKNOWN: a pinned ENTRY_PA
                # or a base already recovered is an answer, and bootbreak's own gate
                # (`ENTRY_PA is None`) stands down for exactly those.  `not _is_va` plus
                # ring 0 keeps a post-MMU attach calibrating as before, including one
                # that happens to interrupt userspace, whose pc is low but is not the
                # pre-kernel boot path -- that path is always ring 0.
                _cpl = evi("$cs")
                if _pc is not None and not a._is_va(_pc) and (_cpl is None or (_cpl & 3) == 0) and (
                        (self.x86_kaslr and config.get("ENTRY_PA") is None
                         and not self._entry_pinned and not self._entry_recovered)
                        or (_dpa is not None and (_pc & MASK) < _dpa)):
                    LOG.add("catcher: x86 still compressed -- not calibrating from the reset vector")
                    print("[%s] kaslr: the kernel is still compressed at this point, so there is "
                          "nothing to calibrate against yet.  Run `kearly bootbreak` (it recovers "
                          "the randomized base); probes you have already armed follow the "
                          "relocation by themselves -- no need to re-arm." % NAME)
                    return
            self.calibrate(quiet=True)          # e.g. armed at the reset vector, pre-entry
        if self.offset is None:
            LOG.add("catcher: skipped (uncalibrated -- run `kearly bootbreak` first)")
            return
        if a.pc_is_virtual() is not False:      # already virtual/unknown -> detect handles it
            LOG.add("catcher: skipped (pc_is_virtual=%s)" % a.pc_is_virtual())
            return
        cr = a.find_crossing(self)
        if not cr or cr.get("pa") is None:
            LOG.add("catcher: skipped (arch %s found no crossing)" % a.key)
            return
        pa = cr["pa"] & MASK
        # Idempotence by ADDRESS.  The liveness probe above can answer "gone" for a
        # perfectly good internal catcher (gdb hides internal breakpoints from
        # gdb.breakpoints()), and then a second catcher was armed at the very same
        # address -- two hardware slots burnt, the slide read twice, and the "slide
        # applied" banner printed twice.  Same PA, already pending: nothing to do.
        if self._kaslr_pending and (self._kaslr_pending.get("pa") or 0) == pa:
            return
        pc0 = reg("pc")
        if pc0 is not None and (pc0 & MASK) == pa:
            # Standing on the crossing already: there is nothing ahead to catch, so
            # arming would leave the probe dead.  The slide is readable right here.
            _sl = self._read_slide_at_crossing(cr)
            if _sl is not None:
                LOG.add("catcher: on the crossing -- slide read in place")
                self.apply_kaslr(_sl)
            return
        self._in_catcher = True
        try:
            bp = None
            # Prefer a silent python breakpoint that applies the slide and resumes on its
            # own, so the user never sees a stop they did not ask for.  Only safe when the
            # arch reads the slide from a register/global; an arch whose crossing needs a
            # stepi cannot resume from inside stop(), so it gets a visible stop instead.
            if use_python and not cr.get("stepi"):
                bp = self._make_silent_catcher(pa, cr)
            if bp is None:
                out = exec_confirmless("hbreak *0x%x" % pa)
                m = re.search(r"[Bb]reakpoint\s+(\d+)", out or "")
                if not m:
                    out = exec_confirmless("break *0x%x" % pa)
                    m = re.search(r"[Bb]reakpoint\s+(\d+)", out or "")
                bp = m.group(1) if m else None
                if bp is None:
                    return
                self._kaslr_pending = {"pa": pa, "bp": bp, "cr": cr, "auto": True, "silent": False}
                print("[%s] kaslr: %s targets a high VA but the slide is still unknown -- armed a "
                      "catcher on the MMU-crossing (phys 0x%x) so the slide is applied before that "
                      "address is reached.  You will stop there once, then continue." % (NAME, why or "that location", pa))
            else:
                self._kaslr_pending = {"pa": pa, "bp": bp, "cr": cr, "auto": True, "silent": True,
                                   "obj": self._catcher_obj}
                print("[%s] kaslr: %s targets a high VA but the slide is still unknown -- armed a "
                      "silent catcher on the MMU-crossing (phys 0x%x); the slide is read and applied "
                      "in passing, without stopping." % (NAME, why or "that location", pa))
            LOG.add("kaslr: auto crossing catcher armed at 0x%x (%s)" % (pa, why))
        finally:
            self._in_catcher = False

    @safe(default=None)
    def _make_silent_catcher(self, pa, cr):
        """A gdb.Breakpoint whose stop() applies the slide and returns False, so
        execution flows straight through the crossing with the symbols fixed up."""
        sess = self

        class _Catcher(gdb.Breakpoint):
            def stop(self):
                try:
                    slide = sess._read_slide_at_crossing(cr)
                    if slide is None:
                        return True             # cannot read it -> let the user see the stop
                    sess._kaslr_pending = None
                    self.enabled = False
                    sess.apply_kaslr(slide)
                    return False                # keep going; nothing to report to the user
                except Exception:
                    return True

        # internal=True: gdb keeps it out of `info breakpoints` AND out of `delete`'s
        # reach.  That is what lets the catcher survive the user clearing their own
        # breakpoints -- a bare `delete` used to take it with them, and nothing could then
        # safely re-arm it from inside gdb's watchpoint-creation path (that path asserts on
        # any breakpoint created while a watchpoint is being built).
        bp = _Catcher("*0x%x" % pa, gdb.BP_HARDWARE_BREAKPOINT, internal=True)
        self._catcher_obj = bp
        return str(bp.number)

    @safe()
    def _service_crossing_catcher(self):
        """Stop-hook side of _arm_crossing_catcher: if this stop is the crossing we
        were waiting for, read the slide, apply it, and retire the catcher."""
        pend = self._kaslr_pending
        if not pend or self._in_advance:
            return
        pc = reg("pc")
        if pc is None or (pc & MASK) != (pend["pa"] & MASK):
            return
        slide = self._read_slide_at_crossing(pend.get("cr"))
        if slide is None:
            # Do NOT retire the catcher on a failed read.  On SMP the crossing is executed
            # by every CPU/hart, so a secondary can reach it in a state where the slide is
            # not readable yet; retiring here left nothing armed and the slide was never
            # applied for the rest of the session (seen intermittently on riscv, whose
            # boot hart varies per run).  Leave it in place and try again next time.
            LOG.add("catcher: slide unreadable at the crossing -- keeping the catcher armed")
            return
        if pend.get("bp"):
            exec_confirmless("delete %s" % pend["bp"])
        self._kaslr_pending = None
        print("[%s] kaslr: crossing reached (the catcher armed earlier) -- applying the slide now."
              % NAME)
        self.apply_kaslr(slide)

    @safe()
    def apply_kaslr(self, slide):
        vm = self.vmlinux_path()
        if not vm:
            print("[%s] no vmlinux path -- cannot relocate symbols" % NAME)
            return
        slide &= MASK
        had_shadow = self.shadow_addr is not None
        if had_shadow:
            self._shadow_unload()
        if slide == 0:
            exec_confirmless("symbol-file %s" % vm)
        else:
            exec_confirmless("symbol-file %s -o 0x%x" % (vm, slide))
        self.kaslr_slide = slide
        if had_shadow:
            self._shadow_load()
        self._rearm_kb(slide)                # move kb IMG locations to linkVA+slide
        self._rearm_kw(slide)                # ... and kw IMG watchpoints
        if "kgdb" in self.panels():
            self._install_pwndbg_section()
        if slide == 0:
            print("[%s] KASLR slide = 0 (symbols at link addresses; nothing shifted)." % NAME)
        else:
            print("[%s] KASLR slide = 0x%x applied: all symbols relocated to runtime VAs -- "
                  "`b SYM` now targets the running kernel.  Undo with 'kearly kaslr off'."
                  % (NAME, slide))

    @safe()
    def set_kaslr(self, arg):
        arg = (arg or "").strip().lower()
        # Bare `kearly kaslr` is NOT a synonym for `auto`: auto may resume the target,
        # which is the wrong thing to do to someone who just wanted to see the options.
        # Print the usage plus the current state and change nothing.
        if arg == "":
            print("usage: kearly kaslr [auto|off|status|<hex-slide>]")
            print("       auto    detect the slide, advancing to the MMU-crossing if needed (RESUMES the CPU)")
            print("       status  report applied vs currently-detected slide (never resumes)")
            print("       off     revert symbols to their link addresses")
            self.set_kaslr("status")
            return
        if arg in ("off", "none"):
            config.set_session("KASLR_APPLY", "off")
            self._retire_catcher("kearly kaslr off")
            self.apply_kaslr(0)
            return
        if arg == "status":
            s = self.detect_kaslr_slide()
            print("[%s] KASLR: applied slide=0x%x  detected(now)=%s" %
                  (NAME, self.kaslr_slide, ("0x%x" % s) if s is not None else "?"))
            return
        if arg not in ("", "auto", "detect"):
            v = evi(arg)
            if v is None:
                print("usage: kearly kaslr [auto|off|status|<hex-slide>]")
                return
            self.apply_kaslr(v)
            return
        config.set_session("KASLR_APPLY", "auto")
        s = self.detect_kaslr_slide()
        if not s:
            s2 = self._advance_to_crossing()      # frozen boot: advance to the crossing, read slide
            if s2 is not None:
                s = s2
        if not s:
            s3 = self._slide_via_pc_pa()          # fresh high-VA attach: derive from pc's PA
            if s3 is not None:
                s = s3
        if s is None:
            a = self.ensure_arch()
            arch = a.key if a else "?"
            if self._kaslr_pending:
                # Not a missing anchor: the anchor is armed and waiting.  Saying
                # "no anchor for this arch" here would be plainly wrong.
                print("[%s] kaslr: slide not readable yet -- a catcher is armed on the "
                      "crossing (phys 0x%x). Carry on debugging; it applies itself when "
                      "execution gets there." % (NAME, self._kaslr_pending["pa"]))
            elif self.offset is None:
                print("[%s] kaslr: uncalibrated -- run `kearly calibrate` (or bootbreak) first." % NAME)
            else:
                print("[%s] kaslr: no automatic slide anchor for arch=%s at this phase." % (NAME, arch))
                print("      set it by hand:   kearly kaslr <hex-slide>")
                print("      get the slide (guest, kptr_restrict=0):  (runtime `_text` from /proc/kallsyms) - (link `_text` from vmlinux)")
                print("      or debug slide-free:  `kb SYM` still catches the PA (MMU-off/idmap) location regardless of slide.")
            return
        self.apply_kaslr(s)
