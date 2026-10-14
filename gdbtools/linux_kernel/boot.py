"""part of gdbtools; see the package docstring."""
import gdb
import re
from ..common.runtime import *
from .pwndbg_glue import PWN


# ----------------------------------------------------------------------------
# Getting to the kernel: entry addresses, calibration, bootbreak, the shadow symbol
# file, early-boot quieting and the MMU crossing.
# Mixed into Session (session.py), which holds the state these methods use.
# ----------------------------------------------------------------------------
class BootMixin:
    # --- manual overrides: everything the auto-pipeline decides is hand-operable
    @safe(default=False)
    def set_offset(self, val):
        """Force the phys<->virt offset (PA-VA) by hand, bypassing calibration."""
        self.offset = val & MASK
        ok = self._sanity()
        print("[%s] offset(PA-VA) = %s%s" % (NAME, fmt(self.offset),
              "" if ok else "  [WARNING: maps the image entry outside the expected phys range]"))
        self._refresh_shadow()
        return True

    @safe()
    def clear_calibration(self):
        self.offset = None
        self._shadow_unload()
        print("[%s] calibration cleared (offset + shadow)" % NAME)

    @safe()
    def set_shadow(self, on):
        config.set_session("SHADOW", "on" if on else "off")
        if on:
            if self.offset is None:
                print("[%s] no offset yet -- run kearly bootbreak / calibrate / offset <hex>" % NAME)
                return
            self._shadow_load()
            print("[%s] shadow loaded at %s" % (NAME, fmt(self.shadow_addr)))
        else:
            self._shadow_unload()
            print("[%s] shadow removed" % NAME)

    @safe(default=None)
    def resolve_entry(self):
        """Physical address of the kernel IMAGE BASE (entry_symbol: _text/_start/
        startup_64).  Sources, high -> low: $GDBTOOLS_ENTRY_PA -> JSON profile
        entry_pa -> QEMU 'info roms' -> Image-magic scan over the supplied RAM
        ranges.  None when none of them answered; there is no hint to fall back
        on, because a hint that is wrong produces a calibrated-looking session in
        which every address is silently off.  Cached."""
        if self.entry_pa is not None:
            return self.entry_pa
        ovr = config.get("ENTRY_PA")
        if ovr is not None:
            self.entry_pa = ovr
            return ovr
        a = self.ensure_arch()
        if a is None:
            return None
        pa = a.find_entry_pa()
        if pa is None:
            # A normal answer, not a failure: this is a query, several callers
            # treat "not resolved yet" as a state to report, and calibration has
            # other routes to the offset.  The one caller that cannot proceed
            # without it -- bootbreak -- says so itself.
            LOG.add("entry PA unresolved: nothing in the target reported it and "
                    "$GDBTOOLS_ENTRY_PA/_PROFILE were not set")
            return None
        self.entry_pa = pa
        return pa

    def _compressed_vmlinux(self):
        """Path to the x86 COMPRESSED kernel (arch/x86/boot/compressed/vmlinux), used
        to recover the decompressor-randomized physical base under x86 KASLR.

        Handed in through $GDBTOOLS_X86_DECOMP_VMLINUX.  It is not derived from the
        loaded vmlinux: where that file sits relative to the build tree is a fact
        about the caller's tree layout, not about the kernel, and guessing it means
        silently analysing the wrong binary when the guess is close but wrong."""
        return config.get("X86_DECOMP_VMLINUX")

    @safe(default=False)
    def _hbreak_to(self, pa):
        """Temporary hardware breakpoint at physical/linear `pa`, continue, and confirm
        we landed there (sw temp fallback if hw is rejected).  Used to walk the x86
        decompressor's fixed-address stages in recover_kaslr_base."""
        pa &= MASK
        out = exec_confirmless("thbreak *0x%x" % pa)
        if "reakpoint" not in (out or ""):
            exec_confirmless("tbreak *0x%x" % pa)
        execstr("continue")
        pc = reg("pc")
        return pc is not None and (pc & MASK) == pa

    @safe(default=False)
    def _hbreak_any(self, pas):
        """Temporary HARDWARE breakpoints at every address in `pas` at once, continue,
        and report whether the guest stopped at one of them.  Hardware only, unlike
        _hbreak_to: these addresses are reached before the firmware has mapped anything
        gdb could write a byte into, so a software breakpoint cannot be planted.  Used
        where the anchor is one of several candidates and only the guest can say which."""
        want = [pa & MASK for pa in pas]
        nums = []
        for pa in want:
            out = exec_confirmless("thbreak *0x%x" % pa) or ""
            if "reakpoint" not in out:
                for n in nums:
                    exec_confirmless("delete %s" % n)
                return False
            m = re.search(r"breakpoint (\d+)", out)
            if m:
                nums.append(m.group(1))
        execstr("continue")
        for n in nums:                      # the one that hit deleted itself
            exec_confirmless("delete %s" % n)
        pc = reg("pc")
        return pc is not None and (pc & MASK) in want

    def _base_symbol(self, a):
        return getattr(a, "image_base_symbol", None) or a.entry_symbol

    def _entry_delta(self, a):
        """Link distance from the image-base symbol to the entry symbol (x86 puts
        startup_64 in .init.text on newer kernels), or None when unresolvable."""
        bsym = self._base_symbol(a)
        if bsym == a.entry_symbol:
            return 0
        e, t = symval(a.entry_symbol), symval(bsym)
        return None if e is None or t is None else (e - t) & MASK

    @safe(default=None)
    def entry_cpu_pa(self):
        """PA where the CPU enters the kernel: the image-base PA moved by
        _entry_delta.  Equal to resolve_entry() on arm64/riscv."""
        a = self.ensure_arch()
        base = self.resolve_entry()
        if a is None or base is None:
            return None
        d = self._entry_delta(a)
        return None if d is None else (base + d) & MASK

    @safe(default=None)
    def link_entry_va(self):
        """LINK virtual address of the entry symbol."""
        a = self.ensure_arch()
        if a is None or not a.entry_symbol:
            return None
        if self._base_symbol(a) == a.entry_symbol:
            return self.link_image_base_va()
        v = symval(a.entry_symbol)
        return (v - self.kaslr_slide) & MASK if v is not None and a._is_va(v) else None

    @safe(default=None)
    def link_image_base_va(self):
        """LINK virtual address of the kernel image base, which is what
        resolve_entry()'s PA locates.

        On a PIE/ET_DYN vmlinux (riscv CONFIG_RELOCATABLE) the physical SHADOW
        (add-symbol-file'd at PA) adds a second copy of the ELF ENTRY symbol
        (_start); gdb then resolves `&_start` -- and even `info files` "Entry
        point" -- to that low PHYSICAL address, not the link VA.  (Non-entry
        symbols keep resolving to the main objfile, so only the entry symbol is
        affected.)  A calibrated offset would then come out zero.  So: use
        symval(entry) only when it is a real VA; otherwise derive the link VA
        arithmetically from the (correct) image-base PA and offset:
            linkVA(base) = PA(base) - offset."""
        a = self.ensure_arch()
        if a is None:
            return None
        sym = self._base_symbol(a)
        v = symval(sym) if sym else None
        if v is not None and a._is_va(v):
            return (v - self.kaslr_slide) & MASK
        base = self.resolve_entry()
        if base is not None and self.offset is not None:
            return (base - self.offset) & MASK
        return (v - self.kaslr_slide) & MASK if v is not None else None

    # --- calibration ---
    @safe(default=False)
    def calibrate(self, anchor=None, quiet=False):
        a = self.ensure_arch()
        if a is None:
            if not quiet:
                print("[%s] no supported arch on this target" % NAME)
            return False
        if anchor:
            pc, va = reg("pc"), symval(anchor)
            if pc is None or va is None:
                if not quiet:
                    print("[%s] cannot read $pc or &%s" % (NAME, anchor))
                return False
            off = (pc - va) & MASK
        else:
            # Scan/constant-based: offset = image_base_PA - &image_base_symbol.
            # Independent of where $pc currently is, so it stays correct even when
            # a preset anchor stopped us at primary_entry / _start_kernel.
            base = self.resolve_entry()
            evs = self.link_image_base_va()      # the symbol that PA locates (PIE-safe)
            if base is not None and evs is not None:
                off = (base - evs) & MASK
            else:
                off = a.auto_calibrate(self)     # read from a running kernel, or None
        if off is None:
            if not quiet:
                print("[%s] calibration failed -- are you stopped in early head.S? "
                      "(try: kearly calibrate <anchor-symbol>)" % NAME)
            return False
        self.offset = off
        ok = self._sanity()
        if ok and not self.kaslr_slide:
            # Command context: the safe place to arm.  Doing it here means the catcher is
            # already in place before the user types anything, so the event-driven paths
            # are only ever a fallback.
            pend = self._kaslr_pending
            if pend is not None and pend.get("obj") is None:
                # The breakpoint-created callback got here first and could only make a
                # plain CLI breakpoint (building a python one from inside gdb's own
                # breakpoint machinery is what used to kill gdb).  A CLI catcher is
                # deletable, so a later bare `delete` silently takes it away and the slide
                # is then never applied.  We are in a safe context now: swap it for the
                # internal, delete-proof one -- whatever armed it, CROSSING or a command.
                if pend.get("bp"):
                    exec_confirmless("delete %s" % pend["bp"])
                LOG.add("catcher: upgrading the CLI catcher to an internal one")
                self._kaslr_pending = None
                self._ensure_crossing_catcher("calibration", use_python=True)
            elif not self._kaslr_pending and self._flag("CROSSING"):
                self._ensure_crossing_catcher("calibration", use_python=True)
        if not quiet:
            print("[%s] arch=%s offset(PA-VA)=%s%s" %
                  (NAME, a.key, fmt(off),
                   "" if ok else "  [WARNING: maps entry outside expected phys range]"))
        self._refresh_shadow()
        return True

    @safe(default=True)
    def _sanity(self):
        a = self.arch
        if a is None or a.entry_symbol is None:
            return True
        va = self.link_entry_va()            # ET_DYN/PIE + shadow safe (not raw symval)
        if va is None:
            return True
        pa = self.v2p(va)
        win = a.eff_phys_window()
        if win is None:
            return True
        lo, hi = win
        return pa is not None and lo <= pa <= hi

    @safe(default=False)
    def bootbreak(self, arm_only=False):
        """Run past the QEMU reset vector / firmware to the kernel entry, then
        calibrate.  At connect time $pc is in QEMU's boot stub / OpenSBI / real
        mode / U-Boot / ATF, not the kernel entry.  Honors the active preset /
        override anchor (where firmware enters, e.g. primary_entry / _start_kernel)
        and break-kind.  If you attach AFTER the MMU is already on (pc is a VA,
        e.g. at start_kernel), it skips the run and just calibrates for VA mode.

        `arm_only` arms the entry breakpoint and returns WITHOUT resuming, for a front
        end that drives the resume itself.  A DAP client (VS Code's cpptools) aborts a
        setup command that answers `^running` instead of `^done`, so there the resume
        has to be the client's own continue.  The stop hook calibrates when the
        breakpoint lands, exactly as on the resume path below; what is given up is the
        automatic retry with the other breakpoint kind, which is still available by
        running `kearly bootbreak` by hand."""
        a = self.ensure_arch()
        if a is None:
            print("[%s] no supported arch on this target" % NAME)
            return False
        self.load_overrides()
        pc = reg("pc")
        if pc is not None and a._is_va(pc):
            print("[%s] already past MMU enable ($pc is virtual) -- calibrating for "
                  "VA mode; native kernel symbolization is live." % NAME)
            return self.calibrate()
        armed = getattr(self, "_armed_entry_pa", None)
        if pc is not None and armed is not None and (pc & MASK) == armed:
            print("[%s] already at the kernel entry %s -- calibrating." % (NAME, fmt(armed)))
            return self.calibrate()
        # x86_64 cold-frozen KASLR: the bzImage decompressor relocates the kernel to a
        # RANDOM physical base, so the nominal entry PA is wrong.  Recover the real base
        # from the decompressor (arm64/riscv return None -- fixed physical load) and pin
        # it as entry_pa, so the normal entry break below lands on the relocated kernel.
        _need_x86 = False
        if a.key == "x86_64" and config.get("ENTRY_PA") is None:
            _need_x86 = self.x86_kaslr
            if not _need_x86 and self._compressed_vmlinux():
                # Auto-detect the cold-frozen case instead of relying on an env flag.
                # Cheap and decisive: a CPU still below the decompressor's fixed load
                # address (the 0xfff0 reset vector) cannot have decompressed the kernel
                # yet, so the nominal entry PA is wrong and a plain break would miss the
                # guest entirely.  Do NOT probe by scanning RAM for the image base -- at
                # this point the kernel is not there, so the scan runs to completion over
                # all of guest memory and takes minutes.
                _pc = reg("pc")
                _dpa = self.x86_decomp_pa()
                _need_x86 = (_pc is not None and _dpa is not None
                             and (_pc & MASK) < _dpa)
                if _need_x86:
                    LOG.add("x86: pc=%s below decompressor load -> auto decompressor recovery" % fmt(_pc))
        if _need_x86:
            _b = a.recover_kaslr_base(self)
            _d = self._entry_delta(a) if _b is not None else None
            if _b is not None and _d is None:
                print("[%s] x86 KASLR: recovered entry %s, but %s/%s are not in the symbol "
                      "table, so the image base it implies is unknown." % (
                          NAME, fmt(_b), a.entry_symbol, self._base_symbol(a)))
                return False
            if _b is not None:
                # Everything derived while the decompressor was still running was based on
                # the NOMINAL load address, because the real kernel was not in RAM yet: a
                # cached entry PA, an offset computed from it, and a shadow symbol file
                # loaded at that offset.  Leaving any of it in place poisons the calibration
                # that follows -- link_entry_va() then reads a shifted symbol and the offset
                # comes out as the nominal 0x1000000 one.  Start clean from the real base.
                self.offset = None
                self.kaslr_slide = 0
                self._shadow_unload()
                self._kaslr_pending = None
                self.entry_pa = (_b - _d) & MASK  # _b is the ELF entry; keep the image base
                self._entry_recovered = True
                # Name the route that produced the number.  X86_DECOMP_PA is what
                # recover_kaslr_base itself routes on: stated means a direct boot, whose
                # decompressor is walked; unset means a firmware chain, where the EFI
                # stub hands the entry over and the decompressor stages never execute.
                _route = ("the decompressor" if self.x86_decomp_pa() is not None
                          else "the EFI stub")
                print("[%s] x86 KASLR: recovered main-kernel phys base %s via %s; "
                      "breaking there." % (NAME, fmt(_b), _route))
            else:
                # No route is named here on purpose: the launcher states X86_DECOMP_PA
                # only when the compressed vmlinux is on disk, so in the branch that
                # reports that file missing it can say nothing about which walk would
                # have run.
                print("[%s] x86 KASLR: base recovery unavailable ($GDBTOOLS_X86_DECOMP_VMLINUX "
                      "unset or unreadable); trying nominal entry -- set $GDBTOOLS_ENTRY_PA "
                      "(or `kearly entry PA`) if it misses."
                      % NAME)
        # resolve_entry() is the IMAGE BASE PA; the CPU enters at the entry symbol,
        # which on newer x86 sits in .init.text well above _text.  Computed here and
        # never written back, so a second bootbreak starts from the same base.
        entry = self.entry_cpu_pa()
        anchor = self.current_anchor()
        # break target PA = entry_PA + (&anchor - &entry_symbol)
        break_pa = entry
        if entry is not None and anchor and a.entry_symbol and anchor != a.entry_symbol:
            d, e = symval(anchor), symval(a.entry_symbol)
            if d is None or e is None:
                print("[%s] anchor '%s' is not a symbol in this vmlinux, so there is no break "
                      "address to compute; fix it ($GDBTOOLS_ANCHOR, the profile, the preset) "
                      "or clear it with `kearly anchor -`." % (NAME, anchor))
                return False
            break_pa = (entry + (d - e)) & MASK
        self._armed_entry_pa = break_pa
        if pc is not None and break_pa is not None and pc == break_pa:
            return self.calibrate()              # already at the entry
        if break_pa is None:
            print("[%s] no entry PA for %s; break at a kernel symbol then "
                  "'kearly calibrate <sym>', or set $GDBTOOLS_ENTRY_PA/_PROFILE/_DTB"
                  % (NAME, a.key))
            return False
        kind = self.current_break_kind()
        cmd = "tbreak" if kind == "sw" else "thbreak"
        if arm_only:
            execstr("%s *0x%x" % (cmd, break_pa))
            print("[%s] armed %s at %s PA %s (%s-bp); continue to reach the kernel entry."
                  % (NAME, cmd, anchor or "entry", fmt(break_pa), kind))
            return True
        print("[%s] running to %s PA %s via %s-bp (past QEMU reset/firmware)..."
              % (NAME, anchor or "entry", fmt(break_pa), kind))
        execstr("%s *0x%x" % (cmd, break_pa))
        execstr("continue")
        pc = reg("pc")
        if pc is not None and not a._is_va(pc) and pc != break_pa:
            # did not land (e.g. hw bp unsupported): try the other breakpoint kind
            alt = "thbreak" if cmd == "tbreak" else "tbreak"
            LOG.add("bootbreak: %s missed entry (pc=%s); retrying with %s" %
                    (cmd, fmt(pc), alt))
            execstr("%s *0x%x" % (alt, break_pa))
            execstr("continue")
        # The stop hook calibrates at the landing FIRST -- from the clean link VA,
        # before _refresh_shadow's add-symbol-file'd copy can shadow the ELF entry
        # symbol (PIE/ET_DYN) and zero the offset.  Only calibrate here if it did
        # not (offset still unset, e.g. a preset anchor where pc != entry PA), so we
        # never recompute the offset with the shadow present.
        if self.offset is not None:
            return True
        return self.calibrate()

    # --- shadow symbol file (revives stock telescope/ctx at physical PCs) ---
    @safe()
    def _refresh_shadow(self):
        # Load the phys-shifted shadow once we have an offset, and KEEP it: PA and
        # VA ranges are disjoint, so physical addresses keep resolving even after
        # the MMU is on (page tables, secondary-CPU bringup, DMA), and we avoid
        # remove-symbol-file churn that orphans name-based breakpoints set during
        # the physical phase (gdb then spams "location number not found").
        # `kearly off` removes it explicitly.
        if self.arch is None or self.offset is None or not self._flag("SHADOW"):
            return
        self._shadow_load()

    @safe()
    def _shadow_load(self):
        vm = self.vmlinux_path()
        a = self.ensure_arch()
        if not vm or self.offset is None or a is None:
            return
        anchor_va = symval(a.entry_symbol) or symval("_text") or 0
        text_pa = self.v2p(anchor_va)
        if self.shadow_addr is not None:
            if self.shadow_addr == text_pa:
                return                        # already loaded correctly
            self._shadow_unload()
        out = exec_confirmless("add-symbol-file %s -o 0x%x" % (vm, self.offset & MASK))
        # Only claim the shadow loaded if add-symbol-file actually succeeded; a gdb
        # error returns '' (via @safe), so an empty / error result must NOT set
        # shadow_addr, else the "already loaded" fast-path would skip every retry.
        if (not out) or any(e in out for e in ("No such file", "not in executable format", "Invalid")):
            LOG.add("shadow load FAILED (add-symbol-file): %r" % (out,))
            return
        self.shadow_addr = text_pa
        LOG.add("shadow +o %s (text@%s)" % (fmt(self.offset), fmt(text_pa)))

    @safe()
    def _shadow_unload(self):
        if self.shadow_addr is None:
            return
        exec_confirmless("remove-symbol-file -a 0x%x" % (self.shadow_addr & MASK))
        LOG.add("shadow removed (was text@%s)" % fmt(self.shadow_addr))
        self.shadow_addr = None

    # --- early-boot quieting: keep -smp N, but tame the SMP/pwndbg chaos ---
    # While the MMU is off we set gdb 'scheduler-locking step' so stepping one vCPU
    # no longer lets the other cores free-run (the "thread 1 PC keeps jumping" / "a
    # secondary steals the stop" noise).  Restored automatically when the MMU comes
    # on, so post-boot SMP debugging is unaffected; the CPU count (-smp N) is never
    # touched.  scheduler-locking is a GDB setting, not a pwndbg feature.
    #
    # We touch exactly ONE pwndbg feature: `auto-explore-pages` (see _quiet_pagescan).
    # It is not a display feature -- it is a heuristic that, on a kernel target with no
    # /proc/maps, PROBES page-aligned addresses to guess permissions, and in "warn"
    # mode prints "Avoided exploring ... / Likely a pagescan bug, please report" for
    # every junk register value telescoped at a stop.  On a kernel target that is pure
    # noise that buries the register telescope, and the probing is the same activity
    # the safe-probe guard exists to contain.  We set it to "no" (quiet, no probing)
    # while enabled and RESTORE the user's prior value on `kearly off`.  Telescope,
    # dereference, symbolization -- every actual display feature -- stay at their
    # defaults; the tool only ADDS to those.
    _PWNDBG_QUIET = ()      # never silence any pwndbg DISPLAY feature

    @safe()
    def _quiet_pagescan(self):
        """Set pwndbg `auto-explore-pages` to "no" while enabled (restored on off).

        Proven on arm64 v6.12 KASLR at the primary __enable_mmu stop: the full
        register telescope and coloring render identically with and without this --
        the ONLY difference is ~11 lines of "Avoided exploring / Likely a pagescan
        bug" warning spam per stop, which this removes.  Guarded so it is a no-op when
        pwndbg (or the parameter) is absent -- stock gdb is unaffected."""
        if not PWN.ok:
            return
        try:
            cur = gdb.parameter("auto-explore-pages")
        except Exception:
            return                          # not this pwndbg version -> leave it alone
        if cur == "no":
            return
        self._param_set("auto-explore-pages", "no")

    @safe()
    def _param_set(self, name, value):
        """Set a gdb/pwndbg parameter, remembering the previous value once so it
        can be restored.  Silent + safe if the parameter does not exist."""
        if name not in self._saved_params:
            try:
                self._saved_params[name] = gdb.parameter(name)
            except Exception:
                self._saved_params[name] = None
        execstr("set %s %s" % (name, value))

    @safe()
    def _param_restore(self, name):
        old = self._saved_params.pop(name, None)
        if old is None:
            return
        if old is True:
            old = "on"
        elif old is False:
            old = "off"
        execstr("set %s %s" % (name, old))

    @safe()
    def _apply_early_quiet(self):
        if self._early_quiet:
            return
        self._param_set("scheduler-locking", "step")
        for nm, val in self._PWNDBG_QUIET:
            self._param_set(nm, val)
        self._early_quiet = True
        LOG.add("early-boot scheduler-locking=step ON (no pwndbg feature touched)")
        print("[%s] early-boot: scheduler-locking=step (siblings frozen while you "
              "single-step; all cores still run on 'continue'/'kearly overmmu').  "
              "Toggle with 'kearly steplock off'." % NAME)

    @safe()
    def _restore_early_quiet(self, reason=""):
        if not self._early_quiet:
            return
        for nm, _val in self._PWNDBG_QUIET:
            self._param_restore(nm)
        self._param_restore("scheduler-locking")
        self._early_quiet = False
        LOG.add("early-boot quiet OFF%s" % (" (%s)" % reason if reason else ""))

    @safe()
    def _sync_early_quiet(self, m):
        """Driven from the stop hook: apply while physical (MMU off), restore once
        virtual (MMU on).  steplock 'on' forces it always; 'off' never applies."""
        want = self.steplock != "off" and (self.steplock == "on" or m == "physical")
        if want and not self._early_quiet:
            self._apply_early_quiet()
        elif not want and self._early_quiet:
            self._restore_early_quiet("MMU on" if m == "virtual" else "steplock")

    @safe()
    def set_steplock(self, mode):
        mode = (mode or "").lower()
        if mode not in ("on", "off", "auto"):
            print("usage: kearly steplock <on|off|auto>   (auto = lock while MMU off)")
            return
        config.set_session("STEPLOCK", mode)
        self.steplock = mode
        self._sync_early_quiet(self.which_map())
        cur = None
        try:
            cur = gdb.parameter("scheduler-locking")
        except Exception:
            pass
        print("[%s] steplock=%s  (gdb scheduler-locking now: %s)" % (NAME, mode, cur))

    @safe()
    def over_mmu(self, sym=None):
        """Cross the MMU-enable boundary the robust way: set a temporary hardware
        breakpoint at the post-MMU VIRTUAL landing and 'continue', instead of
        single-stepping across __enable_mmu -- where QEMU's gdbstub can DROP the
        single-step across the TB flush / idmap->virtual branch and let the CPU
        run away (a secondary reaching __cpu_setup is what then stops the world).
        A plain 'continue' works here because the landing is the first virtual
        instruction on this CPU's path."""
        a = self.ensure_arch()
        if a is None:
            print("[%s] no arch" % NAME)
            return
        if a.pc_is_virtual() is True:
            print("[%s] already past MMU enable ($pc is virtual) -- nothing to cross." % NAME)
            return
        # On a KASLR boot the virtual landing symbol resolves to its LINK VA until the
        # slide is applied, so the thbreak below would sit where the relocated kernel
        # never executes.  Advance to the MMU-crossing first and apply the slide, so
        # the landing symbol now resolves to its runtime VA (no-op if slide==0/known).
        if self.kaslr_slide == 0 and self.offset is not None:
            s = self._advance_to_crossing()
            if s:
                self.apply_kaslr(s)
        cands = [sym] if sym else [s for s in getattr(a, "post_mmu_symbols", ())
                                   if symval(s) is not None]
        if not cands:
            print("[%s] no post-MMU landing symbol known for %s. Pass one explicitly: "
                  "kearly overmmu <symbol>  (e.g. start_kernel / secondary_start_kernel)."
                  % (NAME, a.key))
            return
        try:
            before = set(b.number for b in (gdb.breakpoints() or ()))
        except Exception:
            before = set()
        placed = []
        for s in cands:
            out = execstr("thbreak %s" % s)
            if "reakpoint" not in out:                 # hw bp rejected -> sw temp bp
                execstr("tbreak %s" % s)
            placed.append(s)
        try:
            mine = [b for b in (gdb.breakpoints() or ()) if b.number not in before]
        except Exception:
            mine = []
        print("[%s] over_mmu: continue to virtual landing {%s} ..." % (NAME, ", ".join(placed)))
        execstr("continue")
        for b in mine:                                 # drop any temp bp that did not fire
            try:
                if b.is_valid():
                    b.delete()
            except Exception:
                pass
        pc = reg("pc")
        res = self.symbolize(pc) if pc is not None else None
        where = (res[2] if res else None) or "?"
        vp = a.pc_is_virtual()
        print("[%s] landed pc=%s %s  (MMU %s)" %
              (NAME, fmt(pc), where, "on" if vp else ("off" if vp is False else "?")))
