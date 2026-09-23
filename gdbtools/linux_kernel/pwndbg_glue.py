"""part of gdbtools; see the package docstring."""
import os
import re
import json
import struct
import gdb
from ..common.runtime import *
from ..common import state


# ----------------------------------------------------------------------------
# Optional pwndbg integration.  pwndbg is the FRONTEND; we feed gdb's symbol
# table and (when pwndbg is present) borrow its look: register a custom context
# section so our MMU/PHYS-VIRT badge + key sysregs render INSIDE pwndbg's context
# (styled like the REGISTERS panel via pwndbg.color / pwndbg.chain), and use its
# dereference-chain formatter for chain.  pwndbg is used purely as a LIBRARY -- we
# never modify it.  If it is absent or its API differs, `ok` is False and every
# helper degrades to plain text, so the tool behaves identically in stock gdb.
# ----------------------------------------------------------------------------
class _Pwndbg:
    def __init__(self):
        self.ok = False
        self._ctx = self._ui = self._color = self._chain = None
        try:
            import pwndbg.commands.context as _c
            import pwndbg.ui as _u
            import pwndbg.color as _col
            import pwndbg.chain as _ch
            if isinstance(getattr(_c, "context_sections", None), dict):
                self._ctx, self._ui, self._color, self._chain = _c, _u, _col, _ch
                self.ok = True
        except Exception:
            self.ok = False

    @safe(default=None)
    def banner(self, title, width=None):
        return self._ui.banner(title, width=width) if self.ok else None

    # A telescope must NEVER take the session down.  pwndbg's chain formatter can
    # recurse without bound on a NON-CANONICAL address and overflow gdb's C stack
    # -- a TTBR raw value carries the ASID in bits[63:48], so at runtime it lands
    # in the dead band [2^48, 0xFFFF0000_00000000) that is neither a high-canonical
    # kernel VA (>= 0xFFFF0000_00000000, arm64 & x86) nor a low address (< 2^48).
    # We refuse to telescope anything in that band; callers then show plain hex (and
    # arm64 telescopes the ASID-stripped page-table base instead, so TTBR stays
    # telescoped).  Canonical values are unaffected -> existing display preserved.
    _NONCANON_LO = 1 << 48
    _NONCANON_HI = 0xFFFF000000000000

    @safe(default=None)
    def chain(self, addr, limit=8):
        # Kept for completeness, but the tool's rendering no longer relies on it:
        # pwndbg's chain follows a page-table-base register straight down the table
        # tree until gdb's C stack overflows, and its depth kwarg did not stop that,
        # so all auto-rendered telescopes use the self-bounded safe_chain() instead.
        # Here we still reject the non-canonical ASID band as a courtesy guard.
        if not self.ok or addr is None:
            return None
        a = addr & MASK
        if self._NONCANON_LO <= a < self._NONCANON_HI:
            return None
        try:
            return self._chain.format(a, limit=limit)
        except TypeError:
            return self._chain.format(a)

    @safe(default=None)
    def color(self, name, s):
        fn = getattr(self._color, name, None) if self.ok else None
        return fn(s) if callable(fn) else None


PWN = _Pwndbg()


def context_kgdb(*args, **kwargs):
    """pwndbg context-section callback (registered at runtime, plugin-style).
    Returns the PHYS/VIRT+MMU badge and the key sysregs, banner-wrapped like
    pwndbg's own sections.  Empty (no banner) unless we are enabled on a kernel."""
    try:
        lines = state.session().kgdb_context_lines()
        if not lines:
            return []
        if kwargs.get("with_banner", True):
            b = PWN.banner("kgdb early-boot", width=kwargs.get("width"))
            if b:
                return [b] + lines
        return lines
    except Exception:
        return []


def context_msysreg(*args, **kwargs):
    """pwndbg context-section callback: the system registers the early-boot asm
    touches, each printed as its own value with the bits inside it underneath.

    Separate from 'kgdb' on purpose.  That section answers "where am I" -- the
    PHYS/VIRT badge and the handful of registers that decide it.  This one answers
    "what do the control registers say", which is a longer, differently-shaped
    question, and mixing the two would make both harder to read."""
    try:
        lines = state.session().msysreg_context_lines(width=kwargs.get("width"))
        if not lines:
            return []
        if kwargs.get("with_banner", True):
            b = PWN.banner("kernel sysregs", width=kwargs.get("width"))
            if b:
                return [b] + lines
        return lines
    except Exception:
        return []


def context_flow(*args, **kwargs):
    """pwndbg context-section callback: the radare2-style BRANCH-ARROW view of
    near-pc disassembly, rendered by our own gdb+python engine.  Registered as
    'flow' right AFTER pwndbg's own 'disasm', so both windows always show and run
    in parallel -- pwndbg's 'disasm' carries the rich annotations (emulation /
    telescope / flags), this 'flow' draws the ┌│└─ arrows.  Pure gdb+python, so it
    never hangs or crashes."""
    try:
        lines = state.session().kdisasm_context_lines()
        if not lines:
            return []
        if kwargs.get("with_banner", True):
            title = "disasm + arrows"
            try:                                # match pwndbg's disasm banner arch tag
                import pwndbg.aglib.arch as _a
                title = "disasm + arrows / %s" % _a.name
            except Exception:
                pass
            b = PWN.banner(title, width=kwargs.get("width"))
            if b:
                return [b] + lines
        return lines
    except Exception:
        return []


# Underscore-prefixed helpers are part of this module's public surface for the
# rest of the package (`from .pwndbg_glue import *`), which would otherwise skip them.
# ----------------------------------------------------------------------------
# Safe-probe guard for pwndbg's memory reads.
#
# pwndbg has no /proc/<pid>/maps on a kernel target, so it infers the memory map
# by PROBING: single-byte reads at page-aligned addresses, ~170 of them per
# context render.  Most miss and fail harmlessly.  But a debug read of an address
# that translates outside RAM makes QEMU dispatch into a device model, and that
# path SEGVs -- killing the VM and the gdb session with it.
#
# Measured on arm64 v6.12, KASLR on, stopped in vfs_write (a syscall context, so
# TTBR0 holds the CURRENT USER PROCESS's tables and the probes translate all over
# the place): 4/4 crashes with pwndbg, 0/3 with pwndbg absent, and the trace's last
# line before death was `R 0xffff0207c583b000 1`.  Reproduced with pwndbg alone and
# this tool NOT loaded, so the trigger is pwndbg's probing, not ours.
#
# The fix is additive and removes nothing: wrap that one funnel and ask QEMU whether
# the address is mapped BEFORE reading it.  `monitor gva2gpa` answers exactly that
# and is safe on any input -- verified returning "Unmapped" for the very address
# that crashed the read path.  Unmapped -> raise the ordinary "cannot access"
# error pwndbg already handles, without ever issuing the read.
#
# The danger belongs to the ADDRESS, not to the regime the stopped core is in, so the
# guard is armed wherever HMP can answer -- see _active().  A telescoped register at a
# PRE-MMU stop reaches a device model exactly as easily as a stray probe at a syscall
# stop does, and on a v4.6 arm64 guest it reliably does.
# ----------------------------------------------------------------------------
class _SafeProbe:
    def __init__(self):
        self.installed = False
        self.mode = "auto"          # auto | on | off
        self._orig = None
        self._mod = None
        self._cache = {}            # page -> True/False (mapped)
        self.blocked = 0
        self.rescued = 0            # reads re-served from monitor xp at a physical stop
        self._in_rescue = False     # reentrancy guard around the monitor read
        self._ram_cache = {}        # page -> is-guest-RAM (gpa2hva), for the rescue bound
        self._v2p_cache = {}        # va-page -> gpa-page (gva2gpa), for the VA rescue
        self._pinned = None         # core HMP is pointed at, as far as WE set it
        self._mon = None            # does this target answer HMP at all (session-wide)
        self._level = ""

    # One 4 KiB page: the largest block the rescue re-serves through `monitor xp`.
    # pwndbg's reads are pointer- or instruction-sized; anything larger falls through
    # to the ordinary failure rather than pay a big HMP round-trip.  Not a layout
    # constant -- just a sanity cap on the monitor cost.
    _MAX_RESCUE_BYTES = 4096

    @safe(default=False)
    def install(self):
        """Wrap the LOWEST read choke point, not a convenience wrapper on top of it.

        Every pwndbg memory read -- the register enhancer, chain.py's telescope, a
        stack dump -- ultimately calls `selected_inferior().read_memory`, which on the
        gdb backend is `GDBProcess.read_memory`.  An earlier version wrapped
        `aglib.memory.read` instead; the register enhancer reaches read_memory by a
        path that does NOT go through that wrapper, so a junk pointer telescoped from a
        register sailed past the guard and SEGV'd QEMU anyway.  Wrapping the class
        method catches all of them, because there is no lower level to slip through.
        """
        if self.installed:
            return True
        cls = None
        try:
            from pwndbg.dbg_mod.gdb import GDBProcess as cls
        except Exception:
            cls = None
        if cls is not None and callable(getattr(cls, "read_memory", None)):
            # Stash the true original once on the class so an edit/re-source cycle
            # (which rebuilds this module and this instance) recovers it and never
            # wraps a wrapper. Strip an orphaned wrapper from a prior source first.
            orig = getattr(cls, "_gdbtools_orig_read_memory", None)
            if orig is None:
                orig = cls.read_memory
                try:
                    cls._gdbtools_orig_read_memory = orig
                except Exception:
                    pass
            elif getattr(cls.read_memory, "_gdbtools_safeprobe", False):
                cls.read_memory = orig
            self._mod, self._orig = cls, orig
            guard = self                       # SAFEPROBE instance, closed over
            _orig = orig
            def _wrapped(inferior, address, size, partial=False, _g=guard, _o=_orig):
                # Bound as a CLASS method: `inferior` is the GDBProcess self.
                #
                # For an unmapped address we must NOT issue the read (QEMU SEGVs on a
                # debug read that translates to a device region) and must NOT raise
                # (some pwndbg render paths -- the register enhancer -- don't catch it,
                # and the whole `context` dies).  Stock pwndbg never reaches these
                # addresses because it vmmap-prechecks; we have no vmmap, so instead we
                # answer the read locally with zero bytes.  pwndbg treats that as "reads
                # as 0", shows it, and moves on -- exactly the harmless outcome, with no
                # read sent to QEMU and no exception thrown.
                try:
                    block = _g._active() and _g._mapped(address) is False
                except Exception:
                    block = False
                if block:
                    _g.blocked += 1
                    # Blocked is not the same as unreadable.  At a mixed-regime stop --
                    # a secondary core parked in head.S while the primary runs the
                    # kernel -- a kernel VA does not translate on the core gdb is parked
                    # on (arm64's HMP answers a flat "Unmapped" there), yet the primary
                    # maps it and the physical path reads it.  Zero-filling printed
                    # `X27 0xffffff8008082c00 (__secondary_switched) -> 0` for a pointer
                    # whose target is sitting right there, so try the same cross-core
                    # rescue the read-failed path uses before falling back to zeros.
                    # _rescue reads guest RAM and nothing else, so it cannot reach the
                    # device model this guard exists to keep away from.
                    r = _g._rescue(address, size)
                    if r is not None:
                        return r
                    return bytearray(max(int(size), 0))
                try:
                    return _o(inferior, address, size, partial)
                except Exception:
                    # A live read failed.  At a PHYSICAL-regime stop the QEMU gdbstub
                    # cannot serve a physical read for a secondary CPU's regime while
                    # another core runs MMU-on (measured: gdb `Inferior.read_memory`
                    # raises MemoryError there, yet HMP `monitor xp` still reads it).
                    # Re-serve from monitor xp, bounded to guest RAM, so pwndbg's
                    # telescope / disasm / peek light up at the early-boot secondary
                    # stop instead of going blank.  None -> let the original error stand.
                    r = _g._rescue(address, size)
                    if r is not None:
                        return r
                    raise
            _wrapped._gdbtools_safeprobe = True
            cls.read_memory = _wrapped
            self.installed = True
            self._level = "GDBProcess.read_memory"
            LOG.add("safeprobe: wrapped GDBProcess.read_memory")
            return True
        # Fallback: the high-level wrapper (older pwndbg, or non-gdb backend).
        try:
            import pwndbg.aglib.memory as _m
        except Exception:
            try:
                import pwndbg.gdblib.memory as _m
            except Exception:
                return False
        if not callable(getattr(_m, "read", None)):
            return False
        orig = getattr(_m, "_gdbtools_orig_read", None)
        if orig is None:
            orig = _m.read
            try:
                _m._gdbtools_orig_read = orig
            except Exception:
                pass
        self._mod, self._orig = _m, orig
        _m.read = self._read
        self.installed = True
        self._level = "%s.read" % _m.__name__
        LOG.add("safeprobe: wrapped %s.read (fallback)" % _m.__name__)
        return True

    @safe()
    def uninstall(self):
        if self.installed and self._mod is not None and self._orig is not None:
            lvl = getattr(self, "_level", "")
            if lvl == "GDBProcess.read_memory":
                cls = self._mod
                orig = getattr(cls, "_gdbtools_orig_read_memory", None) or self._orig
                if getattr(cls.read_memory, "_gdbtools_safeprobe", False):
                    cls.read_memory = orig
                try:
                    del cls._gdbtools_orig_read_memory
                except Exception:
                    pass
            else:
                m = self._mod
                orig = getattr(m, "_gdbtools_orig_read", None) or self._orig
                m.read = orig
                try:
                    del m._gdbtools_orig_read
                except Exception:
                    pass
            LOG.add("safeprobe: restored %s" % lvl)
        self.installed = False
        self._mon = None            # the next target may not be a QEMU guest at all

    def flush(self):
        self._cache.clear()
        self._ram_cache.clear()
        self._v2p_cache.clear()
        self._pinned = None

    def _gdb_cpu(self):
        """QEMU cpu index of the core gdb is stopped on (gdb thread N <-> cpu N-1)."""
        try:
            t = gdb.selected_thread()
            if t is not None and int(t.num) >= 1:
                return int(t.num) - 1
        except Exception:
            pass
        return None

    @safe(default=None)
    def _hmp_cpu(self):
        """The core HMP is pointed at right now, read back from `info cpus`."""
        out = execstr("monitor info cpus") or ""
        m = re.search(r"^\s*\*\s*CPU\s*#(\d+)", out, re.M)
        return int(m.group(1)) if m else None

    @safe()
    def _pin_cpu(self, idx):
        """Point HMP at core `idx`, remembering it so the next ask is free."""
        if idx is None or idx < 0 or self._pinned == idx:
            return
        execstr("monitor cpu %d" % idx)
        self._pinned = idx

    @safe(default=None)
    def _va_to_pa(self, va):
        """Translate a guest VA to its physical address via QEMU, so a failed live read of
        a MAPPED kernel VA can still be re-served from `monitor xp`.  Cached per page.

        Crucially, translate through the CPU that actually has the VA mapped -- the
        gdb-selected thread's core, which is the one executing at this stop.  QEMU's HMP
        `gva2gpa` uses the HMP-current CPU, and on riscv the boot hart is nondeterministic,
        so the HMP default (cpu 0) is often a Bare-mode secondary that returns the input VA
        UNCHANGED (identity, no real translation).  We reject that identity answer and, if
        needed, scan the cores until one gives a real (physical, non-identity) address.  A
        VA that no core maps yet (very early boot) yields None -- correctly declined.

        The scan puts HMP back on the core it started from.  HMP's current CPU is monitor
        state shared with every other consumer of this gdbstub -- `_mapped` below, the
        `monitor info registers` sysreg fallback that yields CR3/satp/arm64 sysregs, and
        anything the user types -- so a scan that ended on a parked secondary used to make
        every live kernel VA answer "Unmapped" from then on, which this guard turned into
        silently zero-filled reads."""
        page = va & ~0xFFF
        hit = self._v2p_cache.get(page)
        if hit is not None:
            return None if hit < 0 else (hit + (va & 0xFFF))
        base = self._translate_page(page)
        self._v2p_cache[page] = base if base is not None else -1
        return None if base is None else (base + (va & 0xFFF))

    @safe(default=None)
    def _translate_page(self, page):
        s = state.session()
        a = getattr(s, "arch", None) if s else None
        order = []
        try:
            t = gdb.selected_thread()
            if t is not None:
                order.append(int(t.num) - 1)        # gdb thread N <-> QEMU cpu N-1
        except Exception:
            pass
        try:
            n = len(list(gdb.selected_inferior().threads()))
        except Exception:
            n = 4
        order += [i for i in range(max(n, 1)) if i not in order]
        saved = self._pinned if self._pinned is not None else self._hmp_cpu()
        try:
            for idx in order:
                if idx < 0:
                    continue
                self._pin_cpu(idx)                   # translate via THIS core's page tables
                out = execstr("monitor gva2gpa 0x%x" % page) or ""
                mm = re.search(r"gpa:\s*(0x[0-9a-fA-F]+)", out)
                if not mm:
                    continue
                gpa = int(mm.group(1), 16) & ~0xFFF
                if gpa == page:                      # identity -> Bare/MMU-off core, not real
                    continue
                if a is not None and a._is_va(gpa):   # still a VA -> not a physical answer
                    continue
                return gpa
            return None
        finally:
            back = saved if saved is not None else self._gdb_cpu()
            self._pin_cpu(0 if back is None else back)

    @safe(default=False)
    def _is_ram(self, addr):
        """Is `addr` backed by guest RAM?  Asked of QEMU, so there is NO hardcoded RAM
        span to go stale per machine: `monitor gpa2hva` answers 'Host virtual address
        for 0x.. (pc.ram) is 0x..' for RAM, 'is not RAM' for a device, 'No memory is
        mapped' for a hole.  Reading a device model is the only thing to avoid; RAM is
        always safe for `monitor xp`.  Cached per page.

        Fallback when the command is unavailable (ancient QEMU): the arch's own
        phys_window preset -- an architecture-documented RAM window, not an invented
        magic number.  Returns False when neither is decisive, so the rescue simply
        declines and the ordinary read failure stands."""
        page = addr & ~0xFFF
        hit = self._ram_cache.get(page)
        if hit is not None:
            return hit
        out = execstr("monitor gpa2hva 0x%x" % page) or ""
        if "Host virtual address" in out:
            ok = True
        elif ("not RAM" in out) or ("No memory is mapped" in out):
            ok = False
        else:
            # gpa2hva absent/unrecognised -> fall back to the arch RAM-window preset.
            ok = False
            try:
                s = state.session()
                a = getattr(s, "arch", None) if s else None
                win = a.eff_phys_window() if a is not None else None
                if win:
                    ok = win[0] <= addr <= win[1]
            except Exception:
                ok = False
        self._ram_cache[page] = ok
        return ok

    @safe(default=None)
    def _rescue(self, addr, size):
        """A live pwndbg read of `addr` failed -- re-serve it from QEMU's `monitor xp`.

        The QEMU gdbstub cannot always service a memory read when CPUs sit in different
        translation regimes at once (a secondary on MMU-off physical code while another
        core runs the MMU-on kernel, OR -- measured on riscv SMP -- a MAPPED kernel VA at
        an ordinary virtual stop while a sibling hart is mid-boot): gdb's Inferior read
        raises MemoryError even though the CPU is executing right there.  `monitor xp`
        goes through QEMU's HMP address_space_read, not the gdbstub cpu_memory_rw_debug
        path, and reads a PHYSICAL address regardless of any CPU's regime -- so it always
        works.  We map the failed address to a physical one and read it there:

          * a physical (low) address is used as-is;
          * a virtual address is translated via the guest's own page tables
            (`monitor gva2gpa`), which resolves ONLY where the mapping is actually live
            -- a not-yet-mapped VA (e.g. pre-MMU) declines rather than lie.

        Then the physical target must be real guest RAM (`_is_ram`, asked of QEMU), so no
        device model is ever read.  The virtual-stop CRASH path is untouched: an unmapped
        junk pointer is caught by the zero-fill guard ABOVE and never reaches here.
        Returns the bytes, or None to let the original failure stand."""
        if self.mode == "off" or self._in_rescue:
            return None
        s = state.session()
        a = getattr(s, "arch", None) if s else None
        if a is None or not getattr(s, "enabled", False):
            return None
        n = max(int(size), 0)
        if n == 0:
            return bytearray()
        if n > self._MAX_RESCUE_BYTES:          # pwndbg reads are small; cap monitor cost
            return None
        if a._is_va(addr):
            pa = self._va_to_pa(addr)           # translate a mapped VA; None if not live
            if pa is None:
                return None
        else:
            pa = addr
        if not self._is_ram(pa):                # RAM only -> never dispatch to a device
            return None
        return self._monitor_read(pa, n)

    @safe(default=None)
    def _monitor_read(self, addr, n):
        self._in_rescue = True
        try:
            out = execstr("monitor xp/%dxb 0x%x" % (n, addr))
        finally:
            self._in_rescue = False
        if not out:
            return None
        vals = re.findall(r"0x([0-9a-fA-F]{2})\b", out)
        if len(vals) < n:
            return None
        self.rescued += 1
        return bytearray(int(v, 16) for v in vals[:n])

    @safe(default=None)
    def _mapped(self, addr):
        """True/False/None(unknown) -- is `addr` translatable right now?

        Asked of the core gdb is stopped on, since that is the regime the read being
        guarded will use, and since HMP's current CPU is shared state we must set rather
        than inherit."""
        page = addr & ~0xFFF
        hit = self._cache.get(page)
        if hit is not None:
            return hit
        self._pin_cpu(self._gdb_cpu())
        out = execstr("monitor gva2gpa 0x%x" % page)
        if not out:
            return None                      # no monitor -> cannot judge, allow
        m = re.search(r"gpa:\s*(0x[0-9a-fA-F]+)", out)
        if m is not None:
            # Translating is not the same as being safe to read, and that difference is
            # the whole point of this guard.  At a late-boot stop most of the kernel
            # pages pt-dump reports translate to DEVICE registers rather than RAM -- on
            # QEMU's arm64 `virt`, measured at mm_init: 272 of 283 kernel pages, among
            # them the GIC at 0x8000000, the PL011 at 0x9000000 and PCIe at
            # 0x8000000000.  pwndbg's `is_kernel()` peeks one byte of every one of them
            # while looking for the kernel base, and a debug read of a device model is
            # what takes QEMU -- and with it gdb -- down.  Asking only "does it
            # translate" let all 272 through.  Ask whether it translates to RAM.
            ok = bool(self._is_ram(int(m.group(1), 16)))
        elif "Unmapped" in out:
            ok = False
        else:
            return None                      # unrecognised answer -> allow
        self._cache[page] = ok
        return ok

    @safe(default=False)
    def _monitor_alive(self):
        """Does this target answer QEMU's human monitor?  Asked once per session.

        Every verdict this guard reaches is read out of HMP (`gva2gpa`, `gpa2hva`), so
        on a target that has none -- kgdb over a serial line, a JTAG probe -- it can
        only ever answer "unknown" and allow.  Settling that once costs one round trip;
        leaving it unsettled costs one per page, for ever, on the slowest link in the
        room.  Cached for the session and not per stop, because whether a target HAS a
        monitor does not change while it is attached.  A negative answer is NOT cached
        until something is actually attached, or a guard armed before `target remote`
        would stay inert for the rest of the session."""
        if self._mon is not None:
            return self._mon
        if gdb.selected_thread() is None:
            return False                     # nothing attached yet -- ask again later
        out = execstr("monitor gpa2hva 0") or ""
        self._mon = bool(re.search(r"Host virtual address|is not RAM|No memory is mapped", out))
        LOG.add("safeprobe: QEMU monitor %s"
                % ("answers" if self._mon else "absent -- guard inert"))
        return self._mon

    def _active(self):
        if self.mode == "off":
            return False
        if self.mode == "on":
            return True
        s = state.session()
        a = getattr(s, "arch", None) if s else None
        if a is None or not getattr(s, "enabled", False):
            return False
        # NOT "is this core translating".  The SEGV is a property of the ADDRESS, not of
        # the regime the stopped core happens to be in: a debug read that reaches a
        # device model takes QEMU down whether translation is on or off.  Measured on
        # arm64 `virt` at the FIRST pre-MMU stop, both cores MMU-off, a single
        # `x/1xw 0x8010000` -- the GICv2 CPU interface -- killed QEMU with SIGSEGV and
        # gdb aborted after it (QEMU's gic_get_current_cpu() reads current_cpu->cpu_index,
        # and current_cpu is NULL in the gdbstub's main-loop context whenever num_cpu > 1).
        #
        # The old gate asked `pc_is_virtual() is True`, which switched the guard OFF for
        # every physical-regime stop -- including the one it matters most for.  Stop a
        # v4.6 arm64 guest at `__enable_mmu` and continue: the second stop is the
        # SECONDARY core, still MMU-off in head.S, while the primary already runs the
        # kernel MMU-on.  secondary_startup leaves x8 = kimage_vaddr, and v4.6 defines
        # KIMAGE_VADDR == MODULES_END == VMALLOC_START (asm/memory.h:53, asm/pgtable.h:37),
        # so that one number is also the first address of the ioremap area -- where the
        # GIC distributor is mapped.  pwndbg telescopes x8, the read is served in the
        # MMU-ON core's regime, it lands on the GIC, and the guest and the debugger die
        # together.  The guard was installed, and looking the other way.  6.12 separated
        # the two constants and so does not reproduce it, which is exactly why the gate
        # must not be a guess about which addresses a register can hold.
        #
        # So gate on the instrument instead of on the regime: wherever HMP answers, the
        # guard can decide, and wherever it can decide it should.
        return self._monitor_alive() is True

    def _unmapped_error(self, addr):
        """Raise the SAME exception type pwndbg's own read raises on failure.

        This is the entire correctness of the guard.  pwndbg's callers -- chain.py's
        pointer telescope, the register context enhancer -- wrap each read in
        `except pwndbg.dbg_mod.Error: break`, and pwndbg's gdb backend raises exactly
        that type (`raise pwndbg.dbg_mod.Error(e)` in dbg_mod/gdb/__init__.py) when a
        read fails.  Raising `gdb.MemoryError` instead -- which is NOT a subclass of
        pwndbg.dbg_mod.Error -- sails straight through those handlers and kills the
        whole `context`.  That is the bug the user hit at start_kernel: $x20 held the
        junk value 0xe11, the register enhancer telescoped it, and the guard's wrong
        exception type turned an unreadable pointer into a fatal one.
        """
        msg = "Cannot access memory at address 0x%x" % addr
        # At GDBProcess.read_memory the caller catches `gdb.error` and re-raises it as
        # pwndbg.dbg_mod.Error (dbg_mod/gdb/__init__.py:711), so raising gdb.MemoryError
        # (a gdb.error subclass) here reproduces the exact type the real read failure
        # would have produced.  At the higher aglib.memory.read level there is no such
        # wrapping, so raise pwndbg's Error directly.
        if getattr(self, "_level", "") == "GDBProcess.read_memory":
            return gdb.MemoryError(msg)
        try:
            import pwndbg.dbg_mod as _dm
            return _dm.Error(msg)
        except Exception:
            return gdb.MemoryError(msg)

    def _read(self, addr, count, *a, **kw):
        try:
            block = self._active() and self._mapped(addr) is False
        except Exception:
            block = False                     # never let the guard break a read
        if block:
            self.blocked += 1
            raise self._unmapped_error(addr)
        return self._orig(addr, count, *a, **kw)


SAFEPROBE = _SafeProbe()


# Each entry is (module, attribute, what the call returns when it cannot finish).
# Every one of these is a pwndbg entry point that reads KERNEL memory to produce
# DECORATION -- a release string, a name for a vmmap range -- and does not catch a
# failed read.  Before the MMU is on, and briefly after while the high map is still
# being built, those reads fail, and pwndbg aborts the ENTIRE `context`: the panels
# that would have rendered fine -- registers, disassembly, our own badge -- never
# appear.  Decoration that cannot be read is missing decoration, not a dead panel.
_KGUARDS = (
    # krelease() RAISES whenever kversion() returns a NON-empty string that does not
    # match "Linux version X.Y", and it is cache_until("start"), so it is recomputed
    # after every continue.  At the very first start_kernel stop the linux_banner read
    # is not yet reliable (the high map has only just come up) and can come back as a
    # short garbage string; the context then dies whole with "context: Linux version
    # tuple not found", and works again a few continues later -- which is exactly why
    # it looks intermittent.  pwndbg's own callers already treat a None release as
    # "unknown version", so that is what a failed read becomes here.
    ("pwndbg.aglib.kernel", "krelease", None),
    ("pwndbg.aglib.kernel", "kversion", None),
    # `address_markers` is arch/arm64/mm/dump.c's table of VA-layout labels, which
    # pwndbg walks with a bare memory.u64() on a KERNEL VA to name vmmap ranges.  At
    # head.S _text the MMU is off, so that read raises pwndbg.dbg_mod.Error and it
    # propagates all the way out of the register panel:
    #   context -> context_regs -> get_regs -> vmmap.find -> get_memory_map
    #     -> GDBProcess.vmmap -> kernel_vmmap -> _apply_address_markers
    #       -> markers() -> memory.u64(address_markers)      <- raises here
    # Guarding the CALLER rather than markers() also covers handle_kernel_pages(),
    # which reads kernel memory on the next line, and it costs only the LABELS: the
    # ranges themselves are already in `pages` before any of this runs.
    ("pwndbg.aglib.kernel.vmmap", "_apply_address_markers", None),
    # The same argument one level up, for whatever else building the map may read.
    # A memory map that cannot be built is an empty map, and an empty map renders.
    ("pwndbg.aglib.kernel.vmmap", "kernel_vmmap", ()),
    # `vmmap` annotates its ranges with the CURRENT task's mapped files and user
    # stack.  Before userspace exists there is no such task -- at start_kernel
    # current->mm is null -- so the VMA walk reaches int(None) and raises TypeError,
    # which aborts `vmmap` before it prints a single range.  Only the annotation
    # needs a task; guarding it lets the ranges, the page offsets and the
    # kernel-stack labels through, which is what the command is for.
    ("pwndbg.aglib.kernel.vmmap", "_handle_user_stack_and_filepaths", None),
    # Same shape, next line of the same function: labelling each range with the
    # kernel stack that lives in it walks the task list, which at start_kernel is
    # not built yet.  annotate() already treats an empty answer as "no stacks".
    ("pwndbg.aglib.kernel.vmmap", "_get_kernel_stacks", ()),
)

# How often each guard actually substituted a value, so a session can be asked
# rather than guessed at.  A guard that never fires is one that can be dropped once
# pwndbg guards the read itself; one that fires on every stop is worth looking at.
KGUARD_HITS = {}


# Guards that REFUSE rather than substitute: a condition under which the call must
# not run at all, checked before the original is reached.  Keyed the same way as
# _KGUARDS, with a predicate that returns True when the call should be skipped and
# the value to return in its place.
def _translation_off():
    """True only when translation is definitely OFF right now.

    Deliberately conservative: pwndbg's own paging_enabled() is the source, and any
    failure to answer means "do not refuse".  A guard that refuses on a failed probe
    would break the steady-state case it is not meant to touch."""
    try:
        import pwndbg.aglib.kernel as _k
        return _k.paging_enabled() is False
    except Exception:
        return False


_KREFUSALS = (
    # With translation off there is no current page table: TTBR still holds whatever
    # the previous boot stage left in it.  pwndbg knows this in ONE of its two map
    # builders -- kernel_vmmap_via_page_tables() checks paging_enabled() and returns
    # nothing -- but the scan path does not, so at head.S _text it walks u-boot's
    # tables and `vmmap` prints them as the kernel's memory map: five ranges spanning
    # 0x0-0x200000000000 and up, none of which the kernel has mapped.  vmmap not
    # working before the MMU is on is the correct answer; inventing a map is not.
    ("pwndbg.aglib.kernel.vmmap", "kernel_vmmap_pages", _translation_off, ()),
    # The annotation pass is the other half of the same story.  Its first act is to
    # walk the task list to label ranges, through kernel addresses that do not
    # translate before the MMU is on -- which pwndbg reports as a bare
    # "ERROR (get_ktasks): Cannot access memory at ...".  Everything it adds is a
    # LABEL on ranges that are already correct, so with translation off it is skipped
    # whole, and once translation is on a failure inside it costs labels, never the
    # map (the wrapper absorbs that too).
    ("pwndbg.aglib.kernel.vmmap", "annotate", _translation_off, None),
)


@safe(default=False)
def install_kernel_guards():
    """Wrap the pwndbg reads listed in _KGUARDS so a failed one cannot kill `context`.

    Additive, idempotent, and it removes no display feature: each wrapper calls the
    original first and substitutes only when the original raised.  Degrades to a
    no-op for any entry whose module or symbol is absent, so a pwndbg that has moved
    or fixed one of these simply gets one guard fewer."""
    import importlib
    installed = []
    for modname, name, fallback in _KGUARDS:
        try:
            mod = importlib.import_module(modname)
        except Exception:
            continue
        orig = getattr(mod, name, None)
        if orig is None or getattr(orig, "_kgdb_guarded", False):
            continue
        def _wrapped(*a, _o=orig, _f=fallback, _n=name, **kw):
            try:
                return _o(*a, **kw)
            except Exception:
                KGUARD_HITS[_n] = KGUARD_HITS.get(_n, 0) + 1
                return _f
        _wrapped._kgdb_guarded = True
        _wrapped._kgdb_orig = orig
        setattr(mod, name, _wrapped)
        installed.append(name)
    for modname, name, predicate, refusal in _KREFUSALS:
        try:
            mod = importlib.import_module(modname)
        except Exception:
            continue
        orig = getattr(mod, name, None)
        if orig is None or getattr(orig, "_kgdb_guarded", False):
            continue
        def _refusing(*a, _o=orig, _p=predicate, _r=refusal, _n=name, **kw):
            if _p():
                KGUARD_HITS[_n] = KGUARD_HITS.get(_n, 0) + 1
                return _r
            try:
                return _o(*a, **kw)
            except Exception:
                KGUARD_HITS[_n] = KGUARD_HITS.get(_n, 0) + 1
                return _r
        _refusing._kgdb_guarded = True
        _refusing._kgdb_orig = orig
        setattr(mod, name, _refusing)
        installed.append(name)
    if installed:
        LOG.add("kguard: wrapped %s (a failed decorative read no longer kills context)"
                % ", ".join(installed))
    return bool(installed)


def uninstall_kernel_guards():
    import importlib
    restored = []
    for modname, name in ([(m, n) for m, n, _f in _KGUARDS]
                          + [(m, n) for m, n, _p, _r in _KREFUSALS]):
        try:
            mod = importlib.import_module(modname)
        except Exception:
            continue
        orig = getattr(getattr(mod, name, None), "_kgdb_orig", None)
        if orig is None:
            continue
        setattr(mod, name, orig)
        restored.append(name)
    if restored:
        LOG.add("kguard: restored %s" % ", ".join(restored))
    return bool(restored)


__all__ = ['_Pwndbg', 'PWN', '_SafeProbe', 'SAFEPROBE', 'context_kgdb', 'context_flow', 'context_msysreg',
           'install_kernel_guards', 'uninstall_kernel_guards', 'KGUARD_HITS']
