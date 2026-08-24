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
            self._mod, self._orig = cls, cls.read_memory
            guard = self                       # SAFEPROBE instance, closed over
            _orig = cls.read_memory
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
        self._mod, self._orig = _m, _m.read
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
                self._mod.read_memory = self._orig
            else:
                self._mod.read = self._orig
            LOG.add("safeprobe: restored %s" % lvl)
        self.installed = False

    def _read_memory(self, inferior, address, size, partial=False):
        """Wrapper bound as GDBProcess.read_memory -- `inferior` is the bound self."""
        try:
            block = self._active() and self._mapped(address) is False
        except Exception:
            block = False
        if block:
            self.blocked += 1
            raise self._unmapped_error(address)
        return self._orig(inferior, address, size, partial)

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
        ok = "gpa:" in out
        if not ok and "Unmapped" not in out:
            return None                      # unrecognised answer -> allow
        self._cache[page] = ok
        return ok

    def _active(self):
        if self.mode == "off":
            return False
        if self.mode == "on":
            return True
        s = state.session()
        a = getattr(s, "arch", None) if s else None
        # Only where the danger exists: a kernel target with translation live.
        return bool(a is not None and getattr(s, "enabled", False)
                    and a.pc_is_virtual() is True)

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


@safe(default=False)
def install_kernel_guards():
    """Keep a fragile pwndbg kernel-version probe from killing the whole `context`.

    pwndbg's `krelease()` RAISES `Exception("Linux version tuple not found")` whenever
    `kversion()` returns a NON-empty string that does not match `Linux version X.Y` --
    and it is `cache_until("start")`, so it is recomputed after every `continue`.  At the
    very first `start_kernel` stop the `linux_banner` read is not yet reliable (the high
    map has only just come up), so it can come back as a short garbage string; `krelease`
    then throws and pwndbg aborts the ENTIRE context render ("context: Linux version tuple
    not found").  A few `continue`s later (userspace up) the banner reads cleanly and it
    works again -- which is exactly why it looks intermittent.

    A version we cannot read yet is a "None" situation, not a fatal one: pwndbg's own
    callers already treat `krelease() is None` as "unknown version".  So wrap it to return
    None on failure.  Additive, idempotent, and it touches no display feature -- it only
    stops one early-boot read glitch from taking the panel down.  Degrades to a no-op if
    pwndbg or the symbol is absent."""
    try:
        import pwndbg.aglib.kernel as _k
    except Exception:
        return False
    installed = False
    for name in ("krelease", "kversion"):
        orig = getattr(_k, name, None)
        if orig is None or getattr(orig, "_kgdb_guarded", False):
            continue
        def _wrapped(*a, _o=orig, **kw):
            try:
                return _o(*a, **kw)
            except Exception:
                return None
        _wrapped._kgdb_guarded = True
        _wrapped._kgdb_orig = orig
        setattr(_k, name, _wrapped)
        installed = True
    if installed:
        LOG.add("kguard: krelease/kversion wrapped (no 'version tuple not found' context death)")
    return installed


__all__ = ['_Pwndbg', 'PWN', '_SafeProbe', 'SAFEPROBE', 'context_kgdb', 'context_flow',
           'install_kernel_guards']
