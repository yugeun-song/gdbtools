"""part of gdbtools; see the package docstring."""
import gdb
import os
import re
from ..common.runtime import *
from .pwndbg_glue import SAFEPROBE, install_kernel_guards, uninstall_kernel_guards
from .target import TARGET, QEMU_PRESETS
from ..common.arch import ARCHES, detect_arch
from .presets import PRESETS
from ..common import state
from .addressing import AddressingMixin
from .boot import BootMixin
from .kaslr import KaslrMixin
from .breakpoints import BreakpointMixin
from .views import ViewMixin
from .panels import PanelMixin


# ----------------------------------------------------------------------------
# Session: holds calibration + shadow state, the stop hook, and the API the
# commands call.  Single instance, fully degrade-safe.
# ----------------------------------------------------------------------------
class Session(AddressingMixin, BootMixin, KaslrMixin, BreakpointMixin, ViewMixin, PanelMixin):
    def __init__(self):
        self.arch = None
        self.offset = None          # PA - VA (mod 2^64)
        self.entry_pa = None        # resolved kernel entry physical address (cached)
        self._entry_recovered = False  # entry_pa came from x86 decompressor recovery
        self._entry_pinned = False     # entry_pa was stated by hand (`kearly entry <pa>`)
                                       # (already the ELF entry PA, not the image base)
        self.shadow_addr = None     # PA where the shadow's text is loaded
        self.vmlinux = None
        self.enabled = False
        self._hooked = False
        self.last_map = None
        self.verbose = False        # per-stop pc annotation (off by default)
        self.show_sysregs = True    # per-stop compact MMU + key-sysreg line (on)
        self._section_installed = False  # pwndbg 'kgdb' context section registered?
        self._kdisasm_installed = False  # pwndbg 'arrows' (cfgdis) context section?
        self._msysreg_installed = False  # pwndbg 'msysreg' context section registered?
        self.kdis_before = 6        # context 'arrows': instrs shown before $pc
        self.kdis_after = 12        #                    and after $pc
        self.preset = None          # active preset name
        self.anchor = None          # override break/calibration anchor symbol
        self.break_kind = None      # override "sw"/"hw"
        self.steplock = "off"       # early-boot scheduler-locking: auto|on|off
                                    # (default OFF: never touch gdb's scheduler-locking;
                                    #  opt in with `kearly steplock on` for SMP stepping)
        self._early_quiet = False   # early-boot quiet/steplock currently applied?
        self._saved_params = {}     # gdb/pwndbg params we changed, for restore
        self.census_mode = "off"    # per-stop census in the panel: off|compact|full
        self.msysreg_mode = "compact"  # sysreg+bitfield panel: off|compact|full
        self._census_dead = set()   # census regs the stub cannot expose (skip, fast)
        self.chain_hops = 8         # safe_chain telescope depth (kearly chaindepth N)
        self._saferender_warned = False
        self._bp_hooked = False
        self._managed_bps = set()
        self.kaslr_slide = 0
        self._kb_groups = []        # regime-aware breakpoints: {loc,link,pa,pa_bp,img_addr,img_bp,img_slide}
        self._kb_bp_nums = set()    # gdb bp numbers I created (kb + adopted siblings) -- reentrancy guard
        self._in_catcher = False    # guard: arming the catcher must not recurse into adopt/kb
        self._catch_wanted = False  # a catcher is needed but could not be armed safely yet
        self._catcher_obj = None    # the internal gdb.Breakpoint backing the catcher
        self._cont_hooked = False
        self._prompt_hooked = False
        self._kaslr_pending = None  # persistent crossing catcher: {pa,bp,cr} -- applies the
                                    # slide whenever execution finally reaches the crossing
        self._kw_groups = []        # regime-aware watchpoints: same shape + {kind,size}
        self._kw_bp_nums = set()    # gdb watchpoint numbers I created
        self._adopted = set()       # user bp numbers already adopted into regime-aware candidates
        self._pending_del = set()   # sibling bps orphaned by `delete`, dropped at the next safe point
        self._in_adopt = False      # hard reentrancy guard around sibling creation
        self._in_advance = False     # inside _advance_to_crossing: suppress on_stop auto-apply
        self._armed_entry_pa = None  # where bootbreak last armed the entry break
        self._program = None         # main symbol file the cached state was derived from
        self._objfile_hooked = False
        self._autostart_pending = False  # $GDBTOOLS_AUTO stated before a kernel was loaded
        self.loaded_banner = None    # set by bootstrap; printed when AUTO arms late
        self.platform = None         # what the QEMU monitor says this machine is

    @property
    def x86_kaslr(self):
        """$GDBTOOLS_X86_KASLR: recover the decompressor-randomized physical base in
        bootbreak.  Read at use, so an invalid value is refused where it matters."""
        return bool(config.get("X86_KASLR"))

    # Behaviours that change gdb, pwndbg or the symbol table are read from the
    # GDBTOOLS_* contract at each use, so `kearly set` and every hand control below
    # take effect at once and stay in effect: nothing re-derives them behind the
    # user's back.  Each defaults to off.
    @staticmethod
    def _opt(name, default=None):
        """A stated GDBTOOLS_<name>, or `default` when unset or invalid (an invalid
        value was already reported when the package loaded)."""
        try:
            v = config.get(name)
        except config.ConfigError:
            return default
        return default if v is None else v

    def _flag(self, name):
        return bool(self._opt(name, False))

    def panels(self):
        return self._opt("PANELS", ())

    @property
    def adopt(self):
        return self._flag("ADOPT")

    @property
    def saferender(self):
        return self._opt("SAFERENDER", "off")

    @property
    def bpfix(self):
        return self._flag("BPFIX")

    # BOOT and X86_DECOMP_PA pick a route rather than toggle a feature, so an
    # invalid value is refused where it is used instead of read as unset.
    def boot(self):
        return config.get("BOOT")

    def x86_decomp_pa(self):
        """Where a direct boot loads the bzImage decompressor: stated, or 0x100000,
        the protected-mode kernel load address of the x86 boot protocol
        (Documentation/arch/x86/boot.rst), when the boot is stated as direct.  None
        for a firmware boot, whose EFI stub loads the image wherever its allocator
        chose."""
        pa = config.get("X86_DECOMP_PA")
        if pa is not None:
            return pa
        return 0x100000 if self.boot() == "direct" else None

    @safe()
    def ensure_arch(self):
        self._follow_program()
        if self.arch is None:
            self.arch = detect_arch()
        return self.arch

    def _follow_program(self):
        """Forget what was derived from a program gdb no longer debugs (`file` with
        another image): the arch, the vmlinux path and the calibration.  The old
        shadow objfile is removed by the next _shadow_load / `kearly off`."""
        try:
            main = gdb.current_progspace().filename
        except Exception:
            return
        if not main or main == self._program:
            return
        prev, self._program = self._program, main
        self.platform = None
        if prev is None:
            self.arch = None                   # may have come from gdb's default arch
            return
        self.arch = None
        self.vmlinux = None
        if self.offset is not None or self.kaslr_slide or self.entry_pa is not None:
            self.offset, self.kaslr_slide, self.entry_pa = None, 0, None
            self._entry_recovered = self._entry_pinned = False
            self._kaslr_pending = None
            print("[%s] gdb now debugs %s; the calibration made for %s is cleared"
                  % (NAME, main, prev))

    def try_autostart(self):
        """Arm the session if a kernel image is loaded; False when there is none yet."""
        a = self.ensure_arch()
        if a is None or not self.looks_like_kernel():
            return False
        self._autostart_pending = False
        self.enable()
        self.load_overrides()
        LOG.add("autostarted for arch=%s" % a.key)
        return True

    @safe(boundary="hook")
    def _on_new_objfile(self, _evt):
        # $GDBTOOLS_AUTO stated before gdb loaded the program (an init-file install
        # runs before command-line files are read): arm once the kernel appears.
        if self._autostart_pending and not self.enabled and self.try_autostart():
            if self.loaded_banner:
                print(self.loaded_banner)

    _EVENTS = (("stop", "on_stop"), ("breakpoint_created", "_on_bp_created"),
               ("breakpoint_deleted", "_on_bp_deleted"), ("before_prompt", "_on_prompt"),
               ("cont", "_on_cont"), ("new_objfile", "_on_new_objfile"))
    _NOT_CARRIED = frozenset(("arch", "enabled", "_hooked", "_bp_hooked", "_prompt_hooked",
                              "_cont_hooked", "_objfile_hooked", "_catcher_obj"))

    def _adopt(self, prevs):
        """Take over from sessions an earlier load left connected: detach every
        handler they registered, carry the live one's state over, and re-arm."""
        live = next((p for p in prevs if getattr(p, "enabled", False)), prevs[-1])
        was_enabled = bool(getattr(live, "enabled", False))
        for p in prevs:
            for event, attr in self._EVENTS:
                cb, registry = getattr(p, attr, None), getattr(gdb.events, event, None)
                if cb is not None and registry is not None:
                    try:
                        registry.disconnect(cb)
                    except Exception:
                        pass
            p.enabled = False
        mine = vars(self)
        for k, v in vars(live).items():
            if k in mine and k not in self._NOT_CARRIED:
                mine[k] = v
        key = getattr(getattr(live, "arch", None), "key", None)
        self.arch = next((c() for c in ARCHES if c.key == key), None) if key else None
        pend = self._kaslr_pending
        if pend and pend.get("obj") is not None:
            # The internal catcher calls back into the old session: replace it.
            try:
                pend["obj"].delete()
            except Exception:
                pass
            self._kaslr_pending = None
            self._catch_wanted = not self.kaslr_slide
        if was_enabled:
            self.enable()

    @safe()
    def load_overrides(self):
        """Rebuild the anchor and break kind from what is stated now, low -> high:
        the preset, the JSON profile, then GDBTOOLS_ANCHOR / GDBTOOLS_BREAK_KIND.
        Rebuilt from nothing each time, so a value no longer stated stops applying."""
        name = config.get("PRESET")
        p = PRESETS.get(name) if name else None
        if p is not None and self.preset != name and not p["verified"]:
            print("[%s] preset '%s' is designed, not lab-verified" % (NAME, name))
        self.preset = name if p is not None else None
        self.anchor = p["anchor"] if p is not None else None
        self.break_kind = p["break_kind"] if p is not None else None
        pa = TARGET.anchor()
        if pa:
            self.anchor = pa
        pbk = TARGET.break_kind()
        if pbk:
            self.break_kind = pbk
        an = config.get("ANCHOR")
        if an:
            self.anchor = an
        bk = config.get("BREAK_KIND")
        if bk:
            self.break_kind = bk

    @safe(default=False)
    def apply_preset(self, name):
        """`kearly preset NAME`: state it for the session and rebuild from it."""
        p = PRESETS.get(name)
        if p is None:
            print("[%s] unknown preset '%s' (kearly preset list)" % (NAME, name))
            return False
        a = self.ensure_arch()
        if a is not None and p["arch"] != a.key:
            print("[%s] note: preset '%s' is for %s, target is %s"
                  % (NAME, name, p["arch"], a.key))
        config.set_session("PRESET", name)
        self.preset = name
        self.load_overrides()
        print("[%s] preset '%s'%s: anchor=%s break=%s -- %s" %
              (NAME, name, "" if p["verified"] else " (designed, not lab-verified)",
               self.current_anchor() or "<image-base>", self.current_break_kind(), p["desc"]))
        return True

    def current_anchor(self):
        a = self.arch
        return self.anchor or (a.entry_symbol if a else None)

    def current_break_kind(self):
        """Stated (session, environment, profile, preset), else `hw` for a firmware
        boot -- the firmware copies the image to its load address after reset, over
        any software breakpoint planted while the guest was frozen -- else the
        arch's own default."""
        if self.break_kind:
            return self.break_kind
        if self.boot() in ("uboot", "uefi"):
            return "hw"
        a = self.arch
        return getattr(a, "entry_break_kind", "hw") if a else "hw"

    @safe(default=False)
    def force_arch(self, key):
        if key in ("auto", "-", "reset"):
            self.arch = None
            self.ensure_arch()               # re-detect NOW so status/shadow stay correct
            print("[%s] arch detection reset to auto (-> %s)" %
                  (NAME, self.arch.key if self.arch else "?"))
            return True
        for cls in ARCHES:
            if cls.key == key or key in cls.aliases:
                self.arch = cls()
                print("[%s] arch forced to %s" % (NAME, cls.key))
                return True
        print("[%s] unknown arch '%s' (try x86_64 | arm64 | riscv64 | auto)" % (NAME, key))
        return False

    @safe(default=None)
    def vmlinux_path(self):
        self._follow_program()
        if self.vmlinux:
            return self.vmlinux
        fallback = None
        for o in gdb.objfiles():
            fn = getattr(o, "filename", None)
            if not fn:
                continue
            if os.path.basename(fn) == "vmlinux":
                self.vmlinux = fn
                return fn
            if fallback is None:
                fallback = fn
        self.vmlinux = fallback
        return fallback

    def looks_like_kernel(self):
        vm = self.vmlinux_path()
        if vm and os.path.basename(vm) == "vmlinux":
            return True
        return symval("_stext") is not None

    # --- stop hook ---
    @safe(boundary="hook")
    def on_stop(self, _evt):
        if not self.enabled:
            return
        if self.ensure_arch() is None:
            return
        self.check_platform()
        self._maybe_warn_saferender()
        m = self.which_map()
        self._sync_early_quiet(m)
        if self.offset is None and m == "physical":
            # Auto-calibrate ONLY when stopped exactly at the kernel entry PA.
            # QEMU's reset vector / boot stub / OpenSBI / real-mode entry are
            # also "physical" but are NOT the kernel entry, so calibrating there
            # would be wrong.  Use `kearly bootbreak` to reach the entry first.
            pc = reg("pc")
            if pc is not None and pc in (self.entry_cpu_pa(), self._armed_entry_pa):
                self.calibrate(quiet=True)
        elif self.offset is None and m in ("virtual", "idmap"):
            # Running kernel (post-MMU): resolve_entry's physical Image-magic scan
            # + entry_symbol yields PA-VA in any regime, so calibrate here too --
            # then the KASLR auto-apply below makes symbols work on a plain attach.
            self.calibrate(quiet=True)
        self._refresh_shadow()
        self._service_catch_wanted()
        # If a previous `kearly kaslr auto` was beaten to the crossing by one of the
        # user's own breakpoints/watchpoints, it left a persistent catcher there.  This
        # is the stop where it may finally have fired -- read the slide and apply it.
        self._service_crossing_catcher()
        if m != self.last_map:
            LOG.add("map transition: %s -> %s" % (self.last_map, m))
            if self.last_map is not None:
                self._announce_transition(self.last_map, m)
            self.last_map = m
            self._apply_bpfix()
        elif self.verbose:
            self._annotate(m)
        # The moment the kernel runs relocated (MMU on, high VA) and the slide is
        # readable, auto-apply it -- so symbols / `b` / `kb` target the running
        # kernel with no manual `kearly kaslr auto`.  One-shot (guarded on
        # kaslr_slide == 0); apply_kaslr re-arms kb groups itself.
        if m == "virtual" and self.kaslr_slide == 0 and self.offset is not None \
                and not self._in_advance and self._opt("KASLR_APPLY") == "auto":
            _s = self.detect_kaslr_slide() or self._slide_via_pc_pa()
            if _s:
                self.apply_kaslr(_s)
        # Otherwise, once relocated, still correct any kb IMG armed before the slide.
        # (Suppressed while _advance_to_crossing drives its own controlled stops.)
        if self._kb_groups and m == "virtual" and self.offset is not None \
                and not self._in_advance:
            self._rearm_kb()
        if self._kw_groups and m == "virtual" and self.offset is not None \
                and not self._in_advance:
            self._rearm_kw()
        # When the pwndbg context section is installed it renders the badge+sysregs
        # itself, so skip the standalone line to avoid duplication.
        if self.show_sysregs and not self._section_installed:
            self._sysreg_line()
        self._hint_unreadable_pc()

    @safe()
    def _hint_unreadable_pc(self):
        """Say that `kx` exists when $pc cannot be read through the live tables.

        riscv reaches its high map by trapping: `csrw satp` makes the very next fetch
        fault, and QEMU stops on that faulting fetch -- so $pc holds a physical value
        that the new mapping does not translate, and gdb's `x` answers "Cannot access
        memory".  The state is real and cannot be avoided, but without a pointer the
        user has no way to know there is another way to look at it."""
        a = self.arch
        pc = reg("pc")
        if a is None or pc is None or a._is_va(pc):
            return
        st, _ = self.mmu_state()
        if st != "on":
            return                       # MMU off: a physical pc reads fine
        # Ask the question the user's own command asks.  The target can still serve
        # these bytes -- gdb's Python read_memory returns them -- but `x` translates
        # through the live tables and refuses when the address is not mapped there,
        # which is exactly the riscv trap-boundary case.  On arm64/x86 idmap stops
        # VA==PA, so `x` works and this stays silent.
        probe = execstr("x/1xb $pc")
        if probe and "Cannot access" not in probe:
            return                       # `x` works here -- nothing to say
        if probe is None:
            # execstr swallows the MemoryError and hands back None, which IS the
            # failure signal; treat it the same as the printed message.
            pass
        print("[%s] note: $pc %s is physical and translation is on, so `x` cannot read "
              "it.  Use `kx/16xb $pc` (physical examine) or `cfgdis` here." % (NAME, fmt(pc)))

    @safe()
    def _sysreg_line(self):
        """The compact per-stop line of MMU state + the key sysregs pwndbg's
        register panel does not show (PSTATE/EL/SCTLR/TTBR on arm64, etc.).
        Reads only cheaply-exposed registers so single-stepping stays fast;
        `ksregs` does the full (monitor-backed) dump on demand."""
        a = self.arch
        if a is None:
            return
        summ = a.context_summary(self)
        if summ:
            print("[%s] %s" % (NAME, summ))
        if self.census_mode != "off":
            for ln in self.census_lines(full=(self.census_mode == "full")):
                print("  " + ln)

    @safe(boundary="hook")
    def _on_prompt(self):
        self._service_catch_wanted()

    @safe(boundary="hook")
    def _on_cont(self, _evt=None):
        """Resume is the last safe moment before the guest runs again, and unlike a gdb
        prompt it happens in a scripted -ex session too.  Without this, a `watch SYM`
        (whose catcher must be deferred -- building a breakpoint inside gdb's
        watchpoint-creation path kills gdb) never got a catcher at all when one had not
        already been armed by calibration, and the probe silently missed."""
        self._service_catch_wanted()
        self._drain_pending_del()
        # Page mappings change under us between stops -- a cached "mapped" verdict
        # from the previous stop would be a lie.
        SAFEPROBE.flush()

    @safe()
    def _announce_transition(self, prev, now):
        """Make the MMU on/off switch visible so the user knows the addressing
        regime changed (and that VA symbolization is now native)."""
        pc = reg("pc")
        st, src = self.mmu_state()
        if prev == "physical" and now == "virtual":
            print("[%s] >>> MMU ON: $pc now VIRTUAL %s -- native kernel symbolization "
                  "active%s. kp2v/kv2p still valid."
                  % (NAME, fmt(pc), "; shadow kept for residual physical pointers (page "
                     "tables/DMA)" if self.shadow_addr is not None else ""))
        elif prev == "virtual" and now == "physical":
            print("[%s] <<< back to PHYSICAL %s (MMU %s) -- %s."
                  % (NAME, fmt(pc), st, "shadow symbolization in use" if self.shadow_addr
                     is not None else "no shadow symbols loaded"))
        else:
            self._annotate(now, prefix="transition")

    @safe()
    def _annotate(self, m, prefix=None):
        pc = reg("pc")
        if pc is None:
            return
        res = self.symbolize(pc)
        sym = res[2] if res else None
        head = "[%s%s]" % (NAME, "/" + prefix if prefix else "")
        if m == "physical":
            st, _src = self.mmu_state()
            tag = ("MMU off" if st == "off"
                   else "idmap/low-map" if st == "on" else "MMU state unknown")
            print("%s pc=%s PHYS -> va=%s %s (%s)" %
                  (head, fmt(pc), fmt(self.p2v(pc)) if self.offset else "?",
                   sym or "<no sym>", tag))
        else:
            print("%s pc=%s VA  %s (kernel map, MMU on)" % (head, fmt(pc), sym or "<no sym>"))

    @safe()
    def enable(self):
        if not self._hooked:
            gdb.events.stop.connect(self.on_stop)
            self._hooked = True
        self.enabled = True
        if not self._bp_hooked:
            try:
                gdb.events.breakpoint_created.connect(self._on_bp_created)
                gdb.events.breakpoint_deleted.connect(self._on_bp_deleted)
                self._bp_hooked = True
            except Exception:
                LOG.add("breakpoint events unavailable; bpfix off")
        # A gdb prompt is a safe place to create a breakpoint, unlike the create/delete
        # callbacks -- this is what picks up a catcher deferred from a `watch` command.
        if not self._prompt_hooked:
            try:
                gdb.events.before_prompt.connect(self._on_prompt)
                self._prompt_hooked = True
            except Exception:
                LOG.add("before_prompt event unavailable")
        if not self._cont_hooked:
            try:
                gdb.events.cont.connect(self._on_cont)
                self._cont_hooked = True
            except Exception:
                LOG.add("cont event unavailable")
        # After the hooks: a refused setting must not leave the session half-armed.
        self.apply_settings()
        self.check_platform()

    @staticmethod
    def _connection():
        """Which target connection the platform answer belongs to, so a reconnect
        (to another machine, perhaps) asks again."""
        try:
            c = gdb.selected_inferior().connection
            return (c.num, c.details) if c is not None else None
        except Exception:
            return None

    @safe(default=None)
    def check_platform(self):
        """Ask QEMU which machine this is, and use the default machine's facts only
        if it is that machine.  Asked once per target connection and again after
        the program changes; a different machine, or no QEMU monitor, is said once,
        and then only what the guest reports itself -- or GDBTOOLS_PROFILE /
        GDBTOOLS_DTB -- describes the board."""
        a = self.ensure_arch()
        if a is None:
            return None
        preset = QEMU_PRESETS.get(a.key)
        conn = self._connection()
        if self.platform is None or self.platform.get("conn") != conn:
            # No target yet (an init-file load arms the session before
            # `target remote`): nothing can answer, so ask again at the first stop.
            try:
                live = bool(gdb.selected_inferior().threads())
            except Exception:
                live = False
            if not live:
                TARGET.qemu_preset = None
                return None
            out = execstr("monitor qom-get /machine type") or ""
            m = re.search(r'"([A-Za-z0-9_.+-]+?)-machine"', out)
            machine = m.group(1) if m else None
            self.platform = {"machine": machine, "conn": conn, "qemu": machine is not None,
                             "family": re.sub(r"-\d+(\.\d+)*$", "", machine) if machine else None}
            LOG.add("platform: %r" % (self.platform,))
            ok = preset is not None and self.platform["family"] in preset["family"]
            if not ok and not (self._opt("PROFILE") or self._opt("DTB")):
                if self.platform["qemu"]:
                    print("[%s] QEMU machine '%s' is not the default (%s), so its preset is not "
                          "applied; only what the guest reports describes it.  State "
                          "GDBTOOLS_PROFILE or GDBTOOLS_DTB for this board."
                          % (NAME, machine,
                             "/".join(preset["family"]) if preset else "none for " + a.key))
                else:
                    print("[%s] the target does not answer `monitor qom-get /machine type`, so "
                          "the default QEMU machine is not assumed%s.  State GDBTOOLS_PROFILE "
                          "or GDBTOOLS_DTB to describe the board."
                          % (NAME, "" if SAFEPROBE.mode == "off" else " and safemem cannot judge reads"))
        self.platform["ok"] = preset is not None and self.platform["family"] in preset["family"]
        TARGET.qemu_preset = preset if self.platform["ok"] else None
        return self.platform

    @safe()
    def apply_settings(self, name=None):
        """Bring gdb and pwndbg in line with the stated behaviours -- all of them, or
        only `name` after `kearly set`.  Each is off unless stated:
          SAFEMEM        pwndbg probes a page-aligned address to guess its permissions;
                         one that lands on a device model crashes QEMU's debug-read path,
                         so the guard asks QEMU whether the page is RAM first
          PWNDBG_GUARDS  pwndbg's krelease() throws on the early start_kernel banner and
                         takes the whole context with it; the guards turn that into None
          PANELS         the kgdb badge, the flow arrows, the msysreg window
          EXPLORE_PAGES  `off` silences pwndbg's page-scan warnings at every stop
          SAFERENDER     arm64: pwndbg's emulated disassembly can SIGABRT gdb
          STEPLOCK       scheduler-locking while stepping"""
        if not self.enabled:
            return
        if name in (None, "SAFEMEM"):
            SAFEPROBE.mode = self._opt("SAFEMEM", "off")
            if SAFEPROBE.mode != "off":
                SAFEPROBE.install()
            else:
                SAFEPROBE.uninstall()
        if name in (None, "PWNDBG_GUARDS"):
            if self._flag("PWNDBG_GUARDS"):
                install_kernel_guards()
            else:
                uninstall_kernel_guards()
        if name in (None, "PANELS"):
            want = self.panels()
            for key, add, drop in (
                    ("kgdb", self._install_pwndbg_section, self._remove_pwndbg_section),
                    ("flow", self._install_kdisasm_section, self._remove_kdisasm_section),
                    ("msysreg", self._install_msysreg_section, self._remove_msysreg_section)):
                (add if key in want else drop)()
        if name in (None, "EXPLORE_PAGES"):
            if self._opt("EXPLORE_PAGES") == "off":
                self._quiet_pagescan()
            else:
                self._param_restore("auto-explore-pages")
        if name in (None, "SAFERENDER"):
            if self.saferender in ("on", "auto"):
                self._saferender_warned = False
                self._maybe_warn_saferender()
            elif self.saferender == "off":
                self._param_restore("emulate")
            else:
                self._maybe_warn_saferender()
        if name in (None, "STEPLOCK"):
            st = self._opt("STEPLOCK", "off")
            if st != self.steplock:
                self.steplock = st
                self._sync_early_quiet(self.which_map())
        if name == "SHADOW":
            if self._flag("SHADOW"):
                self._refresh_shadow()
            else:
                self._shadow_unload()
        if name == "BPFIX" and not self.bpfix:
            for n in list(self._managed_bps):
                execstr("enable %d" % n)
            self._managed_bps.clear()
        if name == "CROSSING":
            if not self._flag("CROSSING"):
                self._retire_catcher("CROSSING off")
            elif self.offset is not None and not self.kaslr_slide:
                self._ensure_crossing_catcher("CROSSING", use_python=True)

    @safe()
    def disable(self):
        self.enabled = False
        self._restore_early_quiet("kearly off")
        self._param_restore("emulate")
        self._param_restore("auto-explore-pages")
        if self._hooked:
            try:
                gdb.events.stop.disconnect(self.on_stop)
            except Exception:
                pass
            self._hooked = False
        if self._bp_hooked:
            for _ev, _cb in ((gdb.events.breakpoint_created, self._on_bp_created),
                             (gdb.events.breakpoint_deleted, self._on_bp_deleted)):
                try:
                    _ev.disconnect(_cb)
                except Exception:
                    pass
            self._bp_hooked = False
        if self._prompt_hooked:
            try:
                gdb.events.before_prompt.disconnect(self._on_prompt)
            except Exception:
                pass
            self._prompt_hooked = False
        if self._cont_hooked:
            try:
                gdb.events.cont.disconnect(self._on_cont)
            except Exception:
                pass
            self._cont_hooked = False
        self._catch_wanted = False
        for _n in list(self._managed_bps):
            try:
                execstr("enable %d" % _n)
            except Exception:
                pass
        self._managed_bps.clear()
        self._remove_pwndbg_section()
        self._remove_kdisasm_section()
        self._remove_msysreg_section()
        self._shadow_unload()
        if SAFEPROBE.mode != "on":
            SAFEPROBE.uninstall()
        uninstall_kernel_guards()


def _previous_sessions():
    """Sessions an earlier load of this package left behind in this gdb."""
    prev = getattr(gdb, "_gdbtools_session", None)
    if prev is not None:
        return [prev]
    if getattr(gdb, "_gdbtools_command_names", None) is None:
        return []                              # the first load in this gdb
    import gc                                  # a load that predates the attribute
    return [o for o in gc.get_objects()
            if type(o).__name__ == "Session" and type(o).__module__ == __name__]


# Re-sourcing builds this module afresh; the previous Session's handlers are
# detached and its state carried over, so a re-source neither doubles every hook
# nor drops the calibration.
_PREV = _previous_sessions()
SESSION = Session()
if _PREV:
    SESSION._adopt(_PREV)
gdb._gdbtools_session = SESSION
state.set_session(SESSION)
try:
    gdb.events.new_objfile.connect(SESSION._on_new_objfile)
    SESSION._objfile_hooked = True
except Exception:
    LOG.add("new_objfile event unavailable")
