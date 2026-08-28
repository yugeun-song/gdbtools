"""part of gdbtools; see the package docstring."""
import json
import struct
import gdb
import os
import re
from ..common.runtime import *
from .physmem import *
from .pwndbg_glue import PWN, SAFEPROBE, context_kgdb, context_flow
from .target import TARGET
from ..common.arch import ARCHES, detect_arch, _arch_name
from .presets import PRESETS
from ..common import state
from ..common import cfgdis as _kdismod


# ----------------------------------------------------------------------------
# Session: holds calibration + shadow state, the stop hook, and the API the
# commands call.  Single instance, fully degrade-safe.
# ----------------------------------------------------------------------------
class Session:
    def __init__(self):
        self.arch = None
        self.offset = None          # PA - VA (mod 2^64)
        self.entry_pa = None        # resolved kernel entry physical address (cached)
        self._entry_recovered = False  # entry_pa came from x86 decompressor recovery
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
        self._census_dead = set()   # census regs the stub cannot expose (skip, fast)
        self.chain_hops = 8         # safe_chain telescope depth (kearly chaindepth N)
        self.saferender = "auto"
        self._saferender_warned = False
        self.bpfix = False
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
        self.adopt = True           # auto-upgrade a plain `b SYM` to PA(S)+IMG(S) candidates
        self._pending_del = set()   # sibling bps orphaned by `delete`, dropped at the next safe point
        self._in_adopt = False      # hard reentrancy guard around sibling creation
        self._in_advance = False     # inside _advance_to_crossing: suppress on_stop auto-apply
        self.x86_kaslr = bool(_env("X86_KASLR"))  # x86 cold-frozen: recover the
                                    # decompressor-randomized physical base in bootbreak

    @safe()
    def ensure_arch(self):
        if self.arch is None:
            self.arch = detect_arch()
        return self.arch

    @safe()
    def load_overrides(self):
        """Apply overrides idempotently in precedence order (low -> high):
        preset -> JSON profile (anchor/break) -> explicit env flags.  So an
        explicit --anchor wins over the profile, which wins over the preset."""
        p = _env("PRESET")
        if p and self.preset != p:
            self.apply_preset(p, quiet=True)
        pa = TARGET.anchor()
        if pa:
            self.anchor = pa
        pbk = TARGET.break_kind()
        if pbk in ("sw", "hw"):
            self.break_kind = pbk
        an = _env("ANCHOR")
        if an:
            self.anchor = an
        bk = _env("BREAK_KIND")
        if bk in ("sw", "hw"):
            self.break_kind = bk

    @safe(default=False)
    def apply_preset(self, name, quiet=False):
        p = PRESETS.get(name)
        if p is None:
            if not quiet:
                print("[%s] unknown preset '%s' (kearly preset list)" % (NAME, name))
            return False
        a = self.ensure_arch()
        if a is not None and p["arch"] != a.key and not quiet:
            print("[%s] note: preset '%s' is for %s, target is %s"
                  % (NAME, name, p["arch"], a.key))
        self.preset = name
        self.anchor = p["anchor"]
        self.break_kind = p["break_kind"]
        if not quiet:
            print("[%s] preset '%s'%s: anchor=%s break=%s -- %s" %
                  (NAME, name, "" if p["verified"] else " (designed, not lab-verified)",
                   self.anchor or "<image-base>", self.break_kind or "<arch-default>", p["desc"]))
        return True

    def current_anchor(self):
        a = self.arch
        return self.anchor or (a.entry_symbol if a else None)

    def current_break_kind(self):
        a = self.arch
        return self.break_kind or (getattr(a, "entry_break_kind", "hw") if a else "hw")

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
        if on:
            if self.offset is None:
                print("[%s] no offset yet -- run kearly bootbreak / calibrate / offset <hex>" % NAME)
                return
            self._shadow_load()
            print("[%s] shadow loaded at %s" % (NAME, fmt(self.shadow_addr)))
        else:
            self._shadow_unload()
            print("[%s] shadow removed" % NAME)

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
    def resolve_entry(self):
        """Physical address of the kernel IMAGE BASE (entry_symbol: _text/_start/
        startup_64).  Sources, high -> low: $GDBTOOLS_ENTRY_PA -> JSON profile
        entry_pa -> QEMU 'info roms' -> Image-magic scan over the supplied RAM
        ranges.  None when none of them answered; there is no hint to fall back
        on, because a hint that is wrong produces a calibrated-looking session in
        which every address is silently off.  Cached."""
        if self.entry_pa is not None:
            return self.entry_pa
        ovr = _env_int("ENTRY_PA")
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

    @safe(default=None)
    def vmlinux_path(self):
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

    def _compressed_vmlinux(self):
        """Path to the x86 COMPRESSED kernel (arch/x86/boot/compressed/vmlinux), used
        to recover the decompressor-randomized physical base under x86 KASLR.

        Handed in through $GDBTOOLS_X86_DECOMP_VMLINUX.  It is not derived from the
        loaded vmlinux: where that file sits relative to the build tree is a fact
        about the caller's tree layout, not about the kernel, and guessing it means
        silently analysing the wrong binary when the guess is close but wrong."""
        return _env("X86_DECOMP_VMLINUX")

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

    @safe(default="")
    def regime_phrase(self):
        """The current regime in a few words, for commands that must refuse.

        A command that assumes one side of the VA/PA divide should not just fail
        when it is run on the other side -- and above all must not answer anyway.
        Every refusal in this tool says the same three things: what the command
        assumed, what is actually true HERE, and what to use instead.  This
        supplies the middle part so the wording is identical everywhere."""
        st, _src = self.mmu_state()
        m = self.which_map()
        if m == "virtual":
            return "MMU on, running in the kernel high map"
        if st == "on":
            return "MMU on but execution is still identity-mapped (VA==PA)"
        return "MMU off, so addresses here are PHYSICAL"

    # --- translation ---
    def p2v(self, pa):
        # offset is PA - LINK va.  Once the KASLR slide is applied the kernel actually
        # runs at link+slide, so the virtual address a physical one corresponds to is
        # shifted by the slide as well -- without this kp2v handed back link addresses
        # that the running kernel never uses (and kv2p turned a live VA into a wrong PA).
        if self.offset is None or pa is None:
            return None
        return (pa - self.offset + self.kaslr_slide) & MASK

    def v2p(self, va):
        if self.offset is None or va is None:
            return None
        return (va - self.kaslr_slide + self.offset) & MASK

    @safe(default=None)
    def info_symbol(self, va):
        out = execstr("info symbol 0x%x" % (va & MASK)).strip()
        if not out or "No symbol matches" in out:
            return None
        return out

    @safe(default=None)
    def symbolize(self, addr):
        """(kind, addr, symbol_text|None) with kind in {"VA", "PA", "ADDR"}, or None.

        "ADDR" means no phys<->virt map has been established, so the address is
        reported exactly as given and looked up in gdb's own symbol table.  That
        is the normal state for a userspace target and for a kernel before
        `kearly calibrate`, and it has to be distinct from "PA": `_is_va` is a
        bit test (bit 63 on x86_64, the top twelve on arm64), so without a map
        every userspace address would otherwise come back labelled physical, and
        the callers that print that label would state it as fact."""
        if addr is None:
            return None
        a = self.ensure_arch()
        if a is not None:
            if a._is_va(addr):
                return ("VA", addr, self.info_symbol(addr))
            if self.offset is not None:
                va = self.p2v(addr)
                if va is None:
                    return ("PA", addr, None)
                return ("PA", va, self.info_symbol(va))
        return ("ADDR", addr, self.info_symbol(addr))

    # --- regime-aware breakpoints (kb): PA(S) + IMG(S), no whitelist ---------
    @safe(default=None)
    def _link_va(self, resolved):
        """Recover the vmlinux LINK VA of a location from whatever `&sym`/eval
        currently returns -- robust to the phys shadow AND to an applied KASLR
        slide.  A high VA is link+slide -> strip the applied slide; a low/physical
        address is the shadow's (link+offset) -> strip offset."""
        a = self.ensure_arch()
        if resolved is None:
            return None
        if a is not None and a._is_va(resolved):
            return (resolved - self.kaslr_slide) & MASK
        if self.offset is None:
            return None
        return (resolved - self.offset) & MASK

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

    @safe(default=None)
    def _loc_resolve(self, loc):
        """Resolve a kb location (SYMBOL | *ADDR | FILE:LINE) to whatever address
        gdb currently holds for it (may be a VA or, under the shadow, a PA)."""
        loc = (loc or "").strip()
        if not loc:
            return None
        if loc.startswith("*"):
            return evi(loc[1:].strip())
        if ":" in loc and not loc.lower().startswith("0x"):
            out = execstr("info line %s" % loc)
            m = re.search(r"address\s+(0x[0-9a-fA-F]+)", out or "")
            return int(m.group(1), 16) & MASK if m else None
        v = evi("(unsigned long long)&%s" % loc)
        if v is None:
            v = evi("(unsigned long long)%s" % loc)
        return None if v is None else (v & MASK)

    @safe()
    def kb(self, loc, sides="both", link=None):
        """Regime-aware kernel breakpoint.  Arm the location at BOTH its invariant
        physical address PA(S)=linkVA+offset and its runtime kernel VA
        IMG(S)=linkVA+slide, as hardware breakpoints.  Whichever regime executes
        the code, the matching one fires; the other never matches.  No whitelist:
        PA(S) is arithmetic and HW breakpoints need no live mapping."""
        a = self.ensure_arch()
        if a is None:
            print("[%s] kb: no supported arch on this target" % NAME)
            return
        if self.offset is None:
            self.calibrate(quiet=True)
        # A caller that already HAS the link address passes it directly.  Resolving it
        # again would be wrong once a slide is applied: _link_va treats a bare address as
        # a RUNTIME one and subtracts the slide, so a link address handed back through
        # that path comes out shifted by -slide.  `kearly regimes` hit exactly this when
        # invoked after the kernel had already relocated.
        if link is None:
            resolved = self._loc_resolve(loc)
            if resolved is None:
                print("[%s] kb: cannot resolve '%s'  (kb SYMBOL | kb *ADDR | kb FILE:LINE)"
                      % (NAME, (loc or "").strip()))
                return
            link = self._link_va(resolved)
        if link is None or self.offset is None:
            print("[%s] kb: uncalibrated -- run `kearly calibrate` (or bootbreak) first" % NAME)
            return
        pa = (link + self.offset) & MASK
        img = (link + self.kaslr_slide) & MASK

        def _arm(addr):
            out = exec_confirmless("hbreak *0x%x" % addr)
            mm = re.search(r"[Bb]reakpoint\s+(\d+)", out or "")
            return mm.group(1) if mm else None

        # `sides` lets a caller that already KNOWS which regime the target runs in
        # arm one location instead of two.  `kearly regimes walk` uses it: head.S
        # code only ever executes physically and start_kernel only ever virtually,
        # so arming both would burn twice the hardware slots for locations that can
        # never match.  Default stays "both" -- plain `kb` cannot know.
        pa_bp = _arm(pa) if sides in ("both", "pa") else None
        img_bp = _arm(img) if (sides in ("both", "img") and img != pa) else None
        self._kb_bp_nums.update(int(x) for x in (pa_bp, img_bp) if x)
        self._kb_groups.append({"loc": (loc or "").strip(), "link": link,
                                "pa": pa, "pa_bp": pa_bp,
                                "img_addr": img, "img_bp": img_bp,
                                "img_slide": self.kaslr_slide, "sides": sides})
        if self.kaslr_slide == 0 and a._is_va(link):
            self._ensure_crossing_catcher("kb '%s'" % (loc or "").strip())
        print("[%s] kb '%s'  linkVA=%s" % (NAME, (loc or "").strip(), fmt(link)))
        print("        HW bp @ %s  PA  MMU-off/idmap  (head.S, pi/, secondary, cpu_resume)%s"
              % (fmt(pa), ("  [bp %s]" % pa_bp) if pa_bp else ""))
        if img_bp:
            print("        HW bp @ %s  IMG high kernel map (start_kernel & steady state)  [bp %s]"
                  % (fmt(img), img_bp))
        if self.kaslr_slide == 0:
            print("        (IMG auto-re-arms to linkVA+slide the moment the KASLR slide is known)")

    @safe()
    def _rearm_kb(self, slide=None):
        """Move each kb group's IMG (high-VA) location to linkVA + the now-known
        KASLR slide.  Called when a slide is applied (apply_kaslr) and from the
        stop hook once the kernel is running relocated (m == 'virtual').  This
        closes the only gap in `kb`: an IMG armed early (slide unknown -> 0) sits
        at the link VA, which the relocated kernel never executes; here it is
        corrected the moment the slide becomes observable.  PA locations are
        slide-invariant and never need this."""
        if not self._kb_groups:
            return
        if slide is None:
            slide = self.kaslr_slide or (self.detect_kaslr_slide() or 0)
        for g in self._kb_groups:
            # A group deliberately armed PA-only names code that never executes from
            # the high map, so giving it an IMG twin at the crossing would occupy a
            # hardware slot that can never match.  `kearly regimes walk` arms three
            # such groups; without this it ended up holding eight breakpoints for
            # five stop points.
            if g.get("sides") == "pa":
                continue
            if g.get("img_slide") == slide:
                continue
            new_img = (g["link"] + slide) & MASK
            if new_img == g.get("img_addr") and g.get("img_bp"):
                g["img_slide"] = slide
                continue
            if g.get("img_bp"):
                self._kb_bp_nums.discard(int(g["img_bp"]))
                exec_confirmless("delete %s" % g["img_bp"])
            out = exec_confirmless("hbreak *0x%x" % new_img)
            mm = re.search(r"[Bb]reakpoint\s+(\d+)", out or "")
            g["img_bp"] = mm.group(1) if mm else None
            if g["img_bp"]:
                self._kb_bp_nums.add(int(g["img_bp"]))
            g["img_addr"] = new_img
            g["img_slide"] = slide
            LOG.add("kb re-arm: '%s' IMG -> %s (slide %s)" % (g["loc"], fmt(new_img), fmt(slide)))

    _KW_CTYPE = {1: "unsigned char", 2: "unsigned short",
                 4: "unsigned int", 8: "unsigned long long"}

    @safe()
    def kw(self, spec):
        """Regime-aware kernel WATCHPOINT -- the data-side twin of `kb`.

        A kernel global is touched through its PHYSICAL address while the MMU is
        off / running on the idmap (head.S writes to __bss, kernel_map, boot args,
        the page tables it is building), and through its runtime kernel VA
        linkVA+slide once the high map is live.  gdb's own `watch SYM` only ever
        covers whichever single address the symbol resolves to right now, so it
        goes blind on the other side of the MMU crossing.  `kw` arms BOTH, exactly
        like `kb`, and re-points the VA side the moment the KASLR slide is known."""
        toks = (spec or "").split()
        kind = "watch"
        while toks and toks[0] in ("-r", "-a", "-w", "r", "a", "w", "read", "access", "write"):
            t = toks.pop(0).lstrip("-")
            kind = {"r": "rwatch", "read": "rwatch",
                    "a": "awatch", "access": "awatch"}.get(t, "watch")
        loc = " ".join(toks).strip()
        a = self.ensure_arch()
        if a is None:
            print("[%s] kw: no supported arch on this target" % NAME)
            return
        if self.offset is None:
            self.calibrate(quiet=True)
        if not loc:
            print("[%s] kw: usage -- kw [-r|-a] SYMBOL | kw [-r|-a] *ADDR [SIZE]" % NAME)
            return
        size = None
        if len(toks) > 1:
            v = evi(toks[-1])
            if v in (1, 2, 4, 8):
                size = v
                loc = " ".join(toks[:-1]).strip()
        resolved = self._loc_resolve(loc)
        if resolved is None:
            print("[%s] kw: cannot resolve '%s'  (kw SYMBOL | kw *ADDR [SIZE])" % (NAME, loc))
            return
        link = self._link_va(resolved)
        if link is None or self.offset is None:
            print("[%s] kw: uncalibrated -- run `kearly calibrate` (or bootbreak) first" % NAME)
            return
        if size is None:
            size = evi("sizeof(%s)" % loc) if not loc.startswith("*") else None
            if size not in (1, 2, 4, 8):
                size = 8            # unknown/aggregate: watch the first machine word
        ctype = self._KW_CTYPE[size]
        pa = (link + self.offset) & MASK
        img = (link + self.kaslr_slide) & MASK

        def _arm(addr):
            out = exec_confirmless("%s *(%s *)0x%x" % (kind, ctype, addr))
            mm = re.search(r"atchpoint\s+(\d+)", out or "")
            if not mm:
                LOG.add("kw: could not arm %s at %s: %s" % (kind, fmt(addr), (out or "").strip()))
            return mm.group(1) if mm else None

        pa_bp = _arm(pa)
        img_bp = _arm(img) if img != pa else None
        self._kw_bp_nums.update(int(x) for x in (pa_bp, img_bp) if x)
        self._kw_groups.append({"loc": loc, "link": link, "kind": kind, "size": size,
                                "pa": pa, "pa_bp": pa_bp,
                                "img_addr": img, "img_bp": img_bp,
                                "img_slide": self.kaslr_slide})
        if self.kaslr_slide == 0 and a._is_va(link):
            self._ensure_crossing_catcher("kw '%s'" % loc)
        print("[%s] kw '%s'  linkVA=%s  %s  %d-byte" % (NAME, loc, fmt(link), kind, size))
        print("        %s @ %s  PA  MMU-off/idmap  (head.S data writes, page tables)%s"
              % (kind, fmt(pa), ("  [wp %s]" % pa_bp) if pa_bp else ""))
        if img_bp:
            print("        %s @ %s  IMG high kernel map (start_kernel & steady state)  [wp %s]"
                  % (kind, fmt(img), img_bp))
        if not pa_bp and not img_bp:
            print("        (nothing armed -- the target may be out of hardware watchpoint slots;"
                  " `delete` some and retry, or watch fewer bytes)")
        elif self.kaslr_slide == 0:
            print("        (IMG auto-re-arms to linkVA+slide the moment the KASLR slide is known)")

    @safe()
    def _rearm_kw(self, slide=None):
        """Move each kw group's IMG (high-VA) watchpoint to linkVA + the now-known
        KASLR slide -- the watchpoint counterpart of _rearm_kb.  PA locations are
        slide-invariant and never move."""
        if not self._kw_groups:
            return
        if slide is None:
            slide = self.kaslr_slide or (self.detect_kaslr_slide() or 0)
        for g in self._kw_groups:
            if g.get("img_slide") == slide:
                continue
            new_img = (g["link"] + slide) & MASK
            if new_img == g.get("img_addr") and g.get("img_bp"):
                g["img_slide"] = slide
                continue
            if g.get("img_bp"):
                self._kw_bp_nums.discard(int(g["img_bp"]))
                exec_confirmless("delete %s" % g["img_bp"])
            out = exec_confirmless("%s *(%s *)0x%x"
                                   % (g["kind"], self._KW_CTYPE[g["size"]], new_img))
            mm = re.search(r"atchpoint\s+(\d+)", out or "")
            g["img_bp"] = mm.group(1) if mm else None
            if g["img_bp"]:
                self._kw_bp_nums.add(int(g["img_bp"]))
            g["img_addr"] = new_img
            g["img_slide"] = slide
            LOG.add("kw re-arm: '%s' IMG -> %s (slide %s)" % (g["loc"], fmt(new_img), fmt(slide)))

    @safe(default="unknown")
    def which_map(self):
        a = self.ensure_arch()
        if a is None:
            return "unknown"
        v = a.pc_is_virtual()
        return "unknown" if v is None else ("virtual" if v else "physical")

    @safe(default=("unknown", "?"))
    def mmu_state(self):
        """(state, source) where state in {'on','off','unknown'}.
        pc being a VA is conclusive (translation is on).  Otherwise consult the
        arch control register (SCTLR_EL1.M / satp.MODE / x86 paging).  pc physical
        + register unreadable == the pre-MMU head.S case -> reported 'off' but
        labelled 'inferred' so the basis is honest."""
        a = self.ensure_arch()
        if a is None:
            return ("unknown", "no-arch")
        if a.pc_is_virtual():
            return ("on", "pc=VA")
        on = a.mmu_translation_on()
        if on is True:
            return ("on", "ctrl-reg")        # reg says on, pc still in idmap/low map
        if on is False:
            return ("off", "ctrl-reg")
        return ("off", "inferred(pc=PHYS)")

    @safe(default=("addressing: ?", "unknown"))
    def state_badge(self):
        """(text, kind) one-glance badge with THREE early-boot regimes:
          PHYS  -- pre-MMU, pc physical, translation off;
          IDMAP -- MMU on but pc still a low addr where VA==PA (the identity map,
                   e.g. idmap_cpu_replace_ttbr1 swapping TTBR1);
          VIRT  -- running in the kernel high (TTBR1) map.
        Colored when pwndbg is present."""
        m = self.which_map()
        st, _src = self.mmu_state()
        if m == "virtual":
            txt = PWN.color("light_green", "VIRT") or "VIRT"
            return ("%s addressing  (MMU on)" % txt, "virtual")
        if m == "physical":
            if st == "on":
                txt = PWN.color("light_yellow", "IDMAP") or "IDMAP"
                return ("%s  VA==PA identity map  (MMU on)" % txt, "idmap")
            txt = PWN.color("light_red", "PHYS") or "PHYS"
            return ("%s addressing  (MMU off)" % txt, "physical")
        return ("addressing=%s  (MMU %s)" % (m, st), m)

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
        tag = "  (KASLR 비활성화)" if disabled else ""
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

    # regime id -> (label, is_physical)
    _REGIME_ORDER = (("entry",    "kernel entry, MMU off, PC physical",        True),
                     ("mmuon",    "translation turned on, PC still physical",  True),
                     ("crossing", "the phys->high-VA transfer instruction",    True),
                     ("virtual",  "first instruction at a true high VA",       False),
                     ("start",    "start_kernel, steady state",                False))

    @safe(default=[])
    def regime_map(self):
        """This build's early-boot MMU stop points, each located by scanning the
        running image rather than by any per-version constant.

        Answering "where does the MMU actually come on in THIS kernel?" used to mean
        leaving gdb, disassembling vmlinux by hand and counting offsets.  Every piece
        was already computed inside the tool -- find_crossing for the transfer,
        resolve_entry for the entry -- and find_mmu_enable adds the one that was
        missing.  Returns a list of dicts: id, label, link, pa, phys, desc."""
        a = self.ensure_arch()
        if a is None or self.offset is None:
            return []
        rows, seen = [], {}
        ent = self.link_entry_va()
        if ent is not None:
            seen["entry"] = {"link": ent, "pa": (ent + self.offset) & MASK,
                             "desc": a.entry_symbol or "entry"}
        me = a.find_mmu_enable(self)
        if me:
            seen["mmuon"] = {"link": me.get("link"), "pa": me.get("pa"), "desc": me.get("desc", "")}
        cr = a.find_crossing(self)
        if cr:
            pa = cr.get("pa")
            # find_crossing returns whatever anchor the KASLR machinery can read the
            # slide at, which is not always the transfer instruction itself: on riscv
            # it is the entry of relocate_enable_mmu, while the actual phys->virt
            # transfer is the `csrw satp` that find_mmu_enable located.  When the
            # anchor names no landing, the satp write is the truthful answer for both
            # roles, and the dedupe below folds them into one row.
            if cr.get("target_link") is None and me and me.get("pa") is not None:
                pa = me["pa"]
                seen["mmuon"]["desc"] += "  -- also the phys->virt transfer on this arch"
            seen["crossing"] = {"link": (pa - self.offset) & MASK if pa is not None else None,
                                "pa": pa, "desc": cr.get("desc", "")}
            tl = cr.get("target_link")
            if tl is None and me:
                # riscv reaches its high map by trapping: `csrw satp` makes the NEXT
                # fetch fault, and stvec was pre-loaded with that instruction's virtual
                # address.  There is no landing symbol to name, and a probe on the
                # landing itself stops on the faulting fetch with a still-physical pc,
                # so the first instruction observable with a virtual pc is one further on.
                tl = (me.get("link") + 8) & MASK if me.get("link") is not None else None
                land = "stvec trap landing"
            else:
                land = cr.get("land") or "?"
            if tl is not None:
                seen["virtual"] = {"link": tl, "pa": (tl + self.offset) & MASK,
                                   "desc": "landing of the transfer (%s)" % land}
        sk = self._link_va(symval("start_kernel"))
        if sk is not None:
            seen["start"] = {"link": sk, "pa": (sk + self.offset) & MASK, "desc": "start_kernel"}
        used = set()
        for rid, label, phys in self._REGIME_ORDER:
            r = seen.get(rid)
            if not r or r.get("link") is None:
                continue
            # On riscv the translation-enable write and the phys->virt transfer are the
            # SAME instruction, so the two ids collapse; listing it twice would imply a
            # stop that does not exist.
            if r["link"] in used:
                continue
            used.add(r["link"])
            r.update({"id": rid, "label": label, "phys": phys})
            rows.append(r)
        return rows

    @safe()
    def regimes(self, sub=None, name=None):
        """`kearly regimes [walk | stop NAME]`."""
        if self.offset is None:
            self.calibrate(quiet=True)
        rows = self.regime_map()
        if not rows:
            print("[%s] regimes: uncalibrated, or this arch exposes no early-boot anchors "
                  "-- try `kearly bootbreak` first" % NAME)
            return
        sub = (sub or "").lower()

        if sub in ("", "list", "show"):
            print("[%s] early-boot MMU regimes for this build" % NAME)
            for r in rows:
                print("  %-9s %-18s link %s  PA %s"
                      % (r["id"], "PHYS" if r["phys"] else "VIRT",
                         fmt(r["link"]), fmt(r["pa"])))
                print("            %s  -- %s" % (r["label"], r["desc"]))
            print("  (`kearly regimes walk` arms them all; `kearly regimes stop <id>` runs to one)")
            return

        if sub == "walk":
            for r in rows:
                # One side only: head.S code never executes from the high map and
                # start_kernel never from the physical one, so arming both twins
                # would double the hardware-slot cost for locations that can never
                # match.  The IMG side re-arms itself at the crossing as usual.
                self.kb("%s (%s)" % (r["id"], r["label"]), link=r["link"],
                        sides=("pa" if r["phys"] else "img"))
            print("[%s] %d regimes armed -- plain `continue` now steps through the "
                  "MMU transition in order" % (NAME, len(rows)))
            return

        if sub == "stop":
            want = (name or "").lower()
            r = next((x for x in rows if x["id"] == want), None)
            if r is None:
                print("[%s] regimes: no regime '%s'  (have: %s)"
                      % (NAME, name, ", ".join(x["id"] for x in rows)))
                return
            self.kb("%s (%s)" % (r["id"], r["label"]), link=r["link"],
                    sides=("pa" if r["phys"] else "img"))
            print("[%s] running to '%s' (%s)..." % (NAME, r["id"], r["label"]))
            exec_confirmless("continue")
            return

        print("[%s] usage: kearly regimes [walk | stop <%s>]"
              % (NAME, "|".join(x["id"] for x in rows)))

    @safe(default="unknown")
    def boot_phase(self):
        """Where the machine is along the early-boot path, as a short phrase.
        Derived from $pc against the entry PA and the MMU state -- the same
        comparison bootbreak makes, lifted out so both can use it."""
        pc = reg("pc")
        a = self.ensure_arch()
        if pc is None or a is None:
            return "unknown"
        if a._is_va(pc):
            return "virtual addressing is up (past the phys->high-VA switch)"
        entry = self.resolve_entry()
        st, _ = self.mmu_state()
        if entry is None:
            return "physical, entry PA not resolved yet"
        if pc < entry:
            return "before the kernel entry -- still in reset vector / firmware / decompressor"
        if pc == entry:
            return "exactly at the kernel entry"
        return "past the kernel entry, still physical (MMU %s)" % st

    @safe(default=[])
    def where_lines(self):
        """`kearly where` -- one command that answers "what is my situation?".

        Every value here is already computed at each stop and rendered into the
        pwndbg panel; what was missing was a way to ASK for it.  Without this,
        orienting yourself cost four separate commands (`kearly status`,
        `kearly mmu`, `sym $pc`, `kearly kaslr status`).

        Strictly read-only: it never writes a register, arms a probe, or resumes
        the CPU, so it is safe to type at any point in any regime."""
        a = self.ensure_arch()
        if a is None:
            return ["[%s] no supported architecture on this target" % NAME]
        label, _kind = self.state_badge()
        st, src = self.mmu_state()
        pc = reg("pc")
        out = ["%s   [%s]" % (label, src)]
        if pc is not None:
            sy = self.symbolize(pc)
            sym = (sy[2] or "?") if sy else "?"
            out.append("  pc       %s  %s" % (fmt(pc), sym.split(" of ")[0]))
            other = self.p2v(pc) if not a._is_va(pc) else self.v2p(pc)
            if other is not None:
                out.append("  twin     %s  (%s)"
                           % (fmt(other), "virtual" if not a._is_va(pc) else "physical"))
        out.append("  offset   %s%s"
                   % (fmt(self.offset) if self.offset is not None else "(uncalibrated)",
                      "   shadow @%s" % fmt(self.shadow_addr) if self.shadow_addr is not None else ""))
        out.append("  KASLR    %s" % self._kaslr_field())
        out.append("  phase    %s" % self.boot_phase())
        out.append("  next     %s" % self._where_suggestion())
        return out

    @safe(default="nothing -- you are live")
    def _where_suggestion(self):
        """The one command that most likely moves this session forward from here."""
        a = self.ensure_arch()
        pc = reg("pc")
        if a is None:
            return "kearly arch <key>   (auto-detect found no supported arch)"
        if self.offset is None:
            return "kearly bootbreak    (reach the kernel entry and calibrate)"
        entry = self.resolve_entry()
        if pc is not None and entry is not None and not a._is_va(pc) and pc < entry:
            return "kearly bootbreak    (still before the kernel entry)"
        if pc is not None and not a._is_va(pc):
            return ("kearly regimes      (list this build's MMU stop points), or "
                    "kearly overmmu to cross now")
        return "nothing -- virtual addressing is up; `b SYM` targets the running kernel"

    @safe(default=[])
    def kgdb_context_lines(self):
        """Lines for the pwndbg 'kgdb' context section: the PHYS/VIRT+MMU badge,
        then the key sysregs styled like the REGISTERS panel (name colored, value
        as a pwndbg dereference chain).  Empty unless we are enabled on a kernel."""
        a = self.ensure_arch()
        if a is None or not self.enabled:
            return []
        label, _kind = self.state_badge()
        off = fmt(self.offset) if self.offset is not None else "(uncalibrated)"
        lines = ["%s   offset(PA-VA)=%s   KASLR=%s" % (label, off, self._kaslr_field())]
        for nm in a.inline_sysreg_names():
            v = a.sysreg(nm)
            if v is None:
                v = evi("$" + nm)
            nmc = PWN.color("cyan", nm) or nm
            if v is None:
                lines.append(" %s  ?" % nmc)
            else:
                lines.append(" %s  %s" % (nmc, a.render_sysreg(nm, v)))
        lines += self.twin_register_lines()
        if self.census_mode != "off":
            lines += self.census_lines(full=(self.census_mode == "full"))
        return lines

    # --- cross-regime register twins (tool's own panel; pwndbg REGISTERS untouched) ---
    # Registers that carry a flags/status word, not an address -- excluded from the twin
    # scan so a value like cpsr=0x800003c5 (the N flag set) is not mistaken for a pointer.
    _FLAG_REGS = frozenset((
        "cpsr", "pstate", "spsr", "spsr_el1", "daif", "nzcv", "fpsr", "fpcr",
        "eflags", "rflags", "mxcsr", "cct_status",
    ))

    @safe(default=[])
    def _gp_registers(self):
        """(name, value) for the target's general-purpose integer registers, read via
        gdb's own register groups so this stays arch-neutral."""
        out = []
        try:
            frame = gdb.selected_frame()
            march = frame.architecture()
            for r in march.registers("general"):
                try:
                    out.append((r.name, int(frame.read_register(r)) & MASK))
                except Exception:
                    continue
        except Exception:
            pass
        return out

    def _pa_plausible(self, pa):
        a = self.arch
        if a is None or pa is None:
            return False
        w = a.eff_phys_window()
        return bool(w and w[0] <= pa <= w[1])

    @safe(default=[])
    def twin_register_lines(self):
        """Show, in the tool's OWN panel, the PHYSICAL twin of any register that holds a
        kernel VIRTUAL address while we are stopped in a PHYSICAL regime -- WITHOUT touching
        pwndbg's native REGISTERS view.

        This is the plasma/crossing case the user asked for: at the phys->virt transfer
        (arm64 `br x8`), x8 = __primary_switched, a VA that is not reachable yet because the
        high map is not active on this core.  We print the address that IS reachable now --
        its physical twin (kv2p) -- so it is actionable.  Only the VA->PA direction is done:
        `_is_va` (top bits all-ones) is an unambiguous test, so a control/ID register that
        merely holds a large value is never mistaken for a pointer.  At a virtual stop the
        addresses are already virtual-correct, so this stays empty and adds no clutter.
        Only twins landing inside the phys window are shown, so a mid-flux KASLR slide never
        prints a bogus address."""
        a = self.ensure_arch()
        if a is None or self.offset is None:
            return []
        if self.which_map() == "virtual":        # VAs are reachable here -> no twin needed
            return []
        hits = []
        for name, val in self._gp_registers():
            if not val or name.lower() in self._FLAG_REGS:
                continue                         # a flags/status word is not an address
            if not a._is_va(val):                # only a VA has an unreachable-here twin
                continue
            pa = self.v2p(val)
            if self._pa_plausible(pa):
                hits.append("%-4s %s%s  ->  PA %s" % (name, fmt(val), self._sym_suffix(val), fmt(pa)))
            if len(hits) >= 8:
                break
        if not hits:
            return []
        head = PWN.color("blue", "cross-regime regs (VA -> reachable PA twin):") \
            or "cross-regime regs (VA -> reachable PA twin):"
        return [" " + head] + ["   " + h for h in hits]

    # --- early-boot register census rendering ---------------------------
    @safe(default=[])
    def census_lines(self, full=False):
        """Lines for the head.S register census.  compact: per category, a dense
        NAME=value row of the currently-readable registers.  full: one annotated
        row per register (acc / value / decode / purpose) -- the `kcensus` view."""
        a = self.ensure_arch()
        if a is None or not getattr(a, "census", ()):
            return []
        groups, order = {}, []
        for name, acc, cat, purpose in a.census:
            if cat not in groups:
                groups[cat] = []
                order.append(cat)
            groups[cat].append((name, acc, purpose))
        lines = []
        for cat in order:
            hdr = PWN.color("blue", cat) or cat
            if full:
                lines.append(hdr)
                for name, acc, purpose in groups[cat]:
                    v = a.sysreg(name)
                    if v is None:
                        v = evi("$" + name)
                    if v is None:
                        val, dec = "?", ""
                    else:
                        val = "0x%x" % v
                        dec = a.decode_sysreg(name, v) or ""
                    nmc = PWN.color("cyan", "%-18s" % name) or ("%-18s" % name)
                    lines.append("  %s %-3s %-20s %s" %
                                 (nmc, acc, val, dec if dec else purpose))
            else:
                parts = []
                for name, acc, _purpose in groups[cat]:
                    if name in self._census_dead:
                        continue
                    v = a.census_read(name)
                    if v is None:
                        self._census_dead.add(name)      # skip next time (fast)
                        continue
                    nmc = PWN.color("cyan", name) or name
                    parts.append("%s=0x%x" % (nmc, v & MASK))
                if parts:
                    lines.append(" %-16s %s" % (cat + ":", "  ".join(parts)))
        if not full and not any(l.strip() for l in lines):
            lines = [" (no census registers currently exposed by the stub)"]
        return lines

    # --- hardware page-table walk rendering -----------------------------
    def _sym_suffix(self, addr):
        """(symbol) annotation for a PA/VA via the shadow, or '' if none."""
        res = self.symbolize(addr)
        if res and res[2]:
            return "  (%s)" % res[2].split(" in section")[0].strip()
        return ""

    @safe(default=None)
    def walk_lines(self, va, hexbytes=False):
        a = self.ensure_arch()
        if a is None:
            return ["[%s] no arch" % NAME]
        if not getattr(a, "pagewalk_supported", False):
            return ["[%s] page-table walk not implemented for %s" % (NAME, a.key)]
        w = a.pagewalk(va)
        if w is None:
            return ["[%s] cannot walk VA 0x%x -- page-table base unreadable, or "
                    "paging is off (MMU/satp/CR0.PG). Try after MMU-enable." %
                    (NAME, va & MASK)]
        lines = ["VA 0x%x   %s   [%s]" % (w["va"], w["regime"], w["config"]),
                 "  top-table PA 0x%x%s" % (w["base"], self._sym_suffix(w["base"]))]
        for lv in w["levels"]:
            nm, idx, ent, desc = lv["name"], lv["index"], lv["entry_pa"], lv["desc"]
            if desc is None:
                lines.append("  %-7s [%3d] @PA 0x%-10x <unreadable>" % (nm, idx, ent))
                continue
            kind = lv["kind"]
            if kind == "table":
                tail = "table -> 0x%x%s" % (lv["next_pa"], self._sym_suffix(lv["next_pa"]))
            elif kind in ("block", "page"):
                tail = "%s  %s" % (kind.upper(), lv.get("attrs", ""))
            else:
                tail = "INVALID / not-present"
            row = "  %-7s [%3d] @PA 0x%-10x desc=0x%016x  %s" % (nm, idx, ent, desc, tail)
            if hexbytes:
                row += "   [%s]" % " ".join("%02x" % c for c in struct.pack("<Q", desc & MASK))
            lines.append(row)
        if w["leaf_pa"] is not None:
            lines.append("  => LEAF PA 0x%x%s" % (w["leaf_pa"], self._sym_suffix(w["leaf_pa"])))
            if self.offset is not None:
                exp = self.v2p(va)
                if exp is not None and getattr(a, "_is_va", None) and a._is_va(va):
                    lines.append("     (kv2p(VA)=0x%x  %s)" %
                                 (exp, "MATCH" if exp == w["leaf_pa"] else
                                  "differs: image-window guess vs real HW walk"))
        else:
            lines.append("  => NOT MAPPED (no valid leaf descriptor)")
        return lines

    @safe(default=None)
    def pgd_dump_lines(self, va=None, table_pa=None, maxrows=80):
        a = self.ensure_arch()
        if a is None or not getattr(a, "pagewalk_supported", False):
            return ["[%s] unsupported" % NAME]
        regime = "table"
        if table_pa is None:
            probe = va if va is not None else reg("pc")
            rb = a.pt_base(probe if probe is not None else 0)
            if rb is None:
                return ["[%s] cannot read the page-table base (paging off / stub)" % NAME]
            regime, table_pa = rb
        cfg = getattr(a, "_ptcfg", {}) or {}
        top_shift = cfg.get("top_shift", 39)
        nlevels = cfg.get("nlevels", 4)
        words = read_phys_words(table_pa, 512)
        if not words:
            return ["[%s] cannot read table @0x%x (physical read failed)" % (NAME, table_pa)]
        lvl0 = a.pt_levels()[0] if a.pt_levels() else "L0"
        lines = ["top table %s @PA 0x%x   regime %s   (non-zero of 512 entries)" %
                 (lvl0, table_pa, regime)]
        shown = 0
        for i, d in enumerate(words):
            if not d:
                continue
            if shown >= maxrows:
                lines.append("  ... (stopped at %d rows; raise with 'kpgd <addr> <n>')" % maxrows)
                break
            kind, nxt, leaf, attrs = a.pt_decode(d, 0, top_shift, nlevels)
            out = nxt if kind == "table" else (leaf if leaf is not None else 0)
            lines.append("  [%3d] 0x%016x  %-7s -> 0x%-10x%s %s" %
                         (i, d, kind, out or 0, self._sym_suffix(out or 0), attrs or ""))
            shown += 1
        if shown == 0:
            lines.append("  (all 512 entries are zero / not-present)")
        return lines

    @safe(default=None)
    def pt_hex_lines(self, va=None, table_pa=None, count=None, full=False):
        a = self.ensure_arch()
        if a is None or not getattr(a, "pagewalk_supported", False):
            return ["[%s] unsupported" % NAME]
        regime = "table"
        if table_pa is None:
            probe = va if va is not None else reg("pc")
            rb = a.pt_base(probe if probe is not None else 0)
            if rb is None:
                return ["[%s] cannot read the page-table base (paging off / stub)" % NAME]
            regime, table_pa = rb
        cfg = getattr(a, "_ptcfg", {}) or {}
        top_shift = cfg.get("top_shift", 39)
        nlevels = cfg.get("nlevels", 4)
        words = read_phys_words(table_pa, 512)
        if not words:
            return ["[%s] cannot read table @0x%x (physical read failed)" % (NAME, table_pa)]
        lines = ["page-table page @PA 0x%x   regime %s   little-endian, as stored in RAM" %
                 (table_pa, regime)]
        if full:
            blob = b"".join(struct.pack("<Q", w & MASK) for w in words)
            for off in range(0, len(blob), 16):
                ch = blob[off:off + 16]
                hx = " ".join("%02x" % c for c in ch)
                asc = "".join(chr(c) if 32 <= c < 127 else "." for c in ch)
                lines.append("  +0x%03x  %-47s  |%s|" % (off, hx, asc))
            return lines
        maxrows = count if (count and count > 0) else 64
        lines.append("   idx  @PA           b0 b1 b2 b3 b4 b5 b6 b7   value (LE)          decode")
        shown = 0
        for i, d in enumerate(words):
            if not d:
                continue
            if shown >= maxrows:
                lines.append("  ... (%d-row cap; raise with 'kpthex 0x%x %d', or the whole "
                             "page with 'kpthex 0x%x full')" % (maxrows, table_pa, maxrows * 4, table_pa))
                break
            ent_pa = table_pa + i * 8
            bstr = " ".join("%02x" % c for c in struct.pack("<Q", d & MASK))
            kind, nxt, leaf, attrs = a.pt_decode(d, 0, top_shift, nlevels)
            if kind == "table":
                dec = "TABLE -> 0x%x%s" % (nxt or 0, self._sym_suffix(nxt or 0))
            elif kind in ("block", "page"):
                dec = "%s 0x%x%s %s" % (kind.upper(), leaf or 0, self._sym_suffix(leaf or 0), attrs or "")
            else:
                dec = "invalid"
            lines.append("  [%3d] 0x%-11x  %s   0x%016x   %s" % (i, ent_pa, bstr, d, dec))
            shown += 1
        if shown == 0:
            lines.append("  (all 512 entries are zero / not-present)")
        return lines

    # --- mmview / memlayout : kernel memory layout (works MMU on OR off) --
    @staticmethod
    def _hsize(n):
        for u, s in ((1 << 30, "G"), (1 << 20, "M"), (1 << 10, "K")):
            if n >= u and n % u == 0:
                return "%d%s" % (n // u, s)
        for u, s in ((1 << 30, "G"), (1 << 20, "M"), (1 << 10, "K")):
            if n >= u:
                return "%.1f%s" % (n / float(u), s)
        return "%dB" % n

    @staticmethod
    def _coalesce(leaves):
        """Merge adjacent leaf mappings with identical attrs where BOTH the VA
        and PA are contiguous (a real region), so the linear map's thousands of
        blocks collapse to a few lines."""
        out = []
        for va, pa, size, attrs, kind in leaves:
            if out:
                pv, pp, psz, pat, pk = out[-1]
                if pv + psz == va and pp + psz == pa and pat == attrs:
                    out[-1] = (pv, pp, psz + size, attrs, pk if pk == kind else "mixed")
                    continue
            out.append((va, pa, size, attrs, kind))
        return out

    @safe(default="")
    def _label_region(self, vs, ve):
        a = self.arch
        hits = []
        for sym, _desc in getattr(a, "va_landmarks", ()):
            v = symval(sym)
            if v is not None and vs <= v < ve:
                hits.append(sym)
        t, e = symval("_text"), symval("_end")
        zone = "kernel image" if (t is not None and e is not None and vs < e and ve > t) else ""
        if hits:
            tag = "{%s%s}" % (",".join(hits[:3]), "+" if len(hits) > 3 else "")
            return (zone + " " + tag) if zone else tag
        return zone

    @safe(default=None)
    def mmview_lines(self, want_idmap=True, show_all=False):
        a = self.ensure_arch()
        if a is None:
            return ["[%s] no arch" % NAME]
        st, src = self.mmu_state()
        off = fmt(self.offset) if self.offset is not None else "(uncalibrated)"
        lines = ["mmview -- kernel memory layout   [MMU=%s %s | %s | offset(PA-VA)=%s]"
                 % (st, src, a.key, off)]
        # (1) symbol landmarks -- always available (needs only symbols + offset),
        # so this half of the map works even pre-MMU on physical addresses.
        lm = []
        for sym, desc in getattr(a, "va_landmarks", ()):
            v = symval(sym)
            if v is None:
                continue
            pa = self.v2p(v) if self.offset is not None else None
            lm.append((sym, v, pa, desc))
        if lm:
            lines.append("")
            lines.append("kernel image / key symbols  (VA -> PA):")
            for sym, v, pa, desc in lm:
                lines.append("  %-17s 0x%016x  %-16s %s" %
                             (sym, v, ("-> PA 0x%x" % pa) if pa is not None else "-> PA ?", desc))
        # (2) live mappings if paging is on; otherwise the physical placement.
        if st == "on" and getattr(a, "pagewalk_supported", False):
            cap = 400
            for label, repva, prefix in (a.pt_dump_roots() or []):
                is_idmap = ("idmap" in label.lower()) or ("ttbr0" in label.lower())
                if is_idmap and not want_idmap:
                    continue
                rb = a.pt_base(repva)
                if rb is None:
                    continue
                _, base = rb
                regions = self._coalesce(a.enumerate_regions(base, prefix))
                total = len(regions)
                hidden = 0
                # a unified root (x86 CR3 / riscv satp) also maps the current user
                # process; hide the user half by default so mmview is the KERNEL map.
                if not show_all and not is_idmap:
                    floor = a.kernel_va_floor()
                    kept = [r for r in regions if r[0] >= floor]
                    hidden = total - len(kept)
                    regions = kept
                lines.append("")
                lines.append("live mappings: %s  root@PA 0x%x   (%d%s regions)   [%s]"
                             % (label, base, len(regions),
                                "/%d" % total if hidden else "", a.pt_config_desc()))
                if hidden:
                    lines.append("  (%d user/low-half regions hidden -- 'mmview all' to include)"
                                 % hidden)
                if not regions:
                    lines.append("  (root present but no kernel-space leaf mappings)")
                shown = 0
                for vs, pa, size, attrs, kind in regions:
                    if shown >= cap:
                        lines.append("  ... (%d more regions; narrow with kpt <VA> / kpgd)"
                                     % (len(regions) - shown))
                        break
                    ve = (vs + size) & MASK
                    lines.append("  0x%016x-0x%016x %6s -> 0x%-11x %-5s %-22s %s" %
                                 (vs, (vs + size - 1) & MASK, self._hsize(size), pa,
                                  kind, attrs, self._label_region(vs, ve)))
                    shown += 1
        else:
            lines.append("")
            lines.append("live VA mappings: NONE yet -- MMU is %s (paging not active)." % st)
            lines.append("  -> showing PHYSICAL placement; re-run mmview after MMU-enable")
            lines.append("     ('kearly overmmu', or step past 'msr sctlr_el1') for live tables.")
            t, e = symval("_text"), symval("_end")
            if t is not None and e is not None and self.offset is not None:
                lines.append("  kernel image PA:     0x%x - 0x%x   (%s)" %
                             (self.v2p(t), self.v2p(e), self._hsize(e - t)))
            epa = self.resolve_entry()
            if epa is not None:
                lines.append("  image-base entry PA: 0x%x" % epa)
            regs = TARGET.ram_regions(a)
            if regs:
                lines.append("  RAM (DTB/profile):   " +
                             ", ".join("0x%x+0x%x" % (b, s) for b, s in regs))
        return lines

    @safe()
    def _install_pwndbg_section(self):
        """Register our context section with pwndbg AT RUNTIME (plugin-style; we do
        not edit pwndbg).  Degrade-safe: if the registry/config shape differs, we
        leave _section_installed False and the standalone per-stop line is used."""
        if not PWN.ok:
            return
        secs = getattr(PWN._ctx, "context_sections", None)
        if not isinstance(secs, dict):
            return
        # pwndbg resolves a section by the FIRST CHARACTER of its name ('kgdb'->'k').
        # Recognise OUR section by function NAME, not object identity: re-sourcing the
        # module rebinds context_kgdb to a NEW object, so an identity check would both
        # mistake our own stale section for a foreign one AND fail to refresh it.  This
        # also makes (re)install idempotent.
        existing = secs.get("k")
        if existing is not None and getattr(existing, "__name__", "") != "context_kgdb":
            return                            # 'k' taken by a different tool; use the line
        secs["k"] = context_kgdb              # (re)point to the current function object
        cfg = getattr(PWN._ctx, "config_context_sections", None)
        val = getattr(cfg, "value", None)
        if cfg is not None and isinstance(val, str):
            if "kgdb" not in val.split():
                parts = val.split()
                if "regs" in parts:
                    parts.insert(parts.index("regs") + 1, "kgdb")
                else:
                    parts.append("kgdb")
                new = " ".join(parts)
                # Assign the value DIRECTLY rather than `set context-sections`: the
                # latter fires pwndbg's validate trigger, which reverts the WHOLE
                # list to default if it contains any name without a registered
                # section (e.g. 'ghidra' when ghidra isn't loaded) -- which would
                # drop our 'kgdb' too.  Direct assignment preserves the user's list.
                try:
                    cfg.value = new
                except Exception:
                    exec_confirmless("set context-sections %s" % new)
            nv = getattr(cfg, "value", "")
            self._section_installed = isinstance(nv, str) and "kgdb" in nv.split()
        if self._section_installed:
            LOG.add("pwndbg 'kgdb' context section installed")

    @safe()
    def _remove_pwndbg_section(self):
        if not self._section_installed:
            return
        secs = getattr(PWN._ctx, "context_sections", None)
        if isinstance(secs, dict) and getattr(secs.get("k"), "__name__", "") == "context_kgdb":
            secs.pop("k", None)
        cfg = getattr(PWN._ctx, "config_context_sections", None)
        val = getattr(cfg, "value", None)
        if isinstance(val, str) and "kgdb" in val.split():
            exec_confirmless("set context-sections %s" %
                             " ".join(p for p in val.split() if p != "kgdb"))
        self._section_installed = False

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

    # --- merged disasm + branch arrows, as a pwndbg context section ---------
    # ONE window that IS pwndbg's own near-pc disassembly -- same format, colours,
    # Capstone mnemonics, and (with `set emulate on`) the emulation annotations
    # X3 => 4 / CPSR flags / taken-not-taken -- with radare2-style branch arrows
    # injected into the left margin.  We pull pwndbg's rendered lines from
    # nearpc(branch_visualization=False) (its OWN branch viz has a separate bug)
    # and prepend our gutter, aligned by address.  Crash surface is exactly
    # pwndbg's disasm's (pwndbg/Capstone cores on a few specific instructions,
    # e.g. some arm64-v4.6 spots; `set emulate off` avoids the emulate path).  If
    # pwndbg is absent we fall back to our own crash-safe gdb+python renderer.
    @safe(default=[])
    def kdisasm_context_lines(self):
        # The 'flow' window is the radare2-style BRANCH-ARROW view, rendered by our
        # OWN gdb+python disassembler (cfgdis engine) -- the visual companion shown
        # next to pwndbg's own 'disasm' section (which carries emulation / telescope
        # / flags).  Distinct on purpose: pwndbg's window = rich annotations,
        # ours = the ┌│└─ arrows.  Own renderer => proper arrows (pwndbg prints
        # branch targets as bare symbol names, which have no address to arrow to)
        # and it can never hang or crash.
        pc = reg("pc")
        if pc is None:
            return []
        arch = self.ensure_arch() or detect_arch()
        _hdr, rows = _kdismod._kdis_disasm("")            # current function, or $pc,+0x60
        if not rows:
            return []
        pci = next((i for i, r in enumerate(rows) if r[1]), None)
        if pci is None:                          # no '=>' (range disasm): match $pc
            pci = next((i for i, r in enumerate(rows) if r[0] == (pc & MASK)), 0)
        lo = max(0, pci - self.kdis_before)
        hi = min(len(rows), pci + self.kdis_after + 1)
        return _kdismod._kdis_lines(rows[lo:hi], arch, color=not _env("NO_COLOR"),
                           ascii_mode=bool(_env("KDIS_ASCII")))

    @safe()
    def _install_kdisasm_section(self):
        """Register the 'flow' context section (key 'f') and slot it in RIGHT AFTER
        pwndbg's own 'disasm' -- we KEEP pwndbg's disasm (its full emulation /
        telescope / flags) and add 'flow' (branch arrows) next to it, so BOTH
        windows always show.  Same degrade-safe, no-pwndbg-edit approach as
        _install_pwndbg_section().  ('f' is a free key; pwndbg's built-ins occupy
        a/r/d/s/b/c/l/e/h/t/g, we use k.)"""
        if not PWN.ok:
            return
        secs = getattr(PWN._ctx, "context_sections", None)
        if not isinstance(secs, dict):
            return
        existing = secs.get("f")
        if existing is not None and getattr(existing, "__name__", "") != "context_flow":
            return                            # 'f' taken by a different tool
        secs["f"] = context_flow
        cfg = getattr(PWN._ctx, "config_context_sections", None)
        val = getattr(cfg, "value", None)
        if cfg is not None and isinstance(val, str):
            if "flow" not in val.split():
                parts = val.split()
                if "disasm" in parts:               # KEEP pwndbg's rich disasm, add flow next to it
                    parts.insert(parts.index("disasm") + 1, "flow")
                elif "code" in parts:
                    parts.insert(parts.index("code") + 1, "flow")
                else:
                    parts.append("flow")
                new = " ".join(parts)
                try:
                    cfg.value = new           # direct: avoid pwndbg's list-reverting validator
                except Exception:
                    exec_confirmless("set context-sections %s" % new)
            nv = getattr(cfg, "value", "")
            self._kdisasm_installed = isinstance(nv, str) and "flow" in nv.split()
        if self._kdisasm_installed:
            LOG.add("pwndbg 'flow' (cfgdis) context section installed")

    @safe()
    def _remove_kdisasm_section(self):
        if not self._kdisasm_installed:
            return
        secs = getattr(PWN._ctx, "context_sections", None)
        if isinstance(secs, dict) and getattr(secs.get("f"), "__name__", "") == "context_flow":
            secs.pop("f", None)
        cfg = getattr(PWN._ctx, "config_context_sections", None)
        val = getattr(cfg, "value", None)
        if isinstance(val, str) and "flow" in val.split():
            parts = val.split()
            fi = parts.index("flow")
            if "disasm" not in parts:           # we replaced disasm -> restore it in place
                parts[fi] = "disasm"
            else:
                parts.pop(fi)
            new = " ".join(parts)
            try:
                cfg.value = new                 # direct: avoid pwndbg's list-reverting validator
            except Exception:
                exec_confirmless("set context-sections %s" % new)
        self._kdisasm_installed = False

    @safe(default=None)
    def link_entry_va(self):
        """LINK virtual address of the kernel image base (the entry symbol).

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
        v = symval(a.entry_symbol) if a.entry_symbol else None
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
            evs = self.link_entry_va()           # image-base link VA (ET_DYN/PIE-safe)
            if base is not None and evs is not None:
                off = (base - evs) & MASK
            else:
                off = a.auto_calibrate(self)     # ($pc-at-entry, or post-MMU VA) fallback
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
                # internal, delete-proof one.
                if pend.get("bp"):
                    exec_confirmless("delete %s" % pend["bp"])
                LOG.add("catcher: upgrading the CLI catcher to an internal one")
                self._kaslr_pending = None
            if not self._kaslr_pending:
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
        lo, hi = a.eff_phys_window()
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
        # x86_64 cold-frozen KASLR: the bzImage decompressor relocates the kernel to a
        # RANDOM physical base, so the nominal entry PA is wrong.  Recover the real base
        # from the decompressor (arm64/riscv return None -- fixed physical load) and pin
        # it as entry_pa, so the normal entry break below lands on the relocated kernel.
        _need_x86 = False
        if a.key == "x86_64" and _env_int("ENTRY_PA") is None:
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
                _dpa = _env_int("X86_DECOMP_PA")
                _need_x86 = (_pc is not None and _dpa is not None
                             and (_pc & MASK) < _dpa)
                if _need_x86:
                    LOG.add("x86: pc=%s below decompressor load -> auto decompressor recovery" % fmt(_pc))
        if _need_x86:
            _b = a.recover_kaslr_base(self)
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
                self.entry_pa = _b               # overwrite the nominal (auto-cached) PA
                self._entry_recovered = True     # _b is the ELF entry PA, not image base
                print("[%s] x86 KASLR: recovered main-kernel phys base %s via the "
                      "decompressor; breaking there." % (NAME, fmt(_b)))
            else:
                print("[%s] x86 KASLR: decompressor recovery unavailable (compressed "
                      "vmlinux missing?); trying nominal entry -- pass --entry-pa if it misses."
                      % NAME)
        base = self.resolve_entry()              # image base (_text load address) PA
        # x86_64: $GDBTOOLS_ENTRY_PA / info-roms report the IMAGE BASE (where the
        # loader places _text), but the CPU enters at the ELF entry point,
        # startup_64.  Older kernels emit startup_64 at _text, so the two coincide;
        # newer ones place it in .init.text, well above _text, and a break at the
        # image base is never reached.  Shift the base to the entry by its link
        # offset from _text (a build constant, read from vmlinux, so a rebuild that
        # moves startup_64 needs no reconfiguration).  Skipped when the base was
        # RECOVERED (that value is already the ELF entry PA) and a no-op on
        # arm64/riscv, whose load address IS the entry symbol.
        if a.key == "x86_64" and base is not None and not self._entry_recovered:
            _e, _t = symval(a.entry_symbol), symval("_text")
            if _e is not None and _t is not None and _e != _t:
                base = (base + (_e - _t)) & MASK
                self.entry_pa = base
        anchor = self.current_anchor()
        # break target PA = entry_PA + (&anchor - &entry_symbol)
        break_pa = base
        if base is not None and anchor and a.entry_symbol and anchor != a.entry_symbol:
            d, e = symval(anchor), symval(a.entry_symbol)
            if d is not None and e is not None:
                break_pa = (base + (d - e)) & MASK
            else:
                print("[%s] anchor '%s' not in vmlinux; using image base" % (NAME, anchor))
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
        if self.arch is None or self.offset is None:
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

    # --- stop hook ---
    @safe()
    def on_stop(self, _evt):
        if not self.enabled:
            return
        if self.ensure_arch() is None:
            return
        self._maybe_warn_saferender()
        m = self.which_map()
        self._sync_early_quiet(m)
        if self.offset is None and m == "physical":
            # Auto-calibrate ONLY when stopped exactly at the kernel entry PA.
            # QEMU's reset vector / boot stub / OpenSBI / real-mode entry are
            # also "physical" but are NOT the kernel entry, so calibrating there
            # would be wrong.  Use `kearly bootbreak` to reach the entry first.
            pc = reg("pc")
            epa = self.resolve_entry()
            if pc is not None and epa is not None and pc == epa:
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
                and not self._in_advance:
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

    @safe()
    def set_census(self, mode):
        mode = (mode or "").lower()
        aliases = {"on": "compact", "c": "compact", "1": "compact",
                   "full": "full", "all": "full", "f": "full",
                   "off": "off", "0": "off", "no": "off"}
        mode = aliases.get(mode, mode)
        if mode not in ("off", "compact", "full"):
            print("usage: kearly census <off|compact|full>  "
                  "(compact = dense per-category row; full = annotated dump)")
            return
        self.census_mode = mode
        self._census_dead.clear()          # re-probe exposure on the next stop
        a = self.ensure_arch()
        n = len(getattr(a, "census", ())) if a else 0
        print("[%s] census panel = %s  (%d early-boot registers tracked for %s; "
              "full annotated dump: kcensus)" % (NAME, mode, n, a.key if a else "?"))

    @safe()
    def set_chain_hops(self, val):
        """Set the telescope depth used by every safe_chain render (the panel's
        TTBR/VBAR/ELR/SP telescopes, ksregs, chain)."""
        try:
            n = int(str(val), 0)
        except Exception:
            print("usage: kearly chaindepth <N>   (telescope hop depth, current=%d)"
                  % self.chain_hops)
            return
        self.chain_hops = max(1, min(n, 256))
        print("[%s] telescope depth = %d hops  (safe_chain: bounded, cycle-guarded; "
              "applies to the panel TTBR/addr telescopes, ksregs, chain)"
              % (NAME, self.chain_hops))

    @safe(default=None)
    def _emulate_state(self):
        if not getattr(PWN, "ok", False):
            return None
        try:
            v = gdb.parameter("emulate")
        except Exception:
            return None
        if isinstance(v, bool):
            return v
        if v is None:
            return False
        return str(v).strip().lower() not in ("off", "0", "false", "none", "no", "disabled", "")

    @safe(default=False)
    def _pwndbg_emulates(self):
        return self._emulate_state() is True

    @safe()
    def set_saferender(self, mode):
        mode = (mode or "").lower()
        if mode in ("", "status"):
            st = self._emulate_state()
            cur = "n/a (pwndbg absent)" if st is None else ("on" if st else "off")
            print("[%s] saferender=%s   pwndbg emulate=%s" % (NAME, self.saferender, cur))
            return
        if mode not in ("warn", "on", "off", "auto"):
            print("usage: kearly saferender <warn|on|off|auto|status>   (on/auto turn "
                  "pwndbg's emulated disasm OFF -- it SIGABRTs gdb on some arm64 instructions; "
                  "off restores it; warn only prints a heads-up)")
            return
        self.saferender = mode
        if mode in ("on", "auto"):
            if "emulate" in self._saved_params:
                print("[%s] saferender=%s  (pwndbg emulate already guarded)" % (NAME, mode))
            elif self._pwndbg_emulates():
                self._param_set("emulate", "off")
                LOG.add("saferender: pwndbg emulate -> off")
                print("[%s] saferender=%s: pwndbg 'emulate' OFF for this session (guards the "
                      "arm64 emulated-disasm SIGABRT; restored on 'kearly off' / 'saferender off')."
                      % (NAME, mode))
            else:
                print("[%s] saferender=%s  (pwndbg emulate already off / pwndbg absent -- nothing to do)"
                      % (NAME, mode))
        elif mode == "off":
            self._param_restore("emulate")
            print("[%s] saferender=off  (pwndbg emulate restored to its previous value)" % NAME)
        else:
            print("[%s] saferender=warn  (no pwndbg setting changed; warns once on arm64)" % NAME)

    @safe()
    def _maybe_warn_saferender(self):
        if self._saferender_warned:
            return
        a = self.ensure_arch()
        if a is None or a.key != "arm64" or not self._pwndbg_emulates():
            return
        self._saferender_warned = True
        if self.saferender in ("on", "auto"):
            if "emulate" not in self._saved_params:
                self._param_set("emulate", "off")
                LOG.add("saferender: pwndbg emulate -> off (auto, arm64)")
                print("[%s] saferender=%s: pwndbg 'emulate' OFF (arm64 disasm crash guard; "
                      "restored on 'kearly off')." % (NAME, self.saferender))
            return
        print("[%s] heads-up (arm64): pwndbg's emulated disasm (Unicorn) can SIGABRT gdb on "
              "some instructions -- notably early secondary-CPU stops on the v4.6 tree. If gdb "
              "core-dumps on a stop, run 'kearly saferender on' (or 'set emulate off') and "
              "re-continue.  pwndbg/Unicorn bug, not the stub." % NAME)

    @safe(default="virtual")
    def _addr_regime(self, addr):
        a = self.arch
        if a is not None and hasattr(a, "_is_va"):
            r = a._is_va(addr)
            if r is True:
                return "virtual"
            if r is False:
                return "physical"
        return "virtual" if (addr >> 48) == 0xffff else "physical"

    @safe(default=None)
    def _bp_locations(self, num):
        """Addresses gdb has actually resolved for breakpoint `num`.

        gdb prints two different shapes.  A multi-location breakpoint gets an
        indented sub-row per location (`3.1  y  0x...`); a single-location one gets
        only the header row (`2  breakpoint  keep y  0x...`).  Parsing just the
        sub-rows made this return [] for every single-location probe, which in turn
        made _adopt_plain_bp bail out before it could add the physical sibling -- so
        `b *0xLINKVA` was armed at a byte the relocated kernel never executes.  Both
        shapes are recognised now.  Watchpoints have no address column and so still
        yield nothing, which is what the callers want.
        """
        out = execstr("info breakpoints %d" % num)
        locs = []
        for line in (out or "").splitlines():
            m = re.match(r"\s*(%d\.\d+)\s+(y|n)\s+(0x[0-9a-fA-F]+)" % num, line)
            if m:
                locs.append((m.group(1), int(m.group(3), 16), m.group(2) == "y"))
                continue
            m = re.match(r"\s*(%d)\s+(?:\S+\s+)+?(?:keep|del|dis)\s+(y|n)\s+(0x[0-9a-fA-F]+)"
                         % num, line)
            if m:
                locs.append((m.group(1), int(m.group(3), 16), m.group(2) == "y"))
        return locs

    @safe()
    def _apply_bpfix(self, num=None):
        if not self.bpfix or self.arch is None:
            return
        mmu_on = (self.which_map() == "virtual")
        for n in ([num] if num is not None else list(self._managed_bps)):
            locs = self._bp_locations(n) or []
            regs = set(self._addr_regime(a) for _, a, _ in locs)
            if len(locs) < 2 or not ({"virtual", "physical"} <= regs):
                continue
            self._managed_bps.add(n)
            for locstr, addr, en in locs:
                if self._addr_regime(addr) != "physical":
                    if not en:
                        execstr("enable %s" % locstr)
                    continue
                if mmu_on and en:
                    execstr("disable %s" % locstr)
                elif not mmu_on and not en:
                    execstr("enable %s" % locstr)

    @safe()
    def _on_bp_created(self, bp):
        n = getattr(bp, "number", None)
        if n is None:
            return
        self._apply_bpfix(n)
        self._adopt_plain_bp(bp, n)
        self._maybe_catch_for(bp, n)
        # Called from here, not from _maybe_catch_for: that returns early once the slide
        # is known, which left the "you typed a link address" note unreachable in exactly
        # the case where it is most useful.
        self._warn_unslid_literal(bp, n)

    @safe(default=False)
    def _link_in_image(self, link):
        """True when `link` is a LINK-time address inside the kernel image, i.e.
        between _text/_stext and _end.  Slide-independent: both ends go through
        _link_va, so it reads the same before and after relocation."""
        lo = next((self._link_va(symval(s)) for s in ("_text", "_stext", "startup_64")
                   if symval(s) is not None), None)
        hi = self._link_va(symval("_end"))
        return lo is not None and hi is not None and lo <= link <= hi

    @safe()
    def _adopt_plain_bp(self, bp, n):
        """Upgrade a plain `b SYM` to the regime-aware candidate set: add the
        missing PA(S)/IMG(S) HW siblings so it fires whatever regime that code
        runs in -- the same guarantee as `kb`, for stock `b`.  Fully guarded:
        reentrancy-safe, skips my own bps / temporaries / watchpoints / anything
        not on a kernel VA or outside the image phys window.  Additive -- gdb's
        own `break` is never overridden."""
        if self._in_adopt or self._in_catcher or not self.adopt or not self.enabled or self.offset is None:
            return
        if n in self._kb_bp_nums or n in self._adopted:
            return
        if getattr(bp, "type", None) != getattr(gdb, "BP_BREAKPOINT", 1):
            return
        if getattr(bp, "temporary", False):
            return
        locs = self._bp_locations(n) or []
        if not locs:
            return
        a = self.arch
        link = self._link_va(locs[0][1])
        if link is None or a is None or not a._is_va(link):
            return
        pa = (link + self.offset) & MASK
        # "Is this probe inside the kernel image?" is the real question, and the
        # image extent answers it exactly.  A coarse physical RAM window answers a
        # different question and gets it wrong wherever the physical base is
        # randomized -- on x86 it rejected every adoption under KASLR.  Fall back to
        # the window only when the image bounds are not resolvable.
        if not self._link_in_image(link):
            win = a.eff_phys_window()
            if win and not (win[0] <= pa <= win[1]):
                return
        img = (link + self.kaslr_slide) & MASK
        have = set(addr for _, addr, _ in locs)
        self._adopted.add(n)
        self._in_adopt = True
        try:
            made = []
            for cand in (pa, img):
                if cand in have:
                    continue
                out = exec_confirmless("hbreak *0x%x" % cand)
                mm = re.search(r"[Bb]reakpoint\s+(\d+)", out or "")
                if mm:
                    num = int(mm.group(1))
                    self._kb_bp_nums.add(num)
                    made.append((num, cand))
        finally:
            self._in_adopt = False
        if made:
            imgnum = next((str(num) for num, c in made if c == img), None)
            panum = next((str(num) for num, c in made if c == pa), None)
            self._kb_groups.append({"loc": (getattr(bp, "location", None) or "b#%d" % n),
                                    "link": link, "pa": pa, "pa_bp": panum,
                                    "img_addr": img, "img_bp": imgnum,
                                    "img_slide": self.kaslr_slide, "owner": n})
            LOG.add("adopt b#%d -> +%s" % (n, ",".join(fmt(c) for _, c in made)))

    @safe()
    def _prune_groups(self, num):
        """Forget a kb/kw group once every breakpoint it owns has been deleted.

        Without this, `delete` removed the gdb breakpoints but left the group in
        the bookkeeping, and _rearm_kb / _rearm_kw then RECREATED it at linkVA +
        slide the moment the crossing was reached -- so a probe the user had
        deleted came back to life and stopped them at it again.  Observed on
        arm64 v4.6, where `delete; kb start_kernel; continue` stopped at the
        deleted __mmap_switched instead."""
        for groups in (self._kb_groups, self._kw_groups):
            for g in list(groups):
                live = False
                for key in ("pa_bp", "img_bp"):
                    if g.get(key) is None:
                        continue
                    if str(g[key]) == str(num):
                        g[key] = None
                    else:
                        live = True
                # An adopted group also dies with the plain breakpoint it shadows --
                # and its siblings should go with it, or deleting "your" breakpoint
                # silently leaves hardware slots occupied.  Removing them from inside
                # gdb's own delete callback is what killed gdb before, so queue them
                # for the next safe point instead.
                if g.get("owner") is not None and str(g["owner"]) == str(num):
                    for key in ("pa_bp", "img_bp"):
                        if g.get(key) is not None:
                            self._pending_del.add(str(g[key]))
                    live = False
                if not live:
                    groups.remove(g)

    @safe()
    def _on_bp_deleted(self, bp):
        num = getattr(bp, "number", -1)
        self._managed_bps.discard(num)
        self._kb_bp_nums.discard(num)
        self._adopted.discard(num)
        self._kw_bp_nums.discard(num)
        self._prune_groups(num)
        # `delete` takes our crossing catcher with it.  Do not re-arm from inside this
        # callback (gdb is mid-way through tearing a breakpoint down); just remember that
        # one is wanted again and let a safe point re-arm it.
        pend = self._kaslr_pending
        if pend and str(pend.get("bp")) == str(num):
            self._kaslr_pending = None
            if not self.kaslr_slide:
                self._catch_wanted = True
                LOG.add("catcher: deleted by the user -- will re-arm at the next safe point")

    @safe()
    def set_bpfix(self, mode):
        mode = (mode or "").lower()
        if mode in ("on", "1", "true", ""):
            self.bpfix = True
            self._apply_bpfix()
            print("[%s] bpfix=on  (dual native/shadow breakpoints follow the MMU regime: "
                  "physical while MMU off, virtual once on)" % NAME)
        elif mode in ("off", "0", "false"):
            self.bpfix = False
            for n in list(self._managed_bps):
                execstr("enable %d" % n)
            self._managed_bps.clear()
            print("[%s] bpfix=off  (all breakpoint locations re-enabled; gdb default)" % NAME)
        else:
            print("usage: kearly bpfix <on|off>")

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
        if not self._catch_wanted or self.kaslr_slide or self._kaslr_pending:
            self._catch_wanted = False
            return
        self._catch_wanted = False
        # A stop hook or a gdb prompt is a safe context, so use the internal python
        # catcher here too -- the CLI one is deletable and would be lost to a `delete`.
        self._ensure_crossing_catcher("a probe armed earlier", use_python=True)

    @safe()
    def _on_prompt(self):
        self._service_catch_wanted()

    @safe()
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
    def _drain_pending_del(self):
        """Remove sibling breakpoints orphaned by a `delete`, from a context where
        creating and destroying breakpoints is safe."""
        if not self._pending_del:
            return
        nums, self._pending_del = sorted(self._pending_del), set()
        for n in nums:
            self._kb_bp_nums.discard(int(n)) if n.isdigit() else None
            exec_confirmless("delete %s" % n)
        LOG.add("delete: dropped orphaned sibling bp %s" % ",".join(nums))

    @safe()
    def _maybe_catch_for(self, bp, n):
        """Any new breakpoint that targets a kernel high VA while the KASLR slide is
        still unknown needs the crossing catcher, or it will never fire.  Hooked on
        breakpoint creation so it covers stock `b SYM` regardless of whether the
        adopt path applied (the shadow alone already yields two locations)."""
        if self.kaslr_slide or self._in_catcher:
            return
        if not self.enabled:
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
                _dpa = _env_int("X86_DECOMP_PA")
                if _pc is not None and _dpa is not None and (_pc & MASK) < _dpa:
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

    @safe()
    def _announce_transition(self, prev, now):
        """Make the MMU on/off switch visible so the user knows the addressing
        regime changed (and that VA symbolization is now native)."""
        pc = reg("pc")
        st, src = self.mmu_state()
        if prev == "physical" and now == "virtual":
            print("[%s] >>> MMU ON: $pc now VIRTUAL %s -- native kernel symbolization "
                  "active; shadow kept for residual physical pointers (page tables/DMA). "
                  "kp2v/kv2p still valid." % (NAME, fmt(pc)))
        elif prev == "virtual" and now == "physical":
            print("[%s] <<< back to PHYSICAL %s (MMU %s) -- shadow symbolization in use."
                  % (NAME, fmt(pc), st))
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
            tag = "MMU off" if st == "off" else "idmap/low-map"
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
        self._install_pwndbg_section()       # render badge+sysregs inside pwndbg ctx
        self._install_kdisasm_section()      # arrowed disasm next to SOURCE(CODE)
        self._quiet_pagescan()               # silence the useless auto-explore-pages spam
        self._maybe_warn_saferender()
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
        self._shadow_unload()


try:
    SESSION                      # re-sourcing preserves calibration / shadow state
except NameError:
    SESSION = Session()
state.set_session(SESSION)
