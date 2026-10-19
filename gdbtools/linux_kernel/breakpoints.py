"""part of gdbtools; see the package docstring."""
import gdb
import re
from ..common.runtime import *


# ----------------------------------------------------------------------------
# Regime-aware breakpoints and watchpoints (kb, kw), bpfix, and adopting a plain `b`.
# Mixed into Session (session.py), which holds the state these methods use.
# ----------------------------------------------------------------------------
class BreakpointMixin:
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

    @safe(default="virtual")
    def _addr_regime(self, addr):
        a = self.arch
        if a is not None and hasattr(a, "_is_va"):
            r = a._is_va(addr)
            if r is True:
                return "virtual"
            if r is False:
                return "physical"
        # No arch loaded, so there is no VA layout to test against.  The 48-bit
        # canonical form is the common one and is what this answers -- but say so
        # in the log rather than letting a 52-bit-VA arm64 or a 5-level x86
        # address be classified by a rule that does not apply to it.
        LOG.add("_addr_regime(%s): no arch; classified by the 48-bit canonical "
                "rule, which is an assumption" % fmt(addr))
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

    _FN_SPEC = re.compile(r"(?:-function\s+)?(?:[^\s:]+:)?([A-Za-z_][\w.]*)")

    @safe(default=(None, None))
    def _minsym_at(self, addr):
        """(ELF symbol, offset) covering addr, as `info symbol` names it."""
        s = re.match(r"(\S+)(?: \+ (\d+))? in section ", execstr("info symbol 0x%x" % addr) or "")
        return (s.group(1), int(s.group(2) or 0)) if s else (None, None)

    @safe(default=frozenset())
    def _entry_duplicates(self, num, locs):
        """Locations of a function breakpoint that repeat another one in the same
        function instance and regime.  When DWARF starts a function after its ELF
        symbol (riscv's patchable ftrace entry), gdb resolves `b fn` once from each,
        and one call stopped twice.  The location furthest into the function stays."""
        bp = next((b for b in gdb.breakpoints() if b.number == num), None)
        m = self._FN_SPEC.fullmatch((getattr(bp, "location", None) or "").strip())
        if m is None or len(locs) < 2:
            return frozenset()
        fn = m.group(1)
        minsym = self._minsym_at
        groups, bare = {}, []
        for locstr, addr, _ in locs:
            blk = gdb.block_for_pc(addr)
            while blk is not None and (blk.function is None or blk.function.name != fn):
                blk = blk.superblock
            if blk is None:
                bare.append((locstr, addr))
            else:
                groups.setdefault((self._addr_regime(addr), blk.start), []).append((locstr, addr))
        # A location outside every block of fn counts only when it is fn's ELF symbol
        # and the nearest instance after it starts inside that same symbol.
        for locstr, addr in bare:
            if minsym(addr) != (fn, 0):
                continue
            reg = self._addr_regime(addr)
            after = sorted(s for r, s in groups if r == reg and s > addr)
            if after and minsym(after[0]) == (fn, after[0] - addr):
                groups[(reg, after[0])].append((locstr, addr))
        dup = set()
        for members in groups.values():
            keep = max(a for _, a in members)
            dup.update(l for l, a in members if a != keep)
        return frozenset(dup)

    @safe()
    def _drop_entry_duplicates(self, num):
        locs = self._bp_locations(num) or []
        for locstr in self._entry_duplicates(num, locs):
            if any(l == locstr and en for l, _, en in locs):
                execstr("disable %s" % locstr)

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
            dup = self._entry_duplicates(n, locs)
            for locstr, addr, en in locs:
                if locstr in dup:
                    if en:
                        execstr("disable %s" % locstr)
                    continue
                if self._addr_regime(addr) != "physical":
                    if not en:
                        execstr("enable %s" % locstr)
                    continue
                if mmu_on and en:
                    execstr("disable %s" % locstr)
                elif not mmu_on and not en:
                    execstr("enable %s" % locstr)

    @safe(boundary="hook")
    def _on_bp_created(self, bp):
        n = getattr(bp, "number", None)
        if n is None:
            return
        if self._FN_SPEC.fullmatch((getattr(bp, "location", None) or "").strip()):
            self._fn_bps.add(n)
            self._drop_entry_duplicates(n)
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
        # A split entry leaves a regime's locations at different offsets of one call:
        # follow a location that stays, and take any location in the same function
        # and regime as already there, or a sibling adds a second stop to the call.
        dup = self._entry_duplicates(n, locs)
        a = self.arch
        link = self._link_va(next((addr for l, addr, _ in locs if l not in dup), locs[0][1]))
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
                if dup:
                    fn_c = self._minsym_at(cand)[0]
                    if fn_c is not None and any(self._addr_regime(h) == self._addr_regime(cand)
                                                and self._minsym_at(h)[0] == fn_c for h in have):
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

    @safe(boundary="hook")
    def _on_bp_deleted(self, bp):
        num = getattr(bp, "number", -1)
        self._managed_bps.discard(num)
        self._fn_bps.discard(num)
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
            config.set_session("BPFIX", "on")
            self._apply_bpfix()
            print("[%s] bpfix=on  (dual native/shadow breakpoints follow the MMU regime: "
                  "physical while MMU off, virtual once on)" % NAME)
        elif mode in ("off", "0", "false"):
            config.set_session("BPFIX", "off")
            for n in list(self._managed_bps):
                execstr("enable %d" % n)
            self._managed_bps.clear()
            print("[%s] bpfix=off  (all breakpoint locations re-enabled; gdb default)" % NAME)
        else:
            print("usage: kearly bpfix <on|off>")

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
