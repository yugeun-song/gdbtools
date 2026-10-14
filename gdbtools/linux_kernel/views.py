"""part of gdbtools; see the package docstring."""
import struct
from ..common.runtime import *
from .physmem import *
from .target import TARGET


# ----------------------------------------------------------------------------
# What the inspection commands print: page tables, the memory layout, regimes, where.
# Mixed into Session (session.py), which holds the state these methods use.
# ----------------------------------------------------------------------------
class ViewMixin:
    @safe(default=("unknown", "no arch"))
    def pt_provenance(self, root_pa):
        """(provenance, why) for a live top-level table -- 'kernel', 'foreign' or
        'unknown'.

        Translation being on does not make the tables the kernel's.  On a
        firmware chain the kernel's first instruction runs on the bootloader's
        tables: the walk is valid, but calling that root "the kernel PGD" is a
        lie the operator cannot see through.  Every input here is read from the
        live target -- the symbol addresses come from the loaded vmlinux and the
        PA conversion from this session's own calibration -- so nothing is
        assumed about where a kernel puts its tables.  When the offset is not
        calibrated the question genuinely has no answer and 'unknown' is it."""
        a = self.ensure_arch()
        if a is None or root_pa is None:
            return ("unknown", "no arch")
        syms = getattr(a, "pt_root_symbols", ()) or ()
        if not syms:
            return ("unknown", "this architecture names no kernel page-table roots")
        if self.offset is None:
            return ("unknown", "PA<->VA offset is not calibrated, so the kernel's "
                               "own table addresses cannot be computed")
        known = []
        for nm in syms:
            va = symval(nm)
            if va is None:
                continue                      # absent on this kernel version
            pa = self.v2p(va)
            if pa is not None:
                known.append((nm, pa & ~0xFFF))
        if not known:
            return ("unknown", "none of (%s) resolves in this vmlinux" % ", ".join(syms))
        for nm, pa in known:
            if pa == (root_pa & ~0xFFF):
                return ("kernel", "matches %s @PA 0x%x" % (nm, pa))

        # Not one of the kernel's NAMED static roots -- which is not the same as
        # not the kernel's.  Every user process has its own pgd carrying the
        # kernel half, so a booted guest stopped in a syscall is on one of those;
        # calling that "foreign, the kernel has not installed its own tables yet"
        # is false while the dump underneath shows kernel-half entries.  Ask the
        # table instead: does it map the kernel's own text?  One that does belongs
        # to the kernel's address space whether or not it is a static root; a
        # firmware table does not.
        # A root that lies INSIDE the loaded kernel image is the kernel's own by
        # construction, whatever it is called.  This is what catches a static root
        # that pt_root_symbols does not name -- arm64's init_idmap_pg_dir on 6.12,
        # and whatever a future kernel adds -- without another hardcoded name.
        tv = symval("_text") or symval("_stext") or symval("startup_64")
        ev = symval("_end")
        if tv is not None and ev is not None:
            lo, hi = self.v2p(tv), self.v2p(ev)
            if lo is not None and hi is not None and lo <= (root_pa & ~0xFFF) < hi:
                return ("kernel", "inside the kernel image%s" % self._sym_suffix(root_pa))

        # Otherwise ask the table itself.  A process pgd is not a static root and
        # never will be, but it carries the kernel half -- so a booted guest
        # stopped in a syscall is on one, and calling that foreign is false.
        if tv is not None:
            w = a.pagewalk(tv, root_pa=root_pa)
            if w and w.get("leaf_pa") is not None:
                return ("kernel", "not one of (%s) and not inside the image, but it maps "
                                  "the kernel's own text" % ", ".join(n for n, _ in known))
            if w is not None:
                # Says what was checked and nothing more.  "The kernel has not
                # installed its tables yet" was a claim about a sequence this code
                # has no way to observe.
                return ("foreign", "not one of (%s), not inside the kernel image, and does "
                                   "not map the kernel's own text"
                                   % ", ".join("%s@PA 0x%x" % (n, p) for n, p in known))
        return ("unknown", "not one of (%s); whether it maps the kernel's own text could "
                           "not be determined" %
                           ", ".join("%s@PA 0x%x" % (n, p) for n, p in known))

    @safe(default="")
    def _shape_caveat(self):
        """A note for the explicit path, when the shape came from registers that
        do not currently govern anything.

        With translation off, TCR / CR4 / satp still READ -- they hold whatever
        the last stage to configure them left there -- and that is often exactly
        the shape the named table was built with, which is why the dump is still
        useful.  But it is not a description of a live regime, and presenting it
        as one is the same class of claim the gate exists to stop."""
        a = self.ensure_arch()
        ts = (a.translation_state() if a is not None else None) or {}
        if ts.get("state") == "on":
            return ""
        return ("   [shape read from control registers that do NOT govern now -- "
                "translation is %s]" % ts.get("state", "unknown"))

    @safe(default=None)
    def _no_live_tables(self, cmd, hint_extra=""):
        """Why a live-table command cannot answer, in three sentences: what it
        assumed, what is true here (with the register that says so), and what to
        do instead.  The stale root is printed on purpose -- seeing the
        bootloader's table is often what the operator actually wanted, and the
        line is meant to be copied."""
        a = self.ensure_arch()
        ts = (a.translation_state() if a is not None else None) or {}
        state = ts.get("state", "unknown")
        lines = ["[%s] %s needs a live translation regime, and there is none here."
                 % (NAME, cmd)]
        if state == "off":
            lines.append("  translation OFF   %s   (source %s)"
                         % (ts.get("evidence") or "?", ts.get("source") or "?"))
            lines.append("  With translation off there is no current page table: the base "
                         "register keeps")
            lines.append("  whatever the previous stage left in it, so a dump of it would "
                         "describe the")
            lines.append("  bootloader's tables, not the kernel's.")
        elif state == "unknown":
            lines.append("  translation UNKNOWN   %s" % (ts.get("evidence") or
                         "no register answered"))
            lines.append("  Neither the gdb register set, nor the QEMU monitor, nor a "
                         "profile 'mmu' hint")
            lines.append("  could say whether translation is on.  Refusing rather than "
                         "guessing: a wrong")
            lines.append("  'on' here prints a plausible table that means nothing.")
        else:
            lines.append("  the page-table base register did not answer, though "
                         "translation reads as on")
        raw = a.pt_base_raw(reg("pc") or 0) if a is not None else None
        if raw:
            lines.append("  base register now: %s = 0x%x  (NOT a live table root)"
                         % (raw[0], raw[1]))
            lines.append("  To dump that table anyway, say so explicitly:  %s 0x%x"
                         % (cmd, raw[1]))
        lines.append("  Or reach a regime where the kernel's own tables are live:  "
                     "kearly overmmu")
        if hint_extra:
            lines.append("  %s" % hint_extra)
        return lines

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
            pc = reg("pc")
            if r["phys"]:
                here = r["pa"]
            else:
                here = (r["link"] + self.kaslr_slide) & MASK if r["link"] is not None else None
            if pc is not None and here is not None and pc == here:
                print("[%s] already at '%s' (%s)" % (NAME, r["id"], r["label"]))
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
        entry = self.entry_cpu_pa()
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
        entry = self.entry_cpu_pa()
        if pc is not None and entry is not None and not a._is_va(pc) and pc < entry:
            return "kearly bootbreak    (still before the kernel entry)"
        if pc is not None and not a._is_va(pc):
            return ("kearly regimes      (list this build's MMU stop points), or "
                    "kearly overmmu to cross now")
        return "nothing -- virtual addressing is up; `b SYM` targets the running kernel"

    # --- hardware page-table walk rendering -----------------------------
    def _sym_suffix(self, addr):
        """(symbol) annotation for a PA/VA via the shadow, or '' if none."""
        res = self.symbolize(addr)
        if res and res[2]:
            return "  (%s)" % res[2].split(" in section")[0].strip()
        return ""

    @safe(default=None)
    def walk_lines(self, va, hexbytes=False, root_pa=None):
        a = self.ensure_arch()
        if a is None:
            return ["[%s] no arch" % NAME]
        if not getattr(a, "pagewalk_supported", False):
            return ["[%s] page-table walk not implemented for %s" % (NAME, a.key)]
        w = a.pagewalk(va, root_pa=root_pa)
        if w is None:
            if root_pa is not None:
                cfg = getattr(a, "_ptcfg", None) or {}
                if not cfg:
                    ts = a.translation_state() or {}
                    return ["[%s] cannot walk through the table at 0x%x: the paging SHAPE "
                            "is unknown." % (NAME, root_pa),
                            "  %s, so the registers that would give the granule and level "
                            "count" % (ts.get("evidence") or "translation is not on"),
                            "  describe nothing right now.  A walk needs a shape; the raw "
                            "bytes do not:",
                            "    kpthex 0x%x full" % root_pa]
                return ["[%s] cannot walk VA 0x%x through the table at 0x%x -- the "
                        "physical read failed" % (NAME, va & MASK, root_pa)]
            return (self._no_live_tables("kpt")
                        or ["[%s] kpt: translation is not on, and the reason could not "
                            "be rendered -- see 'kearly log'" % NAME])
        lines = ["VA 0x%x   %s   [%s]" % (w["va"], w["regime"], w["config"])]
        if root_pa is None:
            prov, why = self.pt_provenance(w["base"])
            lines.append("  top-table PA 0x%x%s   provenance %s -- %s"
                         % (w["base"], self._sym_suffix(w["base"]), prov.upper(), why))
        else:
            lines.append("  top-table PA 0x%x%s   (EXPLICIT root -- not read from a "
                         "translation register)" % (w["base"], self._sym_suffix(w["base"])))
        for depth, lv in enumerate(w["levels"]):
            nm, idx, ent, desc = lv["name"], lv["index"], lv["entry_pa"], lv["desc"]
            if desc is None:
                lines.append("  %-7s [%3d] @PA 0x%-10x <unreadable>" % (nm, idx, ent))
                continue
            kind = lv["kind"]
            if kind == "table":
                tail = "table -> 0x%x%s  (kpgd 0x%x level %d)" % (
                    lv["next_pa"], self._sym_suffix(lv["next_pa"]), lv["next_pa"], depth + 1)
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

    def _table_level(self, a, level, explicit, cmd):
        """(level, shift, count, label) for a table dump, or a list of refusal lines.
        A live root is the top table; an explicit TABLE_PA is at `level` (default 0,
        the top), because nothing in the bytes says which level a table is."""
        cfg = getattr(a, "_ptcfg", {}) or {}
        names = a.pt_levels()
        nlevels = cfg.get("nlevels") or len(names)
        level = level or 0
        if level and not explicit:
            return ["[%s] %s: `level` applies to an explicit TABLE_PA; the live root is "
                    "the top table" % (NAME, cmd)]
        if not 0 <= level < nlevels:
            return ["[%s] %s: level %d is outside this shape's 0..%d"
                    % (NAME, cmd, level, nlevels - 1)]
        shift = a.pt_index(0, level)[1]
        label = names[level] if level < len(names) else "L%d" % level
        return level, shift, a.pt_entries(top=(level == 0)), label

    @safe(default=None)
    def pgd_dump_lines(self, va=None, table_pa=None, maxrows=80, level=None):
        a = self.ensure_arch()
        if a is None or not getattr(a, "pagewalk_supported", False):
            return ["[%s] unsupported" % NAME]
        regime, note = "explicit TABLE_PA", ""
        if table_pa is None:
            probe = va if va is not None else reg("pc")
            rb = a.pt_base(probe if probe is not None else 0)
            if rb is None:
                return (self._no_live_tables("kpgd")
                        or ["[%s] kpgd: translation is not on, and the reason could not "
                            "be rendered -- see 'kearly log'" % NAME])
            regime, table_pa = rb
            prov, why = self.pt_provenance(table_pa)
            note = "   provenance %s -- %s" % (prov.upper(), why)
        else:
            # An explicit root is the operator asserting what this table is, so it
            # is honoured in every regime -- including MMU-off, which is exactly
            # when someone wants to look at the bootloader's tables.  The SHAPE is
            # still read from the live target rather than assumed: decoding an
            # Sv39 or 16K-granule table as 4KB/4-level misreads every index and
            # says nothing about having done so.  Which half of a split control
            # applies is decided by $pc's regime, since an explicit root names no
            # VA of its own.
            a.pt_config_probe_for(reg("pc"))
            note = "   (EXPLICIT -- not read from a translation register)"
            note += self._shape_caveat()
        cfg = getattr(a, "_ptcfg", {}) or {}
        if not cfg:
            return ["[%s] the paging shape could not be read from the target "
                    "(no TCR/CR4/satp), so the entries at 0x%x cannot be decoded."
                    % (NAME, table_pa),
                    "  Raw bytes are still available and need no shape:  kpthex 0x%x full"
                    % table_pa]
        lv = self._table_level(a, level, regime == "explicit TABLE_PA", "kpgd")
        if isinstance(lv, list):
            return lv
        level, shift, _n, label = lv
        nlevels = cfg["nlevels"]
        words = read_phys_words(table_pa, _n)
        if not words:
            return ["[%s] cannot read table @0x%x (physical read failed)" % (NAME, table_pa)]
        lines = ["table %s (level %d%s) @PA 0x%x   regime %s   [%s]%s   (non-zero of %d entries)" %
                 (label, level, ", top" if level == 0 else "", table_pa, regime,
                  a.pt_config_desc(), note, _n)]
        shown = 0
        for i, d in enumerate(words):
            if not d:
                continue
            if shown >= maxrows:
                lines.append("  ... (stopped at %d rows; raise with 'kpgd <addr> <n>')" % maxrows)
                break
            kind, nxt, leaf, attrs = a.pt_decode(d, level, shift, nlevels)
            out = nxt if kind == "table" else (leaf if leaf is not None else 0)
            lines.append("  [%3d] 0x%016x  %-7s -> 0x%-10x%s %s" %
                         (i, d, kind, out or 0, self._sym_suffix(out or 0), attrs or ""))
            shown += 1
        if shown == 0:
            lines.append("  (all %d entries are zero / not-present)" % _n)
        return lines

    @safe(default=None)
    def pt_hex_lines(self, va=None, table_pa=None, count=None, full=False, level=None):
        a = self.ensure_arch()
        if a is None or not getattr(a, "pagewalk_supported", False):
            return ["[%s] unsupported" % NAME]
        regime, note = "explicit TABLE_PA", ""
        if table_pa is None:
            probe = va if va is not None else reg("pc")
            rb = a.pt_base(probe if probe is not None else 0)
            if rb is None:
                # `full` needs no decode at all -- it is a hexdump -- but it still
                # needs a table to dump, and with no live root there is none to
                # pick.  The refusal names the stale register value so the
                # operator can pass it explicitly.
                return (self._no_live_tables("kpthex")
                        or ["[%s] kpthex: translation is not on, and the reason could not "
                            "be rendered -- see 'kearly log'" % NAME])
            regime, table_pa = rb
            prov, why = self.pt_provenance(table_pa)
            note = "   provenance %s -- %s" % (prov.upper(), why)
        else:
            a.pt_config_probe_for(reg("pc"))
            note = "   (EXPLICIT -- not read from a translation register)"
            note += self._shape_caveat()
        cfg = getattr(a, "_ptcfg", {}) or {}
        # The short decode beside each row needs the shape; the raw bytes do not.
        # With no shape read from the target, print the bytes and say the decode
        # is missing rather than decode them against an assumed 4-level/39-bit
        # layout that is wrong on Sv39 and on a 16K granule.
        nlevels = cfg.get("nlevels")
        shift = None
        if cfg.get("top_shift") is None or nlevels is None:
            note += "   [no decode -- paging shape unread]"
            if level:
                return ["[%s] kpthex: level %d needs the paging shape, which could not be read"
                        % (NAME, level)]
            _n = a.pt_entries()
        else:
            lv = self._table_level(a, level, regime == "explicit TABLE_PA", "kpthex")
            if isinstance(lv, list):
                return lv
            level, shift, _n, _label = lv
            note += "   level %d" % level
        if full:
            _n = a.pt_entries()                # the whole granule page, raw
        words = read_phys_words(table_pa, _n)
        if not words:
            return ["[%s] cannot read table @0x%x (physical read failed)" % (NAME, table_pa)]
        lines = ["page-table page @PA 0x%x   regime %s%s   little-endian, as stored in RAM" %
                 (table_pa, regime, note)]
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
            if shift is None:
                # Bytes are a fact; a decode without a known granule is not.
                lines.append("  [%3d] 0x%-11x  %s   0x%016x   (shape unread)"
                             % (i, ent_pa, bstr, d))
                shown += 1
                continue
            kind, nxt, leaf, attrs = a.pt_decode(d, level, shift, nlevels)
            if kind == "table":
                dec = "TABLE -> 0x%x%s" % (nxt or 0, self._sym_suffix(nxt or 0))
            elif kind in ("block", "page"):
                dec = "%s 0x%x%s %s" % (kind.upper(), leaf or 0, self._sym_suffix(leaf or 0), attrs or "")
            else:
                dec = "invalid"
            lines.append("  [%3d] 0x%-11x  %s   0x%016x   %s" % (i, ent_pa, bstr, d, dec))
            shown += 1
        if shown == 0:
            lines.append("  (all %d entries are zero / not-present)" % _n)
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
                # Translation being on does not make these the kernel's tables.
                # On a firmware chain the kernel's first instruction runs on the
                # bootloader's, and labelling that root "kernel+user CR3" (or
                # "kernel TTBR1") states something the operator cannot check.
                prov, why = self.pt_provenance(base)
                lines.append("")
                lines.append("live mappings: %s  root@PA 0x%x   (%d%s regions)   [%s]"
                             % (label, base, len(regions),
                                "/%d" % total if hidden else "", a.pt_config_desc()))
                lines.append("  provenance %s -- %s" % (prov.upper(), why))
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
