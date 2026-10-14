"""part of gdbtools; see the package docstring."""
import gdb
from ..common.runtime import *
from .pwndbg_glue import PWN, context_kgdb, context_flow, context_msysreg
from ..common.arch import detect_arch
from ..common import cfgdis as _kdismod


# ----------------------------------------------------------------------------
# The pwndbg context sections (kgdb, msysreg, flow) and the settings that shape them.
# Mixed into Session (session.py), which holds the state these methods use.
# ----------------------------------------------------------------------------
class PanelMixin:
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

    # --- sysreg + bit-field panel -------------------------------------------
    # The indent of a register entry.  Its field rows hang directly under it at the
    # same column, so both are printed with this one value.
    _MSYSREG_LEAD = "  "

    def _msysreg_field_lines(self, a, name, value, width):
        """The field rows under one register: 'NAME[hi:lo]=value reading', wrapped.

        Rendered as a separate row from the value deliberately.  The register's whole
        value and one flag inside it are two different facts, and a panel that prints
        `M=1` without saying which register's bit 0 that is, or what the rest of that
        register held, is the kind of half-answer this panel exists to avoid."""
        specs = a.field_specs(name)
        if not specs:
            return []
        cells = []
        for fname, hi, lo, reading in specs:
            if hi < lo:
                continue                       # malformed entry: say nothing, never guess
            v = a.field_extract(value, hi, lo)
            span = "[%d]" % lo if hi == lo else "[%d:%d]" % (hi, lo)
            # The field's KIND picks the base, not its value: flipping base with
            # the value would make one field look different between two stops.
            # A single bit is 0 or 1.  An enumerated field is an encoding and is
            # written in hex wherever it is documented (ESR.EC 0x24, MAIR 0xff).
            # Everything else is a number -- TxSZ, counter counts -- except that
            # a field 8 bits or wider is a value, not a count, so hex again.
            if hi == lo:
                shown = "%d" % v
            elif isinstance(reading, dict) or (hi - lo + 1) >= 8:
                shown = "0x%x" % v
            else:
                shown = "%d" % v
            note = a.field_reading(reading, v, value)
            cells.append("%s%s=%s%s" % (fname, span, shown, (" " + note) if note else ""))
        if not cells:
            return []
        # Wrap to the panel width, leaving room for the lead and tree glyph this row
        # is printed with, so a narrow panel stays inside its width instead of
        # wrapping a second time in the terminal.
        prefix = self._MSYSREG_LEAD + "\u251c\u2500 "
        avail = max(24, (width or 100) - len(prefix) - 1)
        rows, cur = [], ""
        for c in cells:
            add = c if not cur else (cur + "  " + c)
            if len(add) > avail and cur:
                rows.append(cur); cur = c
            else:
                cur = add
        if cur:
            rows.append(cur)
        out = []
        for i, r in enumerate(rows):
            glyph = "\u2514\u2500" if i == len(rows) - 1 else "\u251c\u2500"
            out.append("%s%s %s" % (self._MSYSREG_LEAD, glyph, PWN.color("gray", r) or r))
        return out

    def msysreg_context_lines(self, width=None):
        """Lines for the 'msysreg' context section: every system register the early
        asm touches, each as its own value, with the bits inside it underneath.

        The register list is the arch's `entry_sysregs`, which is derived from the
        msr/mrs operands in head.S / entry.S / proc.S rather than chosen by hand.
        A register the target will not answer for is SKIPPED in compact mode and
        shown as '?' in full mode -- never as 0, which would read as a real value."""
        a = self.ensure_arch()
        if a is None or not self.enabled or self.msysreg_mode == "off":
            return []
        names = getattr(a, "entry_sysregs", ())
        if not names:
            return []
        full = (self.msysreg_mode == "full")
        meta = {}
        for ent in getattr(a, "census", ()):
            if len(ent) >= 3:
                meta[ent[0].lower()] = ent[2]
        groups, order = {}, []
        for nm in names:
            v = a.sysreg(nm)
            if v is None:
                v = evi("$" + nm)
            if v is None and not full:
                continue
            cat = meta.get(nm.lower(), "other")
            if cat not in groups:
                groups[cat] = []
                order.append(cat)
            groups[cat].append((nm, v))
        lines = []
        for cat in order:
            lines.append(PWN.color("blue", cat) or cat)
            for nm, v in groups[cat]:
                nmc = PWN.color("cyan", "%-16s" % nm) or ("%-16s" % nm)
                if v is None:
                    lines.append("%s%s ?" % (self._MSYSREG_LEAD, nmc))
                    continue
                val = PWN.color("yellow", "0x%016x" % v) or ("0x%016x" % v)
                rows = self._msysreg_field_lines(a, nm, v, width)
                if not rows:
                    # No field table for this one.  The older one-line decoder still
                    # knows some of them (DAIF/NZCV normalisation among them), and a
                    # short reading next to the value beats a bare number.
                    note = None
                    try:
                        note = a.decode_sysreg(nm, v)
                    except Exception:
                        note = None
                    if note:
                        val += "   " + (PWN.color("gray", note) or note)
                lines.append("%s%s %s" % (self._MSYSREG_LEAD, nmc, val))
                lines += rows
        # The flags register last.  No msr/mrs names it -- the asm writes DAIF and
        # NZCV, or the flags themselves -- so it is not in entry_sysregs, and showing
        # a flag without its owner is exactly the omission this panel exists to
        # close.  Each port names its own (arm64 PSTATE, x86_64 EFLAGS); a port that
        # has no such register sets it to None and this block does nothing.
        fr = getattr(a, "flags_reg", None)
        if fr:
            fv = reg(fr)
            if fv is None and fr == "pstate":
                fv = reg("cpsr")          # older gdb spells the same register cpsr
            if fv is not None:
                lines.append(PWN.color("blue", "flags") or "flags")
                nmc = PWN.color("cyan", "%-16s" % fr.upper()) or ("%-16s" % fr.upper())
                lines.append("%s%s %s" % (self._MSYSREG_LEAD, nmc,
                                          PWN.color("yellow", "0x%016x" % fv) or ("0x%016x" % fv)))
                lines += self._msysreg_field_lines(a, fr, fv, width)
        return lines

    @safe()
    def _install_msysreg_section(self):
        """Register the 'msysreg' context section (key 'm') after our 'kgdb' badge.

        Same runtime, no-pwndbg-edit approach as the other two sections.  'm' is free:
        pwndbg's built-ins take a/r/d/s/b/c/l/e/h/t and this package already holds
        k (kgdb) and f (flow), and a section is resolved by its name's FIRST LETTER,
        so the name has to start with a letter nobody else claims."""
        if not PWN.ok:
            return
        # An arch that states no register list has nothing to put in this window.
        # Registering it anyway would leave a name in the user's context-sections
        # that never prints, which reads as a broken section rather than as an
        # arch that does not implement one yet.
        a = self.ensure_arch()
        if a is None or not getattr(a, "entry_sysregs", ()):
            return
        secs = getattr(PWN._ctx, "context_sections", None)
        if not isinstance(secs, dict):
            return
        existing = secs.get("m")
        if existing is not None and getattr(existing, "__name__", "") != "context_msysreg":
            return                            # 'm' taken by a different tool
        secs["m"] = context_msysreg
        cfg = getattr(PWN._ctx, "config_context_sections", None)
        val = getattr(cfg, "value", None)
        if cfg is not None and isinstance(val, str):
            if "msysreg" not in val.split():
                parts = val.split()
                if "kgdb" in parts:
                    parts.insert(parts.index("kgdb") + 1, "msysreg")
                elif "regs" in parts:
                    parts.insert(parts.index("regs") + 1, "msysreg")
                else:
                    parts.append("msysreg")
                try:
                    cfg.value = " ".join(parts)   # direct: avoid the list-reverting validator
                except Exception:
                    exec_confirmless("set context-sections %s" % " ".join(parts))
            nv = getattr(cfg, "value", "")
            self._msysreg_installed = isinstance(nv, str) and "msysreg" in nv.split()
        if self._msysreg_installed:
            LOG.add("pwndbg 'msysreg' context section installed")

    @safe()
    def _remove_msysreg_section(self):
        if not self._msysreg_installed:
            return
        secs = getattr(PWN._ctx, "context_sections", None)
        if isinstance(secs, dict) and getattr(secs.get("m"), "__name__", "") == "context_msysreg":
            secs.pop("m", None)
        cfg = getattr(PWN._ctx, "config_context_sections", None)
        val = getattr(cfg, "value", None)
        if isinstance(val, str) and "msysreg" in val.split():
            new = " ".join(p for p in val.split() if p != "msysreg")
            try:
                cfg.value = new               # direct: avoid pwndbg's list-reverting validator
            except Exception:
                exec_confirmless("set context-sections %s" % new)
        self._msysreg_installed = False

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
            # Direct assignment, for the same reason the install path uses it and the
            # removal path did not: `set context-sections` fires pwndbg's validator,
            # which reverts the WHOLE list to its default the moment it contains a
            # name with no registered section.  "ghidra" is in pwndbg's own default
            # list and is unregistered unless ghidra is loaded, so the validator
            # fires on a stock setup -- and removing one of our sections through that
            # command took the other two with it, along with the user's own ordering.
            new = " ".join(p for p in val.split() if p != "kgdb")
            try:
                cfg.value = new
            except Exception:
                exec_confirmless("set context-sections %s" % new)
        self._section_installed = False

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
        return _kdismod._kdis_lines(rows[lo:hi], arch, color=not config.get("NO_COLOR"),
                                    ascii_mode=bool(config.get("KDIS_ASCII")))

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
            # The install only inserted `flow`; take exactly that back out.
            new = " ".join(p for p in val.split() if p != "flow")
            try:
                cfg.value = new                 # direct: avoid pwndbg's list-reverting validator
            except Exception:
                exec_confirmless("set context-sections %s" % new)
        self._kdisasm_installed = False

    @safe()
    def set_msysreg(self, mode):
        mode = (mode or "").lower()
        aliases = {"on": "compact", "c": "compact", "1": "compact",
                   "full": "full", "all": "full", "f": "full",
                   "off": "off", "0": "off", "no": "off"}
        mode = aliases.get(mode, mode)
        if mode not in ("off", "compact", "full"):
            print("usage: kearly msysreg <off|compact|full>  "
                  "(compact = only registers this target answers for; "
                  "full = every one, unreadable ones as '?')")
            return
        # The window is one of PANELS, so the hand control states PANELS too and a
        # later `kearly on` or re-source keeps what was chosen here.
        want = [p for p in self.panels() if p != "msysreg"] + ([] if mode == "off" else ["msysreg"])
        config.set_session("PANELS", " ".join(want) or "-")
        if mode != "off":
            self.msysreg_mode = mode
        print("[%s] msysreg panel = %s" % (NAME, mode))
        if mode == "off":
            self._remove_msysreg_section()
        elif self.enabled:
            self._install_msysreg_section()

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
        config.set_session("SAFERENDER", mode)
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
        if self._saferender_warned or self.saferender == "off":
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
