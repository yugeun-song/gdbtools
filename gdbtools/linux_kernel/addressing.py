"""part of gdbtools; see the package docstring."""
from ..common.runtime import *
from .pwndbg_glue import PWN


# ----------------------------------------------------------------------------
# Phys<->virt translation, the MMU regime, and symbolizing an address in it.
# Mixed into Session (session.py), which holds the state these methods use.
# ----------------------------------------------------------------------------
class AddressingMixin:
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
        if st == "off":
            return "MMU off, so addresses here are PHYSICAL"
        return ("MMU state UNKNOWN (no control register answered), so whether these "
                "addresses are physical cannot be stated")

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

        The verdict and the fallback chain behind it live in the arch class, so
        this and the page-table commands cannot reach opposite conclusions about
        one stop -- which they could when this consulted mmu_translation_on()
        while pt_base() read the base register through a longer chain.

        'unknown' is a real answer and is no longer folded into 'off'.  A pc that
        is physical does not mean translation is off: it means the pc is low, and
        the identity map is exactly the case where that is true with translation
        ON.  Reporting 'off' there was a guess dressed as a reading."""
        a = self.ensure_arch()
        if a is None:
            return ("unknown", "no-arch")
        ts = a.translation_state()
        if not ts:
            return ("unknown", "probe failed")
        return (ts.get("state", "unknown"), ts.get("source") or "?")

    @safe(default=None)
    def translation(self):
        """The full arch verdict: state, source, regime and the evidence string."""
        a = self.ensure_arch()
        return a.translation_state() if a is not None else None

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
