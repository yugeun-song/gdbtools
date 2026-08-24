"""Architecture knowledge that does not depend on the target being a kernel.

Only what the disassembly and control-flow views need: which mnemonics are
branches, how gdb spells them, and where a direct branch points.  Everything
that needs a phys<->virt map, page tables or system registers lives in
`gdbtools.linux_kernel.arch`.
"""
import re

from ..runtime import MASK


class ArchCommon:
    key = "base"
    aliases = ()                 # substrings matched against gdb arch name
    entry_symbol = None          # symbol whose PA == $pc at the first frozen stop
    expected_entry_pa = None     # PA the QEMU machine loads the entry at (hint)
    phys_window = (0, MASK)      # plausible physical image range (sanity check)
    entry_break_kind = "hw"      # "sw": entry not overwritten -> sw bp ok (no hw-bp
                                 # dependency); "hw": entry gets relocated/decompressed
                                 # over, so a sw bp there would be clobbered
    entry_magic = None           # (word, offset_from_text): scan RAM for the Image
    ram_scan = None              # (start,end): header magic to LOCATE the load addr,
                                 # so we don't hardcode QEMU's load offset
    dtb_pointer_reg = None       # reg holding the DTB PA at entry (arm64 x0/riscv a1)
    return_reg = None            # reg holding a just-called fn's return addr (lr/ra)
    post_mmu_symbols = ()        # virtual landing(s) reached just after the MMU is
                                 # enabled; `kearly overmmu` breaks here + continues

    @classmethod
    def matches(cls, archname):
        a = (archname or "").lower()
        return any(x in a for x in cls.aliases)

    # --- branch/jump detection for the arrowed disassembler (cfgdis) -----------
    # Per-arch regex of the control-flow mnemonics that carry a DIRECT, in-image
    # code target and that we want an arrow for: conditional branches + the
    # unconditional intra-function jump.  CALLs (jal ra / bl / callq) and RETURNs
    # are deliberately excluded -- like radare2's linear view we arrow *jumps*,
    # not calls, so a `jal ra, sibling` never sprouts an arrow.  Indirect targets
    # (jr/jalr/br/blr/jmp *%rax) either fail the regex or carry no bare-hex
    # operand, so branch_target() returns None.  None disables arrows entirely.
    BRANCH_RE = None

    # gdb/binutils spells some mnemonics differently from Capstone (which pwndbg
    # uses), e.g. arm64 conditional branches: binutils `b.cc`/`b.cs` vs Capstone
    # `b.lo`/`b.hs`.  We rewrite to the Capstone spelling so our arrow window's
    # mnemonics match pwndbg's DISASM window verbatim.
    MNEM_ALIASES = {}

    def normalize_mnem(self, mnem):
        """gdb/binutils mnemonic -> the Capstone spelling pwndbg prints."""
        return self.MNEM_ALIASES.get(mnem, mnem)

    def branch_target(self, mnem, ops):
        """Absolute target address of a direct jump, else None.  Arch-independent
        extraction: gate on BRANCH_RE, then take the LAST comma-separated operand,
        drop any '<sym+off>' annotation gdb appended, and accept it only if what
        remains is a bare hex address.  The caller checks that the target is a row
        actually on screen, so out-of-window targets simply draw no arrow."""
        if not self.BRANCH_RE or not self.BRANCH_RE.match(mnem):
            return None
        # Drop a trailing disassembler comment first: arm64 renders b.<cond> as
        # e.g. `b.eq 0x... <sym>  // b.none`, and the comment would otherwise hide
        # the target.  Only '//' and ';' are stripped -- never '#', which is a
        # real operand on arm (`tbz w0, #0x1f, <target>`).
        ops = re.sub(r"\s*(?://|;).*$", "", ops)
        last = ops.split(",")[-1].strip()
        last = re.sub(r"\s*<[^>]*>\s*$", "", last).strip()
        m = re.match(r"^[\$#]?(0x[0-9a-fA-F]+)$", last)
        return (int(m.group(1), 16) & MASK) if m else None
