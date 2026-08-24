"""x86_64: the target-independent half."""
import re

from .base import ArchCommon


class X86_64Common(ArchCommon):
    key = "x86_64"
    aliases = ("x86-64", "i386:x86-64", "x86_64", "x86")
    # jmp + all Jcc + loop*; callq excluded (arrow jumps, not calls).  AT&T
    # suffixed forms (jmpq) covered by the generic j[a-z]{1,4} arm too.
    BRANCH_RE = re.compile(r"^(?:jmp|jmpq|loop(?:e|ne|z|nz)?|j[a-z]{1,4})$")
    # binutils prints an unconsumed instruction prefix as a leading token, e.g.
    # `data16 jmp 0x... <l>` or `bnd jmp 0x...` (alternatives/retpoline padding).
    # Peel prefixes so the real branch mnemonic reaches BRANCH_RE.
    _PREFIXES = frozenset((
        "lock", "bnd", "notrack", "rep", "repe", "repz", "repne", "repnz",
        "data16", "data32", "addr16", "addr32", "rex", "rex.w",
        "cs", "ds", "es", "fs", "gs", "ss"))

    def branch_target(self, mnem, ops):
        while mnem.lower() in self._PREFIXES and ops:
            p = ops.split(None, 1)
            mnem, ops = p[0], (p[1] if len(p) > 1 else "")
        return super(X86_64Common, self).branch_target(mnem, ops)
