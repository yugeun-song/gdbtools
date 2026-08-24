"""arm64: the target-independent half."""
import re

from .base import ArchCommon


class Arm64Common(ArchCommon):
    key = "arm64"
    aliases = ("aarch64", "arm64")
    # b + b.<cond> + cbz/cbnz + tbz/tbnz.  bl (call), br/blr (indirect) excluded.
    BRANCH_RE = re.compile(r"^(?:b|b\.[a-z]{2}|cbn?z|tbn?z)$")
    # binutils condition-code spellings -> Capstone's (what pwndbg prints)
    MNEM_ALIASES = {"b.cc": "b.lo", "b.cs": "b.hs"}
