"""riscv64: the target-independent half."""
import re

from .base import ArchCommon


class Riscv64Common(ArchCommon):
    key = "riscv64"
    aliases = ("riscv:rv64", "riscv64", "riscv")
    # conditional branches (b*, incl. gdb's pseudo bleu/bgtu/... and RVC c.b*) plus
    # the unconditional intra-fn jump `j` / `c.j`.  jal/jalr/call/tail/jr excluded.
    BRANCH_RE = re.compile(
        r"^(?:c\.)?(?:b(?:eq|ne|lt|ge|ltu|geu|eqz|nez|lez|gez|ltz|gtz|gt|le|gtu|leu)|j)$")
