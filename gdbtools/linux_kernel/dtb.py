"""part of gdbtools; see the package docstring."""
import gdb
import os
import re
import json
import struct
from ..common.runtime import *


# ----------------------------------------------------------------------------
# Flattened Device Tree (DTB/FDT) -- minimal pure-python reader.
# We only need the /memory reg (RAM base+size) to drive the Image-magic scan and
# the phys sanity window on non-QEMU machines.  No external `dtc`/`fdtget`
# dependency; degrade-safe (returns None on any malformed blob).
# FDT is big-endian; tokens: BEGIN_NODE=1 END_NODE=2 PROP=3 NOP=4 END=9.
# ----------------------------------------------------------------------------
@safe(default=None)
def parse_dtb(data):
    if not data or len(data) < 40:
        return None
    magic, totalsize, off_struct, off_strings = struct.unpack_from(">IIII", data, 0)
    if magic != 0xD00DFEED:
        return None
    size_strings, size_struct = struct.unpack_from(">II", data, 32)
    strings = data[off_strings: off_strings + size_strings] if size_strings else data[off_strings:]
    end_struct = off_struct + size_struct if size_struct else len(data)
    p = off_struct
    depth = 0
    node_stack = []
    addr_cells, size_cells = 2, 2          # arm64 default if root omits them
    mem_regs = []
    bootargs = None
    guard = 0
    while p + 4 <= end_struct and guard < 1 << 20:
        guard += 1
        (tok,) = struct.unpack_from(">I", data, p)
        p += 4
        if tok == 1:                       # FDT_BEGIN_NODE
            end = data.index(b"\0", p)
            name = data[p:end].decode("latin1", "replace")
            p = (end + 1 + 3) & ~3
            node_stack.append(name)
            depth += 1
        elif tok == 2:                     # FDT_END_NODE
            if node_stack:
                node_stack.pop()
            depth -= 1
        elif tok == 3:                     # FDT_PROP
            plen, nameoff = struct.unpack_from(">II", data, p)
            p += 8
            val = data[p:p + plen]
            p = (p + plen + 3) & ~3
            try:
                pend = strings.index(b"\0", nameoff)
                pname = strings[nameoff:pend].decode("latin1", "replace")
            except Exception:
                pname = ""
            cur = node_stack[-1] if node_stack else ""
            if depth == 1 and pname == "#address-cells" and len(val) >= 4:
                addr_cells = struct.unpack(">I", val[:4])[0]
            elif depth == 1 and pname == "#size-cells" and len(val) >= 4:
                size_cells = struct.unpack(">I", val[:4])[0]
            elif cur.startswith("memory") and pname == "reg":
                ab, sb = addr_cells * 4, size_cells * 4
                stride = ab + sb
                if stride:
                    for i in range(0, len(val) - stride + 1, stride):
                        a = int.from_bytes(val[i:i + ab], "big")
                        s = int.from_bytes(val[i + ab:i + stride], "big")
                        mem_regs.append((a & MASK, s & MASK))
            elif cur == "chosen" and pname == "bootargs":
                bootargs = val.split(b"\0", 1)[0].decode("latin1", "replace")
        elif tok == 4:                     # FDT_NOP
            continue
        elif tok == 9:                     # FDT_END
            break
        else:
            break
    if not mem_regs and bootargs is None:
        return None
    return {"memory": mem_regs, "bootargs": bootargs}


@safe(default=None)
def read_guest_dtb(pa):
    """Read+parse a DTB sitting in guest RAM at `pa` (the bootloader leaves the
    DTB PA in x0 on arm64 / a1 on riscv at the kernel entry)."""
    hdr = read_guest_bytes(pa, 8)
    if not hdr or len(hdr) < 8:
        return None
    if int.from_bytes(hdr[0:4], "big") != 0xD00DFEED:
        return None
    total = int.from_bytes(hdr[4:8], "big")
    if total < 40 or total > (4 << 20):
        return None
    blob = read_guest_bytes(pa, total)
    return parse_dtb(blob) if blob else None


# Underscore-prefixed helpers are part of this module's public surface for the
# rest of the package (`from .dtb import *`), which would otherwise skip them.
__all__ = ['parse_dtb', 'read_guest_dtb']
