"""part of gdbtools; see the package docstring.

Complete, lossless reader for the LIVE flattened device tree.

`dtb.py` deliberately extracts only /memory and bootargs to drive the phys
window; this module is the opposite trade-off -- it decodes every header field,
every reservation entry, every node and every property, and reports structural
anomalies instead of silently stopping.  Nothing here writes to the target.
"""
import os
import re
import struct
import gdb
from ..common.runtime import *
from .physmem import *


FDT_MAGIC = 0xD00DFEED
FDT_BEGIN_NODE = 0x1
FDT_END_NODE = 0x2
FDT_PROP = 0x3
FDT_NOP = 0x4
FDT_END = 0x9

FDT_MAX_TOTALSIZE = 8 << 20
FDT_MAX_TOKENS = 1 << 22

_HDR_FIELDS = ("magic", "totalsize", "off_dt_struct", "off_dt_strings",
               "off_mem_rsvmap", "version", "last_comp_version",
               "boot_cpuid_phys", "size_dt_strings", "size_dt_struct")

_DEFAULT_ADDRESS_CELLS = 2
_DEFAULT_SIZE_CELLS = 1

_STRING_PROPS = frozenset((
    "compatible", "model", "status", "device_type", "bootargs", "stdout-path",
    "linux,stdout-path", "name", "label", "enable-method", "method",
    "mmu-type", "riscv,isa", "clock-names", "clock-output-names",
    "interrupt-names", "reg-names", "dma-names", "reset-names",
    "pinctrl-names", "gpio-names", "phy-names", "power-domain-names",
))

_CELL_PROPS = frozenset((
    "#address-cells", "#size-cells", "#interrupt-cells", "#clock-cells",
    "#gpio-cells", "#dma-cells", "#power-domain-cells", "#phandle-cells",
    "#reset-cells", "#pwm-cells", "#hwlock-cells", "#mbox-cells",
    "phandle", "linux,phandle", "ibm,phandle", "interrupt-parent",
    "interrupts", "interrupts-extended", "clock-frequency",
    "timebase-frequency", "cpu-release-addr", "riscv,ndev", "cpu",
))

_ADDR_PROPS = frozenset(("reg", "assigned-addresses"))
_RANGE_PROPS = frozenset(("ranges", "dma-ranges"))


class FdtError(Exception):
    pass


def _cstr(data, off):
    if off is None or off < 0 or off >= len(data):
        return None
    z = data.find(b"\0", off)
    if z < 0:
        z = len(data)
    return data[off:z].decode("utf-8", "replace")


def fdt_parse_header(data):
    """Decode the 40-byte header. Raises FdtError when it is not an FDT."""
    if len(data) < 40:
        raise FdtError("blob shorter than a 40-byte header (%d bytes)" % len(data))
    h = dict(zip(_HDR_FIELDS, struct.unpack_from(">10I", data, 0)))
    if h["magic"] != FDT_MAGIC:
        raise FdtError("bad magic 0x%08x, expected 0x%08x" % (h["magic"], FDT_MAGIC))
    if h["version"] < 3:
        h["size_dt_strings"] = 0
    if h["version"] < 17:
        h["size_dt_struct"] = 0
    return h


def fdt_content_span(hdr):
    """Bytes that actually carry content, and whether that bound is trustworthy.

    A blob is routinely padded far past its content -- QEMU hands the kernel a
    1 MiB region whose totalsize says 1 MiB while the struct and strings blocks
    together occupy under 8 KiB.  Reading totalsize would mean pulling a megabyte
    of zeroes across the stub for nothing, and on the physical path it exceeds
    what one HMP `xp` can carry.
    """
    total = hdr["totalsize"]
    bounded = bool(hdr["size_dt_struct"]) and bool(hdr["size_dt_strings"])
    if not bounded:
        return total, False
    need = max(40,
               hdr["off_dt_struct"] + hdr["size_dt_struct"],
               hdr["off_dt_strings"] + hdr["size_dt_strings"],
               hdr["off_mem_rsvmap"] + 16)
    return min(need, total), True


def fdt_header_notes(data, hdr):
    """Structural sanity findings for the header, as a list of strings."""
    out = []
    n = len(data)
    if hdr["totalsize"] < n:
        out.append("totalsize 0x%x is smaller than the %d bytes read" % (hdr["totalsize"], n))
    if hdr["last_comp_version"] > hdr["version"]:
        out.append("last_comp_version %d > version %d" % (hdr["last_comp_version"], hdr["version"]))
    if hdr["version"] < 16:
        out.append("version %d: FDT_PROP values >= 8 bytes are 8-byte aligned" % hdr["version"])
    for k in ("off_mem_rsvmap", "off_dt_struct", "off_dt_strings"):
        if hdr[k] >= n:
            out.append("%s 0x%x lies outside the blob" % (k, hdr[k]))
    if hdr["off_mem_rsvmap"] & 7:
        out.append("off_mem_rsvmap 0x%x is not 8-byte aligned" % hdr["off_mem_rsvmap"])
    if hdr["off_dt_struct"] & 3:
        out.append("off_dt_struct 0x%x is not 4-byte aligned" % hdr["off_dt_struct"])
    if hdr["size_dt_struct"] and hdr["off_dt_struct"] + hdr["size_dt_struct"] > n:
        out.append("struct block runs past the end of the blob")
    if hdr["size_dt_strings"] and hdr["off_dt_strings"] + hdr["size_dt_strings"] > n:
        out.append("strings block runs past the end of the blob")
    return out


def fdt_reservations(data, hdr):
    """Return (entries, terminated) for the memory reservation block."""
    out, p = [], hdr["off_mem_rsvmap"]
    while p + 16 <= len(data) and len(out) < 8192:
        a, s = struct.unpack_from(">QQ", data, p)
        p += 16
        if a == 0 and s == 0:
            return out, True
        out.append((a, s))
    return out, False


def fdt_walk(data, hdr):
    """Yield (kind, depth, offset, payload) over the whole structure block.

    kind is one of: node, endnode, prop, nop, end, error.  The walk always
    terminates -- on a malformed token it emits an error event and stops.
    """
    ver = hdr["version"]
    stroff = hdr["off_dt_strings"]
    p = hdr["off_dt_struct"]
    end = len(data)
    if hdr["size_dt_struct"]:
        end = min(end, hdr["off_dt_struct"] + hdr["size_dt_struct"])
    depth = 0
    seen = 0
    while p + 4 <= end:
        seen += 1
        if seen > FDT_MAX_TOKENS:
            yield ("error", depth, p, "token limit %d reached, aborting walk" % FDT_MAX_TOKENS)
            return
        at = p
        (tok,) = struct.unpack_from(">I", data, p)
        p += 4
        if tok == FDT_NOP:
            yield ("nop", depth, at, None)
            continue
        if tok == FDT_END:
            yield ("end", depth, at, p)
            if depth != 0:
                yield ("error", depth, at, "FDT_END at depth %d, %d node(s) left open" % (depth, depth))
            return
        if tok == FDT_BEGIN_NODE:
            z = data.find(b"\0", p)
            if z < 0 or z >= end:
                yield ("error", depth, at, "unterminated node name")
                return
            name = data[p:z].decode("utf-8", "replace")
            p = (z + 1 + 3) & ~3
            yield ("node", depth, at, name)
            depth += 1
            continue
        if tok == FDT_END_NODE:
            depth -= 1
            if depth < 0:
                yield ("error", depth, at, "FDT_END_NODE without a matching FDT_BEGIN_NODE")
                return
            yield ("endnode", depth, at, None)
            continue
        if tok == FDT_PROP:
            if p + 8 > end:
                yield ("error", depth, at, "truncated FDT_PROP header")
                return
            plen, nameoff = struct.unpack_from(">II", data, p)
            p += 8
            if ver < 16 and plen >= 8:
                p = (p + 7) & ~7
            if p + plen > len(data):
                yield ("error", depth, at,
                       "property value runs past the blob (len 0x%x at 0x%x)" % (plen, p))
                return
            val = bytes(data[p:p + plen])
            p = (p + plen + 3) & ~3
            name = _cstr(data, stroff + nameoff)
            yield ("prop", depth, at, (name, val, nameoff, plen))
            continue
        yield ("error", depth, at, "unknown token 0x%08x" % tok)
        return
    yield ("error", depth, p, "structure block ended without FDT_END")


def _printable_stringlist(val):
    if not val or val[-1] != 0:
        return False
    body = val[:-1]
    if not body:
        return True
    for part in body.split(b"\0"):
        if not part:
            return False
        for c in part:
            if c != 0x09 and (c < 0x20 or c > 0x7E):
                return False
    return True


def _fmt_stringlist(val):
    body = val[:-1]
    if not body:
        return '""'
    parts = body.split(b"\0")
    out = []
    for s in parts:
        t = s.decode("utf-8", "replace").replace("\\", "\\\\").replace('"', '\\"')
        out.append('"%s"' % t)
    return ", ".join(out)


def _fmt_cells(val):
    n = len(val) // 4
    return "<%s>" % " ".join("0x%08x" % struct.unpack_from(">I", val, i * 4)[0]
                             for i in range(n))


def _fmt_bytes(val):
    return "[%s]" % " ".join("%02x" % b for b in val)


def _be(val, off, cells):
    return int.from_bytes(val[off:off + cells * 4], "big") if cells else 0


def _decode_reg(val, ac, sc):
    stride = (ac + sc) * 4
    if stride <= 0 or not len(val) or len(val) % stride:
        return None
    out = []
    for i in range(0, len(val), stride):
        out.append((_be(val, i, ac), _be(val, i + ac * 4, sc)))
    return out


def _decode_ranges(val, child_ac, child_sc, parent_ac):
    stride = (child_ac + parent_ac + child_sc) * 4
    if stride <= 0 or not len(val) or len(val) % stride:
        return None
    out = []
    for i in range(0, len(val), stride):
        ca = _be(val, i, child_ac)
        pa = _be(val, i + child_ac * 4, parent_ac)
        ln = _be(val, i + (child_ac + parent_ac) * 4, child_sc)
        out.append((ca, pa, ln))
    return out


def fdt_format_value(name, val, parent_ac, parent_sc, own_ac, own_sc):
    """Return (dts_text, extra_lines) -- lossless, never truncated.

    parent_ac/parent_sc are the enclosing node's #address-cells/#size-cells,
    which is what `reg` is measured in; own_ac/own_sc are this node's own,
    which is what the child half of `ranges` is measured in.
    """
    if not val:
        return None, []
    extra = []
    if name in _STRING_PROPS and _printable_stringlist(val):
        return _fmt_stringlist(val), extra
    if name in _CELL_PROPS and len(val) % 4 == 0:
        return _fmt_cells(val), extra
    if name in _ADDR_PROPS:
        dec = _decode_reg(val, parent_ac, parent_sc)
        if dec is not None:
            for a, s in dec:
                extra.append("addr 0x%016x  size 0x%016x" % (a, s))
            return _fmt_cells(val), extra
    if name in _RANGE_PROPS:
        dec = _decode_ranges(val, own_ac, own_sc, parent_ac)
        if dec is not None:
            for ca, pa, ln in dec:
                extra.append("child 0x%016x -> parent 0x%016x  len 0x%016x" % (ca, pa, ln))
            return _fmt_cells(val), extra
    if _printable_stringlist(val):
        return _fmt_stringlist(val), extra
    if len(val) % 4 == 0:
        return _fmt_cells(val), extra
    return _fmt_bytes(val), extra


class FdtStats(object):
    def __init__(self):
        self.nodes = 0
        self.props = 0
        self.nops = 0
        self.prop_bytes = 0
        self.max_depth = 0
        self.errors = []
        self.end_offset = None
        self.name_offsets = set()


def fdt_dump_lines(data, hdr, want_hex=False, path=None, grep=None, terse=False):
    """Render the tree as DTS-shaped text. Yields lines; never truncates a value."""
    rx = re.compile(grep) if grep else None
    want = None
    if path:
        want = "/" if path == "/" else "/" + path.strip("/")

    cells = [(_DEFAULT_ADDRESS_CELLS, _DEFAULT_SIZE_CELLS)]
    names = []
    emitting = want is None
    base = 0

    for kind, depth, at, payload in fdt_walk(data, hdr):
        if kind in ("nop", "end", "error"):
            continue

        if kind == "node":
            name = payload
            names.append(name)
            cur = "/" if depth == 0 else "/" + "/".join(names[1:])
            if want is not None and not emitting and cur == want:
                emitting, base = True, depth
            if emitting and rx is None:
                yield "%s%s {" % ("    " * (depth - base), name if name else "/")
            cells.append((_DEFAULT_ADDRESS_CELLS, _DEFAULT_SIZE_CELLS))
            continue

        if kind == "endnode":
            if emitting and rx is None:
                yield "%s};" % ("    " * (depth - base))
            if len(cells) > 1:
                cells.pop()
            if names:
                names.pop()
            if want is not None and emitting and depth == base:
                emitting = False
            continue

        name, val, nameoff, plen = payload
        if name is None:
            name = "<bad-nameoff-0x%x>" % nameoff
        d = depth - 1
        if 0 <= d < len(cells) - 1:
            if name == "#address-cells" and len(val) >= 4:
                cells[d + 1] = (struct.unpack_from(">I", val, 0)[0], cells[d + 1][1])
            elif name == "#size-cells" and len(val) >= 4:
                cells[d + 1] = (cells[d + 1][0], struct.unpack_from(">I", val, 0)[0])
        default = (_DEFAULT_ADDRESS_CELLS, _DEFAULT_SIZE_CELLS)
        parent_ac, parent_sc = cells[d] if 0 <= d < len(cells) else default
        own_ac, own_sc = cells[d + 1] if 0 <= d + 1 < len(cells) else default
        text, extra = fdt_format_value(name, val, parent_ac, parent_sc, own_ac, own_sc)

        if rx is not None:
            cur = "/" if len(names) <= 1 else "/" + "/".join(names[1:])
            hay = "%s:%s = %s" % (cur, name, text if text is not None else "")
            if rx.search(hay):
                yield hay
            continue
        if not emitting:
            continue

        ind = "    " * (depth - base)
        yield "%s%s;" % (ind, name) if text is None else "%s%s = %s;" % (ind, name, text)
        if terse:
            continue
        for e in extra:
            yield "%s        %s" % (ind, e)
        if want_hex and val:
            for i in range(0, len(val), 16):
                yield "%s        %04x  %s" % (
                    ind, i, " ".join("%02x" % b for b in val[i:i + 16]))


def fdt_tree_lines(data, hdr):
    names = []
    for kind, depth, at, payload in fdt_walk(data, hdr):
        if kind == "node":
            names.append(payload)
            label = payload if payload else "/"
            yield "%s%s" % ("    " * depth, label)
        elif kind == "endnode" and names:
            names.pop()


def fdt_collect(data, hdr):
    """Walk once and return an FdtStats (used for the trailing summary)."""
    stats = FdtStats()
    for kind, depth, at, payload in fdt_walk(data, hdr):
        if kind == "node":
            stats.nodes += 1
            stats.max_depth = max(stats.max_depth, depth)
        elif kind == "prop":
            stats.props += 1
            stats.prop_bytes += payload[3]
            stats.name_offsets.add(payload[2])
        elif kind == "nop":
            stats.nops += 1
        elif kind == "end":
            stats.end_offset = at
        elif kind == "error":
            stats.errors.append("0x%08x: %s" % (at, payload))
    return stats


_PHYS_WORDS_PER_XP = 4096
_CHUNK = 32 << 10


@safe(default=None)
def _read_chunk(addr, n, phys):
    if not phys:
        return read_guest_bytes(addr, n)
    base = addr & ~7
    words = min((n + (addr & 7) + 7) // 8, _PHYS_WORDS_PER_XP)
    got = read_phys_words(base, words)
    if not got:
        return None
    raw = b"".join(struct.pack("<Q", w) for w in got)
    return raw[addr & 7:][:n]


@safe(default=None)
def _read_blob_bytes(addr, n, phys=False):
    """Read n bytes, in pieces small enough for both transports.

    QEMU's HMP `xp` is capped at 4096 words per command, and a single oversized
    virtual read fails atomically even when most of the range is mapped, so a
    failed piece is retried at decreasing sizes before giving up.  A short read
    is returned as-is; the caller reports it rather than pretending it is whole.
    """
    if n <= 0 or n > FDT_MAX_TOTALSIZE:
        return None
    out = bytearray()
    cur, left = addr, n
    while left > 0:
        step = min(left, _CHUNK)
        chunk = _read_chunk(cur, step, phys)
        if not chunk:
            for small in (4096, 1024, 256):
                chunk = _read_chunk(cur, min(left, small), phys)
                if chunk:
                    break
        if not chunk:
            break
        out.extend(chunk)
        cur += len(chunk)
        left -= len(chunk)
    return bytes(out) if out else None


@safe(default=None)
def _p2v(pa):
    from .session import SESSION
    return SESSION.p2v(pa)


@safe(default=[])
def fdt_candidates():
    """Blob addresses worth probing, as (addr, how, phys) in priority order.

    Which one is right depends on the MMU regime, so every plausible reading of
    both pointers is offered and the caller keeps the first that shows FDT
    magic.  All of them are reads; probing a wrong one costs nothing.
    """
    out = []
    v = evi("initial_boot_params")
    if v:
        v &= MASK
        out.append((v, "initial_boot_params", False))
        out.append((v, "initial_boot_params, read as physical", True))
    v = evi("__fdt_pointer")
    if v:
        pa = v & MASK
        out.append((pa, "__fdt_pointer, read as physical", True))
        va = _p2v(pa)
        if va:
            out.append((va, "__fdt_pointer via kp2v", False))
        out.append((pa, "__fdt_pointer, read directly", False))
    return out


@safe(default=None)
def fdt_probe(addr, phys):
    """Read the 40-byte header at addr; return it when the magic is right."""
    head = _read_blob_bytes(addr, 40, phys)
    if not head or len(head) < 40:
        return None
    if int.from_bytes(head[0:4], "big") != FDT_MAGIC:
        return None
    total = int.from_bytes(head[4:8], "big")
    if total < 40 or total > FDT_MAX_TOTALSIZE:
        return None
    return head


class KDtb(gdb.Command):
    """kdtb [OPTIONS] [ADDR] : dump the LIVE flattened device tree, in full.

The kernel keeps the DTB verbatim in memory long after boot, but nothing in gdb
can read it: `lx-*` has no FDT support, the unflattened `of_*` tree does not
exist yet during setup_arch, and by the time it does the blob is still the only
place the raw values live.  kdtb parses the blob straight out of guest memory
and prints EVERYTHING -- header, memory reservation block, every node, every
property -- with no truncation and no sampling.  Read-only; it never writes to
the target.

The blob address is found automatically from `initial_boot_params` (set by
early_init_dt_scan, so it is already valid inside setup_arch), falling back to
`__fdt_pointer`.  Pass any expression to override:  kdtb $x22,  kdtb 0x40000000.

OPTIONS
  --header, -H     header fields + structural sanity checks only
  --rsv            memory reservation block only
  --tree           node names only, no properties
  --path P         restrict the dump to the subtree at path P  (kdtb --path /soc)
  --grep RE        print every 'path:prop = value' matching a python regex
  --hex            add the full raw bytes of every property, 16 per line
  --terse          drop the decoded reg/ranges annotations
  --phys           treat the address as PHYSICAL and read via the QEMU monitor
                   (use while the MMU is still off, or for a raw PA)
  --save FILE      write the raw blob to FILE, then:  dtc -I dtb -O dts FILE
  --stats          summary only

Everything degrades to a message instead of an exception, so a bad address or a
dead memory-read path can never take the session down."""

    def __init__(self, name="kdtb"):
        super(KDtb, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        toks = (arg or "").split()
        opts = {"header": False, "rsv": False, "tree": False, "hex": False,
                "terse": False, "phys": False, "stats": False}
        path = grep = save = None
        expr_parts = []
        i = 0
        while i < len(toks):
            t = toks[i]
            if t in ("--header", "-H"):
                opts["header"] = True
            elif t == "--rsv":
                opts["rsv"] = True
            elif t == "--tree":
                opts["tree"] = True
            elif t == "--hex":
                opts["hex"] = True
            elif t == "--terse":
                opts["terse"] = True
            elif t == "--phys":
                opts["phys"] = True
            elif t == "--stats":
                opts["stats"] = True
            elif t == "--path" and i + 1 < len(toks):
                i += 1
                path = toks[i]
            elif t == "--grep" and i + 1 < len(toks):
                i += 1
                grep = toks[i]
            elif t == "--save" and i + 1 < len(toks):
                i += 1
                save = toks[i]
            elif t.startswith("-"):
                print("[%s] kdtb: unknown option %s" % (NAME, t))
                return
            else:
                expr_parts.append(t)
            i += 1

        expr = " ".join(expr_parts).strip()
        if expr:
            a = evi(expr)
            if a is None:
                print("[%s] kdtb: cannot evaluate '%s'" % (NAME, expr))
                return
            a &= MASK
            cands = [(a, "argument '%s', read as physical" % expr, True)] if opts["phys"] \
                else [(a, "argument '%s'" % expr, False),
                      (a, "argument '%s', read as physical" % expr, True)]
        else:
            cands = fdt_candidates()
            if opts["phys"]:
                cands = [(x, h, True) for (x, h, _) in cands]
            if not cands:
                print("[%s] kdtb: no FDT pointer is set yet.\n"
                      "        initial_boot_params only becomes valid inside setup_arch "
                      "(early_init_dt_scan),\n"
                      "        and __fdt_pointer only after __mmap_switched stores it. "
                      "Before that the\n"
                      "        boot protocol still carries the blob's physical address "
                      "in x0 on arm64:\n"
                      "            kdtb --phys $x0\n"
                      "        Or break later -- at unflatten_device_tree both pointers "
                      "are set." % NAME)
                return

        addr = how = head = None
        phys = False
        for (a, h, p) in cands:
            hd = fdt_probe(a, p)
            if hd:
                addr, how, phys, head = a, h, p, hd
                break
        if addr is None:
            print("[%s] kdtb: no FDT magic at any candidate:" % NAME)
            for (a, h, p) in cands:
                print("        %s  %s%s" % (fmt(a), h, "  [phys]" if p else ""))
            print("        The first word must be 0xedfe0dd0. If every read on this target "
                  "returns\n        zero, the memory path is down -- check with  x/1wx 0x%x."
                  % (cands[0][0] & MASK))
            return

        try:
            hdr0 = fdt_parse_header(head)
        except FdtError as e:
            print("[%s] kdtb: %s" % (NAME, e))
            return
        total = hdr0["totalsize"]
        span, bounded = fdt_content_span(hdr0)

        data = _read_blob_bytes(addr, span, phys)
        if not data:
            print("[%s] kdtb: header read at %s but the %d-byte body did not.\n"
                  "        Retry the other transport:  kdtb %s0x%x"
                  % (NAME, fmt(addr), span, "" if phys else "--phys ", addr & MASK))
            return
        if len(data) < span:
            print("[%s] kdtb: SHORT READ -- %d of %d bytes; output below is partial"
                  % (NAME, len(data), span))

        try:
            hdr = fdt_parse_header(data)
        except FdtError as e:
            print("[%s] kdtb: %s" % (NAME, e))
            return

        if save:
            blob = data
            if total > len(data):
                full = _read_blob_bytes(addr, total, phys)
                if full and len(full) >= len(data):
                    blob = full
                else:
                    print("[%s] kdtb: could not read the padding past 0x%x; saving the "
                          "%d content bytes only" % (NAME, span, len(data)))
            try:
                p = os.path.expanduser(save)
                with open(p, "wb") as f:
                    f.write(blob)
                print("[%s] kdtb: wrote %d bytes to %s" % (NAME, len(blob), p))
                print("        cross-check with:  dtc -I dtb -O dts -o %s.dts %s" % (p, p))
            except Exception as e:
                print("[%s] kdtb: cannot write %s: %s" % (NAME, save, e))
            return

        print("[%s] FDT at %s  (%s)%s" % (NAME, fmt(addr), how,
                                          "  [physical read]" if phys else ""))
        if span < total:
            print("        read %d content bytes of totalsize 0x%x; the rest is padding"
                  % (len(data), total))
        elif not bounded:
            print("        version %d gives no block sizes, so the full 0x%x bytes were read"
                  % (hdr["version"], total))
        self._print_header(data, hdr)
        if opts["header"]:
            return

        self._print_rsv(data, hdr)
        if opts["rsv"]:
            return

        stats = fdt_collect(data, hdr)
        if opts["stats"]:
            self._print_stats(data, hdr, stats)
            return

        if opts["tree"]:
            print("")
            for ln in fdt_tree_lines(data, hdr):
                print(ln)
            self._print_stats(data, hdr, stats)
            return

        print("")
        if not grep:
            print("/dts-v1/;")
            print("")
        emitted = 0
        for ln in fdt_dump_lines(data, hdr, want_hex=opts["hex"], path=path,
                                 grep=grep, terse=opts["terse"]):
            print(ln)
            emitted += 1
        if path and emitted == 0:
            print("(no node at path '%s')" % path)
        if grep and emitted == 0:
            print("(no property matches /%s/)" % grep)
        self._print_stats(data, hdr, stats)

    def _print_header(self, data, hdr):
        print("  header")
        for k in _HDR_FIELDS:
            v = hdr[k]
            if k in ("magic",):
                print("    %-18s 0x%08x" % (k, v))
            elif k in ("version", "last_comp_version", "boot_cpuid_phys"):
                print("    %-18s %d" % (k, v))
            else:
                print("    %-18s 0x%-8x (%d)" % (k, v, v))
        for n in fdt_header_notes(data, hdr):
            print("    ! %s" % n)

    def _print_rsv(self, data, hdr):
        entries, terminated = fdt_reservations(data, hdr)
        print("  memory reservations (%d)" % len(entries))
        if not entries:
            print("    (none)")
        for i, (a, s) in enumerate(entries):
            print("    [%d] 0x%016x  len 0x%016x  (%d bytes)" % (i, a, s, s))
        if not terminated:
            print("    ! reservation block is not terminated by a {0,0} entry")

    def _print_stats(self, data, hdr, stats):
        used = len(stats.name_offsets)
        print("")
        print("  summary")
        print("    nodes %d   properties %d   max depth %d   NOPs %d"
              % (stats.nodes, stats.props, stats.max_depth, stats.nops))
        print("    property payload %d bytes   distinct property names %d" % (stats.prop_bytes, used))
        if stats.end_offset is not None:
            consumed = stats.end_offset + 4 - hdr["off_dt_struct"]
            print("    struct block consumed 0x%x of 0x%x bytes"
                  % (consumed, hdr["size_dt_struct"] or consumed))
        else:
            print("    ! FDT_END never reached")
        tail = len(data) - (hdr["off_dt_strings"] + hdr["size_dt_strings"]) \
            if hdr["size_dt_strings"] else 0
        if tail > 0:
            print("    %d trailing byte(s) after the strings block" % tail)
        for e in stats.errors:
            print("    ! %s" % e)


__all__ = ['FDT_MAGIC', 'FDT_BEGIN_NODE', 'FDT_END_NODE', 'FDT_PROP', 'FDT_NOP',
           'FDT_END', 'FdtError', 'FdtStats', 'fdt_parse_header', 'fdt_header_notes',
           'fdt_reservations', 'fdt_walk', 'fdt_format_value', 'fdt_dump_lines',
           'fdt_tree_lines', 'fdt_collect', 'fdt_locate', 'KDtb']
