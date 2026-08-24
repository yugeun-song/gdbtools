"""part of gdbtools; see the package docstring."""
import os
import json
import struct
import gdb
import re
from .runtime import *
from . import state
from .arch import detect_arch


# ----------------------------------------------------------------------------
# cfgdis -- disassembly WITH radare2/pdf-style branch arrows in the left margin.
#
# Regime-independent by construction: it drives gdb's own `disassemble`, which
# resolves whatever address space is live -- PHYSICAL in the pre-MMU head.S
# phase AND VIRTUAL once paging is on -- so the same command keeps working for
# the whole session, not just early boot.  Pure host-side (no target writes),
# and like every command here it can never raise into the session.  With an
# unknown arch it still prints, just without arrows.
#
# Arrows come from the disassembly text alone: for each direct jump whose target
# is another instruction ON SCREEN we add an edge, pack the edges into
# non-overlapping vertical "tracks" (widest span outermost, like radare2), then
# paint corners/verticals/crossings with an arrowhead '>' at the landing line.
# ----------------------------------------------------------------------------
_DIS_LINE = re.compile(
    r"^\s*(=>)?\s*(0x[0-9a-fA-F]+)\s*(?:<[^>]*>)?\s*:\s+(.*\S)\s*$")

_KDIS_UTF = {"v": "│", "tl": "┌", "bl": "└", "h": "─",
             "x": "┼", "tu": "┴", "td": "┬", "head": ">"}
_KDIS_ASC = {"v": "|", "tl": ".", "bl": "`", "h": "-",
             "x": "+", "tu": "+", "td": "+", "head": ">"}

_KDIS_ANSI = {
    "reset": "\033[0m", "arrow": "\033[33m", "addr": "\033[38;5;245m",
    "br": "\033[1;33m", "mnem": "\033[36m", "sym": "\033[32m",
    "num": "\033[38;5;209m", "pc": "\033[1;32m",
}


def _kdis_parse(txt):
    header, rows = "", []
    for ln in (txt or "").splitlines():
        s = ln.strip()
        if s.startswith("Dump of assembler"):
            header = s.rstrip(":")
            continue
        if s.startswith("End of assembler"):
            continue
        m = _DIS_LINE.match(ln)
        if not m:
            continue
        insn = m.group(3)
        parts = insn.split(None, 1)
        rows.append((int(m.group(2), 16) & MASK, bool(m.group(1)),
                     parts[0], parts[1].strip() if len(parts) > 1 else ""))
    return header, rows


def _kdis_disasm(arg):
    """Drive gdb's disassembler; return (header, rows) with
    rows = [(addr:int, is_pc:bool, mnem:str, ops:str)]."""
    a = (arg or "").strip()
    # cfgdis renders its own columns, so gdb's display modifiers (/r raw bytes,
    # /s|/m source) would only corrupt the parse -- drop a leading one.  A
    # location/range never begins with '/', so this is unambiguous.
    a = re.sub(r"^/\S+\s*", "", a)
    if a:
        return _kdis_parse(execstr("disassemble %s" % a))
    header, rows = _kdis_parse(execstr("disassemble"))
    if not rows:                          # no current-function frame: fall back to $pc
        pc = reg("pc")
        if pc is not None:
            header, rows = _kdis_parse(execstr("disassemble 0x%x, +0x60" % pc))
    return header, rows


def _kdis_edges(rows, arch):
    """One edge per direct jump whose target is another visible instruction."""
    idx = {}
    for i, r in enumerate(rows):
        idx.setdefault(r[0], i)
    edges = []
    if arch is None:
        return edges
    for i, (_addr, _pc, mnem, ops) in enumerate(rows):
        t = arch.branch_target(mnem, ops)
        if t is None:
            continue
        j = idx.get(t)
        if j is None or j == i:
            continue
        top, bot = (i, j) if i < j else (j, i)
        edges.append({"top": top, "bot": bot, "dst": j})
    return edges


def _kdis_tracks(edges):
    """Assign each edge a track column: widest span first, greedily to the
    leftmost column with no overlapping (or touching) edge.  Returns #columns."""
    order = sorted(range(len(edges)),
                   key=lambda k: (edges[k]["top"] - edges[k]["bot"], edges[k]["top"]))
    occ = []                              # occ[col] = [(top,bot), ...]
    for k in order:
        t, b = edges[k]["top"], edges[k]["bot"]
        c = 0
        while True:
            if c == len(occ):
                occ.append([])
            if all(b < ot or ob < t for (ot, ob) in occ[c]):
                occ[c].append((t, b))
                edges[k]["col"] = c
                break
            c += 1
    return len(occ)


def _kdis_gutter(nrows, edges, g):
    """Render the arrow gutter as one string per row.  Track columns 0..ncols-1
    hold the verticals/corners; column ncols is the shared arrowhead lane so all
    heads line up just left of the address."""
    ncols = _kdis_tracks(edges) if edges else 0
    if not ncols:
        return [""] * nrows
    grid = [[" "] * (ncols + 1) for _ in range(nrows)]
    for e in edges:                       # verticals through the interior
        c = e["col"]
        for r in range(e["top"] + 1, e["bot"]):
            if grid[r][c] == " ":
                grid[r][c] = g["v"]
    for e in edges:                       # corner at each endpoint
        grid[e["top"]][e["col"]] = g["tl"]
        grid[e["bot"]][e["col"]] = g["bl"]
    for e in edges:                       # BOTH endpoints get an equal-length
        c = e["col"]                      # horizontal reaching the address column
        for row in (e["top"], e["bot"]):  # (source and destination line up); the
            for col in range(c + 1, ncols):   # landing caps with '>', the source
                ch = grid[row][col]           # with a plain stroke -- same length
                if ch == g["v"]:
                    grid[row][col] = g["x"]    # cross another track
                elif ch == g["bl"]:
                    grid[row][col] = g["tu"]   # pass through a landing corner -> tee
                elif ch == g["tl"]:
                    grid[row][col] = g["td"]   # pass through a starting corner -> tee
                elif ch == " ":
                    grid[row][col] = g["h"]
            if row == e["dst"]:
                grid[row][ncols] = g["head"]
            elif grid[row][ncols] != g["head"]:
                grid[row][ncols] = g["h"]
    return ["".join(r) for r in grid]


def _kdis_ops(ops, C):
    """Light syntax colour for operands: '<sym+off>' green, 0x-immediates warm."""
    if not ops or not C["reset"]:
        return ops
    def repl(m):
        if m.group("sym"):
            return C["sym"] + m.group(0) + C["reset"]
        return C["num"] + m.group(0) + C["reset"]
    return re.sub(r"(?P<sym><[^>]*>)|(?P<num>0x[0-9a-fA-F]+)", repl, ops)


def _kdis_lines(rows, arch, color=True, ascii_mode=False):
    """Format disassembled rows WITH radare2-style branch arrows -> list of
    printable strings (no header).  Shared by the `cfgdis` command and the pwndbg
    'arrows' context section, so both render identically."""
    if not rows:
        return []
    edges = _kdis_edges(rows, arch)
    g = _KDIS_ASC if ascii_mode else _KDIS_UTF
    gutters = _kdis_gutter(len(rows), edges, g)
    gw = max((len(x) for x in gutters), default=0)
    C = _KDIS_ANSI if color else {k: "" for k in _KDIS_ANSI}
    R = C["reset"]
    awidth = max(8, len("%x" % max(r[0] for r in rows)))
    brm = arch.BRANCH_RE if arch is not None else None
    norm = arch.normalize_mnem if arch is not None else (lambda m: m)
    out = []
    for i, (addr, is_pc, mnem, ops) in enumerate(rows):
        gut = gutters[i].ljust(gw)
        if color and gut.strip():
            gut = C["arrow"] + gut + R
        mk = (C["pc"] + "=>" + R) if is_pc else "  "
        dmnem = norm(mnem)                               # Capstone spelling, to match pwndbg
        dops = re.sub(r"\s*(?://|;).*$", "", ops)        # drop binutils alias/comment hint
        mcol = C["br"] if (brm and brm.match(dmnem)) else C["mnem"]
        acol = C["pc"] if is_pc else C["addr"]
        out.append("%s %s %s0x%0*x%s  %s%-7s%s %s" % (
            mk, gut, acol, awidth, addr, R, mcol, dmnem, R, _kdis_ops(dops, C)))
    return out


class CfgDis(gdb.Command):
    """cfgdis [ascii] [mono] [WHAT] : disassemble WHAT with radare2-style branch
arrows in the left margin (arrowhead '>' at every in-view jump target).  WHAT is
a location or range gdb's `disassemble` accepts (its /r,/s,/m display modifiers
are ignored -- cfgdis draws its own columns) -- omit it for the current function:
    cfgdis                       current function ($pc,+0x60 if $pc is not in one)
    cfgdis start_kernel          by symbol or address
    cfgdis 0x80200000, +0x80     an explicit range
    cfgdis __memset, __memset+0x40
Options: `ascii` (ASCII glyphs for non-UTF terminals), `mono` (no colour).
Works in every regime -- physical early-boot addresses and virtual post-MMU
addresses alike -- so it stays useful for the whole session, not just before the
MMU comes up.  Arrows cover *jumps* (conditional branches + the unconditional
intra-function jump), not calls -- exactly like radare2's linear view."""

    def __init__(self, name="cfgdis"):
        super(CfgDis, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        toks = (arg or "").split()
        ascii_mode = False
        color = not _env("NO_COLOR")
        while toks and (toks[0].startswith("/")
                        or toks[0].lower() in ("ascii", "utf8", "mono", "nocolor", "color")):
            t = toks.pop(0).lower()
            if t.startswith("/"):
                continue                  # gdb display modifier (/r,/s,/m): cfgdis draws its own columns
            if t == "ascii":
                ascii_mode = True
            elif t == "utf8":
                ascii_mode = False
            elif t in ("mono", "nocolor"):
                color = False
            elif t == "color":
                color = True
        what = " ".join(toks)
        header, rows = _kdis_disasm(what)
        if not rows:
            print("[%s] cfgdis: nothing to disassemble (%s)"
                  % (NAME, what or "current function"))
            return
        _s = state.session()
        arch = (_s.ensure_arch() if _s else None) or detect_arch()
        if header:
            print(header)
        for ln in _kdis_lines(rows, arch, color=color, ascii_mode=ascii_mode):
            print(ln)
        if arch is None:
            print("[%s] cfgdis: arch unknown -> arrows disabled (plain listing)" % NAME)
