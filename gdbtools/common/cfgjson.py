"""part of gdbtools; see the package docstring."""
import bisect
import json
import os
import re
import struct
import gdb
from .runtime import *
from .arch import detect_arch
from . import state
from .cfgdis import _kdis_parse, _kdis_edges, _kdis_tracks, _kdis_gutter, _KDIS_UTF


# cfgjson -- one JSON object per stop describing the function around an address:
# instructions, direct branches, gutter lanes, basic blocks and their edges.
#
# Structure only.  Whether a branch is taken depends on register state and the
# editor already has a per-ISA evaluator for it; two implementations would
# eventually disagree.
#
# Regime-independent like cfgdis: it disassembles whatever address space is live.
# Nothing is inferred -- a guessed bound says so, an absent source line says why,
# and an unknowable branch target is reported unresolved.

# Sizeless symbols have no end: `_text` is 16384 instructions on arm64 and
# `__entry_text_end` over a million on x86-64.
MAX_INSNS = 4096

# gdb hands out anonymous-CU blocks tens of megabytes wide in early boot.
MAX_BLOCK_SPAN = 256 * 1024

_SYM_SECTION = re.compile(r"\bin section (\S+)")
_SYM_NAME = re.compile(r"^(.+?)(?:\s*\+\s*(\d+))?\s+in section\b")


# ARM mapping symbols: `$d` marks where data begins, the only exact answer to
# "where does the code end" for a sizeless symbol.  Without it the listing at
# `_text` disassembles the PE/COFF header as SVE instructions.
#
# Read from the ELF because gdb hides mapping symbols from `info symbol`, and as
# raw structs because iterating pyelftools' symbol objects costs six seconds
# against eighty milliseconds.  Built lazily, only for a bound that is not solid.
_MAP_CACHE = {}
_SYM64 = struct.Struct("<IBBHQQ")


def _mapping_symbols(path):
    """Sorted link-time addresses where data begins, for `path`."""
    key = None
    try:
        stat = os.stat(path)
        key = (path, stat.st_mtime_ns, stat.st_size)
    except OSError:
        return None
    if key in _MAP_CACHE:
        return _MAP_CACHE[key]
    try:
        from elftools.elf.elffile import ELFFile
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            symtab = elf.get_section_by_name(".symtab")
            strtab = elf.get_section_by_name(".strtab")
            if symtab is None or strtab is None:
                _MAP_CACHE[key] = None
                return None
            raw, strs = symtab.data(), strtab.data()
        data = []
        for i in range(len(raw) // _SYM64.size):
            nm_off, _info, _other, _shndx, val, _size = _SYM64.unpack_from(raw, i * _SYM64.size)
            # '$' then 'd', two byte comparisons.
            if nm_off < len(strs) and strs[nm_off] == 0x24 and strs[nm_off + 1] == 0x64:
                data.append(val)
        data.sort()
    except Exception:
        data = None
    _MAP_CACHE[key] = data
    return data


def _link_address(addr):
    """`addr` as the linker saw it, or None.

    Which space `addr` is in comes from `addr`, never from the program counter:
    parked on the MMU crossing the counter is still physical while symbols are
    already relocated, and using the counter converts the wrong way."""
    sess = state.session()
    if sess is None or getattr(sess, "arch", None) is None:
        return None                       # no kernel session: addresses are already
                                          # what the linker saw
    try:
        va = addr
        if not sess.arch._is_va(addr):
            if sess.offset is None:
                return None
            va = sess.p2v(addr)
        if va is None:
            return None
        return (va - (sess.kaslr_slide or 0)) & MASK
    except Exception:
        return None


def _code_end(addr, hi):
    """`hi` pulled back to the first byte marked as data, when nearer.  Returns
    `hi` unchanged when unanswerable: a bound that shrank for an unknown reason
    is worse than a wide one."""
    prog = None
    try:
        prog = gdb.current_progspace().filename
    except Exception:
        pass
    if not prog:
        return hi
    table = _mapping_symbols(prog)
    if not table:
        return hi
    link = _link_address(addr)
    if link is None:
        return hi
    i = bisect.bisect_right(table, link)
    if i >= len(table):
        return hi
    return min(hi, addr + (table[i] - link))


def _arch_obj():
    """The gdb Architecture to disassemble with, without requiring a frame."""
    for get in (lambda: gdb.selected_frame().architecture(),
                lambda: gdb.selected_inferior().architecture()):
        try:
            a = get()
            if a is not None:
                return a
        except Exception:
            continue
    return None


def _pc():
    try:
        return reg("pc")
    except Exception:
        return None


def _info_symbol(addr):
    """(name, offset, section), or (None, None, None).  One round trip, so it is
    asked once per function."""
    txt = execstr("info symbol 0x%x" % addr) or ""
    if "No symbol matches" in txt:
        return None, None, None
    sec = _SYM_SECTION.search(txt)
    nm = _SYM_NAME.match(txt.strip())
    name = nm.group(1) if nm else None
    off = int(nm.group(2)) if (nm and nm.group(2)) else 0
    return name, off, (sec.group(1) if sec else None)


def _block_bounds(addr):
    """Function bounds from debug info, or None.  A block with no function and a
    block wider than any real function are both rejected."""
    try:
        b = gdb.block_for_pc(addr)
    except Exception:
        return None
    # The OUTERMOST enclosing function, not the first one found: an inlined
    # callee is a block with a function on it too, and stopping there reports
    # three instructions of memblock_cap_size as though they were the whole of
    # memblock_add_range.
    best = None
    depth = 0
    while b is not None and depth < 32:
        if getattr(b, "is_global", False) or getattr(b, "is_static", False):
            break
        if b.function is not None:
            best = b
        b = b.superblock
        depth += 1
    b = best
    if b is None or b.start is None or b.end is None:
        return None
    if b.end <= b.start or (b.end - b.start) > MAX_BLOCK_SPAN:
        return None
    return int(b.start) & MASK, int(b.end) & MASK


def _inlined_at(addr):
    """The inlined callee the address sits inside, if any.  Worth saying: the
    listing is the outer function, but these instructions came from another."""
    try:
        b = gdb.block_for_pc(addr)
    except Exception:
        return None
    names, depth = [], 0
    while b is not None and depth < 32:
        if getattr(b, "is_global", False) or getattr(b, "is_static", False):
            break
        if b.function is not None:
            names.append(b.function.name)
        b = b.superblock
        depth += 1
    # innermost first, outermost last; anything before the last is an inline
    return names[0] if len(names) > 1 else None


def _disassemble_bounds(addr):
    """Bounds from gdb's disassembler, which knows a minimal symbol's size with
    no debug info.  Bounds only: instructions come from the architecture API,
    which is far faster where there is no symtab to cache against."""
    txt = execstr("disassemble 0x%x" % addr)
    if not txt or "No function contains" in txt:
        return None
    _, rows = _kdis_parse(txt)
    if not rows:
        return None
    return rows[0][0], rows[-1][0] + 4


def _bounds(addr):
    """(lo, hi, how) where `how` records what the bound rests on, because a
    synthetic bound must never look like a real one."""
    b = _block_bounds(addr)
    if b:
        return b[0], b[1], "debug-info"
    b = _disassemble_bounds(addr)
    if b:
        lo, hi = b
        # A span this wide means a boundary label, not a function.  Only then
        # are mapping symbols consulted: inside a real function a `$d` is an
        # inline literal pool and cutting there would end it early.
        if (hi - lo) > 4 * MAX_INSNS:
            end = _code_end(lo, hi)
            if end < hi:
                return lo, end, "mapping-symbol"
        return lo, hi, "symbol-size"
    # Nothing named this address, so the only honest bound is a window.
    hi = (addr + 4 * MAX_INSNS) & MASK
    if hi <= addr:
        hi = MASK
    end = _code_end(addr, hi)
    return addr, end, "mapping-symbol" if end < hi else "window"


def _rows(arch_obj, lo, hi):
    """[(addr, is_pc, mnem, ops)] over [lo, hi), clamped, plus whether it was."""
    pc = _pc()
    out, clamped = [], False
    try:
        insns = arch_obj.disassemble(lo, hi - 1)
    except Exception as exc:
        raise RuntimeError("disassemble 0x%x..0x%x failed: %s" % (lo, hi, exc))
    for ins in insns:
        if len(out) >= MAX_INSNS:
            clamped = True
            break
        addr = int(ins["addr"]) & MASK
        parts = str(ins.get("asm", "")).split(None, 1)
        mnem = parts[0] if parts else ""
        ops = parts[1].strip() if len(parts) > 1 else ""
        out.append((addr, pc is not None and addr == (pc & MASK), mnem, ops))
    return out, clamped


def _line_of(addr):
    """(file, line), or (None, None).  Per address, not per section: inside a
    region that mostly has none there are functions that do."""
    try:
        sal = gdb.find_pc_line(addr)
    except Exception:
        return None, None
    if sal is None or not sal.line:
        return None, None
    st = sal.symtab
    return (st.fullname() if st else None), int(sal.line)


# Terminators per ISA.  NOT `Arch.BRANCH_RE`: that matches only branches an
# arrow can be drawn for, so `br x8` -- the MMU crossing itself -- is missing.
# By mnemonic and operands rather than disassembler groups, which were measured
# wrong on riscv64 (`ret` reports as a call, `c.jr ra` as a jump).
#
# A call is not a terminator: it returns, so the block continues through it.
_TERMS = {
    "Arm64": {
        "ret": ("ret",), "retaa": ("ret",), "retab": ("ret",),
        "eret": ("eret",), "eretaa": ("eret",), "eretab": ("eret",),
        "br": ("indirect",), "braa": ("indirect",), "brab": ("indirect",),
        "braaz": ("indirect",), "brabz": ("indirect",),
        "svc": ("trap",), "hvc": ("trap",), "smc": ("trap",),
        "brk": ("trap",), "hlt": ("trap",), "udf": ("undef",),
    },
    "X86_64": {
        "ret": ("ret",), "retq": ("ret",), "repz retq": ("ret",),
        "iret": ("eret",), "iretq": ("eret",), "sysret": ("eret",),
        "sysretq": ("eret",), "sysexit": ("eret",),
        "syscall": ("trap",), "sysenter": ("trap",), "int3": ("trap",),
        "int": ("trap",), "ud0": ("undef",), "ud1": ("undef",), "ud2": ("undef",),
    },
    "Riscv64": {
        "ret": ("ret",), "sret": ("eret",), "mret": ("eret",), "uret": ("eret",),
        "jr": ("indirect",), "c.jr": ("indirect",),
        "ecall": ("trap",), "ebreak": ("trap",), "c.ebreak": ("trap",),
        "unimp": ("undef",),
    },
}

# Control transfer through a register or memory.  The destination is knowable
# only at the moment control arrives, so away from the counter it is unresolved.
_INDIRECT_IF_NOT_IMMEDIATE = {
    "X86_64": ("jmp", "jmpq"),
    "Riscv64": ("jalr", "c.jalr", "j"),
}

_IMMEDIATE = re.compile(r"^[\$#]?0x[0-9a-fA-F]+$")


def _terminator(arch, mnem, ops):
    """What ends this row's block.  `indirect` is a real answer: the branch is
    there, its destination is not in the text."""
    if arch is None:
        return None
    key = arch.__class__.__name__
    m = arch.normalize_mnem(mnem)
    fixed = _TERMS.get(key, {}).get(m)
    if fixed:
        return fixed[0]
    if arch.BRANCH_RE and arch.BRANCH_RE.match(m):
        return "branch" if arch.branch_target(mnem, ops) is not None else "indirect"
    if m in _INDIRECT_IF_NOT_IMMEDIATE.get(key, ()):
        if arch.branch_target(mnem, ops) is not None:
            return "branch"
        first = re.sub(r"\s*<[^>]*>\s*$", "", (ops or "").split(",")[0].strip())
        return "branch" if _IMMEDIATE.match(first) else "indirect"
    return None


# A branch that has a fall-through as well as a target.  Needed to know whether a
# block has one successor or two, and, like the terminator table, written out per
# ISA rather than taken from a disassembler's instruction groups.
_CONDITIONAL = {
    "Arm64": re.compile(r"^(?:b\.[a-z]{2}|cbn?z|tbn?z)$"),
    "X86_64": re.compile(r"^(?:loop(?:e|ne|z|nz)?|j(?!mp$|mpq$)[a-z]{1,4})$"),
    "Riscv64": re.compile(r"^(?:c\.)?b(?:eq|ne|lt|ge|ltu|geu|eqz|nez|lez|gez|ltz|gtz|gt|le|gtu|leu)$"),
}

# Terminators that end a block without handing control to a successor inside this
# function.  An indirect branch belongs here: it goes somewhere, but where is not
# knowable from the text, and inventing an edge would be worse than showing none.
_NO_SUCCESSOR = frozenset(("ret", "eret", "indirect", "trap", "undef"))


def _blocks(rows, insns, arch):
    """Basic blocks and their edges.  Leaders: the first row, every row a branch
    lands on, and every row after a terminator."""
    n = len(rows)
    if n == 0:
        return [], []
    index = {}
    for i, r in enumerate(rows):
        index.setdefault(r[0], i)

    leaders = {0}
    targets = {}
    for i, (_a, _pc, mnem, ops) in enumerate(rows):
        term = insns[i]["terminator"]
        if term is None:
            continue
        if term == "branch":
            t = arch.branch_target(mnem, ops) if arch else None
            j = index.get(t) if t is not None else None
            if j is not None:
                leaders.add(j)
                targets[i] = j
        if i + 1 < n:
            leaders.add(i + 1)

    starts = sorted(leaders)
    block_of = {}
    for b, s in enumerate(starts):
        end = starts[b + 1] - 1 if b + 1 < len(starts) else n - 1
        for r in range(s, end + 1):
            block_of[r] = b

    blocks, edges = [], []
    for b, s in enumerate(starts):
        end = starts[b + 1] - 1 if b + 1 < len(starts) else n - 1
        term = insns[end]["terminator"]
        mnem = arch.normalize_mnem(rows[end][2]) if arch else rows[end][2]
        conditional = bool(_CONDITIONAL.get(arch.__class__.__name__ if arch else "", re.compile(r"^$")).match(mnem))
        blocks.append({
            "id": b, "first": s, "last": end,
            "start": "0x%x" % rows[s][0], "end": "0x%x" % rows[end][0],
            "terminator": term,
        })
        if term in _NO_SUCCESSOR:
            continue
        if term == "branch" and end in targets:
            edges.append({"from": b, "to": block_of[targets[end]],
                          "kind": "true" if conditional else "uncond"})
            if conditional and end + 1 < n:
                edges.append({"from": b, "to": block_of[end + 1], "kind": "false"})
        elif end + 1 < n:
            edges.append({"from": b, "to": block_of[end + 1], "kind": "fall"})
    return blocks, edges


def _succ_pred(nblocks, edges):
    succ = [[] for _ in range(nblocks)]
    pred = [[] for _ in range(nblocks)]
    for e in edges:
        succ[e["from"]].append(e["to"])
        pred[e["to"]].append(e["from"])
    return succ, pred


def _dominators(nblocks, pred, entry=0):
    """Immediate dominators, Cooper-Harvey-Kennedy.  A block dominating the one
    with the program counter has provably executed -- the only part of "was this
    path taken" answerable without guessing."""
    if nblocks == 0:
        return []
    order, seen = [], set()
    stack = [entry]
    # Reverse post-order over the successor graph, rebuilt from pred.
    succ = [[] for _ in range(nblocks)]
    for b in range(nblocks):
        for p in pred[b]:
            succ[p].append(b)
    def visit(u):
        seen.add(u)
        for v in succ[u]:
            if v not in seen:
                visit(v)
        order.append(u)
    try:
        visit(entry)
    except RecursionError:
        return [None] * nblocks
    rpo = list(reversed(order))
    pos = {b: i for i, b in enumerate(rpo)}
    idom = [None] * nblocks
    idom[entry] = entry

    def intersect(a, b):
        while a != b:
            while pos.get(a, 1 << 30) > pos.get(b, 1 << 30):
                a = idom[a]
                if a is None:
                    return b
            while pos.get(b, 1 << 30) > pos.get(a, 1 << 30):
                b = idom[b]
                if b is None:
                    return a
        return a

    changed = True
    while changed:
        changed = False
        for b in rpo:
            if b == entry:
                continue
            new = None
            for p in pred[b]:
                if idom[p] is None:
                    continue
                new = p if new is None else intersect(p, new)
            if new is not None and idom[b] != new:
                idom[b] = new
                changed = True
    return idom


def _chain(idom, b):
    out, seen = set(), set()
    while b is not None and b not in seen:
        seen.add(b)
        out.add(b)
        nxt = idom[b]
        if nxt == b:
            break
        b = nxt
    return out


def _reachable(start, succ):
    out, stack = set(), [start]
    while stack:
        u = stack.pop()
        if u in out:
            continue
        out.add(u)
        stack.extend(succ[u])
    return out


def _layer(nblocks, edges):
    """Rank by longest path from the entry ignoring back edges, then order within
    a rank by the average position of the predecessors.  Coordinates are left to
    the renderer: a character grid and a browser want different ones."""
    if nblocks == 0:
        return [], []
    succ, pred = _succ_pred(nblocks, edges)
    # Back edges by depth-first search, so ranking sees an acyclic graph.
    colour = [0] * nblocks
    back = set()

    def dfs(u):
        colour[u] = 1
        for i, e in enumerate(edges):
            if e["from"] != u:
                continue
            v = e["to"]
            if colour[v] == 1:
                back.add(i)
            elif colour[v] == 0:
                dfs(v)
        colour[u] = 2

    try:
        for b in range(nblocks):
            if colour[b] == 0:
                dfs(b)
    except RecursionError:
        back = set()

    forward = [e for i, e in enumerate(edges) if i not in back]
    fsucc, fpred = _succ_pred(nblocks, forward)
    rank = [0] * nblocks
    for _ in range(nblocks):
        moved = False
        for b in range(nblocks):
            for v in fsucc[b]:
                if rank[v] < rank[b] + 1:
                    rank[v] = rank[b] + 1
                    moved = True
        if not moved:
            break

    by_rank = {}
    for b in range(nblocks):
        by_rank.setdefault(rank[b], []).append(b)
    order = [0] * nblocks
    for r in sorted(by_rank):
        group = by_rank[r]
        if r > 0:
            group.sort(key=lambda b: (sum(order[p] for p in fpred[b]) / len(fpred[b])) if fpred[b] else b)
        for i, b in enumerate(group):
            order[b] = i
    return rank, order, sorted(back)


def _payload(addr):
    try:
        return _payload_unguarded(addr)
    except Exception as exc:
        return {"error": "%s: %s" % (type(exc).__name__, exc)}


def _payload_unguarded(addr):
    arch = detect_arch()
    arch_obj = _arch_obj()
    if arch_obj is None:
        return {"error": "no architecture available; is a target connected?"}

    lo, hi, how = _bounds(addr)
    rows, clamped = _rows(arch_obj, lo, hi)
    if not rows:
        return {"error": "nothing disassembled at 0x%x" % addr}

    name, _off, section = _info_symbol(lo)
    edges = _kdis_edges(rows, arch)
    ncols = _kdis_tracks(edges) if edges else 0
    gutter = _kdis_gutter(len(rows), edges, _KDIS_UTF)

    insns, missing = [], 0
    for i, (a, is_pc, mnem, ops) in enumerate(rows):
        f, line = _line_of(a)
        if line is None:
            missing += 1
        insns.append({
            "addr": "0x%x" % a,
            "mnemonic": arch.normalize_mnem(mnem) if arch else mnem,
            "operands": re.sub(r"\s*(?://|;).*$", "", ops),
            "is_pc": is_pc,
            "file": f,
            "line": line,
            "terminator": _terminator(arch, mnem, ops),
            "gutter": gutter[i],
        })

    why = None
    if missing:
        why = ("no line table covers %d of %d instructions%s"
               % (missing, len(insns), (" in section %s" % section) if section else ""))

    pc_row = next((i for i, r in enumerate(rows) if r[1]), None)
    blocks, bedges = _blocks(rows, insns, arch)
    if blocks:
        succ, pred = _succ_pred(len(blocks), bedges)
        rank, order, back = _layer(len(blocks), bedges)
        pc_block = None
        if pc_row is not None:
            for b in blocks:
                if b["first"] <= pc_row <= b["last"]:
                    pc_block = b["id"]
                    break
        # Two of these five are proved: a dominator has run, a post-dominator
        # will.  The rest are unknown rather than coloured as if settled.
        state = ["unknown"] * len(blocks)
        if pc_block is not None:
            idom = _dominators(len(blocks), pred)
            exits = [b["id"] for b in blocks if not succ[b["id"]]]
            rpred = [list(succ[b]) for b in range(len(blocks))]
            post = _dominators(len(blocks), rpred, exits[0]) if exits else None
            dom = _chain(idom, pc_block)
            pdom = _chain(post, pc_block) if post else set()
            fwd = _reachable(pc_block, succ)
            for b in range(len(blocks)):
                if b == pc_block:
                    state[b] = "current"
            for b in dom:
                if b != pc_block:
                    state[b] = "executed"
            for b in pdom:
                if b != pc_block and state[b] == "unknown":
                    state[b] = "will-execute"
            for b in range(len(blocks)):
                if state[b] == "unknown" and b not in fwd and pc_block not in _reachable(b, succ):
                    state[b] = "unreachable"
        for b in blocks:
            i = b["id"]
            b["rank"], b["order"], b["state"] = rank[i], order[i], state[i]
        for i, e in enumerate(bedges):
            e["back"] = i in back
    else:
        pc_block = None

    return {
        "arch": arch.__class__.__name__ if arch else None,
        "inlined_at": _inlined_at(addr),
        "blocks": blocks,
        "block_edges": bedges,
        "pc_block": pc_block,
        "function": {
            "name": name,
            "lo": "0x%x" % lo,
            "hi": "0x%x" % hi,
            "bounded_by": "clamp" if clamped else how,
        },
        "pc": ("0x%x" % (_pc() & MASK)) if _pc() is not None else None,
        "pc_row": pc_row,
        "gutter_width": (ncols + 1) if ncols else 0,
        "line_info": {"missing": missing, "total": len(insns), "why": why},
        "edges": [{"from": e["top"] if e["dst"] != e["top"] else e["bot"],
                   "to": e["dst"], "lane": e.get("col", 0)} for e in edges],
        "insns": insns,
    }


class CfgJson(gdb.Command):
    """cfgjson [ADDR] : one JSON object describing the function around ADDR
(default $pc).  Errors come back as {"error": ...} so a broken query is never
mistaken for an empty function."""

    def __init__(self, name="cfgjson"):
        super(CfgJson, self).__init__(name, gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        try:
            a = (arg or "").strip()
            addr = evi(a) if a else _pc()
            if addr is None:
                print(json.dumps({"error": "no address given and $pc unavailable"}))
                return
            print(json.dumps(_payload(int(addr) & MASK)))
        except Exception as exc:
            print(json.dumps({"error": "%s: %s" % (type(exc).__name__, exc)}))
