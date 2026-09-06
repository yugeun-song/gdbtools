"""`kmemblock` -- the memory map the kernel was handed, before it owns one.

memblock is what the kernel has instead of a page allocator for the whole of
early boot: firmware's or the DT's memory ranges in `memblock.memory`, and every
range claimed back out of them in `memblock.reserved`.  Between `_text` and
`mem_init()` it is the only description of RAM that exists, and it is exactly
the window this package debugs in.

Everything about its shape is read from DWARF, never assumed, because the shape
moved across the versions this workspace holds:

  4.6      region.flags is `unsigned long` with no named type; memblock_type has
           no `name`; physmem is a member of `struct memblock`.
  6.12     flags is `enum memblock_flags` (5 values); memblock_type gained
           `name`; physmem left the struct for a file-scope static.
  mainline the same, with MEMBLOCK_RSRV_KERN and MEMBLOCK_RSRV_HUGETLB added.

So the members are discovered by walking the struct's fields and the flag names
come from the DWARF type of the flags field itself.  A version that adds a flag
or renames a member is described correctly without being taught about.
"""
import gdb

from ..common.runtime import *
from .session import SESSION


CAP = 512          # regions printed per type before truncating; raise with $GDBTOOLS_MEMBLOCK_CAP


def _mib(n):
    if n >= (1 << 30) and n % (1 << 30) == 0:
        return "%d GiB" % (n >> 30)
    if n >= (1 << 20):
        return "%.1f MiB" % (n / float(1 << 20))
    if n >= (1 << 10):
        return "%.1f KiB" % (n / float(1 << 10))
    return "%d B" % n


@safe(default=None)
def _flag_names(field_type):
    """{bit value: name} from the DWARF type of memblock_region.flags.

    An enum gives the names; 4.6's plain `unsigned long` gives nothing, and the
    caller then prints the raw value rather than inventing labels for it.
    """
    try:
        if field_type.code != gdb.TYPE_CODE_ENUM:
            return None
    except Exception:
        return None
    out = {}
    for f in field_type.fields():
        v = int(getattr(f, "enumval", 0))
        if v:
            out[v] = f.name
    return out or None


def _decode_flags(val, names):
    if not names:
        return "0x%x" % val
    if val == 0:
        return "0x0 NONE"
    hit = [n for v, n in sorted(names.items()) if val & v]
    left = val & ~sum(v for v in names if val & v)
    if left:
        hit.append("0x%x?" % left)
    return "0x%x %s" % (val, "|".join(hit))


@safe(default=None)
def _types_of(mb):
    """[(label, gdb.Value of struct memblock_type)] for this kernel.

    The members of `struct memblock` that ARE a memblock_type, in declaration
    order, plus the file-scope `physmem` that 5.10 moved out of the struct.  Both
    spellings are found the same way -- by type, not by a name this code carries.
    """
    out = []
    try:
        fields = mb.type.fields()
    except Exception:
        return None
    for f in fields:
        try:
            if f.type.tag == "memblock_type":
                out.append((f.name, mb[f.name]))
        except Exception:
            continue
    if not any(n == "physmem" for n, _ in out):
        pm = ev("physmem")
        if pm is not None:
            try:
                if pm.type.tag == "memblock_type":
                    out.append(("physmem", pm))
            except Exception:
                pass
    return out


@safe(default=None)
def _liveness():
    """"freed" / "live" / "unbuilt", or None when this kernel cannot say.

    6.x keeps `memblock_memory` pointing at `memblock.memory` and sets it to
    NULL inside memblock_discard().  Reading NULL is not enough to call it
    freed, because it has a second cause.

    memblock_discard() is a real function only where ARCH_KEEP_MEMBLOCK is
    unset -- x86_64 here, since the only symbol selecting it is INTEL_TDX_HOST.
    arm64 and riscv compile it to an empty static inline, so the symbol does not
    exist and nothing there can ever NULL the pointer.

    And a CONFIG_RELOCATABLE riscv64 image keeps a relocated pointer's value in
    the RELA addend rather than in .data, so `memblock_memory` reads 0 from
    _start until relocate_kernel() runs inside setup_vm() -- before the MMU is
    even on.  `memblock.memory.regions` reads 0 with it, and memblock_discard()
    never NULLs regions, so regions==0 with max!=0 is the not-yet-relocated
    signature and not a freed one.  Before this, `kmemblock` on either riscv
    tree announced "arrays FREED" on a kernel that cannot discard them.

    4.6 has no such pointer at all, and the answer is then honestly unknown.
    """
    v = ev("memblock_memory")
    if v is None:
        return None
    try:
        if int(v) != 0:
            return "live"
    except Exception:
        return None
    if symval("memblock_discard") is None:
        return "unbuilt"
    try:
        if int(ev("memblock.memory.regions")) == 0 and int(ev("memblock.memory.max")) != 0:
            return "unbuilt"
    except Exception:
        pass
    return "freed"


class KMemblock(gdb.Command):
    """kmemblock [TYPE] [full] : the kernel's early memory map, from memblock.

TYPE is one of the memblock types this kernel has -- memory, reserved, and
physmem where it exists -- and with none given, every one of them.
`full` lifts the per-type region cap ($GDBTOOLS_MEMBLOCK_CAP, default 512).

memory   is what firmware or the device tree said exists.
reserved is what has been claimed back out of it: the kernel image, the initrd,
         the DT, the early page tables, every memblock_alloc so far.

Valid from the kernel's first instruction until mem_init().  After that it
depends on CONFIG_ARCH_KEEP_MEMBLOCK -- arm64 and riscv select it, x86_64 does
not -- and this says which case it is looking at rather than printing a freed
array as if it were live."""

    def __init__(self, name="kmemblock"):
        super(KMemblock, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        parts = (arg or "").split()
        full = any(p.lower() == "full" for p in parts)
        want = [p for p in parts if p.lower() != "full"]
        cap = _env_int("MEMBLOCK_CAP") or CAP

        mb = ev("memblock")
        if mb is None:
            print("[%s] kmemblock: no `memblock` symbol in this image -- either the "
                  "vmlinux has no debug information for mm/memblock.c, or this is not "
                  "a kernel built with memblock at all" % NAME)
            return

        types = _types_of(mb)
        if not types:
            print("[%s] kmemblock: `memblock` is present but no member of it has type "
                  "`struct memblock_type`; the struct's shape is not what this reads" % NAME)
            return

        st, src = SESSION.mmu_state()
        gone = _liveness()
        state = {
            "freed": "arrays FREED (memblock_memory is NULL)",
            "live": "arrays live",
            "unbuilt": "arrays NOT SET UP YET (memblock_memory still reads 0 -- on a "
                       "relocatable image it holds its value in the RELA addend until "
                       "relocate_kernel() runs)",
        }.get(gone, "liveness unknown -- this kernel has no memblock_memory pointer")
        head = "[%s] memblock  %s" % (NAME, state)
        for extra in ("bottom_up", "current_limit"):
            try:
                v = mb[extra]
                head += "  %s=%s" % (extra, fmt(int(v)) if extra != "bottom_up" else bool(v))
            except Exception:
                pass
        print(head + "   [MMU=%s %s]" % (st, src))
        if gone == "freed":
            print("     the regions below were freed by memblock_discard(); what the "
                  "pointers reach now is whatever the page allocator put there.  This "
                  "is the normal state on x86_64 after mem_init(): ARCH_KEEP_MEMBLOCK "
                  "is selected only by INTEL_TDX_HOST there.")

        for label, t in types:
            if want and label not in want:
                continue
            self._one(label, t, cap, full)

        if want and not any(label in want for label, _ in types):
            print("[%s] no such memblock type here; this kernel has: %s"
                  % (NAME, " ".join(n for n, _ in types)))

    @safe()
    def _one(self, label, t, cap, full):
        try:
            cnt = int(t["cnt"])
            mx = int(t["max"])
            total = int(t["total_size"])
            regs = t["regions"]
        except Exception as e:
            print("  %-9s unreadable (%s)" % (label, e))
            return
        name = ""
        try:
            nm = t["name"]
            if int(nm) != 0:
                name = "  name=%s" % nm.string()
        except Exception:
            pass
        print("  %-9s cnt=%d/%d  total=%s (%s)%s" % (label, cnt, mx, fmt(total), _mib(total), name))
        if int(regs) == 0:
            print("      regions pointer is NULL -- nothing to read")
            return
        if cnt < 0 or cnt > mx or mx <= 0:
            # A freed array reads as whatever now occupies the page, and cnt is
            # then arbitrary.  Refuse rather than printing thousands of rows of
            # somebody else's data as a memory map.
            print("      cnt=%d against max=%d is not a possible state; the array is "
                  "stale or was freed, so nothing is printed" % (cnt, mx))
            return

        names = None
        try:
            names = _flag_names(regs.dereference()["flags"].type)
        except Exception:
            names = None
        shown = cnt if full else min(cnt, cap)
        for i in range(shown):
            try:
                r = regs[i]
                base = int(r["base"])
                size = int(r["size"])
                fl = int(r["flags"])
            except Exception as e:
                print("      [%3d] unreadable (%s)" % (i, e))
                break
            nid = ""
            try:
                nid = "  nid=%d" % int(r["nid"])
            except Exception:
                pass
            print("      [%3d] %s..%s  size %s (%s)  %s%s"
                  % (i, fmt(base), fmt(base + size - 1 if size else base), fmt(size),
                     _mib(size), _decode_flags(fl, names), nid))
        if shown < cnt:
            print("      ... %d more; `kmemblock %s full` for all of them"
                  % (cnt - shown, label))
        if names is None:
            print("      flags print as raw values: this kernel types them as a plain "
                  "integer, so DWARF carries no names for the bits")


__all__ = ["KMemblock"]
