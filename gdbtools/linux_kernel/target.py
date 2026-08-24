"""part of gdbtools; see the package docstring."""
import gdb
import re
import struct
import json
import os
from ..common.runtime import *
from .dtb import *


# ----------------------------------------------------------------------------
# Target / machine descriptor.  Merges machine parameters from, high -> low:
#     explicit env flags  >  JSON profile ($GDBTOOLS_PROFILE)  >  DTB ($GDBTOOLS_DTB or
#     guest-RAM)  >  arch class defaults.
# Every field is optional; a missing field yields None so the caller falls back
# to the arch default.  This is what makes the tool work beyond the QEMU lab
# WITHOUT hardcoding any board's addresses into the code.
# ----------------------------------------------------------------------------
class Target:
    def __init__(self):
        self._prof = None          # parsed JSON profile dict
        self._dtb = None           # parsed DTB dict {'memory':[(base,size)],...}
        self._loaded = False

    @safe()
    def load(self):
        if self._loaded:
            return
        self._loaded = True
        pf = _env("PROFILE")
        if pf:
            self.set_profile(pf, quiet=True)
        dt = _env("DTB")
        if dt:
            self.set_dtb(dt, quiet=True)

    @safe(default=False)
    def set_profile(self, path, quiet=False):
        if not path or not os.path.isfile(path):
            if not quiet:
                print("[%s] profile not found: %s" % (NAME, path))
            return False
        with open(path) as f:
            self._prof = json.load(f)
        LOG.add("profile loaded: %s (%d keys)" %
                (path, len(self._prof) if isinstance(self._prof, dict) else 0))
        if not quiet:
            print("[%s] profile loaded: %s" % (NAME, path))
        return True

    @safe(default=False)
    def set_dtb(self, path, quiet=False):
        if not path or not os.path.isfile(path):
            if not quiet:
                print("[%s] dtb not found: %s" % (NAME, path))
            return False
        with open(path, "rb") as f:
            blob = f.read()
        d = parse_dtb(blob)
        if d is None:
            if not quiet:
                print("[%s] dtb parse failed: %s" % (NAME, path))
            return False
        self._dtb = d
        LOG.add("dtb loaded: %s (%d mem regions)" % (path, len(d.get("memory", []))))
        if not quiet:
            print("[%s] dtb loaded: %s -> memory=%s" %
                  (NAME, path, ", ".join("%s+%s" % (fmt(b), fmt(s)) for b, s in d.get("memory", [])) or "(none)"))
        return True

    @safe()
    def try_guest_dtb(self, arch):
        """Opportunistically read the DTB straight from guest RAM via the arch's
        boot-pointer register (arm64 x0 / riscv a1).  Only succeeds once we are
        stopped at/after the kernel entry where that register still holds the DTB
        PA; harmless otherwise (magic check fails -> None).  No QEMU needed."""
        if self._dtb is not None or arch is None:
            return
        regname = getattr(arch, "dtb_pointer_reg", None)
        if not regname:
            return
        pa = reg(regname)
        if pa is None:
            return
        d = read_guest_dtb(pa)
        if d and d.get("memory"):
            self._dtb = d
            LOG.add("dtb auto-read from guest @%s ($%s)" % (fmt(pa), regname))

    def _p(self, key):
        return self._prof.get(key) if isinstance(self._prof, dict) else None

    def ram_regions(self, arch):
        """[(base,size), ...] from profile ram_base/ram_size then DTB /memory."""
        self.load()
        self.try_guest_dtb(arch)
        out = []
        rb, rs = _as_int(self._p("ram_base")), _as_int(self._p("ram_size"))
        if rb is not None:
            out.append((rb, rs or 0))
        if self._dtb:
            out.extend(self._dtb.get("memory", []))
        return out

    def scan_ranges(self):
        """Explicit profile scan ranges: ["lo:hi", ...] or [[lo,hi], ...]."""
        self.load()
        sc = self._p("scan")
        out = []
        if isinstance(sc, str):
            sc = [sc]
        if isinstance(sc, list):
            for it in sc:
                if isinstance(it, str) and ":" in it:
                    lo, hi = it.split(":", 1)
                    lo, hi = _as_int(lo), _as_int(hi)
                elif isinstance(it, (list, tuple)) and len(it) == 2:
                    lo, hi = _as_int(it[0]), _as_int(it[1])
                else:
                    lo = hi = None
                if lo is not None and hi is not None:
                    out.append((lo, hi))
        return out

    def entry_pa(self):
        self.load()
        return _as_int(self._p("entry_pa"))

    def phys_window(self, arch):
        self.load()
        pw = self._p("phys_window")
        if isinstance(pw, (list, tuple)) and len(pw) == 2:
            lo, hi = _as_int(pw[0]), _as_int(pw[1])
            if lo is not None and hi is not None:
                return (lo, hi)
        regs = self.ram_regions(arch)
        if regs:
            b, s = regs[0]
            if s:
                return (b, (b + s) & MASK)
        return None

    def anchor(self):
        self.load()
        v = self._p("anchor")
        return v if isinstance(v, str) and v else None

    def break_kind(self):
        self.load()
        v = self._p("break_kind")
        return v if v in ("sw", "hw") else None

    def mmu_hint(self):
        """Optional {'reg': 'SCTLR_EL1', 'bit': 0} to read the MMU-enable bit on
        machines/firmware where the arch default register name does not apply."""
        self.load()
        m = self._p("mmu")
        return m if isinstance(m, dict) else None

    def describe(self):
        self.load()
        bits = []
        if self._prof:
            bits.append("profile(%d keys)" % len(self._prof))
        if self._dtb:
            bits.append("dtb(mem=%s)" %
                        ",".join(fmt(b) for b, _ in self._dtb.get("memory", [])))
        return " ".join(bits) if bits else "(arch defaults)"


TARGET = Target()


# Underscore-prefixed helpers are part of this module's public surface for the
# rest of the package (`from .target import *`), which would otherwise skip them.
__all__ = ['Target', 'TARGET']
