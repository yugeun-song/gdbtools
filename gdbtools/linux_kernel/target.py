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
# Every field is optional; a field that is absent yields None.  A description that
# was handed in and does not load is an error that every use re-raises, so nothing
# quietly runs on arch defaults while the operator believes their board is in effect.
# ----------------------------------------------------------------------------
class Target:
    def __init__(self):
        self._prof = None          # validated profile fields (config.parse_profile)
        self._dtb = None           # parsed DTB dict {'memory':[(base,size)],...}
        self._loaded = False
        self._errors = {}          # "PROFILE"/"DTB" -> ConfigError from the environment
        self._dtb_probe = None     # (pc, pointer) of the last guest-DTB miss

    @safe()
    def load(self):
        """Read the machine description that was handed in, once."""
        if not self._loaded:
            self._loaded = True
            for name, setter in (("PROFILE", self.set_profile), ("DTB", self.set_dtb)):
                try:
                    path = config.get(name)
                    if path:
                        setter(path, label="%s%s=%s" % (config.PREFIX, name, path))
                except ConfigError as e:
                    self._errors[name] = e
        for name in ("PROFILE", "DTB"):
            if name in self._errors:
                raise self._errors[name]

    @safe(default=False)
    def set_profile(self, path, quiet=False, label=None):
        label = label or "profile %s" % path
        try:
            with open(path) as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            raise ConfigError("%s: cannot be read as JSON (%s)" % (label, e))
        self._prof = config.parse_profile(data, label)
        self._errors.pop("PROFILE", None)
        LOG.add("profile loaded: %s (%d fields)" % (path, len(self._prof)))
        if not quiet:
            print("[%s] profile loaded: %s" % (NAME, path))
        return True

    @safe(default=False)
    def set_dtb(self, path, quiet=False, label=None):
        label = label or "dtb %s" % path
        try:
            with open(path, "rb") as f:
                blob = f.read()
        except OSError as e:
            raise ConfigError("%s: cannot be read (%s)" % (label, e))
        d = parse_dtb(blob)
        if d is None:
            raise ConfigError("%s: not a flattened device tree with /memory or /chosen" % label)
        self._dtb = d
        self._errors.pop("DTB", None)
        LOG.add("dtb loaded: %s (%d mem regions)" % (path, len(d.get("memory", []))))
        if not quiet:
            print("[%s] dtb loaded: %s -> memory=%s" %
                  (NAME, path, ", ".join("%s+%s" % (fmt(b), fmt(s)) for b, s in d.get("memory", [])) or "(none)"))
        return True

    @safe()
    def try_guest_dtb(self, arch):
        """Read the DTB straight from guest RAM via the arch's boot-pointer register
        (arm64 x0 / riscv a1).  Only while translation is known to be OFF: with it on
        the register is not a physical pointer, and a read through the live tables
        can land on a device.  Returns None when a DTB is in hand, else why not."""
        if self._dtb is not None:
            return None
        regname = getattr(arch, "dtb_pointer_reg", None) if arch is not None else None
        if not regname:
            return "this architecture hands over no DTB pointer in a register"
        pa = reg(regname)
        if pa is None:
            return "$%s is unreadable" % regname
        key = (reg("pc"), pa)
        if key == self._dtb_probe:
            return "nothing new to read at this stop"
        self._dtb_probe = key
        if arch.mmu_translation_on() is not False:
            return "translation is on or unknown, so $%s is not a physical pointer" % regname
        d = read_guest_dtb(pa)
        if d and d.get("memory"):
            self._dtb = d
            LOG.add("dtb auto-read from guest @%s ($%s)" % (fmt(pa), regname))
            return None
        return "no DTB at $%s=%s" % (regname, fmt(pa))

    def _p(self, key):
        return self._prof.get(key) if isinstance(self._prof, dict) else None

    def ram_regions(self, arch):
        """[(base,size), ...] from profile ram_base/ram_size then DTB /memory."""
        self.load()
        self.try_guest_dtb(arch)
        out = []
        rb = self._p("ram_base")
        if rb is not None:
            out.append((rb, self._p("ram_size") or 0))
        if self._dtb:
            out.extend(self._dtb.get("memory", []))
        return out

    def scan_ranges(self):
        """Explicit profile scan ranges, validated as lo:hi."""
        self.load()
        return list(self._p("scan") or [])

    def entry_pa(self):
        self.load()
        return self._p("entry_pa")

    def phys_window(self, arch):
        self.load()
        pw = self._p("phys_window")
        if pw is not None:
            return pw
        regs = self.ram_regions(arch)
        if regs:
            b, s = regs[0]
            if s:
                return (b, (b + s) & MASK)
        return None

    def anchor(self):
        self.load()
        return self._p("anchor")

    def break_kind(self):
        self.load()
        return self._p("break_kind")

    def mmu_hint(self):
        """Optional {'reg': 'SCTLR_EL1', 'bit': 0} to read the MMU-enable bit on
        machines/firmware where the arch default register name does not apply."""
        self.load()
        return self._p("mmu")

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
