"""`enumvals` -- list every enumerator of a C/C++ enum from the loaded debug info.

Target-independent: reads types only, no inferior memory and no running target,
so it answers the same for a user program, a kernel, any arch, or a remote, and
cannot crash a session or affect anything else.
"""
import gdb

from .runtime import *

_HEX = ("/x", "-x", "hex")
_DEC = ("/d", "-d", "dec")


def _split_flag(arg):
    # Peel an optional base flag from the front or the back; default decimal. A
    # type name is a single token (or `enum NAME`), so splitting on spaces is safe.
    s = (arg or "").strip()
    if not s:
        return False, ""
    parts = s.split()
    if parts[0].lower() in _HEX:
        return True, " ".join(parts[1:]).strip()
    if parts[0].lower() in _DEC:
        return False, " ".join(parts[1:]).strip()
    if len(parts) > 1 and parts[-1].lower() in _HEX:
        return True, " ".join(parts[:-1]).strip()
    if len(parts) > 1 and parts[-1].lower() in _DEC:
        return False, " ".join(parts[:-1]).strip()
    return False, s


def _lookup_enum(name):
    # Try the name as given, then with an `enum ` prefix, following typedefs.
    t = None
    for cand in (name, "enum " + name):
        try:
            t = gdb.lookup_type(cand)
            break
        except gdb.error:
            t = None
    if t is None:
        return None, "no type named %r in the current symbols" % name
    try:
        t = t.strip_typedefs()
    except gdb.error:
        pass
    if t.code != gdb.TYPE_CODE_ENUM:
        return None, "%r is not an enum (it is %s)" % (name, _code_name(t))
    return t, None


def _code_name(t):
    try:
        return t.name or "an unnamed type"
    except Exception:
        return "another type"


def _mask_for(t):
    try:
        n = int(t.sizeof)
        if n > 0:
            return (1 << (8 * n)) - 1
    except Exception:
        pass
    return MASK


class EnumVals(gdb.Command):
    """enumvals [/x|/d] ENUM : list every value of a C/C++ enum type.

Values are read from this build's debug info, config-dependent enumerators
included. Base defaults to decimal; `/x` prints hex. ENUM may carry the `enum `
keyword or be a typedef of an enum. Works for a user program, a kernel, any
arch and a remote target; no running inferior required.

    enumvals state
    enumvals /x pud_flags"""

    def __init__(self, name="enumvals"):
        super(EnumVals, self).__init__(name, gdb.COMMAND_DATA)

    @safe()
    def invoke(self, arg, from_tty):
        want_hex, name = _split_flag(arg)
        if not name:
            print("usage: enumvals [/x|/d] ENUM   (base defaults to decimal)")
            return

        enum_type, reason = _lookup_enum(name)
        if enum_type is None:
            print("[%s] %s" % (NAME, reason))
            return

        try:
            fields = list(enum_type.fields())
        except gdb.error as e:
            print("[%s] cannot read the enumerators of %r: %s" % (NAME, name, e))
            return

        label = _code_name(enum_type)
        print("type = enum {" if label == "an unnamed type" else "type = enum %s {" % label)

        mask = _mask_for(enum_type)
        try:
            signed = bool(getattr(enum_type, "is_signed", True))
        except Exception:
            signed = True
        last = len(fields) - 1
        for i, field in enumerate(fields):
            comma = "," if i < last else ""
            val = getattr(field, "enumval", None)
            if val is None:
                shown = "<unknown>"
            elif want_hex:
                shown = "0x%x" % (int(val) & mask)
            elif int(val) < 0 and not signed:
                shown = "%d" % (int(val) & mask)  # unsigned enum: show the unsigned value
            else:
                shown = "%d" % int(val)
            print("    %s = %s%s" % (field.name, shown, comma))

        print("}")


__all__ = ["EnumVals"]
