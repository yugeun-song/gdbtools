"""The GDBTOOLS_* contract: every variable gdbtools reads, its type and meaning.

Unset (or empty) means "not stated" and leaves the feature on its default.  A
value that is set and does not parse raises ConfigError naming the variable and
the value; the feature that needed it refuses instead of falling back.  The same
types validate a machine profile's fields.  Pure Python, so README's table can
be checked without gdb:

    python3 -B -m gdbtools.common.config --check README.md
"""
import os
import shutil
import sys

PREFIX = "GDBTOOLS_"
_MAX = (1 << 64) - 1


class ConfigError(Exception):
    """A GDBTOOLS_* value or a profile field that was stated and is invalid."""


def _integer(v):
    # A bare ValueError means "use the type's own description" in the message.
    if isinstance(v, bool):
        raise ValueError
    if isinstance(v, int):
        return v
    try:
        return int(str(v).strip(), 0)
    except ValueError:
        raise ValueError from None


def _address(v):
    n = _integer(v)
    if not 0 <= n <= _MAX:
        raise ValueError
    return n


def _range(v):
    if isinstance(v, (list, tuple)) and len(v) == 2:
        lo, hi = v
    elif isinstance(v, str) and ":" in v:
        lo, hi = v.split(":", 1)
    else:
        raise ValueError
    lo, hi = _address(lo), _address(hi)
    if lo >= hi:
        raise ValueError
    return (lo, hi)


_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")


def _boolean(v):
    s = str(v).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    raise ValueError


def _count(v):
    n = _integer(v)
    if n <= 0:
        raise ValueError
    return n


def _nonneg(v):
    n = _integer(v)
    if n < 0:
        raise ValueError
    return n


def _file(v):
    if not (os.path.isfile(v) and os.access(v, os.R_OK)):
        raise ValueError
    return v


def _program(v):
    if not shutil.which(v):
        raise ValueError
    return v


def _symbol(v):
    s = str(v).strip()
    if not s or any(c.isspace() for c in s):
        raise ValueError
    return s


def _words(v):
    return str(v).split()


# type -> (parser, what a valid value looks like)
_TYPES = {
    "bool": (_boolean, "1/0, true/false, yes/no or on/off"),
    "address": (_address, "an address (0x-prefixed hex or decimal)"),
    "range": (_range, "a lo:hi address range with lo < hi"),
    "count": (_count, "an integer greater than 0"),
    "int": (_nonneg, "a non-negative integer"),
    "file": (_file, "a readable file"),
    "program": (_program, "a program on $PATH or an executable path"),
    "symbol": (_symbol, "a symbol name"),
    "words": (_words, "words"),
    "enum": (None, None),
    "custom": (None, None),
}

# (name, type, choices or None, meaning).  README's table is rendered from this.
_DECL = (
    ("AUTO", "bool", None,
     "arm the kernel session once a kernel image is loaded: stop hook, shadow symbols, "
     "MMU-transition notices. Unset: `kearly on` is manual"),
    ("ENTRY_PA", "address", None,
     "physical address of the kernel image base. On x86_64 a stated base suppresses "
     "the decompressor recovery"),
    ("SCAN", "range", None, "physical range searched for the image magic; replaces every derived range"),
    ("RAM_BASE", "address", None, "RAM base; the scan covers `SCAN_SPAN` bytes from it"),
    ("SCAN_SPAN", "count", None,
     "bytes scanned past `RAM_BASE` or a DTB `/memory` base. Default 128 MiB"),
    ("PHYS_WINDOW", "range", None,
     "physical range the image may occupy, for the calibration sanity check. Unset: "
     "the check is skipped"),
    ("PROFILE", "file", None, "JSON machine description (see `profiles/`), validated field by field"),
    ("DTB", "file", None, "device tree blob describing the board"),
    ("PRESET", "enum", None, "boot-combination preset (`kearly preset list`)"),
    ("ANCHOR", "symbol", None, "calibration and entry-break anchor symbol, overriding the preset"),
    ("BREAK_KIND", "enum", ("sw", "hw"), "breakpoint kind for the entry break"),
    ("X86_KASLR", "bool", None, "recover the decompressor-randomized physical base in `kearly bootbreak`"),
    ("X86_DECOMP_PA", "address", None,
     "where a direct boot loads the bzImage decompressor; selects the direct-boot "
     "recovery. Unset: the EFI-stub recovery"),
    ("X86_DECOMP_VMLINUX", "file", None, "`arch/x86/boot/compressed/vmlinux`, read by the x86 base recovery"),
    ("BINUTIL_NM", "program", None, "`nm` for the x86 decompressor parse. Unset: `nm` on `$PATH`"),
    ("BINUTIL_OBJDUMP", "program", None, "`objdump` for the same parse. Unset: `objdump` on `$PATH`"),
    ("NO_COLOR", "bool", None, "monochrome `cfgdis` and pwndbg flow panel"),
    ("KDIS_ASCII", "bool", None, "ASCII arrows in `cfgdis` and the pwndbg flow panel"),
    ("DEBUG", "bool", None,
     "report every exception the safety layer swallows on gdb's stderr; NameError, "
     "AttributeError and TypeError are reported regardless"),
    ("MAP_CAP_LEAVES", "count", None, "`mmview` leaf cap (default 20000); `mmview` says when it truncated"),
    ("MAP_CAP_NODES", "count", None, "`mmview` table-node cap (default 60000)"),
    ("MEMBLOCK_CAP", "count", None, "regions `kmemblock` prints per type (default 512); `kmemblock TYPE full` lifts it"),
    ("FZF", "program", None, "fzf binary for `fz`. Unset: `fzf` on `$PATH`, else a numbered prompt"),
    ("FZF_OPTS", "words", None, "options appended to fzf's arguments"),
    ("FZ_KEY", "custom", None,
     "readline key, optionally with a subject (`\\C-t`, `\\C-r history`), bound to `fz` at load"),
    ("RISCV_KERNEL_MAP_VIRT_OFF", "int", None,
     "offset of `virt_addr` in `struct kernel_mapping`, for a riscv vmlinux without "
     "DWARF (8 on 6.12, 0 on mainline)"),
)

_BY_NAME = {d[0]: d for d in _DECL}
_PROVIDED = {}


def provide(name, choices=None, check=None):
    """Supply what a variable's declaration cannot carry itself: the choices of
    an enum whose values live in another module, or the checker of a custom type
    (check(text) returns the parsed value or raises ValueError(expected))."""
    if name not in _BY_NAME:
        raise KeyError(name)
    _PROVIDED[name] = (tuple(choices) if choices is not None else None, check)


def _choices(name, choices):
    if choices is None:
        choices = (_PROVIDED.get(name) or (None, None))[0]
    return choices


def parse(name, raw, label=None):
    """Parse `raw` as variable `name`'s type, or raise ConfigError."""
    _n, kind, choices, _m = _BY_NAME[name]
    label = label or (PREFIX + name)
    expect = _TYPES[kind][1]
    try:
        if kind == "enum":
            choices = _choices(name, choices)
            if choices is None:
                return str(raw).strip()
            expect = "one of: " + ", ".join(choices)
            s = str(raw).strip().lower()
            for c in choices:
                if c.lower() == s:
                    return c
            raise ValueError
        if kind == "custom":
            check = (_PROVIDED.get(name) or (None, None))[1]
            return check(raw) if check else raw
        return _TYPES[kind][0](raw)
    except ValueError as e:
        why = e.args[0] if e.args else expect
        raise ConfigError("%s is set to %r, which is not %s" % (label, raw, why))
    except (TypeError, OverflowError):
        raise ConfigError("%s is set to %r, which is not %s" % (label, raw, expect))


def get(name):
    """The stated value of GDBTOOLS_<name>, parsed; None when unset or empty."""
    raw = os.environ.get(PREFIX + name)
    if raw is None or raw == "":
        return None
    return parse(name, raw)


def validate_all():
    """Messages for every variable that is set and invalid."""
    out = []
    for name in _BY_NAME:
        try:
            get(name)
        except ConfigError as e:
            out.append(str(e))
    return out


# Machine profile fields (keys starting with "_" are comments).
_PROFILE = {
    "arch": ("enum", ("x86_64", "arm64", "riscv64")),
    "ram_base": ("address", None),
    "ram_size": ("count", None),
    "entry_pa": ("address", None),
    "scan": ("ranges", None),
    "phys_window": ("range", None),
    "anchor": ("symbol", None),
    "break_kind": ("enum", ("sw", "hw")),
    "mmu": ("mmu", None),
}


def _profile_value(kind, choices, v):
    if kind == "enum":
        if isinstance(v, str) and v.lower() in choices:
            return v.lower()
        raise ValueError("one of: " + ", ".join(choices))
    if kind == "ranges":
        items = [v] if isinstance(v, str) else v
        if not isinstance(items, list) or not items:
            raise ValueError("a lo:hi range or a list of them")
        return [_range(it) for it in items]
    if kind == "mmu":
        if not (isinstance(v, dict) and set(v) <= {"reg", "bit"} and "reg" in v):
            raise ValueError('{"reg": NAME, "bit": N}')
        reg = _symbol(v["reg"])
        bit = _nonneg(v.get("bit", 0))
        if bit > 63:
            raise ValueError("a bit number 0..63")
        return {"reg": reg, "bit": bit}
    return _TYPES[kind][0](v)


def parse_profile(data, label):
    """Validate a decoded profile; raise ConfigError naming `label` and the field."""
    if not isinstance(data, dict):
        raise ConfigError("%s: a profile is a JSON object, not %s" % (label, type(data).__name__))
    out = {}
    for key, v in data.items():
        if key.startswith("_"):
            continue
        if key not in _PROFILE:
            raise ConfigError("%s: unknown field %r (known: %s)"
                              % (label, key, ", ".join(sorted(_PROFILE))))
        kind, choices = _PROFILE[key]
        try:
            out[key] = _profile_value(kind, choices, v)
        except (ValueError, TypeError, OverflowError) as e:
            why = e.args[0] if (isinstance(e, ValueError) and e.args) else \
                _PROFILE_EXPECT.get(kind) or _TYPES[kind][1]
            raise ConfigError("%s: field %r is %r, which is not %s" % (label, key, v, why))
    return out


_PROFILE_EXPECT = {"ranges": "a lo:hi range or a list of them",
                   "mmu": '{"reg": NAME, "bit": N}'}


def _type_label(kind, choices):
    if kind == "enum":
        return " \\| ".join("`%s`" % c for c in choices) if choices else "preset name"
    return {"custom": "key [subject]"}.get(kind, kind)


def markdown_table():
    rows = ["| variable | type | meaning |", "| --- | --- | --- |"]
    for name, kind, choices, meaning in _DECL:
        rows.append("| `%s%s` | %s | %s |" % (PREFIX, name, _type_label(kind, choices), meaning))
    return "\n".join(rows)


_BEGIN, _END = "<!-- gdbtools-env:begin -->", "<!-- gdbtools-env:end -->"


def _check(path):
    text = open(path, encoding="utf-8").read()
    if _BEGIN not in text or _END not in text:
        print("%s: no %s ... %s block" % (path, _BEGIN, _END))
        return 1
    have = text.split(_BEGIN, 1)[1].split(_END, 1)[0].strip()
    if have != markdown_table():
        print("%s: the GDBTOOLS_* table differs from gdbtools/common/config.py; expected:\n%s"
              % (path, markdown_table()))
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        sys.exit(_check(sys.argv[2]))
    print(markdown_table())
