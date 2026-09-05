"""`cmdinfo` -- which extension registered each command in this session.

A session with pwndbg, this package and the kernel's own scripts/gdb answers to
well over a thousand command words, and nothing in gdb says where any of them
came from.  Tab at an empty prompt is not an answer either: gdb hands readline
every candidate at once and readline stops to ask whether to print them all,
and `complete` silently truncates at `max-completions` (200 by default).
Measured here: `complete ''` returned 200 names where `help all` had 1500, with
nothing said about having stopped short.

Attribution is positional, not nominal.  Every Python-registered command is an
object gdb still holds a reference to, so the garbage collector can be asked for
them; the class's module says which file registered it, and the name it was
registered under is the string literal its own source passes to __init__.  A
name-prefix rule would be wrong on its first counterexample and the kernel
already ships one: scripts/gdb registers `translate-vm`, which no `lx-` rule
catches.
"""
import ast
import gc
import inspect
import sys
import textwrap

import gdb

from .runtime import *


GROUPS = ("gdbtools", "pwndbg", "kernel", "python", "user", "gdb")

_LABEL = {
    "gdbtools": "this package",
    "pwndbg":   "pwndbg, its aliases included",
    "kernel":   "the kernel's own scripts/gdb",
    "python":   "other Python extensions, gdb's bundled ones included",
    "user":     "`define` macros, or a Python command that could not be placed",
    "gdb":      "gdb itself",
}

_CACHE_ATTR = "_gdbtools_cmdinfo_cache"


def _parse_help_all(out):
    """Top-level command words from `help all`.

    An entry that has abbreviations spells them all out on one line -- "break,
    brea, bre, br, b -- Set breakpoint..." -- and every one of those is a word
    the user can type and that Tab offers, so all of them are collected.  Taking
    only `split()[0]`, as pwndbg's own parser does, records the literal `break,`
    with the comma attached and loses the other four.

    Subcommands fold into their prefix, so `set ada print-signatures` counts as
    `set`.  Keeping full paths would bury the answer under ~1200 set/show lines.

    A line counts only if it carries the " -- " separator.  `help all` has no
    prose at all, but `help user-defined` -- which this also parses -- opens with
    three sentences and they were being read as the commands `User-defined`,
    `The` and `Use`.  Verified against both a stock gdb and this lab's full
    session: every real entry has the separator, zero lines lack it.
    """
    names = set()
    for line in out.splitlines():
        line = line.strip()
        if " -- " not in line or line.startswith(("Command class:", "Unclassified commands")):
            continue
        for word in line.split(" -- ")[0].split(","):
            word = word.strip()
            if word:
                names.add(word.split()[0])
    return names


@safe(default=None)
def _help_words(what="all"):
    """`help WHAT` reduced to command words, with pagination left as found.

    `help all` is ~1800 lines and would stop at a --More-- prompt that nothing
    in a script will answer, so pagination is turned off around the call.  The
    restore is conditional: a session that already had it off -- which this
    lab's gdbinit sets -- is left exactly as it was.
    """
    try:
        prev = gdb.parameter("pagination")
    except Exception:
        prev = None
    if prev:
        execstr("set pagination off")
    try:
        out = gdb.execute("help " + what, from_tty=False, to_string=True) or ""
    except gdb.error:
        return set()
    finally:
        if prev:
            execstr("set pagination on")
    return _parse_help_all(out)


def _registered_name(cls):
    """The name a gdb.Command subclass registers itself under, from its source.

    gdb.Command exposes no name attribute -- checked on gdb 17.2, where an
    instance's only public members are `invoke` and `dont_repeat` -- so the name
    has to come from the source that passed it.  Every registration is
    `__init__("the-name", ...)` or `__init__(name="the-name", ...)`, positional
    or keyword, on `super()` or on `gdb.Command` directly; the first string
    constant in that call is the name.

    Returns None when the name is not a literal there.  That is the honest
    answer for a class that computes it, and the caller reports such a class as
    unplaced rather than inventing a name for it.
    """
    try:
        src = textwrap.dedent(inspect.getsource(cls))
        tree = ast.parse(src)
    except Exception:
        return None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not (isinstance(f, ast.Attribute) and f.attr == "__init__"):
            continue
        for a in node.args:
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                return a.value
        for kw in node.keywords:
            if kw.arg == "name" and isinstance(kw.value, ast.Constant) \
                    and isinstance(kw.value.value, str):
                return kw.value.value
    return None


@safe(default=({}, [], 0))
def _python_commands(skip_modules=("pwndbg", "gdbtools")):
    """({name: source file}, [unplaced classes], subcommand count).

    gdb keeps every Python command object alive, so gc.get_objects() finds all
    of them.  Modules whose commands are already known from an authoritative
    registry are skipped -- reading pwndbg's 245 generated wrappers would cost
    more than the rest of this function and answer nothing new.

    Multi-word names are counted, not returned: `info frame-filter` folds into
    the `info` prefix in `help all`, and letting it claim that prefix would
    reassign every `info` subcommand gdb owns.
    """
    classes = {}
    for o in gc.get_objects():
        if isinstance(o, gdb.Command):
            classes[type(o)] = None
    out, unplaced, sub = {}, [], 0
    for cls in classes:
        mod = getattr(cls, "__module__", "") or ""
        if mod.split(".")[0] in skip_modules:
            continue
        f = getattr(sys.modules.get(mod), "__file__", None) or ""
        n = _registered_name(cls)
        if n is None:
            unplaced.append((cls.__name__, mod, f))
        elif " " in n:
            sub += 1
        else:
            out[n] = f
    return (out, unplaced, sub)


@safe(default=(set(), set(), "pwndbg's registry could not be read"))
def _pwndbg_names():
    """(commands, aliases, note).  Empty sets and a note when pwndbg is absent."""
    try:
        import pwndbg.commands as pc
    except Exception:
        return (set(), set(), "pwndbg is not loaded in this session")
    cmds, aliases = set(), set()
    for c in getattr(pc, "commands", ()) or ():
        n = getattr(c, "command_name", None)
        if n:
            cmds.add(n)
        for a in (getattr(c, "aliases", None) or ()):
            aliases.add(a)
    if not cmds:
        return (cmds, aliases, "pwndbg is importable but its command list is empty")
    return (cmds, aliases, None)


def _columns(names, width, indent="  "):
    names = sorted(names)
    if not names:
        return [indent + "(none)"]
    col = max(len(n) for n in names) + 2
    per = max(1, (width - len(indent)) // col)
    return [indent + "".join(n.ljust(col) for n in names[i:i + per]).rstrip()
            for i in range(0, len(names), per)]


@safe(default=None)
def classify():
    """{group: set(names)} plus notes.  Cached until the command count changes.

    The gc walk and the source parsing cost about 35 ms together, which is
    nothing next to the pagination prompt this command exists to replace, but it
    is also pure waste on a second call.  `help all` is ~1 ms and has to be read
    anyway, so the name set itself is the cache key -- not its size, which would
    survive one command being added while another was removed.
    """
    now = _help_words("all")
    if now is None:
        return None
    key = frozenset(now)
    cached = getattr(gdb, _CACHE_ATTR, None)
    if cached is not None and cached[0] == key:
        return cached[1]

    ours = set(getattr(gdb, "_gdbtools_command_names", None) or ())
    pw, pw_alias, pw_note = _pwndbg_names()
    pwndbg = pw | pw_alias
    py, unplaced, subs = _python_commands()

    notes = []
    if pw_note:
        notes.append(pw_note + ", so its commands are reported as gdb's own")

    kernel = {n for n, f in py.items() if "/scripts/gdb/" in f}
    other_py = set(py) - kernel
    # Precedence, most authoritative first: our own claimed names, then
    # pwndbg's registry, then what the loaded source files say about
    # themselves.  Each group is subtracted from the next so a name is
    # reported once and the counts add up.
    kernel -= ours | pwndbg
    other_py -= ours | pwndbg | kernel
    placed = ours | pwndbg | kernel | other_py
    # `define` macros land in gdb's user-defined class, and so do Python
    # commands registered as COMMAND_USER -- which is why this is taken last,
    # after everything with a real source has been claimed.
    user = (_help_words("user-defined") or set()) - placed
    builtin = now - placed - user

    groups = {"gdbtools": ours & now, "pwndbg": pwndbg & now, "kernel": kernel,
              "python": other_py, "user": user, "gdb": builtin}
    # A name we registered over someone else's.  _register() says so at load
    # time; saying it here as well keeps the counts from hiding it.
    contested = sorted(ours & (pwndbg | kernel | other_py))
    dirs = sorted({f.rsplit("/", 1)[0] for f in py.values() if f})
    if unplaced:
        notes.append("%d Python command class(es) build their name at runtime and "
                     "are not listed: %s"
                     % (len(unplaced), ", ".join(sorted(c for c, _, _ in unplaced))))
    if subs:
        notes.append("%d Python subcommand(s) sit under an existing prefix word "
                     "(`info ...`, `set ...`) and are counted with that prefix" % subs)

    res = {"groups": groups, "now": now, "alias": pw_alias,
           "contested": contested, "notes": notes, "dirs": dirs}
    setattr(gdb, _CACHE_ATTR, (key, res))
    return res


class CmdInfo(gdb.Command):
    """cmdinfo [GROUP | COMMAND] [-1] [-c] : which extension registered each command.

  gdbtools   this package
  pwndbg     pwndbg, aliases included
  kernel     the kernel's own scripts/gdb
  python     other Python extensions, gdb's bundled ones included
  user       `define` macros from a gdbinit
  gdb        gdb itself

Nothing is inferred from a name.  Our own names and pwndbg's come from their
registries; every other Python command is traced to the file that registered it;
what is left over is gdb's.

  cmdinfo                every group
  cmdinfo kernel         one group
  cmdinfo kpgd           which group one command is in
  cmdinfo -1             one name per line, for piping
  cmdinfo -c             counts only

Subcommands count as their prefix word, so `set ada print-signatures` is `set`."""

    def __init__(self, name="cmdinfo"):
        super(CmdInfo, self).__init__(name, gdb.COMMAND_USER)

    def _lookup(self, want, r):
        g = r["groups"]
        hits = [k for k in GROUPS if want in g[k]]
        if not hits:
            if want in r["now"]:
                print("%-18s exists, but this session cannot place it" % want)
            else:
                print("%-18s is not a command word in this session" % want)
            return
        for k in hits:
            extra = " (alias)" if k == "pwndbg" and want in r["alias"] else ""
            print("%-18s %s%s" % (want, _LABEL[k], extra))
        if want in r["contested"]:
            print("%-18s another extension owned this name before we took it" % want)

    @safe()
    def invoke(self, arg, from_tty):
        parts = (arg or "").split()
        oneline = any(p in ("-1", "--names") for p in parts)
        counts = any(p in ("-c", "--count", "counts") for p in parts)
        rest = [p for p in parts if not p.startswith("-") and p != "counts"]

        r = classify()
        if r is None:
            print("[%s] cmdinfo: gdb's command table could not be read" % NAME)
            return
        g = r["groups"]

        if rest and rest[0] not in GROUPS:
            self._lookup(rest[0], r)
            return

        try:
            width = int(gdb.parameter("width") or 0) or 100
        except Exception:
            width = 100

        order = [rest[0]] if rest else list(GROUPS)
        for k in order:
            print("%-9s %5d  %s" % (k, len(g[k]), _LABEL[k]))
            if not counts:
                if oneline:
                    for n in sorted(g[k]):
                        print(n)
                else:
                    for line in _columns(g[k], width):
                        print(line)
                if len(order) > 1:
                    print("")

        if not counts and (not rest or rest[0] in ("kernel", "python")):
            for d in r["dirs"]:
                print("registered from: %s" % d)
        if r["contested"]:
            print("[%s] names taken from another extension: %s"
                  % (NAME, " ".join(r["contested"])))
        for n in r["notes"]:
            print("[%s] %s" % (NAME, n))


__all__ = ["CmdInfo", "classify"]
