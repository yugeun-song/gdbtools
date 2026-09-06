"""`cmdinfo` -- which extension registered each command gdb answers to now.

Two questions, and this answers both from the running gdb rather than from a
list written down somewhere.

WHAT IS RECOGNISED.  Every name reported here is one gdb resolves at the moment
you ask.  A name is not accepted because a source file mentions it, or because
an extension once registered it: it has to appear in this session's `help all`
AND survive a `help NAME` that answers with real help rather than "Undefined
command" or "Ambiguous command".  Verifying all of them costs about 4 ms, so
there is no reason to skip it.  A name that fails is reported as unrecognised,
never listed as if it were usable.

Recognised also means structurally correct.  `set`, `info`, `show` and 27 others
are prefixes with 2036 subcommands between them; folding those into the prefix
word would claim `set` is one command and hide the 745 things you can actually
type after it.  Leaves and prefixes are therefore listed apart, and a prefix
carries its subcommand count.

WHO REGISTERED IT.  Positionally, never by name.  Our own names and pwndbg's
come from their registries.  gdb.Command exposes no name attribute -- checked on
gdb 17.2, where an instance's only public members are `invoke` and
`dont_repeat` -- so every other Python command is traced through the garbage
collector to the class that registered it and the file that class lives in, and
the name is the string literal that class's own source passes to __init__.
Whatever is left is gdb's own.  A `lx-` prefix rule would be wrong on its first
counterexample and the kernel ships one: scripts/gdb registers `translate-vm`.
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


def _paths(out):
    """Command paths from `help all` output, as written.

    An entry is "path -- summary", and one with abbreviations spells them out on
    the same line: "break, brea, bre, br, b -- Set breakpoint...".  Each of those
    is a name the user can type and that Tab offers, so all are kept.  pwndbg's
    own parser takes `split()[0]` and so records the literal `break,` with the
    comma attached while losing the other four.

    The " -- " is required.  `help all` carries no prose, but `help
    user-defined` -- parsed here too -- opens with three sentences that were
    otherwise read as the commands `User-defined`, `The` and `Use`.  Checked
    against both a stock gdb and this lab's full session: every real entry has
    the separator and no line lacks it.
    """
    out_paths = []
    for line in (out or "").splitlines():
        line = line.strip()
        if " -- " not in line or line.startswith(("Command class:", "Unclassified commands")):
            continue
        for piece in line.split(" -- ")[0].split(","):
            piece = piece.strip()
            if piece:
                out_paths.append(piece)
    return out_paths


@safe(default=None)
def _help(what):
    """`help WHAT`, with pagination left exactly as it was found.

    `help all` is ~2500 lines and would stop at a --More-- prompt that nothing in
    a script will answer.  The restore is conditional, so a session that already
    had pagination off -- which this lab's gdbinit sets -- is not touched.
    """
    try:
        prev = gdb.parameter("pagination")
    except Exception:
        prev = None
    if prev:
        execstr("set pagination off")
    try:
        return gdb.execute("help " + what, from_tty=False, to_string=True) or ""
    except gdb.error:
        return ""
    finally:
        if prev:
            execstr("set pagination on")


def _resolves(name):
    """Does gdb answer this exact word right now?

    `help` and not `complete`: completion lists what gdb would offer, which is
    blind to a unique prefix abbreviation of a builtin, and it truncates at
    max-completions without saying so.  "Ambiguous command" counts as not
    resolving -- the word is a prefix of several and does nothing on its own.
    """
    try:
        out = (gdb.execute("help " + name, from_tty=False, to_string=True) or "").strip()
    except gdb.error as e:
        out = str(e).strip()
    low = out.lower()
    return bool(out) and "undefined command" not in low and "ambiguous command" not in low


def _registered_name(cls):
    """The name a gdb.Command subclass registers itself under, from its source.

    Every registration is `__init__("the-name", ...)` or `__init__(name="...")`,
    positional or keyword, on `super()` or on `gdb.Command` directly, so a string
    constant in that call is the name.  None when there is no literal, or when
    which literal ran cannot be told -- the honest answer, and the caller reports
    such a class rather than inventing a name for it.

    Two things this has to work around.

    A file loaded with plain `source foo.py` runs in __main__, and CPython
    deletes __main__.__file__ again when the file finishes, so inspect cannot
    reach the class through its module and raises.  The class's own __init__
    code object still carries the real path, so it is asked instead.  Without
    that, every command from a sourced script fell through to gdb's own group.

    A class that registers under different names in two branches has more than
    one literal, and ast.walk visits If.body before If.orelse, so taking the
    first would name the branch that did not run.  Every literal is collected
    and gdb is asked which one it actually answers to.
    """
    try:
        src = inspect.getsource(cls)
    except Exception:
        if "__init__" not in vars(cls):
            return None
        try:
            src = inspect.getsource(cls.__init__)
        except Exception:
            return None
    try:
        tree = ast.parse(textwrap.dedent(src))
    except Exception:
        return None
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not (isinstance(f, ast.Attribute) and f.attr == "__init__"):
            continue
        for a in node.args:
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                found.append(a.value)
                break
        else:
            for kw in node.keywords:
                if kw.arg == "name" and isinstance(kw.value, ast.Constant) \
                        and isinstance(kw.value.value, str):
                    found.append(kw.value.value)
                    break
    uniq = list(dict.fromkeys(found))
    if len(uniq) == 1:
        return uniq[0]
    live = [n for n in uniq if _resolves(n)]
    return live[0] if len(live) == 1 else None


@safe(default=({}, [], []))
def _python_commands(skip=("pwndbg", "gdbtools")):
    """({name: file}, [unplaced classes], [subcommand paths]).

    gdb holds a reference to every Python command object, so the collector finds
    them all.  Modules whose names come from an authoritative registry are
    skipped: reading pwndbg's 245 generated wrappers would cost more than the
    rest of this function and answer nothing new.
    """
    classes = {}
    for o in gc.get_objects():
        if isinstance(o, gdb.Command):
            classes[type(o)] = None
    names, unplaced, subs = {}, [], []
    for cls in classes:
        mod = getattr(cls, "__module__", "") or ""
        if mod.split(".")[0] in skip:
            continue
        n = _registered_name(cls)
        if n is None:
            unplaced.append(cls.__name__)
        elif " " in n:
            subs.append(n)
        else:
            f = getattr(sys.modules.get(mod), "__file__", None) or ""
            if not f:
                # __main__ has no __file__ once `source` has finished, so the
                # class's own code object is where the path survives.
                f = getattr(getattr(vars(cls).get("__init__"), "__code__", None),
                            "co_filename", "") or ""
            names[n] = f
    return (names, unplaced, subs)


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
    """Everything this command reports, cached until the command set changes.

    The collector walk and the source parsing cost about 35 ms; `help all` costs
    about 2 ms and has to be read anyway, so the set of recognised names is both
    the answer and the cache key.  Its size would not do: one command added while
    another was removed leaves the count alone.
    """
    out_all = _help("all")
    paths = _paths(out_all)
    if not paths:
        return None
    leaves = {p for p in paths if " " not in p}
    subs = {}
    for p in paths:
        if " " in p:
            subs.setdefault(p.split()[0], []).append(p)
    # `help all` spells a prefix's abbreviations on the prefix's own line --
    # "info, inf, i -- ..." -- but prints every subcommand path under the
    # canonical spelling alone.  Without this, `i` and `inf` are recognised
    # leaves that answer `help i` with the whole info listing, and `cmdinfo i`
    # and `cmdinfo info` gave two different answers for one command.
    for line in (out_all or "").splitlines():
        line = line.strip()
        if " -- " not in line or line.startswith(("Command class:", "Unclassified commands")):
            continue
        spelt = [w.strip() for w in line.split(" -- ")[0].split(",") if w.strip()]
        if not spelt or spelt[0] not in subs:
            continue
        for a in spelt[1:]:
            if " " not in a:
                subs.setdefault(a, subs[spelt[0]])

    # The key is every path, not just the leaves.  1612 of the names reported in
    # a plain session are subcommands, and a change confined to them -- one
    # gdb.Parameter is enough -- leaves the leaf set identical, so a leaf-only
    # key served a stale answer for the rest of the session.
    key = frozenset(paths)
    cached = getattr(gdb, _CACHE_ATTR, None)
    if cached is not None and cached[0] == key:
        return cached[1]

    # Nothing is reported that gdb does not answer to right now.  Cheap enough
    # (about 4 ms for 500 names) that there is no argument for trusting the
    # listing instead.
    recognised = {n for n in leaves if _resolves(n)}
    unrecognised = sorted(leaves - recognised)

    ours = set(getattr(gdb, "_gdbtools_command_names", None) or ())
    pw, pw_alias, pw_note = _pwndbg_names()
    pwndbg = pw | pw_alias
    py, unplaced, py_subs = _python_commands()

    kernel = {n for n, f in py.items() if "/scripts/gdb/" in f}
    other_py = set(py) - kernel
    # Claimed by name derivation but not answered by gdb: the class registered
    # something else, or another extension has since taken the word.  Said out
    # loud rather than listed among the usable ones.
    derived_gone = sorted((kernel | other_py) - recognised)
    kernel &= recognised
    other_py &= recognised

    # Most authoritative first, each subtracted from the next, so a name is
    # reported once and the counts add up to what gdb answers to.
    ours_r = ours & recognised
    pwndbg_r = (pwndbg & recognised) - ours_r
    kernel -= ours_r | pwndbg_r
    other_py -= ours_r | pwndbg_r | kernel
    placed = ours_r | pwndbg_r | kernel | other_py
    # `define` macros land in gdb's user-defined class and so do Python commands
    # registered as COMMAND_USER, which is why this is taken last -- after
    # everything with a source file of its own has been claimed.
    user = (set(_paths(_help("user-defined"))) & recognised) - placed
    user = {u for u in user if " " not in u}
    builtin = recognised - placed - user

    notes = []
    if pw_note:
        notes.append(pw_note + ", so its commands are reported as gdb's own")
    if unplaced:
        notes.append("%d Python command class(es) build their name at runtime and are "
                     "not listed: %s" % (len(unplaced), ", ".join(sorted(unplaced))))
    if derived_gone:
        notes.append("registered by a Python class but not answered by gdb now: %s"
                     % " ".join(derived_gone))
    if unrecognised:
        notes.append("listed by `help all` but not resolvable on their own: %s"
                     % " ".join(unrecognised))

    groups = {"gdbtools": ours_r, "pwndbg": pwndbg_r, "kernel": kernel,
              "python": other_py, "user": user, "gdb": builtin}
    res = {"groups": groups, "recognised": recognised, "subs": subs,
           "alias": pw_alias, "contested": sorted(ours & (pwndbg | kernel | other_py)),
           "dirs": sorted({f.rsplit("/", 1)[0] for f in py.values() if f}),
           "py_subs": sorted(py_subs), "notes": notes}
    setattr(gdb, _CACHE_ATTR, (key, res))
    return res


class CmdInfo(gdb.Command):
    """cmdinfo [GROUP | COMMAND] [-1] [-c] [--sub] : who registered what gdb answers to.

  gdbtools   this package
  pwndbg     pwndbg, aliases included
  kernel     the kernel's own scripts/gdb
  python     other Python extensions, gdb's bundled ones included
  user       `define` macros from a gdbinit
  gdb        gdb itself

Every name shown is one gdb resolves right now -- present in `help all` and
answered by `help NAME`.  Prefix commands are listed apart from leaves with
their subcommand counts, because `set` alone is not a command you can run.

  cmdinfo                every group
  cmdinfo gdb            one group
  cmdinfo kpgd           who registered one command
  cmdinfo set            a prefix: its subcommands
  cmdinfo gdb --sub      include every subcommand path
  cmdinfo -1             one name per line, for piping
  cmdinfo -c             counts only"""

    def __init__(self, name="cmdinfo"):
        super(CmdInfo, self).__init__(name, gdb.COMMAND_USER)

    def _lookup(self, want, r):
        g, subs = r["groups"], r["subs"]
        hits = [k for k in GROUPS if want in g[k]]
        if not hits:
            if want in subs:
                print("%-18s a prefix whose own word gdb does not answer" % want)
            else:
                print("%-18s is not a command gdb answers to in this session" % want)
                return
        for k in hits:
            extra = " (alias)" if k == "pwndbg" and want in r["alias"] else ""
            print("%-18s %s%s" % (want, _LABEL[k], extra))
        if want in r["contested"]:
            print("%-18s another extension owned this name before we took it" % want)
        if want in subs:
            paths = sorted(subs[want])
            print("%-18s prefix, %d subcommands:" % ("", len(paths)))
            for p in paths:
                print("    %s" % p)

    @safe()
    def invoke(self, arg, from_tty):
        parts = (arg or "").split()
        oneline = any(p in ("-1", "--names") for p in parts)
        counts = any(p in ("-c", "--count", "counts") for p in parts)
        withsub = any(p == "--sub" for p in parts)
        rest = [p for p in parts if not p.startswith("-") and p != "counts"]

        r = classify()
        if r is None:
            print("[%s] cmdinfo: gdb's command table could not be read" % NAME)
            return
        g, subs = r["groups"], r["subs"]

        if rest and rest[0] not in GROUPS:
            self._lookup(rest[0], r)
            return

        try:
            width = int(gdb.parameter("width") or 0) or 100
        except Exception:
            width = 100

        order = [rest[0]] if rest else list(GROUPS)
        for k in order:
            names = g[k]
            pref = sorted(n for n in names if n in subs)
            leaf = sorted(n for n in names if n not in subs)
            # Counted over the set of paths, not summed per prefix: an
            # abbreviation now shares its canonical's subcommand list, so
            # summing would count `info breakpoints` once for `info`, once for
            # `inf` and once for `i`.
            allsub = sorted({q for n in pref for q in subs[n]})
            head = "%-9s %5d  %s" % (k, len(names), _LABEL[k])
            if pref:
                head += "   (+%d subcommands under %d prefixes)" % (len(allsub), len(pref))
            print(head)
            if counts:
                continue
            if oneline:
                for n in leaf + pref:
                    print(n)
            else:
                if pref:
                    print("  prefixes:")
                    for line in _columns(pref, width, "    "):
                        print(line)
                    print("  leaves:")
                for line in _columns(leaf, width, "    " if pref else "  "):
                    print(line)
            if withsub and pref:
                print("  subcommands:")
                for q in allsub:
                    print("    %s" % q)
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
