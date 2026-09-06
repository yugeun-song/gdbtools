r"""`fz` -- pick something out of gdb through fzf, or through a numbered prompt.

gdb's own searching is `apropos`, `info functions REGEX` and readline's Ctrl-R.
All three answer with a wall of text you then read by eye, and on a vmlinux with
60k symbols that is not a search, it is a scroll.  fzf is the tool for exactly
that shape of problem, and gdb has no reason to know about it -- which is why
this stays a separate command and touches nothing gdb or pwndbg owns.

Nothing here is required.  fzf missing, no controlling terminal, a
`--batch` session, a pipe: each has an answer that ends without hanging, and
they are tried in that order -- fzf, then a numbered prompt on /dev/tty, then
printing the list and saying why it could not ask.

The fzf binary is `$GDBTOOLS_FZF` when set and `fzf` on $PATH otherwise, and
`$GDBTOOLS_FZF_OPTS` is appended to its arguments.  No path is written down
here: which fzf, and how it should behave, is a property of the machine.

`fz bind` puts it on a key, the way Ctrl-R is a key in a shell.  What that can
and cannot be was measured against gdb 17.2 with system readline 8.3, in a real
pty, rather than assumed:

  works    A readline macro fires at the gdb prompt.  Both routes work -- an
           `$if gdb` block in ~/.inputrc, and readline.parse_and_bind() called
           from gdb's own Python, which is what `fz bind` uses so that nothing
           outside this package has to be edited.
  works    Clearing a half-typed line first.  The macro is "\C-a\C-k" then the
           command, so the key does the same thing whether or not something is
           already on the line.
  NOT      Putting the pick on the prompt for editing, the way a shell's Ctrl-R
           does.  readline.insert_text() from a pre_input_hook DISPLAYS the
           text and gdb does not execute it: a prefilled `print 1234567` never
           printed $1, and gdb's empty-line repeat ran the previous command
           instead.  gdb drives readline through its callback interface and
           keeps its own line state.  So a pick is run, not offered for edit.
  NOT      Reading this session's history.  gdb's history is not in the
           readline state Python sees -- measured as length 0 in a pty after
           two commands -- and gdb writes its history file at exit.
"""
import os
import subprocess

import gdb

from .runtime import *


SUBJECTS = ("history", "commands", "functions", "variables", "files", "breakpoints")

_MAX_PRINT = 200          # how many lines the last-resort listing prints


def _fzf_bin():
    return _env("FZF") or "fzf"


@safe(default=None)
def _have_tty():
    """A terminal this command may take over, or None.

    fzf draws on /dev/tty rather than on stdout, so stdout being a pipe proves
    nothing either way -- opening /dev/tty is the actual question.  A batch or
    MI session usually has none, and that is the case this exists to answer
    politely instead of blocking on a read that never returns.
    """
    try:
        fd = os.open("/dev/tty", os.O_RDWR)
    except OSError:
        return False
    os.close(fd)
    return True


@safe(default=(None, "fzf could not be run"))
def _pick_fzf(items, prompt, query):
    """(selected line, note).  (None, note) when fzf is absent or declined."""
    argv = [_fzf_bin(), "--prompt", prompt + "> ", "--height", "60%", "--reverse",
            "--no-multi", "--exit-0"]
    if query:
        argv += ["--query", query]
    extra = _env("FZF_OPTS")
    if extra:
        argv += extra.split()
    try:
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             text=True)
    except OSError as e:
        return (None, "no fzf on this machine (%s); set $GDBTOOLS_FZF to name one" % e.strerror)
    try:
        out, _ = p.communicate("\n".join(items))
    except KeyboardInterrupt:
        try:
            p.kill()
        except Exception:
            pass
        return (None, None)
    if p.returncode == 130 or (p.returncode != 0 and not (out or "").strip()):
        # 130 is ESC or ctrl-c, and --exit-0 makes an empty match exit 1.
        # Neither is an error worth a message.
        return (None, None)
    line = (out or "").strip().splitlines()
    return (line[0] if line else None, None)


@safe(default=(None, "could not ask"))
def _pick_prompt(items, prompt):
    """Numbered prompt read from /dev/tty.  The fallback when fzf is absent.

    /dev/tty and not input(): gdb's stdin may be a script or a pipe while a
    terminal is still attached, and reading the wrong one either blocks forever
    or eats the rest of the script.
    """
    if not _have_tty():
        return (None, "no controlling terminal, so nothing can be asked here")
    shown = items[:_MAX_PRINT]
    try:
        with open("/dev/tty", "r+") as tty:
            for i, it in enumerate(shown, 1):
                tty.write("%4d  %s\n" % (i, it))
            if len(items) > len(shown):
                tty.write("      ... %d more; narrow it with a query argument\n"
                          % (len(items) - len(shown)))
            tty.write("%s [1-%d, empty to cancel]: " % (prompt, len(shown)))
            tty.flush()
            ans = tty.readline().strip()
    except (OSError, KeyboardInterrupt):
        return (None, None)
    if not ans:
        return (None, None)
    try:
        n = int(ans)
    except ValueError:
        return (None, "not a number: %s" % ans)
    if not (1 <= n <= len(shown)):
        return (None, "out of range: %s" % ans)
    return (shown[n - 1], None)


def _listing(items, why):
    """Last resort: print what there is, and why it could not be asked about."""
    print("[%s] fz: %s -- listing instead" % (NAME, why))
    for it in items[:_MAX_PRINT]:
        print("  %s" % it)
    if len(items) > _MAX_PRINT:
        print("  ... %d more" % (len(items) - _MAX_PRINT))
    return None


def _pick(items, prompt, query):
    """fzf, else a numbered prompt, else print what there is and say why.

    Each step is tried only when it can work, so a session with no terminal
    reaches the listing with one explanation rather than collecting one from
    every step it could never have taken.
    """
    if not items:
        print("[%s] fz: nothing to pick from" % NAME)
        return None
    # Off the interactive path a query is still a query: fzf would have used it
    # to narrow the list, so the fallbacks narrow it the same way rather than
    # printing everything and calling that an answer.
    narrowed = [i for i in items if query.lower() in i.lower()] if query else items
    if query and not narrowed:
        print("[%s] fz: nothing matches %r" % (NAME, query))
        return None
    if not _have_tty():
        return _listing(narrowed, "no controlling terminal, so nothing can be asked here")
    sel, note = _pick_fzf(items, prompt, query)
    if sel:
        return sel
    if note is None:
        return None                          # the user cancelled; say nothing
    items = narrowed
    sel, note2 = _pick_prompt(items, prompt)
    if sel:
        return sel
    if note2:
        return _listing(items, "%s -- %s" % (note, note2))
    return None


# ----------------------------------------------------------------- subjects

@safe(default=[])
def _items_history():
    """Past commands, newest first, from gdb's own history file.

    gdb writes that file when it exits, not as you type -- confirmed on gdb
    17.2 -- so this session's own commands are not in it yet.  That is a gdb
    property, not something this can work around: gdb's Python API exposes no
    command-entered event, and the readline history Python can see is its own,
    which in gdb is empty.  Said here rather than silently returning a list that
    looks complete and is not.
    """
    path = None
    try:
        path = gdb.parameter("history filename")
    except Exception:
        path = None
    path = path or os.environ.get("GDBHISTFILE") or os.path.expanduser("~/.gdb_history")
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = [l.rstrip("\n") for l in f]
    except OSError:
        return []
    seen, out = set(), []
    for l in reversed(lines):
        l = l.strip()
        if l and l not in seen:
            seen.add(l)
            out.append(l)
    return out


@safe(default=[])
def _items_commands():
    """Every command gdb answers to, tagged with who registered it."""
    from .cmdinfo import classify, GROUPS
    r = classify()
    if not r:
        return []
    out = []
    for k in GROUPS:
        for n in sorted(r["groups"][k]):
            out.append("%-28s %s" % (n, k))
    return out


@safe(default=[])
def _items_syms(kind, query=""):
    """Symbol names from `info functions` / `info variables`.

    A query is handed to gdb as the regex those commands already take, rather
    than being left to fzf.  On a vmlinux the unfiltered form prints well over a
    hundred thousand lines and takes seconds to produce; letting gdb narrow it
    first is the difference between instant and unusable, and fzf still refines
    what comes back.

    Those commands print "File x.c:" headers, blank lines and a trailing
    "Non-debugging symbols:" block; only a declaration line carries a name, and
    the name is the last identifier before the parameter list.
    """
    cmd = "info " + kind + ((" " + query) if query else "")
    out = gdb.execute(cmd, from_tty=False, to_string=True) or ""
    names = set()
    for line in out.splitlines():
        line = line.strip()
        if not line or line.endswith(":") or line.startswith(("File ", "Non-debugging")):
            continue
        if line.startswith("0x"):                     # non-debugging: "0xADDR  name"
            parts = line.split()
            if len(parts) >= 2:
                names.add(parts[-1])
            continue
        decl = line.rstrip(";")
        head = decl.split("(")[0].strip() if "(" in decl else decl
        tok = head.replace("*", " ").replace("[", " ").split()
        if tok:
            names.add(tok[-1])
    return sorted(names)


@safe(default=[])
def _items_files():
    out = gdb.execute("info sources", from_tty=False, to_string=True) or ""
    files = set()
    for line in out.splitlines():
        line = line.strip()
        if not line or line.endswith(":") or line.startswith(("Source files", "(Objfile")):
            continue
        for piece in line.split(","):
            piece = piece.strip()
            if piece and ("/" in piece or piece.endswith((".c", ".h", ".S", ".rs"))):
                files.add(piece)
    return sorted(files)


@safe(default=[])
def _items_breakpoints():
    out = gdb.execute("info breakpoints", from_tty=False, to_string=True) or ""
    return [l.rstrip() for l in out.splitlines()
            if l[:1].isdigit() or l.strip().startswith("stop only")]


DEFAULT_KEY = r"\C-t"

# Keys that submit the line.  Bound to a macro, the macro runs instead of the
# line being accepted, and nothing else can be entered.
_LINE_KEYS = frozenset((r"\C-m", r"\C-M", r"\C-j", r"\C-J", r"\r", r"\n",
                        r"\015", r"\012", r"\x0d", r"\x0D", r"\x0a", r"\x0A"))


def _refuse_key(key):
    r"""Why KEY must not be bound, or None.

    readline's parse_and_bind never fails: it takes what it can parse and drops
    the rest without a word.  Measured on readline 8.3 -- `a"b` binds the single
    letter `a`, so every `a` typed thereafter fires the macro, and a nonsense
    spell like `\Q-zz` binds nothing while this function would still have
    reported success.  There is no binding-lookup API in Python's readline, so
    the spec has to be judged before it is handed over.

    Only the common mistakes are caught.  `\M-\C-m` and `\C-x\C-m` still reach
    the line key; to recover from one, submit with Ctrl-J -- which stays
    accept-line -- and run
      python import readline; readline.parse_and_bind(r'"KEY": accept-line')
    """
    if not key or '"' in key or any(c.isspace() for c in key):
        return "a key spec cannot be empty, quoted, or contain whitespace"
    if key in _LINE_KEYS:
        return "that key submits the line; bound here, nothing else could be run"
    if len(key) == 1 and key.isprintable():
        return "a plain character fires while typing; use a control or function key"
    return None


@safe(default=False)
def bind_key(key, subject="history"):
    r"""Bind KEY to `fz SUBJECT` in gdb's readline.  True when it took.

    The macro is "\C-a\C-k" and then the command: beginning-of-line, kill-line,
    so the key behaves the same whether the prompt is empty or half typed.
    Verified in a pty with `some half typed garbage` on the line -- the macro
    cleared it and ran the command.

    Nothing is bound unless asked for.  A debugger's keys are the user's, and
    an extension that quietly takes one is the sort of surprise this package
    exists not to be.
    """
    try:
        import readline
    except Exception as e:
        print("[%s] fz bind: no readline in this gdb's Python (%s)" % (NAME, e))
        return False
    if subject not in SUBJECTS:
        print("[%s] fz bind: unknown subject %r; one of: %s"
              % (NAME, subject, " ".join(SUBJECTS)))
        return False
    why = _refuse_key(key)
    if why:
        print("[%s] fz bind: refusing key %r -- %s" % (NAME, key, why))
        return False
    try:
        readline.parse_and_bind(r'"%s": "\C-a\C-kfz %s\n"' % (key, subject))
    except Exception as e:
        print("[%s] fz bind: readline refused %r (%s)" % (NAME, key, e))
        return False
    return True


@safe()
def bind_from_env():
    r"""Honour $GDBTOOLS_FZ_KEY at load time, and only then.

    The value is a readline key spec, optionally followed by a subject:
    `\C-t`, or `\C-r history`, or `\e[15~ commands`.
    """
    spec = _env("FZ_KEY")
    if not spec:
        return
    parts = spec.split()
    key = parts[0]
    subject = parts[1] if len(parts) > 1 else "history"
    if bind_key(key, subject):
        print("[%s] fz: %s runs `fz %s`" % (NAME, key, subject))


class Fz(gdb.Command):
    r"""fz [SUBJECT] [QUERY] [--run] [--dry] : pick something with fzf.

  fz                     past commands from gdb's history file; runs the pick
  fz history [QUERY]     the same, with fzf started on QUERY
  fz commands            every command gdb answers to, tagged with its owner;
                         shows `help` for the pick, or runs it with --run
  fz functions [QUERY]   function names; QUERY is gdb's own regex, so it
                         narrows the image before fzf ever sees it
  fz variables [QUERY]   the same for variables
  fz files               source files gdb knows about
  fz breakpoints         the breakpoint table

  fz bind [KEY] [SUBJECT]  put it on a key, default \C-t running `fz history`.
                         KEY is readline syntax: \C-t, \C-r, \e[15~.  The key
                         clears a half-typed line first, so it behaves the same
                         wherever the cursor is.  Set $GDBTOOLS_FZ_KEY to have
                         this happen when gdbtools loads.

--dry prints the pick instead of acting on it.

A bound key RUNS the pick; it cannot offer it for editing the way a shell's
Ctrl-R does.  gdb drives readline through its callback interface and keeps its
own line state, so text inserted from Python is displayed and then ignored --
measured, not assumed.

fzf is used when it is there and a terminal is attached; otherwise a numbered
prompt on /dev/tty; otherwise the list is printed with the reason it could not
ask.  Which fzf, and with what options, comes from $GDBTOOLS_FZF and
$GDBTOOLS_FZF_OPTS.

gdb writes its history file at exit, so `fz history` sees previous sessions and
not the commands typed in this one."""

    def __init__(self, name="fz"):
        super(Fz, self).__init__(name, gdb.COMMAND_SUPPORT)

    @safe()
    def invoke(self, arg, from_tty):
        parts = (arg or "").split()
        run = any(p == "--run" for p in parts)
        dry = any(p == "--dry" for p in parts)
        rest = [p for p in parts if not p.startswith("--")]
        if rest and rest[0] == "bind":
            key = rest[1] if len(rest) > 1 else DEFAULT_KEY
            subject = rest[2] if len(rest) > 2 else "history"
            if bind_key(key, subject):
                print("[%s] fz: %s now runs `fz %s`" % (NAME, key, subject))
                if key in (r"\C-r", r"\C-R"):
                    print("[%s]   that key was readline's reverse-i-search; inside "
                          "gdb it is this now" % NAME)
            return

        subject = rest[0] if rest and rest[0] in SUBJECTS else "history"
        query = " ".join(rest[1:] if (rest and rest[0] in SUBJECTS) else rest)

        if subject == "history":
            items, action = _items_history(), "run"
            if not items:
                print("[%s] fz: gdb's history file is empty or unreadable "
                      "(`show history filename`); gdb writes it when it exits, so a "
                      "session that has not ended yet contributes nothing" % NAME)
                return
        elif subject == "commands":
            items, action = _items_commands(), ("run" if run else "help")
        elif subject in ("functions", "variables"):
            # The query is spent narrowing gdb's own output; fzf then opens on
            # the result rather than on the whole image.
            items, action = _items_syms(subject, query), "address"
            query = ""
            if not items:
                print("[%s] fz: no %s match %r" % (NAME, subject, " ".join(rest[1:])))
                return
        elif subject == "files":
            items, action = _items_files(), "print"
        else:
            items, action = _items_breakpoints(), "print"

        sel = _pick(items, subject, query)
        if not sel:
            return
        word = sel.split()[0] if action in ("run", "help", "address") else sel
        if dry:
            print("%s" % sel)
            return
        if action == "run":
            print(">>> %s" % word if subject == "commands" else ">>> %s" % sel)
            # from_tty=True, not False.  This line is only ever reached after a
            # person picked something interactively -- with no terminal `_pick`
            # returns None long before here -- so it should behave exactly as if
            # they had typed it at the prompt.  With from_tty=False gdb skips its
            # confirmation queries, and a `delete` or a `run` recalled out of the
            # history would take effect with nothing asked.  Measured on gdb
            # 17.2: from_tty=False deleted every breakpoint silently and
            # restarted the inferior, from_tty=True asked both times.
            gdb.execute(sel if subject == "history" else word, from_tty=True)
        elif action == "help":
            gdb.execute("help " + word, from_tty=False)
        elif action == "address":
            print(sel)
            execstr("info address " + word)
            out = execstr("info line " + word)
            if out and "No line number" not in out:
                print(out.strip())
        else:
            print(sel)


__all__ = ["Fz", "bind_key", "bind_from_env"]
