"""gdbtools -- gdb extensions for low-level work.  Source this file.

    (gdb) source /path/to/gdbtools/gdbtools.py

or start gdb with `gdbtools gdb`; `setup.sh --global` writes that line into the
gdb init file instead.  Sourcing is idempotent and re-sourcing picks up edited
modules, so a hacking loop is: edit, re-source, run.

The tool locates its own package as this file's sibling and needs nothing else
to be true about where the repository lives -- clone it anywhere.
"""
import os
import sys

# The code object's own file name, not __file__: when this is sourced from inside
# another Python file (pwndbg re-sources ~/.gdbinit from its loader), __main__
# keeps the OUTER file's __file__ and the package would be looked for next to it.
# realpath, not abspath: the loader is commonly reached through a symlink.
_HERE = os.path.dirname(os.path.realpath(sys._getframe().f_code.co_filename))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Re-sourcing should pick up edited modules rather than silently reusing cached
# ones.  Drop ours first; gdb-side state (commands, hooks) is reconciled by
# bootstrap below.
for _m in [m for m in list(sys.modules) if m == "gdbtools" or m.startswith("gdbtools.")]:
    del sys.modules[_m]

# A cross gdb that shares its data directory with a newer host gdb has only the
# low-level _gdb module: its `gdb` package fails to import.  Say that, once,
# instead of the package failing halfway on an ImportError about _gdb internals.
try:
    import gdb as _gdb_pkg
    _why = None if hasattr(_gdb_pkg, "execute") else "it has no gdb.execute"
except ImportError as _e:
    _why = str(_e)

if _why is None:
    import gdbtools.bootstrap as _bootstrap

    _bootstrap.main()
else:
    sys.stderr.write(
        "[gdbtools] not loaded: this gdb's Python `gdb` package does not work (%s).\n"
        "[gdbtools] Its data directory belongs to a different gdb version; start it with\n"
        "[gdbtools] --data-directory=<its own data directory>, or use a gdb whose Python\n"
        "[gdbtools] layer starts (`gdb -nx -batch -ex 'python gdb.VERSION'`).\n" % _why)
