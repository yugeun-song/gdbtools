"""gdbtools -- gdb extensions for low-level work.  Source this file.

    (gdb) source /path/to/gdbtools/gdbtools.py

or, once, through setup.sh, which writes that line into the gdb init file gdb
actually reads.  Sourcing is idempotent and re-sourcing picks up edited modules,
so a hacking loop is: edit, re-source, run.

The tool locates its own package as this file's sibling and needs nothing else
to be true about where the repository lives -- clone it anywhere.
"""
import os
import sys

# realpath, not abspath: the loader is commonly reached through a symlink, and
# abspath would leave sys.path pointing at the link's directory, where there is
# no `gdbtools` package to import.
_HERE = os.path.dirname(os.path.realpath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Re-sourcing should pick up edited modules rather than silently reusing cached
# ones.  Drop ours first; gdb-side state (commands, hooks) is reconciled by
# bootstrap below.
for _m in [m for m in list(sys.modules) if m == "gdbtools" or m.startswith("gdbtools.")]:
    del sys.modules[_m]

import gdbtools.bootstrap as _bootstrap

_bootstrap.main()
