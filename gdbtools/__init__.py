"""gdbtools -- gdb extensions for low-level work.

Two halves, split by whether the debuggee has to be a kernel:

    common/         control-flow graphs, arrowed disassembly, address
                    symbolization, pointer telescopes.  Works on any target.
    linux_kernel/   early-boot (pre-MMU) symbolization, page-table walking,
                    system registers, device trees.  Needs a vmlinux.

Load it by sourcing `gdbtools.py` at the top of the repository; importing this
package directly does not register any command.
"""

__version__ = "0.1.0"
