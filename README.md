# gdbtools

gdb extensions for low-level work, in two halves split by whether the debuggee
has to be a kernel.

**`gdbtools/common/`** works against anything gdb can attach to, kernel or not:

| command | what it does |
| --- | --- |
| `cfgjson` | the control-flow graph of the function around an address, as JSON: basic blocks, typed edges, layered ranks, and which blocks are proved executed, unreachable or still unknown |
| `cfgdis` | the same structure as text, with branch arrows drawn in the left margin |
| `sym` | name the symbol at an address |
| `stackscan` | read the stack word by word and name every value that resolves, for when `backtrace` cannot work |
| `chain` | follow a pointer chain, bounded and cycle-guarded |

**`gdbtools/linux_kernel/`** is a Linux early-boot debugger. In `head.S`, before
the MMU is switched to the kernel's high mapping, `$pc` and pointers hold
*physical* addresses while gdb's symbol table is linked at *virtual* ones, so
`info symbol`, `backtrace` and pwndbg's `telescope` resolve nothing — exactly
where they are needed most. This half measures the per-boot phys↔virt offset
from a `head.S` anchor at runtime, never from a constant, so it survives KASLR,
a different load address and a different kernel version. It then loads a
phys-shifted shadow symbol file, which revives stock gdb and pwndbg alike
without patching either.

It adds `kearly kp2v kv2p kb kw ksr ksregs kfin kcensus kpt kpgd kpthex koff kx
kdtb kconnect mmview`, and stays inert until a vmlinux is loaded, so sourcing it
globally costs an ordinary session nothing.

Targets arm64, x86_64 and riscv64.

## Install

Clone it wherever you keep things; nothing depends on the location.

```sh
git clone https://github.com/yugeun-song/gdbtools
./gdbtools/setup.sh
```

`setup.sh` asks gdb which init file it actually reads, writes one `source` line
into it, and records the checkout path under `$XDG_CONFIG_HOME/gdbtools` so
other tools can find it. `--check` reports the state of an installation and
changes nothing; `--uninstall` removes what it added and leaves the checkout
alone.

To load it by hand instead:

```
(gdb) source /path/to/gdbtools/gdbtools.py
```

Re-sourcing is idempotent and picks up edited modules, so the hacking loop is
edit, re-source, run.

## Using the kernel half

Attach to a frozen kernel and calibrate:

```
(gdb) target remote :1235
(gdb) kearly on
(gdb) kearly bootbreak
```

Or export `GDBTOOLS_AUTO=1` before starting gdb and all of that happens on
attach. Boards that QEMU cannot describe take a JSON profile through
`$GDBTOOLS_PROFILE` (see `profiles/`) or a device tree through `$GDBTOOLS_DTB`.

`docs/early-boot.md` is the full manual: calibration, MMU regimes, page tables,
system registers, watchpoints and the crossing catcher.

## Dependencies

**Required**

- `gdb` built with Python 3 support. Check with `gdb --configuration | grep python`.

**Optional, detected rather than assumed**

- [pwndbg](https://github.com/pwndbg/pwndbg). Not required, but if it is present
  this integrates with it: two extra context sections, and a guard that stops
  pwndbg's page probing from killing a QEMU target. **Load order matters** —
  pwndbg must be sourced *before* this, which is what `setup.sh` arranges by
  appending. pwndbg refuses to load over a command another extension already
  registered and aborts its entire command set with an `AssertionError`, so a
  hand-reordered init file breaks pwndbg, not this.
- A cross-gdb, or a `gdb` built `--enable-targets=all`, for kernels of another
  architecture.
- QEMU, or any other gdbstub, for the kernel half. Booting one is not this
  project's job.

**Depended on by**

- [nvim-config](https://github.com/yugeun-song/nvim-config) — its control-flow
  panel has no other data source. The Lua side does block layout and rendering;
  every basic block, edge and dominator answer comes from `cfgjson` here. That
  panel works against ordinary userspace programs too, not only kernels, which
  is why the analysis lives in `common/`. Without this repository installed the
  panel reports that the toolkit is not loaded and stays empty.
