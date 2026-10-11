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
| `enumvals` | list every value of a C/C++ enum as this build defines them, decimal by default or `/x` for hex |
| `cmdinfo` | which extension registered each command gdb answers to right now — this package, pwndbg, the kernel's `scripts/gdb`, another Python extension, a `define` macro, or gdb itself |
| `fz` | pick a past command, a command name, a symbol or a source file through fzf, falling back to a numbered prompt and then to a plain listing |

**`gdbtools/linux_kernel/`** is a Linux early-boot debugger. In `head.S`, before
the MMU is switched to the kernel's high mapping, `$pc` and pointers hold
*physical* addresses while gdb's symbol table is linked at *virtual* ones, so
`info symbol`, `backtrace` and pwndbg's `telescope` resolve nothing — exactly
where they are needed most. This half measures the per-boot phys↔virt offset from
a `head.S` anchor at runtime, never from a constant, so it survives KASLR, a
different load address and a different kernel version. It then loads a
phys-shifted shadow symbol file, which revives stock gdb and pwndbg alike without
patching either.

It adds `kearly kp2v kv2p kb kw ksr ksregs kbits kfin kcensus kpt kpgd kpthex koff kx
kdtb mmview memlayout kmemblock`, and stays inert until a vmlinux is loaded, so
sourcing it globally costs an ordinary session nothing. Targets arm64, x86_64 and
riscv64.

`docs/early-boot.md` is the full manual: calibration, MMU regimes, page tables,
system registers, watchpoints and the crossing catcher.

## Install

Clone it anywhere; nothing depends on the location.

```sh
git clone https://github.com/yugeun-song/gdbtools
./gdbtools/setup.sh
```

`setup.sh` asks gdb which init file it actually reads, writes one `source` line
into it, and records the checkout path under
`${XDG_CONFIG_HOME:-~/.config}/gdbtools/root` so other tools can find it.
`--check` reports the state of an installation and changes nothing; `--uninstall`
removes what it added and leaves the checkout alone.

`setup.sh --library` (alias `--no-global`) records only the checkout path and
writes no global `source` line, so a plain `gdb` stays exactly stock and a caller
— an editor's debug adapter, a lab script — sources `gdbtools.py` itself when it
wants the extension. kbuildlab's `attach` and the nvim adapter both find the
checkout through that root pointer.

To load it by hand instead:

```
(gdb) source /path/to/gdbtools/gdbtools.py
```

Re-sourcing is idempotent and picks up edited modules, so the hacking loop is
edit, re-source, run.

### The `sym` takeover

Library mode is the recommended mode, because of `sym`. In stock gdb `sym` is the
unique-prefix abbreviation of `symbol-file`, and registering a command by that
name silently replaces it for the whole session. Sourcing this package globally
would therefore change what `sym` does in every gdb session on the machine. In
library mode the takeover happens only in a session that asked for it, and it is
announced when it does:

```
[gdbtools] took over existing gdb command(s): sym
[gdbtools]   the previous meaning is gone for this session; the full name still
             works where one exists (e.g. `symbol-file` for `sym`)
```

## Finding commands: cmdinfo and fz

With pwndbg, this package and a vmlinux loaded, a session answers to hundreds of
command words. `cmdinfo` reports which extension registered each one — this
package, pwndbg, the kernel's `scripts/gdb`, another Python extension, a `define`
macro, or gdb itself. Attribution is positional, read from each command's
registry, never inferred from its name.

`cmdinfo GROUP` lists one group, `cmdinfo NAME` says who registered one command
(for a prefix, lists its subcommands). `--sub` includes every subcommand path,
`-1` prints one name per line for piping, `-c` gives the counts alone.

`fz` searches rather than lists, through fzf:

```
(gdb) fz                       past commands, from gdb's history file
(gdb) fz commands              every command gdb answers to, tagged with its owner
(gdb) fz functions ^start_     QUERY is gdb's own regex, narrowing before fzf sees it
(gdb) fz variables memblock
(gdb) fz files
(gdb) fz breakpoints
```

It uses fzf when installed and a terminal is attached, otherwise a numbered
prompt on `/dev/tty`, otherwise it prints the list with the reason it could not
ask. `$GDBTOOLS_FZF` names the binary and `$GDBTOOLS_FZF_OPTS` is appended to its
arguments.

`fz` goes on a key, the way Ctrl-R is a key in a shell:

```
(gdb) fz bind                  \C-t runs `fz history`
(gdb) fz bind \C-r history      take the reverse-i-search key, inside gdb only
(gdb) fz bind \e[15~ commands   F5
```

or `GDBTOOLS_FZ_KEY='\C-t history'` in the environment to bind it when gdbtools
loads. Nothing is bound otherwise. The binding uses `readline.parse_and_bind()`
from gdb's own Python, so `~/.inputrc` is not touched. gdb's own history is not in
the readline state Python sees and is written only at exit, so `fz history`
searches previous sessions, not the current one.

## Using the kernel half

Attach to a frozen kernel and calibrate:

```
(gdb) target remote :1235
(gdb) kearly on
(gdb) kearly bootbreak
```

Or export `GDBTOOLS_AUTO=1` before starting gdb: `kearly on` then arms itself the
moment a kernel image is loaded. Boards that QEMU cannot describe take a JSON
profile through `$GDBTOOLS_PROFILE` (see `profiles/`) or a device tree through
`$GDBTOOLS_DTB`. On x86_64, whether the image base is recovered and by which route
(direct boot or EFI stub) is controlled by `GDBTOOLS_ENTRY_PA` and the
`GDBTOOLS_X86_*` variables below; `docs/early-boot.md` covers it.

`kmemblock` reads memblock — firmware's or the device tree's memory ranges in
`memblock.memory`, and everything claimed back out of them in `memblock.reserved`.
Between `_text` and `mem_init()` that is the only description of RAM that exists,
which is the window this half debugs in. Its struct shape and flag names are read
from DWARF, so a kernel that moved or added a `memblock` flag is described
correctly without being taught about it.

```
(gdb) kmemblock
[gdbtools] memblock  arrays live  bottom_up=False  current_limit=0xffffffffffffffff   [MMU=on SCTLR_EL1.M]
  memory    cnt=1/1024  total=0x40000000 (1024.0 MiB)  name=memory
      [  0] 0x0000000040000000..0x000000007fffffff  size 0x40000000 (1024.0 MiB)  0x0 NONE
  reserved  cnt=9/641   total=0x0281a000 (40.1 MiB)   name=reserved
      ...
```

## Configuration is injected, not discovered

This package operates on what it is handed. It carries no machine constants, it
does not scan the host for a VM to attach to, and it does not derive a path from
another path. Whoever launches gdb — a lab script, an editor's debug adapter —
states the machine; if what they state is wrong, the tool fails and says which
value was missing rather than substituting a plausible one that looks calibrated
while every address is quietly off.

Everything arrives as a `GDBTOOLS_`-prefixed environment variable set before gdb
starts. There is no second spelling and no search path. Each one is parsed by its
type; a variable that is **set** and does not parse is a loud error naming the
variable and the value, not a silent fall-through to another source. Unset keeps
the default. The table is the one declared in `gdbtools/common/config.py` (checked
with `python3 -B -m gdbtools.common.config --check README.md`).

<!-- gdbtools-env:begin -->
| variable | type | meaning |
| --- | --- | --- |
| `GDBTOOLS_AUTO` | bool | arm the kernel session once a kernel image is loaded: stop hook, shadow symbols, MMU-transition notices. Unset: `kearly on` is manual |
| `GDBTOOLS_ENTRY_PA` | address | physical address of the kernel image base. On x86_64 a stated base suppresses the decompressor recovery |
| `GDBTOOLS_SCAN` | range | physical range searched for the image magic; replaces every derived range |
| `GDBTOOLS_RAM_BASE` | address | RAM base; the scan covers `SCAN_SPAN` bytes from it |
| `GDBTOOLS_SCAN_SPAN` | count | bytes scanned past `RAM_BASE` or a DTB `/memory` base. Default 128 MiB |
| `GDBTOOLS_PHYS_WINDOW` | range | physical range the image may occupy, for the calibration sanity check. Unset: the check is skipped |
| `GDBTOOLS_PROFILE` | file | JSON machine description (see `profiles/`), validated field by field |
| `GDBTOOLS_DTB` | file | device tree blob describing the board |
| `GDBTOOLS_PRESET` | preset name | boot-combination preset (`kearly preset list`) |
| `GDBTOOLS_ANCHOR` | symbol | calibration and entry-break anchor symbol, overriding the preset |
| `GDBTOOLS_BREAK_KIND` | `sw` \| `hw` | breakpoint kind for the entry break |
| `GDBTOOLS_X86_KASLR` | bool | recover the decompressor-randomized physical base in `kearly bootbreak` |
| `GDBTOOLS_X86_DECOMP_PA` | address | where a direct boot loads the bzImage decompressor; selects the direct-boot recovery. Unset: the EFI-stub recovery |
| `GDBTOOLS_X86_DECOMP_VMLINUX` | file | `arch/x86/boot/compressed/vmlinux`, read by the x86 base recovery |
| `GDBTOOLS_BINUTIL_NM` | program | `nm` for the x86 decompressor parse. Unset: `nm` on `$PATH` |
| `GDBTOOLS_BINUTIL_OBJDUMP` | program | `objdump` for the same parse. Unset: `objdump` on `$PATH` |
| `GDBTOOLS_NO_COLOR` | bool | monochrome `cfgdis` and pwndbg flow panel |
| `GDBTOOLS_KDIS_ASCII` | bool | ASCII arrows in `cfgdis` and the pwndbg flow panel |
| `GDBTOOLS_DEBUG` | bool | report every exception the safety layer swallows on gdb's stderr; NameError, AttributeError and TypeError are reported regardless |
| `GDBTOOLS_MAP_CAP_LEAVES` | count | `mmview` leaf cap (default 20000); `mmview` says when it truncated |
| `GDBTOOLS_MAP_CAP_NODES` | count | `mmview` table-node cap (default 60000) |
| `GDBTOOLS_MEMBLOCK_CAP` | count | regions `kmemblock` prints per type (default 512); `kmemblock TYPE full` lifts it |
| `GDBTOOLS_FZF` | program | fzf binary for `fz`. Unset: `fzf` on `$PATH`, else a numbered prompt |
| `GDBTOOLS_FZF_OPTS` | words | options appended to fzf's arguments |
| `GDBTOOLS_FZ_KEY` | key [subject] | readline key, optionally with a subject (`\C-t`, `\C-r history`), bound to `fz` at load |
| `GDBTOOLS_RISCV_KERNEL_MAP_VIRT_OFF` | int | offset of `virt_addr` in `struct kernel_mapping`, for a riscv vmlinux without DWARF (8 on 6.12, 0 on mainline) |
<!-- gdbtools-env:end -->

Booleans take `1/0`, `true/false`, `yes/no` or `on/off` (case-insensitive) and
reject anything else; a range is `lo:hi` with `lo < hi`.

`GDBTOOLS_PATH` is deliberately **not** in the table above and is not read by the
package. It is a launcher-side name — kbuildlab and the editor adapter use it to
find `gdbtools.py` before gdb starts — so it lives in this namespace by convention
but is not part of the package's own contract.

## Dependencies

**Required**

- `gdb` built with Python 3 support whose Python layer starts. Check with
  `gdb -nx -batch -ex 'python gdb.VERSION'`.

**Optional, detected rather than assumed**

- [pwndbg](https://github.com/pwndbg/pwndbg). If present, this integrates with it:
  two extra context sections, and a guard that stops pwndbg's page probing from
  killing a QEMU target. **Load order matters** — pwndbg must be sourced *before*
  this, which is what `setup.sh` arranges by appending. pwndbg aborts its entire
  command set with an `AssertionError` if it loads over a command another
  extension already registered, so a hand-reordered init file breaks pwndbg, not
  this.
- A cross-gdb, or a `gdb` built `--enable-targets=all`, for kernels of another
  architecture.
- QEMU, or any other gdbstub, for the kernel half. Booting one is not this
  project's job.

**Depended on by**

- [nvim-config](https://github.com/yugeun-song/nvim-config) — its control-flow
  panel has no other data source: every basic block, edge and dominator answer
  comes from `cfgjson` here. It works against ordinary userspace programs too, not
  only kernels, which is why the analysis lives in `common/`. Without this
  repository installed the panel reports that the toolkit is not loaded.
