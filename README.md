# gdbtools

gdb extensions for low-level work, in two halves split by whether the debuggee
has to be a kernel.

**`gdbtools/common/`** works against anything gdb can attach to, kernel or not:

| command | what it does |
| --- | --- |
| `cfgjson` | the control-flow graph of the function around an address, as JSON: basic blocks, typed edges, layered ranks, and which blocks are proved executed, unreachable or still unknown |
| `cfgdis` | the same structure as text, with branch arrows drawn in the left margin |
| `addr2sym` | name the symbol at an address, physical or virtual |
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
kdtb mmview memlayout kmemblock`. Nothing it does to gdb, pwndbg or the symbol
table happens unless asked for (see Configuration). Targets arm64, x86_64 and
riscv64.

`docs/early-boot.md` is the full manual: calibration, MMU regimes, page tables,
system registers, watchpoints and the crossing catcher.

## Install

Clone it anywhere; nothing depends on the location.

```sh
git clone https://github.com/yugeun-song/gdbtools
./gdbtools/install.sh            # ~/.local/bin/gdbtools; --system: /usr/local/bin (sudo)
gdbtools doctor
```

`install.sh` links the `gdbtools` command into a directory on `PATH` (it says how
to add one that is missing; shell files are never edited) and runs `setup.sh`,
which records the checkout in `${XDG_CONFIG_HOME:-~/.config}/gdbtools/root`.
kbuildlab's `attach` and the nvim adapter find `gdbtools.py` there and source it
themselves; a plain `gdb` stays stock. `setup.sh --global` also writes a `source`
line into the init file gdb reads, so every gdb loads it. `--check` reports,
`--uninstall` removes what was added.

```
gdbtools gdb [GDB ARGS]     gdb with gdbtools loaded ($GDB picks the gdb)
gdbtools path               the loader, for a tool that sources it
gdbtools config             every GDBTOOLS_* setting and its value here
gdbtools doctor             gdb, its Python, pwndbg and the install
(gdb) source /path/to/gdbtools/gdbtools.py      by hand; re-sourcing picks up edits
```

### Command names

No name here replaces a gdb or pwndbg command. A new name still shares
abbreviations: without pwndbg, `kearly` makes `k` stop meaning `kill` and `chain`
makes `ch` stop meaning `checkpoint`; with pwndbg, `kfin` takes `kf` from `kfile`.
Every abbreviation that resolved before the package loaded and is ambiguous after
is kept as an alias of what it meant (`cmdinfo kept` lists them), so typing it
does what it did before.

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
moment a kernel image is loaded. What else the session does -- the shadow symbol
file, the KASLR slide, the pwndbg panels and guards -- is each its own setting,
off unless stated; kbuildlab's `attach` states all of them. Boards that QEMU
cannot describe take a JSON profile through `$GDBTOOLS_PROFILE` (see `profiles/`)
or a device tree through `$GDBTOOLS_DTB`. On x86_64 the image base is recovered
through the decompressor or the EFI stub, chosen by `GDBTOOLS_BOOT`;
`docs/early-boot.md` covers it.

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

This package operates on what it is handed. It does not scan the host for a VM
and does not derive a path from another path. Whoever launches gdb states the
machine; a value that is wrong fails by name instead of being replaced by a
plausible one. The only machine facts it carries are QEMU's default boards (the
RAM base of `virt`, `pc` and `q35`, used once the QEMU monitor names one of them)
and the x86 boot protocol's 0x100000 decompressor address for a direct boot.

A setting arrives two ways: a `GDBTOOLS_` environment variable set before gdb
starts, or `kearly set KEY VALUE` inside the session, which outranks it until
`kearly unset KEY` (`kearly set KEY -` states it unset, hiding the environment's
value). `kearly config` shows each value and where it came from, and the hand
controls (`kearly shadow off`, `kearly kaslr off`, ...) write the same settings,
so nothing re-derives them behind the user's back. A value that is set and does
not parse is an error naming it. Every behaviour that changes gdb, pwndbg or the
symbol table defaults to off. The table is declared in `gdbtools/common/config.py`
(checked with `python3 -B -m gdbtools.common.config --check README.md`).

<!-- gdbtools-env:begin -->
| variable | type | meaning |
| --- | --- | --- |
| `GDBTOOLS_AUTO` | bool | arm the kernel session once a kernel image is loaded: stop hook, calibration, MMU-transition notices. The behaviours below stay off unless stated. Unset: `kearly on` is manual |
| `GDBTOOLS_BOOT` | `direct` \| `uboot` \| `uefi` | how the guest was booted. `uboot` and `uefi` make the entry break `hw` unless `BREAK_KIND` says otherwise; on x86_64 `direct` puts the decompressor at the boot-protocol address 0x100000 unless `X86_DECOMP_PA` says otherwise |
| `GDBTOOLS_SAFEMEM` | `off` \| `auto` \| `on` | guard pwndbg's memory probes by asking QEMU whether a page is RAM before reading it (`kearly safemem`). Unset: off |
| `GDBTOOLS_PWNDBG_GUARDS` | bool | keep pwndbg's context alive on early-boot reads that throw. Unset: off |
| `GDBTOOLS_PANELS` | words of `kgdb`, `flow`, `msysreg` | pwndbg context sections to add: `kgdb` (regime badge), `flow` (branch arrows), `msysreg` (system registers and their fields). Unset: none |
| `GDBTOOLS_EXPLORE_PAGES` | `keep` \| `off` | `off` sets pwndbg's `auto-explore-pages` to `no` while the session is on and restores it after. Unset: keep |
| `GDBTOOLS_SAFERENDER` | `off` \| `warn` \| `auto` \| `on` | arm64 guard for pwndbg's emulated disassembly: `auto` and `on` turn pwndbg `emulate` off, `warn` only prints a notice (`kearly saferender`). Unset: off |
| `GDBTOOLS_SHADOW` | bool | load vmlinux again at the physical offset once calibrated, so physical addresses symbolize. Unset: off |
| `GDBTOOLS_KASLR_APPLY` | `off` \| `auto` | `auto` relocates gdb's symbols to the KASLR slide at the first virtual stop where it is readable (`symbol-file -o`). Unset: off |
| `GDBTOOLS_CROSSING` | bool | when a high-VA probe is set before the slide is known, arm a hidden hardware breakpoint on the MMU crossing that applies the slide in passing. Unset: off |
| `GDBTOOLS_ADOPT` | bool | give a plain `b SYM` hardware siblings at its physical and runtime addresses. Unset: off |
| `GDBTOOLS_BPFIX` | bool | disable a breakpoint's physical location while the MMU is on (`kearly bpfix`). Unset: off |
| `GDBTOOLS_STEPLOCK` | `off` \| `on` \| `auto` | gdb `scheduler-locking step` while stepping; `auto` only while the MMU is off (`kearly steplock`). Unset: off |
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
| `GDBTOOLS_X86_DECOMP_PA` | address | where a direct boot loads the bzImage decompressor; selects the direct-boot recovery. Unset: 0x100000 when `BOOT` is `direct`, else the EFI-stub recovery |
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

Booleans take `1/0`, `true/false`, `yes/no` or `on/off`; a range is `lo:hi` with
`lo < hi`; a list is words separated by spaces or commas.

The default machine is QEMU's own: `virt` on arm64 and riscv64, `pc` or `q35` on
x86_64. It is used only once QEMU's monitor confirms the machine type, and only
for RAM the guest has not described itself. A different machine, or a target with
no QEMU monitor, is said once, and then only what the guest reports, or
`GDBTOOLS_PROFILE` / `GDBTOOLS_DTB`, describes it.

`GDBTOOLS_PATH` is not in the table: kbuildlab and the nvim adapter read it to find
`gdbtools.py` before gdb starts, and the package itself never does.

## Dependencies

**Required**

- `gdb` built with Python 3 support whose Python layer starts. Check with
  `gdb -nx -batch -ex 'python gdb.VERSION'`.

**Optional, detected rather than assumed**

- [pwndbg](https://github.com/pwndbg/pwndbg). If present, this integrates with it:
  three extra context sections, guards that keep pwndbg's context alive on
  early-boot reads, and a guard that stops pwndbg's page probing from killing a
  QEMU target. **Load order matters**: pwndbg must load first, which the launchers
  get by sourcing this after the init file and `setup.sh --global` by appending.
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
