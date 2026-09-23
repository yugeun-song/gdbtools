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
where they are needed most. This half measures the per-boot phys↔virt offset
from a `head.S` anchor at runtime, never from a constant, so it survives KASLR,
a different load address and a different kernel version. It then loads a
phys-shifted shadow symbol file, which revives stock gdb and pwndbg alike
without patching either.

It adds `kearly kp2v kv2p kb kw ksr ksregs kbits kfin kcensus kpt kpgd kpthex koff kx
kdtb mmview memlayout kmemblock`, and stays inert until a vmlinux is loaded, so sourcing
it globally costs an ordinary session nothing.

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

`setup.sh --library` (alias `--no-global`) records only the checkout path and writes no global `source`
line, so a plain `gdb` stays exactly stock and a caller -- an editor's debug
adapter, a lab script -- sources `gdbtools.py` itself when it wants the extension.
Use it when gdbtools should be a library that callers load, not a global default.

To load it by hand instead:

```
(gdb) source /path/to/gdbtools/gdbtools.py
```

Re-sourcing is idempotent and picks up edited modules, so the hacking loop is
edit, re-source, run.

## Which extension owns a command, and finding one

A session with pwndbg, this package and a vmlinux loaded answers to about 535
command words, over 30 of which are prefixes carrying another 2036 subcommands
between them. Tab at an empty prompt does not say where any of them came from,
and it is slow for a reason that cannot be fixed from here: gdb hands readline
every candidate at once and readline stops to ask whether to print them all.
`complete ''` is fast and silently truncates at `max-completions`, 200 by
default — measured here it returned 200 names where `help all` had 1500, with
nothing said about having stopped short.

```
(gdb) cmdinfo -c
gdbtools     26  this package
pwndbg      245  pwndbg, its aliases included
kernel       35  the kernel's own scripts/gdb
python        1  other Python extensions, gdb's bundled ones included   (+2 subcommands under 1 prefixes)
user          3  `define` macros, or a Python command that could not be placed
gdb         227  gdb itself   (+2034 subcommands under 29 prefixes)
```

`cmdinfo GROUP` lists one group, `cmdinfo NAME` says who registered one command
— and for a prefix, lists its subcommands. `--sub` includes every subcommand
path, `-1` prints one name per line for piping, `-c` gives the counts alone.

Every name reported is one gdb resolves at that moment: present in `help all`
*and* answered by `help NAME` rather than "Undefined command" or "Ambiguous
command". Verifying all of them costs about 4 ms, so there is no reason to trust
the listing instead. Prefixes are shown apart from leaves, because `set` alone
is not a command you can run and folding its 745 subcommands into the word would
say it were.

Attribution is positional, never inferred from a name. Our own names and
pwndbg's come from their registries; `gdb.Command` exposes no name attribute, so
every other Python command is traced through the garbage collector to the class
that registered it and the file that class lives in, with the name read from the
string literal that class's own source passes to `__init__`; whatever is left is
gdb's. A `lx-` prefix rule would be wrong on its first counterexample and the
kernel ships one: `scripts/gdb` registers `translate-vm`.

`fz` is the other half — searching rather than listing:

```
(gdb) fz                       past commands, from gdb's history file
(gdb) fz commands              every command gdb answers to, tagged with its owner
(gdb) fz functions ^start_     QUERY is gdb's own regex, so it narrows the image
(gdb) fz variables memblock    before fzf ever sees it
(gdb) fz files
(gdb) fz breakpoints
```

fzf when it is installed and a terminal is attached; otherwise a numbered prompt
on `/dev/tty`; otherwise the list is printed with the reason it could not ask.
None of the three hangs, and a batch or MI session takes the last one.
`$GDBTOOLS_FZF` names the binary and `$GDBTOOLS_FZF_OPTS` is appended to its
arguments, so which fzf and how it behaves stays a property of the machine.

It goes on a key, the way Ctrl-R is a key in a shell:

```
(gdb) fz bind                  \C-t runs `fz history`
(gdb) fz bind \C-r history      take the reverse-i-search key, inside gdb only
(gdb) fz bind \e[15~ commands   F5
```

or `GDBTOOLS_FZ_KEY='\C-t history'` in the environment to have it bound when
gdbtools loads. Nothing is bound otherwise: a debugger's keys are the user's.
The binding is installed with `readline.parse_and_bind()` from gdb's own Python,
so `~/.inputrc` is not touched, and the macro clears a half-typed line first so
the key does the same thing wherever the cursor is.

What that can and cannot do was measured against gdb 17.2 with system readline
8.3, in a real pty, not assumed:

| | |
| --- | --- |
| a macro fires at the `(gdb)` prompt | **works** — both `readline.parse_and_bind()` from gdb's Python and an `$if gdb` block in `~/.inputrc` |
| clearing a half-typed line first | **works** — `\C-a\C-k` ahead of the command |
| running the pick | **works** — Ctrl-T, filter in fzf, Enter, and `$1 = 333333` came back |
| offering the pick for editing, as a shell's Ctrl-R does | **no** — `readline.insert_text()` from a pre-input hook displays the text and gdb does not run it; a prefilled `print 1234567` never printed `$1`, and gdb's empty-line repeat ran the previous command instead. gdb drives readline through its callback interface and keeps its own line state |
| reading this session's history | **no** — gdb's history is not in the readline state Python sees (length 0 in a pty after two commands), and gdb writes its history file at exit. So `fz history` searches previous sessions |

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

### The memory map before there is a memory map

`kmemblock` reads memblock — firmware's or the device tree's memory ranges in
`memblock.memory`, and everything claimed back out of them in
`memblock.reserved`. Between `_text` and `mem_init()` that is the only
description of RAM that exists, which is the window this half debugs in.

```
(gdb) kmemblock
[gdbtools] memblock  arrays live  bottom_up=False  current_limit=0xffffffffffffffff   [MMU=on SCTLR_EL1.M]
  memory    cnt=1/1024  total=0x40000000 (1024.0 MiB)  name=memory
      [  0] 0x0000000040000000..0x000000007fffffff  size 0x40000000 (1024.0 MiB)  0x0 NONE
  reserved  cnt=9/641   total=0x0281a000 (40.1 MiB)   name=reserved
      ...
```

Its shape is read from DWARF rather than assumed, because it moved across the
versions this workspace holds: 4.6 types `flags` as a plain `unsigned long` and
has no `name` member, 6.12 types it as `enum memblock_flags` and adds one, and
mainline adds two more flags. So the members are found by walking the struct's
fields and the flag names come from the DWARF type of the flags field itself —
a kernel that adds a flag is described correctly without being taught about, and
one that carries no enum has its flags printed raw with that said out loud.

After `mem_init()` the arrays survive only where `CONFIG_ARCH_KEEP_MEMBLOCK` is
set. arm64 and riscv select it; x86_64 does not, since the only symbol that
selects it there is `INTEL_TDX_HOST`. 6.x sets `memblock_memory` to NULL in
`memblock_discard()`, so the freed case is reported rather than printed as a
memory map; 4.6 has no such pointer and the answer is then honestly unknown.

## Configuration is injected, not discovered

This package operates on what it is handed. It carries no machine constants, it
does not scan the host for a VM to attach to, and it does not derive a path from
another path. Whoever launches gdb — a lab script, an editor's debug adapter —
states the machine; if what they state is wrong, the tool fails and says which
value was missing rather than substituting a plausible one. A constant like "this
board boots at 0x40200000" is right until the day it is not, and on that day it
produces a session that looks calibrated while every address is quietly off.

Everything arrives as a `GDBTOOLS_`-prefixed environment variable set before gdb
starts. There is no second spelling and no search path.

| variable | what it states |
| --- | --- |
| `GDBTOOLS_AUTO` | arm the kernel session on attach: stop hook, shadow symbols, MMU-transition notices. Without it nothing hooks the session and `kearly on` is manual |
| `GDBTOOLS_ENTRY_PA` | physical address of the kernel image base, for when the target cannot report it. On x86_64 you either pin a base you already know here, or leave it unset so the decompressor recovery below finds the relocated one — the two are exclusive, and a pinned value suppresses the recovery |
| `GDBTOOLS_SCAN` | `lo:hi` physical range to search for the image magic |
| `GDBTOOLS_RAM_BASE` | RAM base, as a shorthand for a scan range starting there |
| `GDBTOOLS_PHYS_WINDOW` | `lo:hi` range the image may plausibly occupy, for the sanity check. Absent, the check is skipped rather than run against some other board's range |
| `GDBTOOLS_PROFILE` | JSON machine description (see `profiles/`) |
| `GDBTOOLS_DTB` | device tree blob describing the board |
| `GDBTOOLS_PRESET` | boot-combination preset: firmware entry symbol and breakpoint kind |
| `GDBTOOLS_ANCHOR` | calibration anchor symbol, overriding the preset |
| `GDBTOOLS_BREAK_KIND` | `sw` or `hw` for the entry breakpoint |
| `GDBTOOLS_X86_KASLR` | recover the decompressor-randomized physical base on attach |
| `GDBTOOLS_X86_DECOMP_PA` | where the bzImage decompressor is loaded, for a direct boot. A firmware chain does not load it that way and needs no value here |
| `GDBTOOLS_X86_DECOMP_VMLINUX` | path to `arch/x86/boot/compressed/vmlinux`, which KASLR recovery reads |
| `GDBTOOLS_NO_COLOR`, `GDBTOOLS_KDIS_ASCII` | plain output, for terminals that need it |
| `GDBTOOLS_DEBUG` | report every exception the safety layer swallows on gdb's stderr, naming the function it came from. A `NameError`, `AttributeError` or `TypeError` is reported even without it, once per site, since those are bugs in this package rather than conditions of the target |
| `GDBTOOLS_BINUTIL_NM`, `GDBTOOLS_BINUTIL_OBJDUMP` | the `nm` / `objdump` to run for the x86 decompressor parse. Unset means the plain name and the usual `$PATH` lookup; state one where binutils is elsewhere, or where the host's cannot read the target's ELF |
| `GDBTOOLS_SCAN_SPAN` | how far past a stated `RAM_BASE` (or a DTB `/memory` base) to scan for the image magic. Default 128 MiB, which covers arm64's TEXT_OFFSET, riscv's 2 MB-aligned convention and x86's 16 MB. `GDBTOOLS_SCAN` replaces the range outright |
| `GDBTOOLS_MAP_CAP_LEAVES`, `GDBTOOLS_MAP_CAP_NODES` | traversal caps for `mmview`'s page-table walk. Not correctness limits -- they stop a corrupt or circular table from being read forever, and `mmview` says when it truncated |
| `GDBTOOLS_MEMBLOCK_CAP` | how many regions `kmemblock` prints per type before truncating. Default 512; `kmemblock TYPE full` lifts it for one call |
| `GDBTOOLS_FZF`, `GDBTOOLS_FZF_OPTS` | the fzf binary `fz` runs, and options appended to its arguments. Unset means the plain name and the usual `$PATH` lookup; `fz` degrades to a numbered prompt and then to a listing when it is not there |
| `GDBTOOLS_FZ_KEY` | a readline key spec, optionally with a subject (`\C-t`, `\C-r history`, `\e[15~ commands`), bound to `fz` when gdbtools loads. Unset binds nothing |
| `GDBTOOLS_RISCV_KERNEL_MAP_VIRT_OFF` | byte offset of `virt_addr` inside `struct kernel_mapping`, for a riscv vmlinux built without DWARF. It is **not** a constant -- 8 on 6.12, 0 on mainline -- so with neither DWARF nor this value the KASLR slide is reported as unknown rather than computed from a guess |

### Install it as a library, not globally

`setup.sh --library` records the checkout in
`${XDG_CONFIG_HOME:-~/.config}/gdbtools/root` and writes nothing into the gdb init
file, so a plain `gdb ./a.out` stays completely stock. Callers that want the
commands source `gdbtools.py` themselves -- kbuildlab's `attach` and the nvim
adapter both find the checkout through that root pointer.

This is the recommended mode, and the reason is `sym`. In stock gdb `sym` is not
an unused word: it is the unique-prefix abbreviation of `symbol-file`, and
registering a command by that name silently replaces it for the whole session.
Sourcing this package globally would therefore change what `sym` does in every
gdb session on the machine, including ones that have nothing to do with a kernel.
In library mode the takeover happens only in a session that asked for it, and it
is announced when it does:

```
[gdbtools] took over existing gdb command(s): sym
[gdbtools]   the previous meaning is gone for this session; the full name still
             works where one exists (e.g. `symbol-file` for `sym`)
```

The detector behind that line asks gdb `help <name>` rather than
`complete <name>`. `complete` lists words gdb would offer and never contains
`sym`, so an exact-match test over it reports the name as free -- which is how
this collision went unreported. `help` answers "Undefined command" for a free
name, "Ambiguous command" for a bare prefix (nothing usable is lost, not
reported), and the command's own help text when a real command is about to be
replaced.

`GDBTOOLS_PATH` is **not** in the contract table above and is not read here. It is a
launcher-side name -- kbuildlab and the editor adapter use it to find
`gdbtools.py` before gdb starts -- so it lives in this namespace by convention
and is deliberately not part of the package's own contract.

The x86 base recovery runs only while `GDBTOOLS_ENTRY_PA` is unset; a pinned
`ENTRY_PA` takes precedence and suppresses it. The recovery fires on
`GDBTOOLS_X86_KASLR=1`, and also auto-detects the cold-frozen case on its own when
`GDBTOOLS_X86_DECOMP_VMLINUX` and `GDBTOOLS_X86_DECOMP_PA` are set and `$pc` is still
below the decompressor's load address.

Which of the two recoveries applies is the launcher's to state: `GDBTOOLS_X86_DECOMP_PA`
is where a DIRECT boot's decompressor is loaded, and only a direct boot has one. Set, the
walk follows the decompressor's own stages: its entry, the self-relocation `jmp *%rax`
that names the moved base, `extract_kernel`, and `finish` to read the decompressed entry.
It cannot be decided by looking, either: with `-kernel` an option ROM copies the image
to that address during boot, so at the reset vector it is legitimately empty and the
breakpoint is what waits for it.

Unset, the image was loaded some other way. Under UEFI the firmware
loads the bzImage as a PE image and enters `efi_pe_entry`, so none of those stages ever
executes: `efi_stub_entry` decompresses and hands over itself, through
`asm("jmp *%0" :: "r"(kernel_addr), "S"(boot_params))` -- an indirect jump whose
register already holds the kernel's absolute physical entry. That `jmp` is the anchor,
and both its offset and *which register it goes through* are read out of the compressed
vmlinux rather than stated, because the register is the compiler's choice and not the
kernel's: gcc-13 inlines the hand-off as `add %rbx,%rax ; jmp *%rax`, gcc-16 as
`mov %rbp,%rsi ; jmp *%rbx`. It is not the function's only register-indirect jump
either -- gcc compiles a switch in the same function to a jump table, which ends in
one too. What separates them is the other half of the same asm statement: `boot_params`
is constrained to `%rsi`, so the hand-off is the register-indirect jump with a write to
`%rsi` just before it, and the jump table is exactly the one without. Both halves are
read tolerantly, since the jump may carry a `notrack`/`bnd` prefix and the `%rsi` write
may be rip-relative and end in an objdump comment. Its address is not: nothing names where the firmware's allocator
put the image, and it moves between runs, so the image is found the way an arm64 or
riscv one is -- by its own signatures, `MZ` at `+0`, the boot flag `0xAA55` at `+0x1fe`
and `HdrS` at `+0x202`, on a page boundary because `LoadImage` allocates pages, each
candidate confirmed against the decompressor's own first bytes.

Every candidate is kept, not the best-looking one. The firmware holds TWO copies at
once: the file the loader read off the ESP, and the separate image `LoadImage`
allocated from it. Their headers are byte-identical, the kernel's PE sections are laid
out so that `VirtualAddress == PointerToRawData`, and only the second is ever executed,
so nothing in the bytes distinguishes them. The anchor is planted in all of them and
the guest says which was right by stopping there. Taking the topmost match picked the
loader's buffer on every measured boot, and a breakpoint there is never reached.

Attached to a guest frozen at reset the image is not in RAM yet, so the guest is
advanced through QEMU's monitor, which starts and stops the machine without gdb
noticing (QEMU 8.1 or newer: an older gdbstub reported the monitor's stop to gdb as a
stop reply, so those are refused and `GDBTOOLS_ENTRY_PA` is the way in). A gdb that did not notice keeps translating addresses through the CPU mode
it recorded at the last real stop -- 16-bit real mode, at reset -- so `find`,
`inferior.read_memory` and `x/` all fail afterwards, with and without a register-cache
flush. Neither step of this recovery needs them. The search reads PHYSICAL memory with
`monitor pmemsave`, which QEMU serves out of the machine model with no CPU translation
in the way, and the anchor is a HARDWARE breakpoint, which is a debug register and not
a byte written into a page the firmware has not mapped.

Measured on QEMU/OVMF with 1GB of guest RAM: one 64MB `pmemsave` window costs 19ms and
a scan of the whole of RAM 0.53s, so RAM is scanned whole every round rather than a
band near the top -- where the firmware puts the image is the allocator's business.
The loader's copy of the file lands around 1300ms of firmware time and `LoadImage`'s
executable copy about 75ms after it, which is why the poll runs coarsely until the
first copy appears and then finely until the set stops growing. The guest is frozen
between steps, so a scan's own cost never races the firmware.

What the tool still works out for itself is the *target*, not the environment:
the architecture gdb reports, the load address QEMU names through `monitor info
roms`, an image magic found in guest RAM, a device tree the bootloader left in
memory. Those are readings, not guesses.

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
