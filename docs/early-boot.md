# gdbtools — head.S (earliest boot) kernel debugging tools

`gdbtools.py` is a custom plugin that runs on top of a host gdb (+pwndbg)
attached to a QEMU gdbstub. The `source` target is this one file as-is; the
implementation lives in the sibling `gdbtools/` package. In the `head.S` region
before the MMU is on, `$pc` and pointers are **physical addresses**, so the gdb
symbol table linked at virtual addresses resolves nothing (`info symbol`, pwndbg
`telescope`/`context` are dead). This tool **calibrates** the phys↔virt offset at
runtime to resolve physical addresses back to symbols, and adds kernel-only
conveniences such as page-table walks, memory layout, and a full register census.

- pwndbg is used **as a library only** and is **never modified**. It works in plain text even without pwndbg.
- arm64 · x86_64 · riscv64, kernel-version independent. Every command works **from the MMU-off physical stage through to runtime**.
- If any gdb call fails it degrades to a no-op/None, so it **never breaks the main gdb or the remote session**.

Every output in this document is captured from a real run (color codes stripped).

---

## How to run

The tool is a Python extension that runs inside gdb: `gdbtools gdb vmlinux`
starts gdb with it loaded, `source gdbtools.py` loads it by hand, and kbuildlab's
`attach` and the nvim adapter source it themselves (`setup.sh --global` loads it
in every gdb instead).

```bash
# terminal 1: frozen VM (-S, waiting on the gdbstub)
qemu-system-aarch64 -M virt -cpu cortex-a72 -kernel Image -S -gdb tcp::1235 ...

# terminal 2
aarch64-linux-gnu-gdb vmlinux
(gdb) target remote :1235
(gdb) kearly on
(gdb) kearly bootbreak
(gdb) kearly status
```

Export `GDBTOOLS_AUTO=1` before starting gdb to arm the session at attach: the
stop hook, the calibration and the MMU-transition notices. What else it does is
each its own setting, off unless stated in the environment or with
`kearly set KEY VALUE` (`kearly config` lists them): the shadow symbol file
(`SHADOW`), the KASLR slide applied at the first virtual stop (`KASLR_APPLY`), the
crossing catcher (`CROSSING`), siblings for plain breakpoints (`ADOPT`), the
pwndbg panels (`PANELS`), its guards (`PWNDBG_GUARDS`, `SAFEMEM`, `SAFERENDER`)
and the quiet page scan (`EXPLORE_PAGES`). kbuildlab's `attach` states all of
them, so its sessions behave as described below. Nothing happens on a non-kernel
target.

Non-QEMU boards take a JSON profile via `$GDBTOOLS_PROFILE` and a DTB via
`$GDBTOOLS_DTB`; mid session use `kearly profile FILE` / `kearly dtb FILE`.

**What `kearly bootbreak` does.** After `target remote :PORT` it advances past
reset/firmware to the kernel entry, calibrates the phys↔virt offset, then runs
`kearly status`. With `$GDBTOOLS_AUTO` set the session is armed at attach (it never
auto-attaches to a plain `gdb vmlinux`; the signal must be present). `kearly bootbreak arm` only arms the entry
breakpoint and does not resume, for a front end that issues `continue` itself.

Right after attach a banner lists the kernel commands:

```
[gdbtools] early-boot symbolizer loaded (kearly | kp2v | kv2p | kb | kw | ksr | ksregs | kfin | kcensus | kpt | kpgd | kpthex | koff | kx | kdtb | mmview | memlayout | kbits | kmemblock)
```

**Safety contract.** (1) It kills nothing (no pkill/fuser; running VMs and
sessions are untouchable). (2) With no stub it does not force a connection and
hang gdb; it loads only the symbols and tools and drops to a live prompt (type
`target remote :PORT` by hand later). (3) It does not touch global gdb/pwndbg
settings.

**Configuration.** There are no command-line options: gdbtools reads `GDBTOOLS_*`
environment variables set before gdb starts. The ones that matter, with their
in-session equivalents:

| setting | effect |
|---|---|
| `target remote :PORT` | connect to the gdbstub (a plain gdb command) |
| `GDBTOOLS_AUTO=1` | arm `kearly on` once a kernel image is loaded |
| `GDBTOOLS_PRESET=NAME`, or `kearly preset NAME` | boot-combination preset (arm64-uefi, x86-pvh, riscv-uefi …) |
| `GDBTOOLS_ENTRY_PA`, `GDBTOOLS_ANCHOR`, `GDBTOOLS_BREAK_KIND`, `GDBTOOLS_RAM_BASE`, `GDBTOOLS_SCAN`, or `kearly entry/anchor/break` | specify a combination that is not auto-detected |
| `GDBTOOLS_PROFILE=FILE.json`, `GDBTOOLS_DTB=FILE`, or `kearly profile/dtb FILE` | inject a machine descriptor for a non-QEMU board |

---

## Command overview

| command | what it does |
|---|---|
| `kearly bootbreak [arm]` | advance past reset/firmware to the kernel entry, then calibrate the offset (auto if `$GDBTOOLS_AUTO`; `arm` arms only, no resume) |
| `kearly status` / `kearly mmu` | arch · offset · map · MMU on/off · config; `mmu` adds the control-register detail |
| `kearly on` / `off` | enable/disable the session: stop hook, and the behaviours stated on |
| `kearly config` / `set KEY VALUE` / `unset KEY` | list the GDBTOOLS_* settings with where each came from; state one for this session (`-` hides the environment's value); drop it |
| `kearly calibrate [SYM]` | (re)compute the phys↔virt offset (auto, or $pc-at-anchor SYM) |
| `kearly overmmu [SYM]` | cross the MMU-enable boundary safely (temp bp at the virtual landing + continue) |
| `kearly where` | one-line orientation: regime, pc+symbol+twin, offset, KASLR, phase, next command (read-only) |
| `kearly regimes [walk\|stop ID]` | this build's early-boot MMU stop points; `walk` arms all, `stop ID` runs to one |
| `kearly kaslr [auto\|off\|status\|<hex>]` | detect the KASLR slide and relocate symbols so `b SYM` fires; only `auto` moves the CPU |
| `kearly safemem [on\|off\|auto\|status]` | guard pwndbg's memory probing so a probe that would reach a device model fails instead of killing QEMU (`GDBTOOLS_SAFEMEM`, default off) |
| `kearly census off\|compact\|full` | keep the `kcensus` register census in the panel at every stop (default off) |
| `kearly chaindepth N` | telescope hop depth for panel chains / `chain` / `ksregs` (default 8) |
| `kearly steplock on\|off\|auto` | freeze the other cores while single-stepping with the MMU off (default off) |
| `kearly saferender warn\|on\|off\|auto` | arm64 pwndbg emulation-disasm SIGABRT guard (`GDBTOOLS_SAFERENDER`, default off; `auto` = `set emulate off`, restored on `kearly off`) |
| `kearly bpfix on\|off` | optional tidy of the dual phys+virt breakpoints (default off; the native dual already fires) |
| `kearly preset [list\|NAME]` | list or apply a boot-combination preset |
| `kearly profile <path\|show>` / `kearly dtb <path\|guest\|show>` | inject a machine descriptor / DTB for a non-QEMU board |
| `kearly offset <hex\|->` | force the phys↔virt offset by hand (`-` clears it) |
| `kb SYM \| *ADDR \| FILE:LINE` | regime-aware breakpoint: arms PA(S)=linkVA+offset **and** IMG(S)=linkVA+slide; only the matching regime fires. IMG re-arms when the slide is known |
| `kw [-r\|-a] SYM \| *ADDR [SIZE]` | regime-aware watchpoint (data twin of `kb`); each consumes 2 HW slots |
| `kp2v ADDR` / `kv2p ADDR` | physical↔virtual translation |
| `addr2sym ADDR` | address (physical or virtual) → kernel symbol |

A hand control given no argument reports its state and changes nothing; given
one, it states the matching `GDBTOOLS_*` key for the session, as `kearly set`
does. `kearly anchor -` and `kearly break -` state the key unset, so the preset,
the profile or the arch decides again.
| `stackscan [N]` | scan N stack words and symbolize code pointers (for head.S where backtrace is dead) |
| `chain [ADDR] [N]` | N-word telescope, physical/virtual aware and symbolized (default $sp, N=8) |
| `ksr NAME` / `ksregs` | one sysreg / a batch dump of the core sysregs with decode |
| `kbits [full]` | every system register the early-boot asm touches, each with its bit fields (same content as the `kernel sysregs` panel window) |
| `kcensus [full]` | every control/system register head.S and its call chain touch, with value + decode + purpose |
| `kpt [VA] [at TABLE_PA] [hex]` | hardware page-table walk; reads physical, so correct even after the MMU is on |
| `kpgd [TABLE_PA [level N]] [MAXROWS]` | dump the non-zero entries of the top-level (or given) page directory |
| `kpthex [TABLE_PA [level N]] [N\|full]` | page-table entries as little-endian bytes (`full` = 4KB xxd dump) |
| `koff [SYM]` | why the runtime address differs from the vmlinux ELF (nm) value |
| `mmview` / `memlayout [all\|noidmap]` | vmmap for the kernel: symbol landmarks + live ptdump |
| `kmemblock [TYPE] [full]` | the memblock map the kernel was handed (`memory` / `reserved`), flags decoded |
| `kx [/NFU] ADDR` | examine **physical** memory, bypassing translation (default `/16xb`) |
| `kfin [ADDR]` | a `finish` replacement for CFI-less head.S (runs to the lr/ra/stack return address) |
| `cfgdis [ascii\|mono] [WHAT]` | branch-arrow disassembly (radare2 `pdf` style); auto-detects arch, excludes calls |
| `kdtb [options] [ADDR]` | full live FDT dump (= `dtc -I dtb -O dts`), inside gdb with no external tool |

---

## 1. Preparation — `kearly`

### `kearly status` / `kearly mmu`

With `$GDBTOOLS_AUTO`, `kearly bootbreak` runs at attach, advancing past reset/
firmware to the kernel entry and fixing the offset. Afterward:

```
(gdb) kearly status
[gdbtools] arch=arm64  enabled=True  offset(PA-VA)=0x0001000038000000
      map=virtual  MMU=on [pc=VA]  steplock=off  census=off  chaindepth=8
      preset=(default)  anchor=_text  break=sw
      target=(arch defaults)
      vmlinux=.../arm64-v4.6/kernel/vmlinux  shadow=0x0000000040080000
```

- `offset(PA-VA)` — physical = virtual + offset.
- `map` / `MMU` — whether the current map is physical or virtual, and MMU on/off.
- `shadow` — the address of the phys-shifted symbol file so physical addresses resolve to symbols too.

`kearly mmu` reports the same with the raw control register:

```
(gdb) kearly mmu
[gdbtools] MMU=off [ctrl-reg]  map=physical  pc=0x0000000040080000  SCTLR_EL1.M=0
      pre-MMU: $pc/pointers are PHYSICAL; shadow symbols active.
# after MMU-enable:
[gdbtools] MMU=on [ctrl-reg]  map=physical  pc=0x00000000408b003c  SCTLR_EL1.M=1
      MMU on: kernel VAs resolve natively; kp2v/kv2p translate either way.
```

### `kearly overmmu` — crossing the MMU boundary

Stepping over `__enable_mmu` with `stepi` makes the QEMU gdbstub leak the
single-step there and the CPU runs away. Instead, set a temporary breakpoint at
the virtual landing and cross with `continue`:

```
(gdb) kearly overmmu start_kernel
[gdbtools] over_mmu: continue to virtual landing {start_kernel} ...
[gdbtools] >>> MMU ON: $pc now VIRTUAL 0xffff000008c365f0 -- native kernel symbolization active
[gdbtools] landed pc=0xffff000008c365f0 start_kernel in section .init.text  (MMU on)
```

`kearly calibrate [SYM]` recomputes the offset by hand; `kearly offset <hex|->`
forces or clears it; `kearly on`/`off` toggle the session.

---

## 2. Address translation and symbolization — `kp2v` / `kv2p` / `addr2sym` / `stackscan`

Both directions work once the MMU is on (runtime `$pc`=`cpu_do_idle+8`):

```
(gdb) kv2p $pc
VA 0xffff000008099f58 -> PA 0x0000000040099f58
(gdb) kp2v 0x40099f58
PA 0x0000000040099f58 -> VA 0xffff000008099f58  cpu_do_idle + 8 in section .text of …/vmlinux
(gdb) addr2sym $pc
0xffff000008099f58 (VA)  cpu_do_idle + 8 in section .text of …/vmlinux
(gdb) addr2sym 0x40099f58
0x0000000040099f58 (PHYS) -> VA 0xffff000008099f58  cpu_do_idle + 8 in section .text of …/vmlinux
```

`stackscan [N]` reads N words from `$sp` and symbolizes the kernel pointers among
them, labelling each PA or VA — the stand-in for `backtrace` in head.S:

```
(gdb) stackscan 24
  [sp+0x008] 0xffff000008109a7c  VA  cpu_startup_entry + 644 in section .text of …/vmlinux
  [sp+0x078] 0x00000000408b0054  PA  __enable_mmu + 84 in section .text of …/vmlinux
  [sp+0x088] 0xffff000008c36968  VA  start_kernel + 888 in section .init.text of …/vmlinux
```

---

## 3. System registers — `ksr` / `ksregs` / `kbits`

`ksregs` batch-dumps the core sysregs with value and decode; `ksr NAME` reads
just one (e.g. `ksr CurrentEL`). The read path is pstate-derived → gdb register →
QEMU monitor fallback, so it captures values the stub otherwise hides, as far as
possible; an unreadable register shows `?` with a single-step hint.

```
(gdb) ksregs
[gdbtools] MMU=on EL1  SCTLR_EL1=0x34d5d91d  TTBR0_EL1=0x6d0000b6fdc000  TTBR1_EL1=0x41200000  PSTATE.DAIF=0x7   [MMU=on pc=VA]
  CurrentEL    0x0000000000000004  (4)   EL1
  SCTLR_EL1    0x0000000034d5d91d  (886429981)   M=1 (MMU on)  C=1 I=1 A=0 SA=1 WXN=0
  TTBR0_EL1    0x006d0000b6fdc000  (30680775531544576)
  TTBR1_EL1    0x0000000041200000  (1092616192)
  TCR_EL1      0x00000034b5103510  (226376037648)   T0SZ=16 (VA 48-bit)  T1SZ=16 (VA 48-bit)
  MAIR_EL1     0x0000bbff440c0400  (206705032692736)
  DAIF         0x0000000000000007  (7)   [d A I F]  (partial)
  NZCV         0x0000000000000000  (0)   [n z c v]
  ...
```

`kbits [full]` prints the registers the early-boot asm (head.S / entry.S /
proc.S) touches, each value with its bit fields on the rows below; a register the
target will not answer for is omitted (shown as `?` with `kbits full`, never 0).
The same content renders live in pwndbg's `kernel sysregs` window, controlled by
`kearly msysreg off|compact|full`, which adds `msysreg` to `GDBTOOLS_PANELS` or
takes it out.

---

## 4. `kcensus` — head.S register census

`kcensus [full]` enumerates **every system/control register read or written at
least once** in `head.S` and every file it reaches along the call chain, by
category, with value, field decode, and purpose. These are exactly the registers
pwndbg's REGISTERS panel does not show (general-purpose x0~x30 excluded). arm64
88 / x86 CR·MSR·segment / riscv 21 CSR.

```
(gdb) kcensus
[gdbtools] head.S early-boot register census -- arm64   [MMU=on pc=VA]   (88 registers)
translation
  TTBR0_EL1          RW  0x760000b68b3000     idmap/user page-table base (MMU enable, switch_mm, resume)
  TTBR1_EL1          RW  0x41200000           kernel/swapper page-table base (KPTI, replace-ttbr1)
  TCR_EL1            RW  0x34b5103510         T0SZ=16 (VA 48-bit)  T1SZ=16 (VA 48-bit)
  TCR2_EL1           RW  ?                    extended translation control (S1PIE/PIE enable) [6.12]
memory-attr
  MAIR_EL1           RW  0xbbff440c0400       memory attribute indirection (Device/Normal/NC/WT encodings)
system-control
  SCTLR_EL1          RW  0x34d5d91d           M=1 (MMU on)  C=1 I=1 A=0 SA=1 WXN=0
el-transition
  CurrentEL          R   0x4                  EL1
  ELR_EL1            W   0xffff000008086844   exception link for EL1->EL1 clean-state eret [6.12]
feature-id
  CTR_EL0            R   0x8444c004           cache type: D/I line size for maintenance loops
  ...
```

- `RW`/`R`/`W` = how head.S uses it. `?` = not exposed by the gdbstub/monitor at
  this EL/moment (marked honestly, never 0). `[6.12]`/`[4.6]`/`[M-mode]` =
  version/mode-specific.
- riscv shows the same shape over its CSRs (`satp`, `stvec`, `sepc`, `sstatus`, …).

`kearly census compact` attaches a one-line-per-category summary to the context
at every stop:

```
 translation:     TTBR0_EL1=0x6d0000b7f34000  TTBR1_EL1=0x41200000  TCR_EL1=0x34b5103510
 memory-attr:     MAIR_EL1=0xbbff440c0400
 system-control:  SCTLR_EL1=0x34d5d91d  CPACR_EL1=0x300000  DAIF=0x7
 el-transition:   CurrentEL=0x4  SPSR_EL1=0x145  ELR_EL1=0xffff000008086844  SP_EL0=0xffff000009080000
```

---

## 5. `kpt` — hardware page-table walk

`kpt [VA]` walks one VA the way the hardware would (L0~L3 arm64 / PML4~PT x86 /
Sv39·48·57 riscv), showing each level's raw descriptor, type, next-table/output
PA, and leaf attributes. The level count comes from the live control registers
(x86 `CR4.LA57` / arm64 `TCR` T0SZ·T1SZ / riscv `satp` MODE), so 3/4/5 levels
adapt automatically. VA omitted → `$pc`; expressions allowed (`kpt &_stext`).
Add `hex` to also print each level's descriptor as little-endian bytes; `at
TABLE_PA` walks a table you name, in any regime.

**Why it matters**: after the MMU is on, gdb `x`/pwndbg `hexdump` read a physical
address by translating it through the current tables, so they cannot read the raw
PT (`Cannot access memory`). `kpt` reads through QEMU HMP `monitor xp` (physical
examine), so it is accurate even after the MMU is on.

```
(gdb) kpt
VA 0xffff000008099f58   TTBR1_EL1 (kernel/high)   [4KB granule, 4-level (L0..L3), 9-bit index/level]
  top-table PA 0x41200000
  L0/PGD  [  0] @PA 0x41200000   desc=0x00000000beffe003  table -> 0xbeffe000
  L1/PUD  [  0] @PA 0xbeffe000   desc=0x00000000beffd003  table -> 0xbeffd000
  L2/PMD  [ 64] @PA 0xbeffd200   desc=0x00000000beffc003  table -> 0xbeffc000
  L3/PTE  [153] @PA 0xbeffc4c8   desc=0x00c0000040099793  PAGE  AF=1 RO- AttrIdx=4 ISh UXN
  => LEAF PA 0x40099f58  (cpu_do_idle + 8)
     (kv2p(VA)=0x40099f58  MATCH)
```

- each level: `[index] @the physical address of that entry  desc=raw value  type -> next/output`.
- leaf attrs: `AF` (access) `RO-` (read-only text) `AttrIdx` (MAIR index) `ISh` (inner share) `UXN` (execute-never at EL0).
- `MATCH` = the software `kv2p` value and the hardware-walk result agree. Page-table pages are symbolized too (e.g. x86 `level3_kernel_pgt`).

It reports non-leaf states honestly: at earliest boot `_stext` resolves through a
**2MB BLOCK** ending at L2 (the initial swapper), then through a **4KB PAGE** down
to L3 after `paging_init` re-lays it; an unmapped VA ends `=> NOT MAPPED (no valid
leaf descriptor)`; and while the MMU is off it refuses:

```
(gdb) kpt &_stext
[gdbtools] cannot walk VA 0xffff000008082000 -- page-table base unreadable, or paging is off
       (MMU/satp/CR0.PG). Try after MMU-enable.
```

---

## 6. `kpgd` / `kpthex` — page directory dumps

`kpgd [TABLE_PA [level N]] [MAXROWS]` dumps the **non-zero entries** of the
top-level page directory (or a given table PA) with index, raw value, type, and
output PA (+symbol). The granule, level count and entries-per-table all come from
the live translation-control registers, never assumed. A lower-level table needs
its level (`kpgd 0x41201000 level 1`); `kpt` prints that command for each `table
-> 0x…` it follows.

**No live table → it refuses.** Without an explicit PA, `kpgd` reports the LIVE
tables and first asks the arch whether translation is on at all (arm64
`SCTLR_EL<n>.M`, x86 `CR0.PG`+`EFER.LMA`+`CR4.PAE`, riscv `satp.MODE`), read
through the same chain as the base register. The base register does not go empty
when translation is off — it keeps the previous stage's value:

```
(gdb) kpgd
[gdbtools] kpgd needs a live translation regime, and there is none here.
  translation OFF   SCTLR_EL1=0xc50838 -> M(bit0)=0   (source gdb:$SCTLR_EL1)
  base register now: TTBR0_EL1 (idmap/low) = 0x7ffe0000  (NOT a live table root)
  To dump that table anyway:  kpgd 0x7ffe0000
  Or reach a regime where the kernel's own tables are live:  kearly overmmu
```

Here `0x7ffe0000` is u-boot's own page-table area, resident and readable; dumping
it blindly would describe a mapping the kernel never uses.

**Provenance.** On a firmware chain the kernel's first instructions run on the
**bootloader's** tables, so every live dump carries a verdict: `KERNEL` if the
root is one of this vmlinux's named static roots (`swapper_pg_dir`,
`idmap_pg_dir`, … / x86 `early_top_pgt`/`init_top_pgt` / riscv
`swapper_pg_dir`/`early_pg_dir`), or inside the loaded image (`_text`…`_end`), or
maps the kernel's own text; `FOREIGN` if it fails all three; `UNKNOWN` with no
calibration. Never a guess.

```
(gdb) kpgd
top table L0/PGD @PA 0x41200000   regime TTBR1_EL1 (kernel/high)   (non-zero of 512 entries)
  [  0] 0x00000000beffe003  table   -> 0xbeffe000
  [247] 0x00000000bedf2003  table   -> 0xbedf2000
  [255] 0x00000000411bd003  table   -> 0x411bd000    (bm_pud)
  [256] 0x00000000beff7003  table   -> 0xbeff7000
```

`kpthex [TABLE_PA [level N]] [N|full]` shows the same entries as the **8
little-endian bytes as laid out in memory**, next to the raw value and decode;
`full` dumps the whole 4KB page xxd-style (16 bytes/row + ASCII). It reads
physical memory via the QEMU monitor, so it works even after the MMU is on:

```
(gdb) kpthex
page-table page @PA 0x41200000   regime TTBR1_EL1 (kernel/high)   little-endian, as stored in RAM
   idx  @PA           b0 b1 b2 b3 b4 b5 b6 b7   value (LE)          decode
  [  0] 0x41200000     03 e0 ff be 00 00 00 00   0x00000000beffe003   TABLE -> 0xbeffe000
  [255] 0x412007f8     03 d0 1b 41 00 00 00 00   0x00000000411bd003   TABLE -> 0x411bd000  (bm_pud)
```

---

## 7. `koff` — why the runtime address differs from the ELF (nm) value

The symbol address `nm`/`readelf` shows (the VA linked into vmlinux) and the
address where that symbol sits now differ for **different reasons per regime**.
`koff [SYM]` (SYM omitted → the image base) summarizes the reason using the CPU
flags/control-registers/`$pc` that determine it, not narration. The regime is
split by whether `$pc` is actually physical or virtual (`which_map`), precisely
to catch x86, where paging is always on but early execution runs at identity/low
addresses.

```
# arm64, MMU off (head.S)                        # x86_64, startup_64 (paging ON but identity)
[koff] arm64  pc PHYSICAL (MMU off) [MMU=off]     [koff] x86_64  pc PHYSICAL (paging ON but
  $pc         = 0x40080000  -> physical/low                 identity/low map) [MMU=on ctrl-reg]
  SCTLR_EL1.M = 0           -> MMU off->PHYS        $pc    = 0x1000000  -> physical/low
  TTBR1_EL1   = 0x0         -> tables not set        CR0.PG = 1         -> paging on
  ELF value   = 0xffff000008080000  (nm)            CR3    = 0x446e000 -> page-table base
  address now = 0x40080000  (QEMU loaded here)      ELF value   = 0xffffffff81000000 (nm)
  offset(PA-VA)=0x1000038000000                     address now = 0x1000000 (identity)

# arm64/riscv, MMU on (high-half live)
[koff] arm64  pc VIRTUAL (high-half map live) [MMU=on pc=VA]
  SCTLR_EL1.M=1  TTBR1_EL1=0x41200000  cmdline kaslr=off (nokaslr)
  ELF value = address now = 0xffff000008080000    KASLR slide = 0 (nokaslr -> VA==ELF, confirmed)
```

Clues are arch-specific (arm64 SCTLR_EL1.M / TTBR1_EL1 / kimage_voffset; x86
CR0.PG / CR3 / CR4.PAE / EFER.LMA / phys_base; riscv satp.MODE / satp.PPN), plus
`$pc` high-vs-low and the cmdline `nokaslr` marker. If `kearly kaslr` has been
applied it reports the true link VA, runtime VA, and slide exactly; otherwise it
reports `0 (confirmed)` under `nokaslr`, or advises measuring with `kearly kaslr`
(koff alone sees only the relocated symbol table). It quietly tries `calibrate`
if the offset does not yet exist.

---

## 8. `mmview` / `memlayout` / `kmemblock` — kernel memory layout

pwndbg `vmmap` cannot read a kernel target, so `mmview` (alias `memlayout`) takes
its place. Two parts: (1) **symbol landmarks (VA→PA)** — needs only the symbol
table + calibration, so it works in the pre-MMU physical stage; (2) **live
ptdump** — walks the page tables, merges contiguous regions, attaches
permissions. Because a unified root (x86 CR3 / riscv satp) mixes user and kernel,
the default is the **kernel half only** (`all` includes user, `noidmap` skips
arm64 TTBR0).

While the MMU is off it shows physical placement + RAM instead of live mappings:

```
(gdb) mmview
mmview -- kernel memory layout   [MMU=off ctrl-reg | arm64 | offset(PA-VA)=0x0001000038000000]

kernel image / key symbols  (VA -> PA):
  _text             0xffff000008080000  -> PA 0x40080000 kernel image start (.head.text)
  _stext            0xffff000008082000  -> PA 0x40082000 .text start
  _end              0xffff000009203000  -> PA 0x41203000 kernel image end
  swapper_pg_dir    0xffff000009200000  -> PA 0x41200000 kernel PGD (TTBR1)
  idmap_pg_dir      0xffff0000091fd000  -> PA 0x411fd000 identity-map PGD (TTBR0)
  vectors           0xffff000008084800  -> PA 0x40084800 EL1 exception vectors (VBAR)

live VA mappings: NONE yet -- MMU is off (paging not active).
  -> showing PHYSICAL placement; re-run mmview after MMU-enable.
  kernel image PA:     0x40080000 - 0x41203000   (17932K)
  RAM (DTB/profile):   0x40000000+0x80000000
```

After the MMU is on it coalesces regions (here the initial swapper's 20MB image,
mapped as 2MB blocks, merged into one):

```
live mappings: kernel  TTBR1_EL1  root@PA 0x41200000   (1 regions)   [4KB granule, 4-level (L0..L3), 9-bit index/level]
  0xffff000008000000-0xffff0000093fffff    20M -> 0x40000000    block AF=1 RW- AttrIdx=4 ISh kernel image {_text,_stext,_etext+}
```

On x86 (CR3) / riscv (satp) the unified root hides the user/low-half regions by
default (`N user/low-half regions hidden -- 'mmview all' to include`), with x86
PTE flags `R/W S A D G NX` and riscv `RW- S G A D` shown per region.

`kmemblock [TYPE] [full]` shows the memory map the kernel was handed:
`memblock.memory` (what firmware or the DT said exists) and `memblock.reserved`
(what has been claimed back — kernel image, initrd, DT, early page tables, every
`memblock_alloc`), with each region's flags decoded from the DWARF type. TYPE is
`memory`/`reserved`/`physmem` (all if omitted); `full` lifts the per-type cap
(`$GDBTOOLS_MEMBLOCK_CAP`, default 512). Valid from the first instruction until
`mem_init()`; after that it states whether the arrays are still live
(CONFIG_ARCH_KEEP_MEMBLOCK) rather than printing a freed one.

---

## 9. Telescope and `kearly chaindepth`

Address-shaped sysregs (TTBR/VBAR/ELR/SP …) render in the panel as a telescope.
It does **not** use pwndbg's default chain: given a page-table base like TTBR,
pwndbg mistakes the value for a pointer and follows PGD→PUD→PMD… down the whole
tree, overflowing gdb's C stack and killing the session (and QEMU). So it renders
with its own `safe_chain` (finite depth + cycle detection), and for TTBR follows
only the PGD→PUD→PMD bases via physical reads.

```
 TTBR1_EL1  0x41200000  PTbase 0x41200000  ->  0xbeffe000  ->  0xbeffd000  ->  0x0
 TTBR0_EL1  0x6d0000b7f34000  PTbase 0xb7f34000  ->  0x0  ASID 0x6d
```

`kearly chaindepth N` adjusts the depth live (default 8). `chain [ADDR] [N]` uses
the same safe telescope. `kfin [ADDR]` is a `finish` for CFI-less head.S: it
takes the return address from `lr`/`ra`/the stack top and runs there (it refuses
when the link register is 0 at an entry point, or holds a foreign address left by
the previous boot stage — running there would lose the stop).

---

## 10. `cfgdis` — branch-arrow disassembly

Like radare2's `pdf`, `cfgdis` draws the control-flow arrows of in-function jumps
in the left margin, stacking non-overlapping edges on vertical tracks with corners
and crossings (`┌│└─┼┬┴`), source and destination aligned to the same column,
arrowhead `>` at the destination.

- **`WHAT` is gdb's `disassemble` argument** — omitted, the current function
  (`$pc,+0x60` if outside one); a symbol/address/range (`cfgdis start_kernel`,
  `cfgdis 0x80200000, +0x80`). The `/r`·`/s`·`/m` modifiers are ignored.
- **Only conditional branches + unconditional jumps** are arrow targets — calls,
  returns and indirect jumps are excluded (like radare2's linear view). The
  mnemonic set is auto-detected per arch.
- **Regime-independent** — it drives gdb `disassemble` directly, so it works the
  same on a physical earliest-boot address or a virtual post-MMU address.
- Options: `ascii` (ASCII glyphs), `mono` (no color; also `$GDBTOOLS_NO_COLOR`).

```
(gdb) cfgdis mono memchr
Dump of assembler code for function memchr
        0xffffffff80e8ffc0  addi    sp,sp,-16
        0xffffffff80e8ffc4  addi    s0,sp,16
        0xffffffff80e8ffc6  add     a2,a2,a0
        0xffffffff80e8ffc8  zext.b  a1,a1
   ┌┬─> 0xffffffff80e8ffcc  bne     a0,a2,0xffffffff80e8ffd8 <memchr+24>
   ││   0xffffffff80e8ffd0  li      a0,0
   ││┌> 0xffffffff80e8ffd2  ld      s0,8(sp)
   │││  0xffffffff80e8ffd4  addi    sp,sp,16
   │││  0xffffffff80e8ffd6  ret
   │└┼> 0xffffffff80e8ffd8  lbu     a4,0(a0)
   │ │  0xffffffff80e8ffdc  addi    a5,a0,1
   │ └─ 0xffffffff80e8ffe0  beq     a4,a1,0xffffffff80e8ffd2 <memchr+18>
   │    0xffffffff80e8ffe4  mv      a0,a5
   └─── 0xffffffff80e8ffe6  j       0xffffffff80e8ffcc <memchr+12>
```

> Mnemonics match the pwndbg window: gdb/binutils and Capstone spell some
> differently (arm64 `b.cc`/`b.cs` ↔ `b.lo`/`b.hs`); `cfgdis`/`flow` normalize to
> the Capstone spelling via `Arch.MNEM_ALIASES`, strip binutils alias comments
> (`// b.none`), and preserve operands (the `#imm` in `tbz w0, #0x1f, <target>`).

### Context sections (`GDBTOOLS_PANELS`)

With `GDBTOOLS_PANELS=kgdb flow msysreg` (what kbuildlab's `attach` states), the
tool adds those three sections to pwndbg; with `EXPLORE_PAGES=off` and
`SAFERENDER=auto` it changes two settings it restores on `kearly off`:
`auto-explore-pages` off (its probe can crash a QEMU target) and, on arm64,
`emulate` off (its disasm can SIGABRT gdb). The `flow` window runs
**beside** pwndbg's own disasm, each independent:

- **`[ DISASM ]`** — pwndbg's own window, untouched (emulation, CPSR flags, branch
  prediction, telescope all as-is).
- **`[ DISASM + ARROWS ]`** (our `flow`) — a radare2-style arrow view drawn by the
  same gdb+python renderer as `cfgdis`. Being pure gdb+python it never hangs or
  crashes, and it draws arrows even where pwndbg prints a branch target as a
  symbol name.

```
[ DISASM / aarch64 / set emulate on ]        [ DISASM + ARROWS ]  (our flow)
 ► 0x…13d8 <memset+24>  cmp x2,#0xf           =>      0x…13d8  cmp   x2, #0xf
   0x…14b0 cmp … CPSR => 0x20000000 [ … C … ] ┌───    0x…13dc  b.hi  0x…1404 <+68>
                                              │┌──    0x…13e0  tbz   w2,#3,0x…13e8
                                              │└┬>    0x…13e8  tbz   w2,#2,0x…13f0
                                              └──>    0x…1404  neg   x4, x8
```

> **arm64-v4.6 SIGABRT guard.** pwndbg's own disasm window can emulation-fault
> (Unicorn) on some instructions of this EOL kernel — the canonical case is the
> secondary-CPU earliest stop at `b __secondary_switched` with `sp`/`x29`
> uninitialized, where **gdb itself dies of SIGABRT**. A native segfault cannot be
> caught from Python, so with `saferender auto` the tool runs its stop
> hook before pwndbg's context render on an arm64 attach and sets `emulate` off
> (restored on `kearly off`). Use `kearly saferender off` to restore emulation or
> `warn` to only warn. Our `flow` never breaks on any kernel.

> **Shadow breakpoints (`kearly bpfix`, default off).** Laying a shadow symbol
> table on physical addresses means a name breakpoint like `b start_kernel` is set
> at **two** locations, physical + virtual. Since QEMU's SW breakpoint matches on
> the virtual PC, the MMU-on symbol fires the virtual location on its own, so the
> native dual catches without `bpfix`. `bpfix on` is optional tidying: it always
> keeps the virtual location on and drops only the dormant physical one; it never
> turns the virtual location off.

> **Split function entries (riscv).** A patchable ftrace entry makes DWARF start a
> function after its ELF symbol, and gdb resolves `b fn` from both, so one call
> stopped twice. For a breakpoint on a function name, the tool keeps, per function
> instance and regime, only the location furthest into the function and disables
> the others, again after a symbol file reload re-resolves them; an adopted sibling
> is not added where the function already has a location in that regime.

---

## 11. `kw` — regime-aware watchpoint

The breakpoint problem has a data twin. head.S writes `__bss`, the boot
arguments, `kernel_map` and the page tables it builds **by physical address**;
code running at high VA uses the same globals by `linkVA+slide`. A plain `watch
SYM` watches only the one address the symbol held when you typed it, blinding the
far side of the crossing. `kw` sets HW watchpoints on both `PA(S)` and `IMG(S)`
and auto-re-arms IMG once the slide is fixed. `-r`=rwatch, `-a`=awatch; `kw *ADDR
[SIZE]` with SIZE ∈ {1,2,4,8}.

```
(gdb) kw kimage_voffset
[gdbtools] kw 'kimage_voffset'  linkVA=0xffff800082148000  watch  8-byte
        watch @ 0x0000000042348000  PA  MMU-off/idmap  (head.S data writes, page tables)  [wp 2]
        watch @ 0xffff800082148000  IMG high kernel map (start_kernel & steady state)  [wp 3]
        (IMG auto-re-arms to linkVA+slide the moment the KASLR slide is known)

(gdb) kearly kaslr auto
[gdbtools] KASLR slide = 0x253005a00000 applied: ...
(gdb) continue                  # fires on a write to the relocated VA side
Thread 1 hit Hardware watchpoint 5: *(unsigned long long *)0xffffa53087b48000
Old value = 0x0
New value = 0xffffa53045800000
__primary_switched () at arch/arm64/kernel/head.S:234
```

The PA side fires symmetrically while the MMU is still off (e.g. `kw boot_args`
catches the DTB-pointer store in `preserve_boot_args`, head.S:174). Each `kw`
consumes **2 HW watchpoint slots**; a real arm64 core usually has only 4, while
QEMU TCG is more generous (6 observed). If arming fails, `kw` reports that it
armed nothing.

---

## 12. The MMU-regime model

The core idea throughout: a kernel address is reached **physically** while the
MMU is off or the CPU runs on the idmap (head.S, pi/, secondary bring-up,
cpu_resume), and by its **runtime VA** (`linkVA+slide`) once the high map is live.
A command that assumes one scheme in the other regime gives a quietly wrong
answer — the worst outcome. So commands check the regime and, when it does not
match, say why rather than answer.

### 12.1 Regime refusals

```
(gdb) kv2p $pc
[gdbtools] kv2p: 0x0000000040200000 is not a kernel virtual address -- it looks PHYSICAL.
      Right now: MMU off, so addresses here are PHYSICAL.
      Use `kp2v` for this direction, or `addr2sym` which accepts either.
```

Every refusal says the same three things — what the command assumed / the actual
state now / what to use instead — with the middle line from
`Session.regime_phrase()` so the wording never diverges. Likewise: `kp2v` refuses
an already-virtual address; `kfin` does not advance when the return address is 0
or foreign; `stackscan` reports that `$sp` is still 0 (arm64 head.S sets sp only
at `adrp x1, early_init_stack` in `__primary_switch`); `kpt`/`kpgd`/`kpthex`
refuse with the register that says translation is off and the stale base value.

### 12.2 `kearly where` — one-line orientation

```
(gdb) kearly where
PHYS addressing  (MMU off)   [ctrl-reg]
  pc       0x0000000040200000  _text in section .head.text
  twin     0xffff800080000000  (virtual)
  offset   0x00007fffc0200000   shadow @0x0000000040200000
  KASLR    x (not readable yet -- still physical, MMU off)
  phase    exactly at the kernel entry
  next     kearly regimes      (list this build's MMU stop points), or kearly overmmu to cross now
```

`twin` is the opposite-side address of the current pc; `phase` says whether you
are before the reset vector, at the entry, past it but still physical, or after
the virtual scheme is up; `next` is the most likely command. It is read-only —
writes no register, sets no probe, resumes no CPU.

### 12.3 `kearly regimes` — this build's MMU stop points

Scans the running image and answers directly, with no per-version constant:

```
(gdb) kearly regimes
[gdbtools] early-boot MMU regimes for this build
  entry     PHYS   link 0xffff800080000000  PA 0x0000000040200000
            kernel entry, MMU off, PC physical  -- _text
  mmuon     PHYS   link 0xffff8000829b84a8  PA 0x0000000042bb84a8
            translation turned on, PC still physical  -- __enable_mmu+0x30: msr sctlr_el1, x0
  crossing  PHYS   link 0xffff8000829b8518  PA 0x0000000042bb8518
            the phys->high-VA transfer instruction  -- __primary_switch: br -> __primary_switched
  virtual   VIRT   link 0xffff8000829ca730  PA 0x0000000042bca730
            first instruction at a true high VA  -- landing of the transfer (__primary_switched)
  start     VIRT   link 0xffff8000829c0bd8  PA 0x0000000042bc0bd8
            start_kernel, steady state  -- start_kernel
```

`mmuon` is found by the `find_mmu_enable` opcode scan: arm64 `msr sctlr_el1, xN`
(`0xD5181000 | Rt`), riscv `csrw satp` (`0x18001073 | rs1<<15`), x86 `mov
%rXX,%cr3` (`0f 22 d?`) — no register number or kernel version needed. `kearly
regimes walk` arms all five so repeated `continue` steps through the transitions
in order (using exactly 1 HW slot per point, only the side that matches each
point's regime). `kearly regimes stop <id>` runs straight to one. riscv shows four
points: its single `csrw satp` is both the translation-on and the phys→virt
transition, so the two merge.

### 12.4 `kx` — physical examine that bypasses translation

`x` always interprets an address through the current page tables, so when `$pc` is
physical but translation is already on it cannot read even the spot it stopped at.
riscv creates exactly that: the fetch after `csrw satp, a0` in
`relocate_enable_mmu` traps to `stvec`, so `$pc` is the physical `0x80201048`,
which is not a valid VA in the new mapping.

```
(gdb) x/16xb $pc
0x80201048 <_start+4168>:	Cannot access memory at address 0x80201048
(gdb) kx/16xb $pc
0x0000000080201048:	0x17 0x05 0x00 0x00 0x13 0x05 0x45 0x07 0x73 0x10 0x55 0x10 0x97 0xc1 0x57 0x02
```

`kx` puts QEMU HMP `xp` through the monitor path to skip translation — the same
path the page-table walkers use, now a user command. Syntax follows `x`
(`kx/16xb $pc`, `kx/8gx 0x40200000`; default `/16xb`; `i` is not supported, use
`cfgdis`). A kernel VA argument is converted to physical first and the conversion
printed, so `kx $pc` is correct in any regime. gdb's `x` is untouched. The tool
also prints a one-line note at a spot where `$pc` is physical and `x` would fail,
deciding by actually trying `x/1xb $pc`.

---

## 13. `kearly safemem` — stop a pwndbg probe from killing QEMU

**Symptom.** On some stops (e.g. a KASLR kernel stopped in a syscall-path
function), when pwndbg draws the context QEMU dies of SIGSEGV and gdb aborts.

**Cause.** pwndbg has no `/proc/<pid>/maps` for a kernel target, so it estimates
the memory map by probing — a 1-byte read at ~170 page-aligned addresses per
render. When a probe address translates outside RAM, QEMU dispatches into a
device model and dies (`gdb_read_byte → cpu_memory_rw_debug → … →
memory_region_dispatch_read → SEGV`). It is not this tool: it reproduces with
pwndbg alone and this plugin not loaded, and stock gdb (`-nx`) is fine. The
trigger is the **address, not the regime** — a single read landing on the GIC
kills qemu even at the very first pre-MMU stop with both cores MMU-off — so the
guard is armed wherever the QEMU monitor answers, not only where translation is
on.

**Handling.** It wraps the lowest single path every pwndbg read goes through (the
gdb backend's `read_memory`). Before a read it asks `monitor gva2gpa` whether that
page is mapped, and if `Unmapped` it returns the ordinary read failure pwndbg
already handles, never touching QEMU. `gva2gpa` is safe on any input. It does not
modify pwndbg; it keeps the original read and filters only dangerous addresses,
passing through when it cannot decide. It caches per page and clears at every
stop.

```
kearly safemem status      installed / armed / whether the monitor answers / probes blocked / reads rescued
kearly safemem on|off|auto (GDBTOOLS_SAFEMEM; auto arms it on a kernel target wherever the QEMU monitor answers)
```

`installed` and `armed` are different questions, and the status line reports both:
the wrapper can be in place while the guard declines to judge, which is what a
silent SEGV looks like from the outside. **auto** arms it on a kernel target
wherever HMP answers, settled once per session with a single `monitor gpa2hva 0`.
On a target with no monitor (kgdb over serial, JTAG) it can only answer "unknown"
and allow, so it says so once instead of paying a round trip per page.

The root defect is in QEMU: no debug read should die of SEGV. This avoids
triggering it; a regression is caught by the crash-guard test.

### 13.1 Keeping pwndbg's TUI usable in early boot

- **Pagescan noise.** pwndbg's `auto-explore-pages` pours out dozens of `Avoided
  exploring … / Likely a pagescan bug` lines per stop on a kernel target (no map),
  burying the register telescope. While active on a kernel target the tool keeps
  this at `no` and restores the user's value on `kearly off`. It touches only this
  one heuristic; telescope / dereference / symbolization are unchanged.

- **Read rescue (regime-independent).** When cores are simultaneously in different
  regimes (a secondary in `__enable_mmu` physical code while another runs MMU-on),
  the gdbstub cannot service a read and `read_memory` fails even though the CPU is
  executing right there, losing the telescope arrows. HMP `monitor xp` is a
  physical path independent of any core's regime, so when a live read fails the
  guard converts the address to physical and rescues it via `xp`: a low address
  as-is; a VA translated via `monitor gva2gpa` relative to the **selected core**
  (aligned with `monitor cpu <core>`, rejecting identity/still-high responses, and
  if needed sweeping cores — the riscv boot hart is random each boot). It reads
  only when the target is actual guest RAM, asked of QEMU via `monitor gpa2hva`
  (`is not RAM`/`No memory is mapped` are declined), so it never touches a device
  model. A truly unmapped junk pointer is caught first by the upper zero-fill
  guard and never reaches rescue. The count is `rescued` in `kearly safemem
  status`.

- **Cross-regime register twin.** In a physical/transition stop a register may
  hold a kernel VA not yet reachable (e.g. `x8 = __primary_switched` at the
  `br x8` moment). Leaving pwndbg's REGISTERS as-is, the tool's own panel shows
  the now-reachable physical twin alongside:

  ```
   cross-regime regs (VA -> reachable PA twin):
     x8   0xffffa9f7289ca730  (__primary_switched)  ->  PA 0x0000000042bca730
  ```

  It does VA→PA one direction only (`_is_va` = all top bits 1), so a large
  control/ID register value is never mistaken for a pointer; only a twin inside
  the physical window is shown, and at a virtual stop the line does not appear.

- **Version-detection guard.** At the earliest `start_kernel`, pwndbg reads
  `linux_banner` to learn the kernel version; `krelease()` throws rather than
  returning None on a non-empty non-`Linux version` string, and the just-up high
  map can return garbage, aborting the whole context. The tool wraps `krelease()`
  /`kversion()` to return None on failure, so the context draws to the end; the
  real tuple is returned unchanged in the normal case. It guards the symptom, not
  the root (early-boot banner read instability).

Core (thread) switching holds too: the regime decision is made from the selected
thread's pc/registers, so `thread N` switches the panel/telescope to that core's
context (one core PHYS, another VIRT, both fully rendered).

---

## 14. KASLR and the crossing catcher

On a KASLR-on cold frozen boot, `b start_kernel` at the head.S entry used to
**quietly miss**: the kernel has not yet computed its virtual base, so the only
address gdb can arm is the link VA, which the relocated kernel never executes, and
the guest boots to the login prompt with no stop or diagnostic. Reproduced on all
four trees.

Now, **setting a breakpoint/watchpoint aimed at a high VA while the slide is
unknown** makes the tool auto-arm a catcher on that arch's physical→high-VA
crossing. The moment execution reaches the crossing it reads the slide, relocates
the symbols, and the catcher retires itself — no further command:

```
(gdb) b start_kernel
Breakpoint 5 at 0x42bc0bd8: start_kernel. (2 locations)
[gdbtools] kaslr: that breakpoint targets a high VA but the slide is still unknown -- armed a silent
       catcher on the MMU-crossing (phys 0x42bb8518); the slide is read and applied in passing.
(gdb) continue
[gdbtools] KASLR slide = 0x3de518400000 applied: all symbols relocated to runtime VAs
Thread 1 hit Breakpoint 5.2, start_kernel () at init/main.c:915
915	{
```

All three arches pass **silently**, because the crossing landing address is read
physically — from a register (arm64 `x8`/`x27`), a global
(`kernel_map.virt_addr`), or an indirect-jump slot (x86 `jmp *0f(%rip)`) — so the
CPU is not moved. If a user breakpoint fires **before** the crossing, the catcher
stays persistent, respecting the stop, and applies when execution later reaches
the crossing.

### 14.1 The physical crossing anchor

The slide is fixed only after relocation, but in a cold frozen boot there is no
natural stopping point between relocation and start_kernel. So the tool uses a
slide-independent **physical crossing anchor**: right after relocation and before
start_kernel it HW-breakpoints the phys→high-VA transition instruction (which runs
MMU-on with idmap, so VA==PA and it fires without the slide), reads the landing
symbol's runtime VA from the transition registers, and fixes `slide = runtimeVA −
linkVA`.

| arch | crossing anchor | slide acquisition |
|---|---|---|
| arm64 6.12 | `br x8` in `__primary_switch` → `__primary_switched` | `x8 − linkVA(__primary_switched)` |
| arm64 4.6 | `br x27` in `__enable_mmu` → `__mmap_switched` | `x27 − linkVA(__mmap_switched)` (= x23) |
| riscv 6.12 | entry of `relocate_enable_mmu` (after setup_vm, MMU-off) | `kernel_map.virt_addr − linkVA(_start)` |
| x86 6.12 | `jmp *0f` in `startup_64` (after loading CR3) → `common_startup_64` | after stepi, `$pc − linkVA(common_startup_64)` |

The crossing instruction is found by opcode-scanning the function's physical bytes
(arm64 `br xN` = `0xD61F0000|N<<5`, stopping at `ret`) or by disasm (x86 `jmp
*..(%rip)`), so no per-version address is hardcoded. Under nokaslr the register
holds the link VA and it lands exactly with slide=0.

`kearly kaslr auto` (recommended): after bootbreak it advances to the crossing,
reads the slide, and relocates every symbol via `symbol-file -o`. It stops
**before** start_kernel, so a following `b start_kernel; continue` lands. Only
`auto` resumes the CPU; a bare `kearly kaslr` prints usage + the current slide and
moves nothing; `kearly kaslr <hex>` applies an explicit slide. Head.S/idmap code
catches at physical/idmap addresses **without relocation**; only post-start_kernel
code at the relocated high VA needs it.

### 14.2 x86: recovering the decompressor physical base

x86 randomizes even the **physical** load address (arm64/riscv only the virtual),
so at the cold frozen point the main kernel is not in RAM yet. The tool sees `$pc`
below the decompressor load address (`0x100000`), confirms the cold frozen state,
and first recovers the random base via the decompressor chain — **no environment
variable or flag needed**:

```
[gdbtools] x86 KASLR: extract_kernel reached; decompressing kernel (finish) ...
[gdbtools] x86 KASLR: recovered main-kernel phys base 0x0000000039e00000 via the decompressor
[gdbtools] KASLR slide = 0x13e00000 applied
Thread 1 hit Breakpoint 5.2, start_kernel () at init/main.c:915
```

Mechanism: HW breakpoint at the decompressor entry (`0x100000`) → read the moved
base at the self-relocation `jmp *%rax` in `startup_64` → `finish` at
`extract_kernel` to get the decompressed main-kernel physical entry (= the random
KASLR base). With that as the entry, the crossing anchor fixes the virtual slide.
The offset is derived version-independently by reading
`arch/x86/boot/compressed/vmlinux` with `nm`/`objdump` (falling back to
`$GDBTOOLS_ENTRY_PA`). On x86, QEMU is run under TCG for deterministic
earliest-boot HW breakpoints.

### 14.3 The KASLR status field

The `KASLR=` field of the `kgdb` panel (and `kearly where`) shows a number
whenever the value is knowable — a slide of 0 is information, not absence:

```
KASLR=0x4ca043800000                  KASLR on, fixed at the crossing
KASLR=0  (KASLR disabled)             nokaslr -- fixed from the reset vector on
KASLR=? (undecided until the crossing -- still physical, MMU off)
```

The `nokaslr` decision is read from the DTB's `/chosen/bootargs` (QEMU passes the
cmdline that way on arm64·riscv, so it can answer even at the reset vector; x86
has no DTB, so it is fixed only after start_kernel), with `saved_command_line` as
a fallback. Before the crossing with KASLR on the slide exists nowhere, so it says
`?` rather than inventing a 0.

### 14.4 Design of the catcher

- **It is a gdb internal breakpoint** — not in `info breakpoints`, and `delete`
  cannot remove it, so the slide applies even if the user deletes all their
  breakpoints and keeps only a watchpoint. This is required by a gdb constraint:
  `watch_command_1` asserts that the end of the breakpoint chain is the watchpoint
  being created, so creating a breakpoint inside a watchpoint-creation event kills
  gdb. So the rule is: if the probe being created is a **watchpoint, only record
  the request** (do not arm there); otherwise create the internal catcher; and
  handle pending requests at safe points (calibration, the stop hook, the prompt).
  In the normal flow the catcher is already set at `kearly bootbreak`'s
  calibration, so setting a watchpoint first is fine.

- **A literal link address is not moved, a sibling is set alongside.** `b
  *0xffff8000829b80a8` keeps the literal in place (a literal means exactly that
  address) and arms a physical twin alongside; once the slide is fixed the IMG
  sibling is re-armed at `linkVA+slide`. A physical-regime target fires the twin,
  a virtual-regime target the re-armed IMG. The slot cost is at most 2 per literal,
  same as `kb`; a `b SYM` that already has two locations adds nothing.

- **The validation is not circular.** `expected = link + slide` is an identity (the
  breakpoint fires where it was armed), so two witnesses outside the tool are used:
  (1) the guest bytes at the stop match the ELF `objdump` value (a wrong slide
  would show different code — e.g. arm64-v4.6 `start_kernel` `fd7bbba9 c0220090
  00002491 fd030091`); (2) an address the kernel printed itself (x86 `Kernel
  Offset:`, arm64-v4.6·riscv the boot-log memory layout).

### 14.5 Known limitations

- **riscv needs `--cpu max`.** The default `rv64` has no Zkr SEED CSR and QEMU's
  DTB has no `/chosen/kaslr-seed`, so the kernel finds no entropy and the slide is
  silently 0 — you can end up testing an un-randomized state while believing KASLR
  is on.
- **x86 cannot set kernel symbols before the decompression point.** With
  `--earliest`/`--no-calibrate`, only the bzImage decompressor is in memory and the
  kernel is still compressed, so that symbol's address exists nowhere and no
  debugger can set it. The tool states the reason; once `kearly bootbreak` recovers
  the random base, a probe you already set follows on its own (`b` → `bootbreak` →
  `continue`). Auto-running the recovery was declined because those flags mean "do
  not advance the CPU" and recovery runs through `extract_kernel`. arm64·riscv have
  no such limit (QEMU `-kernel` loads the whole image), so the location is known
  even at the reset vector.
- **arm64 6.12 `.idmap.text` has no source line info.** `primary_entry` /
  `__enable_mmu` / `__primary_switch` — exactly the "half on" region. The
  `.section ".idmap.text","a"` declaration has no execute flag, so the assembler
  emits no DWARF line info and no debugger can restore it; follow it with `cfgdis`
  symbol+offset disassembly and `stepi`. On v4.6 the same code is in `.text` so
  line info is normal.
- **pwndbg's `context` can abort gdb at a post-early-boot kernel-thread stop** (e.g.
  `kernel_init`) on some gdb/pwndbg builds: its register render trips gdb's
  `inferior_thread` assertion (`current_thread_ != nullptr`). It reproduces with
  pwndbg alone, so it is an upstream pwndbg-vs-gdb issue; being a C-level assertion
  it cannot be caught from Python. gdbtools' own views (`kgdb`/`flow`, `kearly
  where`, `kcensus`, `mmview`) and plain gdb (`p`/`x`/`bt`/`info`) all work there;
  workaround: `set context-sections 'kgdb flow'`.

---

## Cross-validation (direct boot, measured)

| architecture | paging | levels | validation |
|---|---|---|---|
| arm64 v4.6 | 4KB/39-bit | 3 | kpt (initial 2MB block · runtime 4KB page both kv2p MATCH), kpgd, mmview, kcensus(88), panel, chaindepth |
| x86_64 v6.12 (LA57) | 5-level | 5 | kpt/mmview 5-level, kernel filter |
| x86_64 v6.12 (`no5lvl`) | 4-level | 4 | kpt PML4→PDPT→PD, kv2p MATCH |
| riscv64 v6.12 | Sv57 | 5 | kpt L4→L1 BLOCK kv2p MATCH, mmview, kcensus(21 CSR) |

Under KASLR, the auto-applied slide was cross-validated against the independent
`live start_kernel − ELF link value` on all four trees (arm64-v6.12, arm64-v4.6,
riscv64-v6.12, x86_64-v6.12), with a clean start_kernel hit. All pass without a
crash, using pwndbg as a library only (unmodified).

---

## Design principles

- **pwndbg unmodified** — used as a library only. Works in plain text even without it.
- **physical reads after MMU on** — `monitor xp` (HMP, qRcmd tunnel); gdb `x`/`hexdump` translate through the current PT and fail.
- **session inviolable** — every gdb call goes through the safe layer and is a no-op on failure. Telescopes, page walks and enumerators are all finite (depth cap / level counter / node·leaf cap), so infinite recursion is impossible.
- **additive only** — existing commands and behavior are preserved; only features are added.
