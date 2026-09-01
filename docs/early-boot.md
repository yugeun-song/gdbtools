# gdbtools — head.S (earliest boot) kernel debugging tools

`gdbtools.py` is a custom plugin that runs on top of a host gdb (+pwndbg)
attached to a QEMU gdbstub. The `source` target is this one file as-is, and the
implementation lives in the sibling `kgdb/` package (dependency graph:
`runtime` → `physmem` → `pwndbg_glue`/`dtb`/`target` → `arch_*` → `session` → `commands`/`cfgdis`
→ `bootstrap`; `state` breaks the helper↔session cycle). In the `head.S` region before the MMU is on, `$pc` and pointers are **physical addresses**, so
the gdb symbol table linked at virtual addresses resolves nothing (`info symbol`, pwndbg `telescope`/`context` are dead).
This tool **calibrates** the phys↔virt offset at runtime to resolve physical addresses back to symbols,
and adds kernel-only conveniences such as page-table walks, memory layout, and a full register census.

- pwndbg is used **as a library only** and is **never modified**. It works in plain text even without pwndbg.
- arm64 · x86_64 · riscv64, kernel-version independent. Every command works **from the MMU-off physical stage through to runtime**.
- If any gdb call fails it degrades to a no-op/None, so it **never breaks the main gdb or the remote session**.

Every output in this document is **captured directly from a real run** by actually booting and attaching to QEMU (color codes stripped).

---

## How to run

This tool is a Python extension that runs inside gdb. The script that launches
the VM, and any launcher that runs gdb for you, are not included here. All you
need is to `source` `gdbtools.py`, and once you run `setup.sh` once, gdb reads it
automatically at startup.

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

If you would rather not type it every time, export `GDBTOOLS_AUTO=1` before
starting gdb. At attach time the three lines above run automatically, and the
stop hook, shadow symbols, and MMU-transition notices come up with them. Nothing
happens on a non-kernel target.

Boards that need machine information (a real board rather than QEMU, etc.) take a
JSON profile through `$GDBTOOLS_PROFILE` and a DTB through `$GDBTOOLS_DTB`. Mid
session you can also use `kearly profile FILE` / `kearly dtb FILE`.

**What `kearly bootbreak` does**

5. **attach + advance to the entry + calibrate** — after `target remote :PORT`, by default `kearly bootbreak` (advance
   past reset/firmware to the kernel entry + calibrate the phys↔virt offset) → then `kearly status` runs automatically.
6. **arm the automatic hooks** — setting `$GDBTOOLS_AUTO` turns on the stop hook, shadow symbols, and the MMU on/off transition notices
   (it never auto-attaches to a plain `gdb vmlinux` — only when this signal is present).

Right after attach, a banner lists all the commands:

```
[kgdb] early-boot symbolizer loaded (commands: kearly | kp2v | kv2p | sym |
       stackscan | ksr | ksregs | kcensus | kpt | kpgd | koff | mmview/memlayout | kfin | chain | cfgdis | kdtb)
```

**Safety contract** — (1) it kills nothing (no pkill/fuser; running VMs and sessions are untouchable). (2) if there is no stub it does not
force the connection and hang gdb; it loads only the symbols and tools and **drops to a live interactive prompt**
(you can type `target remote :DEFAULT_PORT` by hand later). (3) it does not touch global gdb/pwndbg settings.

**Main options**

| option | effect |
|---|---|
| `target remote :PORT` | connect to the gdbstub |
| `-p, --port N` | force the gdbstub port |
| `--gdb BIN` | force the gdb binary |
| `--no-connect` | load symbols and tools only, do not connect |
| `--no-calibrate` | connect only, skip `kearly bootbreak` |
| `--earliest` (`--raw`) | stop before head.S (reset vector/firmware) — advance later with `kearly bootbreak` |
| `-x, --ex CMD` | run an arbitrary gdb command after connecting (repeatable) |
| `--preset NAME` | boot-combination preset (arm64-uefi, x86-pvh, riscv-uefi …) |
| `--entry-pa` / `--anchor` / `--break-kind` / `--ram-base` / `--scan` | manually specify a combination that is not auto-detected |
| `--profile FILE.json` / `--dtb FILE` | inject a machine descriptor for a non-QEMU board |

> Summary: **attach to a frozen VM and type the single line `kearly bootbreak`**, and everything from advancing the entry,
> loading vmlinux+tools, advancing to the entry, calibration, and the automatic hooks is done. From there you type the commands below.

---

## Command overview

| command | one-line summary |
|---|---|
| `kearly bootbreak` | advance to the kernel entry + calibrate the phys↔virt offset (runs automatically if $GDBTOOLS_AUTO) |
| `kearly status` / `kearly mmu` | arch · offset · map · MMU on/off · configuration state |
| `kearly overmmu [SYM]` | cross the MMU-enable boundary safely (temp bp at the virtual landing + continue) |
| `kearly steplock on\|off\|auto` | freeze the other cores while single-stepping during MMU off (removes SMP noise) |
| `kearly saferender warn\|on\|off\|auto` | arm64 pwndbg emulation-disassembly SIGABRT guard (`on/auto`=`set emulate off`, restored on `kearly off`). **Default `auto`** blocks it automatically on arm64; `off`=restore immediately, `warn`=warn only |
| `kearly bpfix <on\|off>` | tidy up the dual physical+virtual breakpoints (optional): the **virtual location is always kept on** (MMU-on code fires it), only the physical location that sleeps while MMU-on is turned off. **Default off** — a QEMU SW breakpoint matches on the virtual PC, so a native dual works too |
| `kearly kaslr [auto\|off\|status\|<hex>]` | auto-detect the KASLR slide then relocate every symbol to its runtime VA via `symbol-file -o` → `b SYM` fires even under KASLR. `auto`: if it is already readable, read the globals (`kimage_voffset`/`kernel_map.virt_addr`); otherwise (cold frozen) advance to the **arch-specific phys→high-VA crossing anchor** and read the slide from the transition registers (stops before start_kernel → a following `b start_kernel` then fires). Runs automatically if `$GDBTOOLS_X86_KASLR=1`. **Only `auto` moves the CPU** — a bare `kearly kaslr` with no argument only prints usage and the current slide and resumes nothing. `auto` is re-entry safe even when already stopped on the crossing (it reads the slide in place rather than continuing). **You usually do not need to type it yourself** — when the slide is unknown, setting a breakpoint/watchpoint aimed at a high VA makes the tool auto-arm a catcher on the crossing, so `b start_kernel` + `continue` alone catches it (section 11 below) |
| `kb SYM \| *ADDR \| FILE:LINE` | **regime-aware breakpoint (no whitelist)**: sets HW breakpoints on both the invariant physical address `PA(S)=linkVA+offset` and the runtime VA `IMG(S)=linkVA+slide`. MMU-off/idmap execution (head.S · pi · secondary · cpu_resume) fires PA, high-VA execution (start_kernel · normal running code) fires IMG — only the one whose execution regime matches fires; the other is dead code and does not match. IMG auto-re-arms once the slide becomes known |
| `kw [-r\|-a] SYM \| *ADDR [SIZE]` | **regime-aware watchpoint** — the data counterpart of `kb`. A kernel global is accessed by physical address in MMU-off/idmap and by `linkVA+slide` once running at high VA, so a single `watch SYM` blinds the far side of the crossing. `kw` sets HW watchpoints on both `PA(S)` and `IMG(S)`, and auto-re-arms IMG once the slide is fixed. `-r`=rwatch, `-a`=awatch. **Consumes 2 HW slots** — a real arm64 core usually has only 4, while QEMU TCG is more generous (6 observed to be accepted). Filling slots is not the goal, so set only as many as you need |
| `kearly census off\|compact\|full` | toggle whether `kcensus` below is kept in the panel at every stop |
| `kearly chaindepth N` | adjust the telescope (chain) depth — always finite, with cycle detection |
| `kp2v ADDR` / `kv2p ADDR` | physical↔virtual translation |
| `sym ADDR` | physical/virtual address → kernel symbol |
| `stackscan [N]` | find code pointers on the stack and symbolize them (for head.S where backtrace is dead) |
| `ksr NAME` / `ksregs` | one sysreg / a batch dump of the core sysregs (+decode) |
| **`kcensus`** | enumerate **every control/system register that head.S and its call chain touch**, with value and decode |
| **`kpt [VA] [hex]`** | **hardware page-table walk** — L0~L3 / PML4~PT / Sv39-57 (`hex`=also show the raw LE bytes of each level's descriptor) |
| **`kpgd [PA] [N]`** | dump the non-empty entries of the top-level (or the given) page directory |
| **`kpthex [PA] [N\|full]`** | show page-table entries as a **byte-level hex view** (per-entry 8-byte breakdown; `full`=4KB xxd dump). Reads physically, so it works even after the MMU is on |
| **`koff [SYM]`** | **why the runtime address ≠ the vmlinux ELF (nm) value** — using the CPU flags/registers/`$pc` that split MMU on/off as clues, summarize the ELF-value-vs-current-address offset |
| **`mmview` / `memlayout [all\|noidmap]`** | **vmmap for the kernel** — symbol landmarks + live ptdump |
| `kfin` | a `finish` replacement for CFI-less head.S |
| `chain [ADDR] [N]` | N-word telescope (physical/virtual aware, symbolized) |
| **`cfgdis [ascii\|mono] [WHAT]`** | **branch-arrow disassembly** — like radare2's `pdf`, nested arrows in the left margin for every on-screen jump (source/destination lengths aligned). Auto-detects arch, excludes calls, works in both physical and virtual. A `flow` section is added to the context automatically when attached via run-gdb |
| **`kdtb [options] [ADDR]`** | **full live FDT dump** — header · memory reservation block · every node · every property in DTS form, with no truncation. The address is found automatically from `initial_boot_params` (candidates per MMU state are magic-checked in order). Options: `--header` `--rsv` `--tree` `--path P` `--grep RE` `--hex` `--terse` `--phys` `--save FILE` `--stats`. The same result as `dtc -I dtb -O dts`, inside gdb with no external tool |

> A version that uses only pure gdb commands is in a separate file `fdt.gdb` (`source fdt.gdb` → `fdt` / `fdt-header` / `fdt-rsv` / `fdt-tree`). It needs neither python nor a plugin, so it works as-is in stock gdb.

---

## 1. Preparation — `kearly`

### `kearly bootbreak` / `kearly status`

If `$GDBTOOLS_AUTO` is set, `kearly bootbreak` runs at attach, advancing past the QEMU reset/firmware to the kernel
entry and fixing the offset. The state afterward:

```
(gdb) kearly status
[kgdb] arch=arm64  enabled=True  offset(PA-VA)=0x0001000038000000
      map=virtual  MMU=on [pc=VA]  steplock=auto  census=off  chaindepth=8
      preset=(default)  anchor=_text  break=sw
      target=(arch defaults)
      vmlinux=.../arm64-v4.6/kernel/vmlinux  shadow=0x0000000040080000
```

- `offset(PA-VA)` — physical = virtual + offset. Here it is `0x0001000038000000`.
- `map` / `MMU` — whether the current map is physical or virtual, and MMU on/off.
- `shadow` — the address of the phys-shifted symbol file laid down so physical addresses resolve to symbols too.

### `kearly mmu` — MMU state detail

```
(gdb) kearly mmu
[kgdb] MMU=off [ctrl-reg]  map=physical  pc=0x0000000040080000  SCTLR_EL1.M=0
      pre-MMU: $pc/pointers are PHYSICAL; shadow symbols active.
```

After the MMU is turned on:

```
[kgdb] MMU=on [ctrl-reg]  map=physical  pc=0x00000000408b003c  SCTLR_EL1.M=1
      MMU on: kernel VAs resolve natively; kp2v/kv2p translate either way.
```

### `kearly overmmu` — crossing the MMU boundary

Stepping over `__enable_mmu` with `stepi` makes the QEMU gdbstub leak the single-step at that point and the CPU runs away.
Instead, set a temporary breakpoint at the virtual landing (e.g. `start_kernel`) and cross with `continue`:

```
(gdb) kearly overmmu start_kernel
[kgdb] over_mmu: continue to virtual landing {start_kernel} ...
[kgdb] >>> MMU ON: $pc now VIRTUAL 0xffff000008c365f0 -- native kernel symbolization active
[kgdb] landed pc=0xffff000008c365f0 start_kernel in section .init.text  (MMU on)
```

---

## 2. Address translation and symbolization — `kp2v` / `kv2p` / `sym` / `stackscan`

Physical↔virtual translation and symbolization. After the MMU is on, both directions work (measured, runtime `$pc`=`cpu_do_idle+8`):

```
(gdb) kv2p $pc
VA 0xffff000008099f58 -> PA 0x0000000040099f58

(gdb) kp2v 0x40099f58
PA 0x0000000040099f58 -> VA 0xffff000008099f58  cpu_do_idle + 8 in section .text of …/vmlinux

(gdb) sym $pc
0xffff000008099f58 (VA)  cpu_do_idle + 8 in section .text of …/vmlinux

(gdb) sym 0x40099f58
0x0000000040099f58 (PHYS) -> VA 0xffff000008099f58  cpu_do_idle + 8 in section .text of …/vmlinux
```

`stackscan [N]` — in head.S where backtrace is dead, find kernel pointers among the stack words and symbolize them.
It distinguishes and labels physical (PA) and virtual (VA) (measured excerpt):

```
(gdb) stackscan 24
  [sp+0x008] 0xffff000008109a7c  VA  cpu_startup_entry + 644 in section .text of …/vmlinux
  [sp+0x028] 0xffff0000088a3600  VA  rest_init + 136 in section .text of …/vmlinux
  [sp+0x070] 0xffff000008081198  VA  __mmap_switched in section .head.text of …/vmlinux
  [sp+0x078] 0x00000000408b0054  PA  __enable_mmu + 84 in section .text of …/vmlinux
  [sp+0x088] 0xffff000008c36968  VA  start_kernel + 888 in section .init.text of …/vmlinux
```

---

## 3. System registers — `ksr` / `ksregs`

`ksregs` batch-dumps the core sysregs with value and decode (measured, arm64 runtime):

```
(gdb) ksregs
[kgdb] MMU=on EL1  SCTLR_EL1=0x34d5d91d  TTBR0_EL1=0x6d0000b6fdc000  TTBR1_EL1=0x41200000  PSTATE.DAIF=0x7   [MMU=on pc=VA]
  CurrentEL    0x0000000000000004  (4)   EL1
  SCTLR_EL1    0x0000000034d5d91d  (886429981)   M=1 (MMU on)  C=1 I=1 A=0 SA=1 WXN=0
  TTBR0_EL1    0x006d0000b6fdc000  (30680775531544576)
  TTBR1_EL1    0x0000000041200000  (1092616192)
  TCR_EL1      0x00000034b5103510  (226376037648)   T0SZ=16 (VA 48-bit)  T1SZ=16 (VA 48-bit)
  MAIR_EL1     0x0000bbff440c0400  (206705032692736)
  VBAR_EL1     0xffff000008084800  (18446462598867601408)
  SP_EL0       0xffff000009080000  (18446462598884360192)
  ELR_EL1      0xffff000008086844  (18446462598867609668)
  SPSR_EL1     0x0000000000000145  (325)
  ESR_EL1      0x0000000056000000  (1442840576)
  FAR_EL1      0x0000aaaabd6084f8  (187650298381560)
  DAIF         0x0000000000000007  (7)   [d A I F]  (partial)
  NZCV         0x0000000000000000  (0)   [n z c v]
```

`ksr NAME` reads just one (e.g. `ksr CurrentEL`). The read path is pstate-derived → gdb register →
QEMU monitor fallback, so it captures a value even for registers the stub hides, as far as possible.

---

## 4. `kcensus` — head.S register census

**What it does** — it enumerates **every system/control register that is involved in a read/write at least once**
in `head.S` and in every file it reaches (following the entire call chain), by category, with the current value,
field decode, and purpose. These are exactly the registers pwndbg's REGISTERS panel does not show (general-purpose x0~x30 excluded).
arm64 88 / x86 CR·MSR·segment / riscv CSR.

**How to type it**

```
(gdb) kcensus
```

**Measured output (arm64, excerpt — 88 total)**

```
[kgdb] head.S early-boot register census -- arm64   [MMU=on pc=VA]   (88 registers)
translation
  TTBR0_EL1          RW  0x760000b68b3000     idmap/user page-table base (MMU enable, switch_mm, resume)
  TTBR1_EL1          RW  0x41200000           kernel/swapper page-table base (KPTI, replace-ttbr1)
  TCR_EL1            RW  0x34b5103510         T0SZ=16 (VA 48-bit)  T1SZ=16 (VA 48-bit)
  TCR2_EL1           RW  ?                    extended translation control (S1PIE/PIE enable) [6.12]
  VTTBR_EL2          W   ?                    clear stage-2 base (no guest)
memory-attr
  MAIR_EL1           RW  0xbbff440c0400       memory attribute indirection (Device/Normal/NC/WT encodings)
system-control
  SCTLR_EL1          RW  0x34d5d91d           M=1 (MMU on)  C=1 I=1 A=0 SA=1 WXN=0
  CPACR_EL1          RW  0x300000             FP/ASIMD/SVE/SME EL0/EL1 access enable
  HCR_EL2            RW  ?                    hyp config: RW(64-bit EL1), E2H/TGE (VHE), host flags
  DAIF               RW  0x7                  [d A I F]  (partial)
el-transition
  CurrentEL          R   0x4                  EL1
  SPSR_EL1           RW  0x145                saved PSTATE for EL1 eret; rewritten on VHE upgrade
  ELR_EL1            W   0xffff000008086844   exception link for EL1->EL1 clean-state eret [6.12]
  SP_EL0             W   0xffff000009080000   install task/thread_info stack pointer
feature-id
  CTR_EL0            R   0x8444c004           cache type: D/I line size for maintenance loops
  ID_AA64MMFR0_EL1   R   0x1124               TGRAN granule support + PARange for TCR.IPS
  ID_AA64DFR0_EL1    R   0x10305106           PMUVer/PMSVer/TraceBuffer -> gate PMU/SPE/TRBE
  ...
```

- `RW`/`R`/`W` = how head.S uses that register.
- `?` = something the gdbstub/monitor cannot provide at the current EL/moment (e.g. an EL2 register while at EL1). Marked **honestly as `?`**.
- `[6.12]`/`[4.6]`/`[M-mode]` = a version/mode-specific register.

**Measured output (riscv, full — 21 CSRs)**

```
translation
  satp               W   0xa006b000000838bf   MODE=10 (Sv57)  PPN=0x838bf  (PT@0x838bf000)
trap-setup
  stvec              W   0xffffffff80bf6a28   early trap vector (post-satp landing, spin, handle_exception)
  sepc               RW  0xffffffff80bebc98   trap PC (saved on entry, written on return)
  scause             R   0x8000000000000005   trap cause (irq vs exception dispatch)
  stval              R   0x0                  trap value / faulting address
status-control
  sstatus            RW  0x200000020          SIE=0 SPIE=1  SPP=0 (U)  SUM=0 MXR=0
  fcsr               W   0x0                  zero FP control/status after clearing f0-f31
  vcsr               RW  ?                    reset vector control/status
...
```

**Kept in the panel** — turning on `kearly census compact` attaches a one-line-per-category summary to the
pwndbg context (or the automatic line) at every stop:

```
 translation:     TTBR0_EL1=0x6d0000b7f34000  TTBR1_EL1=0x41200000  TCR_EL1=0x34b5103510
 memory-attr:     MAIR_EL1=0xbbff440c0400
 system-control:  SCTLR_EL1=0x34d5d91d  CPACR_EL1=0x300000  DAIF=0x7
 el-transition:   CurrentEL=0x4  SPSR_EL1=0x145  ELR_EL1=0xffff000008086844  SP_EL0=0xffff000009080000
 feature-id:      CTR_EL0=0x8444c004  ID_AA64MMFR0_EL1=0x1124  ID_AA64DFR0_EL1=0x10305106
```

---

## 5. `kpt` — hardware page-table walk

**What it does** — it walks one VA the way the hardware would (L0~L3 arm64 / PML4~PT x86 / Sv39·48·57 riscv),
showing each level's raw descriptor, type (table/block/page/invalid), the next table or output PA, and the leaf attributes.
**The key point**: after the MMU is on, gdb `x`/pwndbg `hexdump` read a physical address by "translating it through the current page tables",
so they cannot read the raw PT (`Cannot access memory`). `kpt` reads through QEMU HMP `monitor xp`
(physical examine), so it is **accurate even after the MMU is on**.

**How to type it** — `kpt [VA]` (VA omitted → `$pc`; expressions allowed: `kpt &_stext`)

**Measured (arm64 runtime, kernel text mapped with 4KB pages)**

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
- leaf attributes: `AF` (access) `RO-` (read-only, kernel text) `AttrIdx` (MAIR index) `ISh` (inner share) `UXN` (execute-never at EL0).
- `=> LEAF` = the final physical address + symbol. `MATCH` = the software kv2p value and the hardware-walk result agree (consistency check).

**Measured (arm64 earliest boot — the initial swapper maps with 2MB blocks)**

```
(gdb) kpt &_stext
VA 0xffff000008082000   TTBR1_EL1 (kernel/high)   [4KB granule, 4-level (L0..L3), 9-bit index/level]
  top-table PA 0x41200000
  L0/PGD  [  0] @PA 0x41200000   desc=0x0000000041201003  table -> 0x41201000
  L1/PUD  [  0] @PA 0x41201000   desc=0x0000000041202003  table -> 0x41202000
  L2/PMD  [ 64] @PA 0x41202200   desc=0x0000000040000711  BLOCK  AF=1 RW- AttrIdx=4 ISh
  => LEAF PA 0x40082000  (do_undefinstr)
     (kv2p(VA)=0x40082000  MATCH)
```

> The same `_stext`, but a **2MB BLOCK** early (ending at L2) and a **4KB PAGE** after boot (down to L3) — you can watch, exactly as it happens,
> the kernel re-laying the mapping into finer granularity in `paging_init`.

**Measured (reports "not mapped" honestly)**

```
(gdb) kpt &_text
  ...
  L3/PTE  [128] @PA 0xbeffc400   desc=0x0000000000000000  INVALID / not-present
  => NOT MAPPED (no valid leaf descriptor)
```

> `_text` (the efi/head page) and `start_kernel` (the `.init.text` freed after boot) really are not mapped,
> and `kpt` reports that as-is.

**Measured (cleanly refuses while the MMU is off)**

```
(gdb) kpt &_stext
[kgdb] cannot walk VA 0xffff000008082000 -- page-table base unreadable, or paging is off
       (MMU/satp/CR0.PG). Try after MMU-enable.
```

**Measured (riscv Sv57, 5-level)**

```
(gdb) kpt
VA 0xffffffff80be9fce   satp Sv57 (PPN 0x838bf)   [Sv57, 5-level, 4KB pages]
  top-table PA 0x838bf000
  L4      [511] @PA 0x838bfff8   desc=0x000000003fffec01  table -> 0xffffb000
  L3      [511] @PA 0xffffbff8   desc=0x000000003fffe801  table -> 0xffffa000
  L2      [510] @PA 0xffffaff0   desc=0x000000003fffe401  table -> 0xffff9000
  L1      [  5] @PA 0xffff9028   desc=0x00000000203000eb  BLOCK  R-X S G A D
  => LEAF PA 0x80de9fce  (arch_cpu_idle + 14)
     (kv2p(VA)=0x80de9fce  MATCH)
```

**Measured (x86, both 4-level and 5-level)**

```
# default (LA57): 5-level
VA ...   CR3 (5-level)   [5-level paging (LA57 5-level)]

# booted with no5lvl: 4-level
VA 0xffffffff821132cf   CR3 (4-level)   [4-level paging (4-level)]
  PML4    [511] @PA 0x4cfeff8    desc=0x0000000003231067  table -> 0x3231000  (level3_kernel_pgt)
  PDPT    [510] @PA 0x3231ff0    desc=0x0000000003232063  table -> 0x3232000  (level2_kernel_pgt)
  => LEAF PA 0x21132cf  (pv_native_safe_halt + 15)
     (kv2p(VA)=0x21132cf  MATCH)
```

> The number of levels is computed at runtime from the hardware configuration registers (x86 `CR4.LA57` / arm64 `TCR` T0SZ·T1SZ / riscv `satp` MODE),
> so it adapts to 3/4/5 levels automatically. Page-table pages are symbolized too, like `level3_kernel_pgt`.

---

## 6. `kpgd` — page directory dump

**What it does** — it dumps the **non-empty entries** of the top-level page directory (or a given table PA)
with index, raw value, type, and output PA (+symbol). You can also pass the `table -> 0x...` PA that `kpt` gave
to dig into a lower level.

**How to type it** — `kpgd [PA] [N]` (omitted → the top of `$pc`'s regime; N = display limit)

**Measured (arm64 runtime, top-level L0/PGD)**

```
(gdb) kpgd
top table L0/PGD @PA 0x41200000   regime TTBR1_EL1 (kernel/high)   (non-zero of 512 entries)
  [  0] 0x00000000beffe003  table   -> 0xbeffe000
  [247] 0x00000000bedf2003  table   -> 0xbedf2000
  [255] 0x00000000411bd003  table   -> 0x411bd000    (bm_pud)
  [256] 0x00000000beff7003  table   -> 0xbeff7000
```

> Only 4 of 512 are valid — corresponding to the kernel image / linear map / fixmap regions. Symbols like `bm_pud` are attached too.

### `kpthex` — entries as real bytes (hex view)

**What it does** — unlike `kpgd`, which shows a 64-bit descriptor as one lump, it **breaks each entry into the 8 little-endian bytes as actually laid out in memory**,
showing them alongside the raw value and decode.
Passing `full` dumps the entire 4KB page xxd-style (16 bytes/line + ASCII). Because it reads physical memory through the QEMU
monitor (`xp`), it works **even after the MMU is on** (exactly the situation where gdb `x`/pwndbg `hexdump` fail at a physical
page-table address).

**How to type it** — `kpthex [TABLE_PA] [N | full]` (omitted → the top of `$pc`'s regime; N = non-empty entry cap of 64)

**Measured (arm64-v4.6 runtime, kernel L0/PGD)**

```
(gdb) kpthex
page-table page @PA 0x41200000   regime TTBR1_EL1 (kernel/high)   little-endian, as stored in RAM
   idx  @PA           b0 b1 b2 b3 b4 b5 b6 b7   value (LE)          decode
  [  0] 0x41200000     03 e0 ff be 00 00 00 00   0x00000000beffe003   TABLE -> 0xbeffe000
  [255] 0x412007f8     03 d0 1b 41 00 00 00 00   0x00000000411bd003   TABLE -> 0x411bd000  (bm_pud)
```

> The value `0x…beffe003` is laid out in memory as `03 e0 ff be 00 00 00 00` (LE). With `kpt VA hex`, each level's descriptor in the walk
> gets bytes attached too, like `[03 e0 ff be 00 00 00 00]`, and `kpthex 0x… full` prints that whole 4KB table page xxd-style.

---

## 6.5 `koff` — why the runtime address differs from the vmlinux ELF (nm) value

The symbol address that `nm`/`readelf` shows (= the VA linked into vmlinux) and the address where that symbol
actually sits right now differ **for different reasons depending on the regime**. `koff [SYM]` (SYM omitted → the image base) summarizes that reason
**not as narration, but using the CPU flags/control registers/`$pc` value that directly determine it** as clues.
The regime is split not by the MMU flag but by **whether `$pc` is actually physical or virtual** (`which_map`) — precisely to catch
the case, as on x86, where paging is always on but early execution runs at identity/low addresses.

```
# arm64, MMU off (head.S)                        # x86_64, startup_64 (paging ON but identity)
[koff] arm64  pc PHYSICAL (MMU off) [MMU=off]     [koff] x86_64  pc PHYSICAL (paging ON but
  $pc         = 0x40080000  -> physical/low                 identity/low map) [MMU=on ctrl-reg]
  SCTLR_EL1.M = 0           -> MMU off->PHYS        $pc    = 0x1000000  -> physical/low
  TTBR1_EL1   = 0x0         -> tables not set        CR0.PG = 1         -> paging on
  ELF value   = 0xffff000008080000  (nm)            CR3    = 0x446e000 -> page-table base
  address now = 0x40080000  (QEMU loaded here)      ELF value   = 0xffffffff81000000 (nm)
  offset(PA-VA)=0x1000038000000                     address now = 0x1000000 (identity)
                                                    why: paging ON but identity -> pc PHYS/low

# arm64/riscv, MMU on (high-half live)
[koff] arm64  pc VIRTUAL (high-half map live) [MMU=on pc=VA]
  SCTLR_EL1.M=1  TTBR1_EL1=0x41200000  cmdline kaslr=off (nokaslr)
  ELF value = address now = 0xffff000008080000    KASLR slide = 0 (nokaslr -> VA==ELF, confirmed)
```

The clues are arch-specific: **arm64** SCTLR_EL1.M / TTBR1_EL1 / kimage_voffset, **x86** CR0.PG / CR3 / CR4.PAE /
EFER.LMA / phys_base, **riscv** satp.MODE (Bare/Sv39-57) / satp.PPN. Common to all, it adds `$pc` (whether it is a high-half VA
or a physical/low address) and the cmdline `nokaslr` marker. KASLR slide: **if you have applied `kearly kaslr`**,
it reflects that slide and prints the **true link VA** (symbol value − applied slide), the **runtime VA**, and the **slide** exactly. Before it is applied,
it reports `0` (confirmed) if `nokaslr` is on the cmdline, otherwise it advises measuring with `kearly kaslr` (koff alone sees only the
relocated symbol table, so it cannot measure the slide itself). If you are attaching at runtime
and the offset does not yet exist, it quietly tries `calibrate`.

---

## 7. `mmview` / `memlayout` — vmmap for the kernel

**What it does** — pwndbg `vmmap` cannot read a kernel target, so this takes its place. Two parts:

1. **Symbol landmarks (VA→PA)** — needs only the symbol table + calibration → **works even in the pre-MMU physical stage**.
2. **Live ptdump** — walks the page tables, merges contiguous regions, and attaches permissions and a `kernel image` label.

While the MMU is off, it shows the **physical placement + RAM** instead of live mappings. Because a unified root (x86 CR3 / riscv satp)
mixes user and kernel, the default is **the kernel half only** (`mmview all` to include user, `noidmap` to skip arm64 TTBR0).

**How to type it** — `mmview` or the alias `memlayout` (options: `all` / `noidmap`)

**Measured (arm64, earliest boot with the MMU off — physical placement shown)**

```
(gdb) mmview
mmview -- kernel memory layout   [MMU=off ctrl-reg | arm64 | offset(PA-VA)=0x0001000038000000]

kernel image / key symbols  (VA -> PA):
  _text             0xffff000008080000  -> PA 0x40080000 kernel image start (.head.text)
  _stext            0xffff000008082000  -> PA 0x40082000 .text start
  __init_begin      0xffff000008c36000  -> PA 0x40c36000 __init start
  __init_end        0xffff000009080000  -> PA 0x41080000 __init end (freed after boot)
  _end              0xffff000009203000  -> PA 0x41203000 kernel image end
  swapper_pg_dir    0xffff000009200000  -> PA 0x41200000 kernel PGD (TTBR1)
  idmap_pg_dir      0xffff0000091fd000  -> PA 0x411fd000 identity-map PGD (TTBR0)
  init_task         0xffff00000908e900  -> PA 0x4108e900 init task_struct
  vectors           0xffff000008084800  -> PA 0x40084800 EL1 exception vectors (VBAR)

live VA mappings: NONE yet -- MMU is off (paging not active).
  -> showing PHYSICAL placement; re-run mmview after MMU-enable
     ('kearly overmmu', or step past 'msr sctlr_el1') for live tables.
  kernel image PA:     0x40080000 - 0x41203000   (17932K)
  image-base entry PA: 0x40080000
  RAM (DTB/profile):   0x40000000+0x80000000
```

**Measured (arm64, right after the MMU is on, the initial swapper — regions merged)**

```
live mappings: kernel  TTBR1_EL1  root@PA 0x41200000   (1 regions)   [4KB granule, 4-level (L0..L3), 9-bit index/level]
  0xffff000008000000-0xffff0000093fffff    20M -> 0x40000000    block AF=1 RW- AttrIdx=4 ISh kernel image {_text,_stext,_etext+}
```

> It shows the initial swapper's 20MB image region — mapped as 2MB blocks — **merged into a single region**.

**Measured (x86, kernel space only filtered — 474 user regions hidden)**

```
live mappings: kernel+user  CR3  root@PA 0x4714000   (14161/14635 regions)   [5-level paging (LA57 5-level)]
  (474 user/low-half regions hidden -- 'mmview all' to include)
  0xff11000000000000-0xff11000000097fff   608K -> 0x0           page  W S A D G NX
  0xff1100000009b000-0xff11000000ffffff 15764K -> 0x9b000       mixed W S A D G NX
  0xff11000001000000-0xff110000031f4fff 34772K -> 0x1000000     mixed R S A G NX
  0xffa0000000000000-0xffa0000000003fff    16K -> 0x7dc02000    page  W S A D G NX
  ...
```

> `0xff11...` = the LA57 linear map (direct mapping), `0xffa0...` = vmalloc/ioremap (devices like `0xfed00000`),
> `R/W S A D G NX` = x86 PTE flags. User-process mappings are hidden to keep the focus on the kernel map.

**Measured (riscv Sv57)**

```
live mappings: kernel  satp  root@PA 0x838bf000   (112/564 regions)   [Sv57, 5-level, 4KB pages]
  (452 user/low-half regions hidden -- 'mmview all' to include)
  0xff1bfffffec00000-0xff1bfffffeffffff     4M -> 0xffe00000    block RW- S G A D
  0xff1c000000000000-0xff1c000001ffffff    32M -> 0xfce00000    block RW- S G A D
  0xff20000000000000-0xff20000000003fff    16K -> 0x825dc000    page  RW- S G A D
  ...
```

---

## 8. Telescope and `kearly chaindepth`

Address-shaped sysregs (TTBR/VBAR/ELR/SP etc.) are rendered in the panel as a **telescope** (→ chain). But it does **not use
pwndbg's default chain as-is**: given a page-table base like TTBR, pwndbg mistakes the value for a pointer and follows PGD→PUD→PMD…
**down the whole table tree, overflowing gdb's C stack and killing the session (and QEMU)**.
So it renders with its own `safe_chain` (always finite depth + cycle detection), and for TTBR it follows **only the PGD→PUD→PMD
bases safely, via physical reads**.

**Measured (the panel's TTBR telescope — safe but kept as-is)**

```
 TTBR1_EL1  0x41200000  PTbase 0x41200000  ->  0xbeffe000  ->  0xbeffd000  ->  0x0
 TTBR0_EL1  0x6d0000b7f34000  PTbase 0xb7f34000  ->  0x0  ASID 0x6d
```

**Adjust the depth live from the command line** — `kearly chaindepth N`

```
(gdb) kearly chaindepth 2
[kgdb] telescope depth = 2 hops  (safe_chain: bounded, cycle-guarded; ...)
# -> TTBR1_EL1  0x41200000  PTbase 0x41200000  ->  0xbeffe000        (stops at 2 hops)

(gdb) kearly chaindepth 8       # default
# -> TTBR1_EL1  0x41200000  PTbase 0x41200000  ->  0xbeffe000  ->  0xbeffd000  ->  0x0
```

`chain [ADDR] [N]` uses the same safe telescope. `kfin` is a `finish` replacement for CFI-less head.S:
it takes the return address from `lr`/`ra`/the stack top and runs to that point.

---

## 9. `cfgdis` — branch-arrow disassembly

Like radare2's `pdf`, it draws the **control-flow arrows** of in-function jumps in the left margin of the disassembly.
It makes an edge for every direct jump that targets an on-screen instruction, stacks them on non-overlapping vertical tracks
(wider span on the outside), and draws them with corners, vertical lines, and crossings (`┌│└─┼┬┴`). It **matches the horizontal-line
length of the source and the destination** (both start at the same track column and extend to the address column), putting an arrowhead `>`
at the destination end and a flat `─` at the source end.

- **`WHAT` is exactly gdb's `disassemble` argument** — omitted, it is the current function (`$pc,+0x60` if the frame is outside a function),
  a symbol/address/range (`cfgdis start_kernel`, `cfgdis 0x80200000, +0x80`, `cfgdis __memset, __memset+0x40`).
  The display modifiers `/r`·`/s`·`/m` are ignored (kdis draws its own columns).
- **Only conditional branches + unconditional jumps** are arrow targets — calls (`jal ra`/`bl`/`callq`), returns, and indirect jumps are excluded (same as radare2's linear view).
  The mnemonic is auto-detected per arch (riscv `b*`/`j`, x86 `jcc`/`jmp`/`loop`, arm64 `b`/`b.cond`/`cbz`/`tbz`).
- **Regime-independent** — because it drives gdb's `disassemble` directly, it works the same on a physical earliest-boot address
  or a virtual address after the MMU is on (a 16-digit kernel VA). It keeps working even after the MMU turns the address virtual.
- Options `ascii` (ASCII glyphs for non-UTF terminals), `mono` (color off; also off via `$GDBTOOLS_NO_COLOR`). Color is on by default.

Measured (riscv64 runtime, kernel VA — source and destination horizontal lines aligned to the same length up to the address column):

```
(gdb) cfgdis mono memchr
Dump of assembler code for function memchr
        0xffffffff80e8ffc0  addi    sp,sp,-16
        0xffffffff80e8ffc2  sd      s0,8(sp)
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

> **Mnemonics match the pwndbg window** — gdb/binutils and Capstone (pwndbg) spell some mnemonics differently
> (arm64 conditional branches: binutils `b.cc`/`b.cs` ↔ Capstone `b.lo`/`b.hs`). When rendering, `cfgdis`/`flow`
> **normalize to the Capstone spelling** via `Arch.MNEM_ALIASES`, so the mnemonics match pwndbg's `[ DISASM ]` window exactly.
> It also strips the alias comments binutils adds, like `// b.none` (pwndbg has none), while
> preserving the actual operands, like the `#imm` in `tbz w0, #0x1f, <target>`.

### Automatic context section — `$GDBTOOLS_AUTO` only (`flow` = radare2 arrow window, parallel to pwndbg disasm)

When attached via `$GDBTOOLS_AUTO`, the tool **adds only two sections (`kgdb`·`flow`) to pwndbg** —
**it removes or changes none of pwndbg's defaults.** So **two disasm windows come up side by side, each independent**:

- **`[ DISASM / … / set emulate on ]`** — pwndbg's own window. Fully untouched, so its emulation (`X3 => 4`,
  `CPSR` flags, `✔`/`✘` branch prediction, telescope) and colors are all as-is. Hang-prone spots (`_text` etc.) are handled by
  pwndbg's own section rendering.
- **`[ DISASM + ARROWS ]`** (our `flow`) — a **radare2-style branch-arrow** view. Drawn by the **same
  gdb+python renderer** as `cfgdis` (gdb `disassemble` → exact hex target → `┌│└─┬>` arrows). A separate perspective that does not
  overlap the pwndbg window, and being pure gdb+python it **never hangs or crashes.**

```
[ DISASM / aarch64 / set emulate on ]        [ DISASM + ARROWS ]  (our flow)
 ► 0x…13d8 <memset+24>  cmp x2,#0xf           =>      0x…13d8  cmp   x2, #0xf
   0x…14b0 cmp … CPSR => 0x20000000 [ … C … ] ┌───    0x…13dc  b.hi  0x…1404 <+68>
                                              │┌──    0x…13e0  tbz   w2,#3,0x…13e8
                                              │└┬>    0x…13e8  tbz   w2,#2,0x…13f0
                                              └──>    0x…1404  neg   x4, x8
```

Previously `flow` tried to reuse the pwndbg lines, which (1) made it nearly a carbon copy of the pwndbg window and
(2) failed to draw arrows when pwndbg printed a branch target as a symbol name. Now, being a **standalone renderer**, the two windows
split cleanly: pwndbg = rich annotation, ours = arrows.

> **arm64-v4.6 note (SIGABRT guard)**: pwndbg's *own* disasm window can emulation (Unicorn) segfault on some instructions of this EOL kernel
> (a pwndbg-specific bug, unrelated to this tool). The canonical case is the **secondary-CPU earliest stop** —
> at `b __secondary_switched` (`head.S:722`, with `sp`/`x29` not yet initialized), pwndbg emulates forward from that point and faults,
> so **the gdb process itself dies of SIGABRT (core dumped)**
> (what prints under `----- Backtrace -----` is not the kernel but gdb's crash dump). Being a native segfault, a Python exception cannot catch it
> (if the first stop crashes immediately there is no time to react — a spot like `cpu_do_idle` right after attach).
> So the tool, at its **default `auto`**, runs its stop hook **before** pwndbg's context render on an arm64 attach
> and turns `emulate` off automatically to block the crash at the source (with a one-line notice), restoring it on
> `kearly off`/`saferender off` — i.e. **it does not die, with no extra action.** To keep emulation, use `kearly saferender off` (restore immediately)
> or `warn` (warn only, setting unchanged). Our `flow` (a separate gdb+python arrow window) does not break on any kernel.
> A plain `gdb vmlinux` does not touch pwndbg and leaves only the manual `cfgdis`.

> **shadow breakpoints (`kearly bpfix`, default off)**: as a side effect of laying a shadow symbol table on physical addresses for MMU-off symbolization,
> a name breakpoint like `b start_kernel` gets set at **two locations, physical (0x40c365f0) + virtual
> (0xffff000008c365f0)** (the prompt shows physical as primary). But since **QEMU's SW breakpoint matches on the virtual PC**,
> an MMU-on symbol **fires the virtual location on its own** when you `continue` (measured:
> `b start_kernel; c` → `Breakpoint 2.2, start_kernel` clean hit). That is, **it catches with the native dual breakpoint alone; `bpfix` is not required.**
>
> `bpfix on` is for optional tidying: it **always keeps the virtual location on** (the one MMU-on code fires) and turns off only the physical location
> that sleeps while MMU-on. It never turns off the virtual location (an early version turned the virtual location off in MMU-off and regressed
> `b start_kernel` into not catching — fixed). It is off by default because the native dual already catches.

> **KASLR debugging (physical crossing anchor)**: with KASLR on, the gdb symbols (link VA) ≠ the runtime VA (link+slide),
> so `b SYM` does not catch. The slide is only fixed after relocation (each arch's early asm), but **in a cold frozen boot there is no
> natural stopping point between relocation and start_kernel** (chicken/egg). So it uses a slide-independent **physical
> crossing anchor**: right after relocation and before start_kernel, it sets a HW breakpoint on the "physical→high-VA
> transition instruction" that executes while the MMU is on with idmap/physical (that address is VA==PA, so it fires without the slide).
> From the transition registers it reads the runtime VA of the landing symbol and fixes `slide = runtimeVA − linkVA`.
>
> | arch | crossing anchor | slide acquisition |
> |---|---|---|
> | arm64 6.12 | `br x8` in `__primary_switch` → `__primary_switched` | `x8 − linkVA(__primary_switched)` |
> | arm64 4.6 | `br x27` in `__enable_mmu` → `__mmap_switched` | `x27 − linkVA(__mmap_switched)` (= x23) |
> | riscv 6.12 | entry of `relocate_enable_mmu` (after setup_vm, MMU-off) | `kernel_map.virt_addr − linkVA(_start)` |
> | x86 6.12 | `jmp *0f` in `startup_64` (after loading CR3) → `common_startup_64` | after stepi, `$pc − linkVA(common_startup_64)` |
>
> The crossing instruction is found by opcode-scanning the function's physical bytes (arm64 `br xN`=`0xD61F0000|N<<5`, stopping at `ret`) or by
> disasm (x86 `jmp *..(%rip)` — both AT&T and Intel syntax) → no per-version address hardcoding. Even under nokaslr the register
> holds the link VA and it lands exactly with slide=0.
>
> **`kearly kaslr auto`** (recommended): after bootbreak it advances to the crossing, reads the slide, and
> relocates every symbol to its runtime VA via `symbol-file -o`. It stops **before start_kernel**, so a following
> `b start_kernel; continue` catches. Measured (direct boot, snapshot): arm64 6.12 `0x4de1aec00000`, arm64 4.6
> `0x2c4cf5c00000`, riscv 6.12 `0x38c00000` — all cross-validated with the **crossing-register value == the kimage_voffset/kernel_map independent
> detection value**, and a clean start_kernel hit. You can also apply an explicit slide with `kearly kaslr <hex>`.
>
> **x86 KASLR — recovering the decompressor physical base**: on x86, physical KASLR places the kernel at a **random physical
> address** in the bzImage decompressor (arm64/riscv have a fixed physical load → the physical anchor is always valid). So in a cold frozen boot
> the load PA of `startup_64` is not known in advance, and `--kaslr` on x86 first recovers that random base using the **decompressor**
> as the anchor (the decompressor loads at the fixed `0x100000` regardless of KASLR):
>
> 1. HW breakpoint at the decompressor entry (`0x100000`) → 2. read `%rax` at the self-relocation `jmp *%rax` in `startup_64` to get the
> moved base `rbx` (= `%rax − IMM`) → 3. `finish` at `extract_kernel` (rbx+off) → `%rax` = the decompressed main-kernel physical
> entry point (= the random KASLR base). With that base as the entry, the crossing anchor above then fixes the virtual slide.
> The offset is derived version-independently by reading `arch/x86/boot/compressed/vmlinux` with `nm`/`objdump` (auto-generated at build time;
> falls back to `--entry-pa` if absent). Measured: it recovers a different random base each boot (`0x52600000`, `0x28a00000`, `0x0ca00000`
> …) every time, the slide (`0x25600000`, `0x27400000` …) cross-validates, and start_kernel hits cleanly. On x86 QEMU is run under TCG for
> deterministic earliest-boot HW breakpoints.
>
> Note: MMU-off/idmap head.S and pi code just catch at physical/idmap addresses **without relocation** (`kb`'s PA location) —
> only the code after start_kernel, running at the relocated high VA, needs relocation.

---

## 10. `kw` — regime-aware watchpoint

The same problem as breakpoints exists on the **data side**. head.S writes `__bss`·the boot arguments·`kernel_map`·the page tables it
builds **by physical address**, and the code after high-VA running uses the same globals by `linkVA+slide`.
gdb's `watch SYM` watches **only the single address the symbol pointed at the moment you typed it**, so it blinds the far side of the crossing.
`kw`, like `kb`, sets both `PA(S)` and `IMG(S)`, and auto-re-arms IMG once the slide is fixed.

```
# armed while MMU off (head.S entry), with the slide still unknown
(gdb) kw kimage_voffset
[kgdb] kw 'kimage_voffset'  linkVA=0xffff800082148000  watch  8-byte
        watch @ 0x0000000042348000  PA  MMU-off/idmap  (head.S data writes, page tables)  [wp 2]
        watch @ 0xffff800082148000  IMG high kernel map (start_kernel & steady state)  [wp 3]
        (IMG auto-re-arms to linkVA+slide the moment the KASLR slide is known)

(gdb) kearly kaslr auto
[kgdb] KASLR slide = 0x253005a00000 applied: ...

(gdb) info watchpoints          # IMG has moved to linkVA+slide
2       hw watchpoint  keep y   *(unsigned long long *)0x42348000
5       hw watchpoint  keep y   *(unsigned long long *)0xffffa53087b48000

(gdb) continue                  # fires on a write to the relocated VA side
Thread 1 hit Hardware watchpoint 5: *(unsigned long long *)0xffffa53087b48000
Old value = 0x0
New value = 0xffffa53045800000
__primary_switched () at arch/arm64/kernel/head.S:234
```

The PA side fires symmetrically too — after `kw boot_args`, `continue` catches at `preserve_boot_args` (head.S:174) while the MMU is
still off, catching the store of the DTB pointer QEMU handed over exactly.

```
Thread 1 hit Hardware watchpoint 3: *(unsigned long long *)0x43a56000
Old value = 0x0
New value = 0x48000000
preserve_boot_args () at arch/arm64/kernel/head.S:174
[kgdb] MMU=off [ctrl-reg]  map=physical  pc=0x0000000042bca710  SCTLR_EL1.M=0
```

`-r` (rwatch)·`-a` (awatch) and `kw *ADDR [SIZE]` (SIZE ∈ {1,2,4,8}) work the same way.
It **consumes 2 HW watchpoint slots per item**. A real arm64 core usually has only 4, so two entries already saturate it,
but QEMU TCG is more generous (three `kw` = 6 watchpoints all armed, measured). Either way, filling
slots is not itself the goal, so set only where needed; if arming fails, `kw` explicitly reports that it
armed nothing.

---

## 10.2 The KASLR field of the status panel

The `KASLR=` field of the pwndbg `kgdb` section (and `kearly where`) shows **a number whenever the value is knowable**,
because that is the reason to look at the panel — a slide of 0 is not "absent", it is information.

```
KASLR=0x4ca043800000                  KASLR on, the value fixed at the crossing
KASLR=0  (KASLR disabled)              nokaslr -- fixed from the reset vector on
KASLR=? (undecided until the crossing -- still physical, MMU off)
```

The `nokaslr` decision is read from the DTB's `/chosen/bootargs`. Since QEMU passes the cmdline to arm64·riscv by that path,
it can answer even at the reset vector, before the kernel has parsed anything (x86 has no DTB, so it is fixed only after
`start_kernel`). The kernel global (`saved_command_line`) is a fallback.

With KASLR on and before the crossing it is `?`. At that point the slide **exists nowhere**,
so instead of inventing a 0 it says what it is waiting for.

## 10.3 If the regime does not match it does not answer, it says why

The worst outcome is **a quietly wrong answer** when a command that assumes one address scheme runs in the other regime.
That actually happened — in head.S before the MMU is on, `kv2p $pc` assumed `$pc` was virtual even though it was physical
and returned a plausible, meaningless value like `0x0000800000400000`. Now it refuses and says why.

```
(gdb) kv2p $pc
[kgdb] kv2p: 0x0000000040200000 is not a kernel virtual address -- it looks PHYSICAL.
      Right now: MMU off, so addresses here are PHYSICAL.
      Use `kp2v` for this direction, or `sym` which accepts either.
```

The refusal text says the same three things everywhere: **what the command assumed / what the actual state is right now /
what to use instead**. The middle line is supplied by `Session.regime_phrase()`, so the wording does not diverge.

Others fixed for the same reason:

- `kp2v` refuses an already-virtual address (with guidance for the other direction).
- `kfin` **does not advance the CPU** at an entry point where the link register is 0. It used to run off to address 0
  and blow away the guest, after which every command failed with "target is running".
- `stackscan` reports, instead of "no symbolizable pointers", the fact that `$sp` is still 0 and that arm64 head.S
  only sets up sp at `adrp x1, early_init_stack` in `__primary_switch`.

The remaining commands already state their reason — confirmed by a census: `kpt` says "paging is off",
`kpgd`/`kpthex` "cannot read the page-table base (paging off / stub)", `ksr` shows how to get a register the stub cannot provide
with a single `mrs` step, and `koff`/`mmview`/`kearly mmu` print the current regime in their header.

## 10.35 `kearly safemem` — stop a pwndbg probe from killing QEMU

**Symptom.** On a KASLR kernel, after stopping in a syscall-path function like `vfs_write`, when pwndbg draws the context,
**QEMU dies of SIGSEGV** and gdb aborts after it. The reproduction rate was 100% (4/4, 3/3, 3/3).

**Cause.** pwndbg has no `/proc/<pid>/maps` for a kernel target, so it **estimates the memory map by probing** —
a 1-byte read at page-aligned addresses, about 170 per render. Most fail quietly. But at that moment the context is a user
process's syscall context, so TTBR0 points at that process's page tables, and when a probe address translates outside RAM,
QEMU dispatches into a device model and dies. The core stack says it plainly:

```
gdb_read_byte -> cpu_memory_rw_debug -> flatview_read_continue
              -> memory_region_dispatch_read -> SEGV
```

**Attribution.** It is not this tool. It died with only pwndbg loaded and this plugin **not loaded**, and conversely
stock gdb (`-nx`) was fine under the same conditions. Three conditions (KASLR + syscall context + a full context render)
must coincide; with any one missing it does not happen — not with `nokaslr`, not if you only break and do not draw the
context, and not in the head.S region.

**Handling.** It wraps the single path every pwndbg read goes through (`read` in `pwndbg/aglib/memory.py`).
Before a read, it asks `monitor gva2gpa` whether that page is mapped, and if `Unmapped` it does not ask QEMU and returns
**the ordinary read failure pwndbg already knows how to handle**. `gva2gpa` is safe on any input —
it returns `Unmapped` normally even for the very address that caused the crash.

```
kearly safemem status      installed / number of probes blocked / number of reads rescued via monitor (rescued)
kearly safemem on|off|auto (default auto: only when kernel target + translation active)
```

It does not modify pwndbg. It wraps the lowest single path (the gdb backend's `GDBProcess.read_memory`) —
the register enhancer, telescope, and stack dumps all come down below this, so there is no path that leaks lower than it.
It keeps the original read and filters only dangerous addresses, and passes through when it cannot decide. It caches per page
and clears at every stop.

The root defect is in QEMU. No matter what address you ask about, a debug read should not die of SEGV. What is done here is
**avoiding triggering it**, not fixing it. A regression is caught by the crash-guard test.

### Keep pwndbg's own polished TUI even in early boot (two reinforcements)

**(1) Remove the pagescan warning spam.** pwndbg's `auto-explore-pages`, on a kernel target (no map),
pours out dozens of lines of `Avoided exploring ... / Likely a pagescan bug, please report` while telescoping junk register values
at each stop, burying the register telescope. This plugin, while active on a kernel target, keeps this value at `no` (checking at each stop)
and **restores it to the user's previous value** on `kearly off`. Measured: at the `__enable_mmu` (MMU off, physical) stop of arm64
v6.12 KASLR, the register telescope and colors are **completely identical** whether it is on or off, and the only difference is the
presence or absence of about 11 warning lines per stop. It does not touch the actual display features like telescope /
dereference / symbolization — it turns off only the one noise-producing heuristic.

**(2) Read rescue — regime-independent.** When CPUs are simultaneously in different translation regimes
(a secondary core is in `__enable_mmu` physical code while another core runs the kernel MMU-on, or a **normal virtual stop** in a riscv SMP
where a sibling hart is booting), the QEMU gdbstub cannot service that read and gdb's `Inferior.read_memory` fails with `MemoryError` —
even though the CPU is executing right there. Then the pwndbg telescope loses its arrows and the native DISASM prints `Invalid address`.
Meanwhile HMP `monitor xp` is a physical path independent of any core's regime, so it **still reads**. When a live read fails,
the safemem guard converts the failed address to a physical address and rescues it via `monitor xp`:

* a physical (low) address is used as-is,
* a virtual address is translated via the guest page tables (`monitor gva2gpa`), but **relative to the page tables of the core executing at that
  stop (= the hart of the thread gdb selected)**. HMP `gva2gpa` uses the HMP-current core by default, but on riscv the **boot hart is random each
  boot**, so the default core (cpu 0) is sometimes a Bare (MMU off) secondary hart, and then gva2gpa **returns the input VA unchanged**
  (identity, not translation). So it first aligns with `monitor cpu <selected core>`, rejects an identity or still-high-VA response, and if
  necessary sweeps the cores to get the real physical address. For a VA not yet mapped on any core (e.g. before the high map is built), it does
  not give a false PA and simply declines.

It reads only when that physical target is **actual guest RAM**. Whether it is RAM it **asks QEMU directly** rather than using a hardcoded
window — `monitor gpa2hva` answers `Host virtual address ... (pc.ram) is 0x..` for RAM, `is not RAM` for a device, and
`No memory is mapped` for an empty spot, so it never touches a device model (with an old QEMU that lacks the command, it falls back to the
per-arch `phys_window` preset). Measured: at the arm64 secondary `__enable_mmu` stop, the whole `context` — even with hundreds of rescues —
brings telescope, colors, and DISASM all back **within 0.1s**, and riscv's three `Invalid address` (sibling-hart timing dependent) also close to
zero. The rescue count is `rescued` in `kearly safemem status`. The original crash path (an **unmapped** junk pointer at a virtual stop) is
caught first by the upper zero-fill guard, so it never reaches rescue, and `crashguard` still passes (verified on arm64·x86·riscv). This rescue is
**architecture-independent** and does nothing when the live read works to begin with — it fires only where needed.

> Correction (fixed by measurement): I previously wrote "if you stop on an MMU-off secondary core, reading a high virtual address is impossible
> in principle", but **that was wrong.** Measurement shows that in such a simultaneous-regime stop, gdbstub reads are commonly routed through the
> context of another core that is MMU-on, so a kernel high VA (`vfs_write` etc.) reads fine even with stock gdb (what actually failed was the
> secondary core's **physical pc**), and even if the read is routed to the secondary core and the high VA fails, the rescue's `gva2gpa` translates
> relative to the **HMP-reference core (usually the MMU-on CPU0)** and rescues it. A kernel high VA is in every core's high mapping after boot, so
> it always translates. The one case that truly cannot be read is the earliest boot where **no core has that mapping yet** (before the high map is
> built), and that declines correctly because the mapping really is absent. So whether routed physical or virtual, the rescue covers it.
>
> Core (thread) switching holds too: the regime decision is made from the **currently selected thread's pc/registers**, so switching cores with
> `thread N` automatically changes the KGDB panel·telescope to that core's execution context (MMU on/off, physical/virtual). Measured: in one stop
> the secondary (MMU off) is `PHYS` and the primary core (MMU on) is `VIRT`, both with a full telescope render.

### Cross-regime register twin (in a physical stop, show the physical twin of a VA alongside)

When stopped in a physical/transition regime, some register may hold a **kernel virtual address that is not yet reachable**.
A representative example: `x8 = __primary_switched` at the phys->virt transition moment (arm64 `br x8`) — the high map is not yet
active on this core, so that VA is not accessible right now. The KGDB panel **leaves pwndbg's native REGISTERS as-is** and,
in the tool's own panel, shows the **now-reachable physical twin** of that VA alongside:

```
 cross-regime regs (VA -> reachable PA twin):
   x5   0xffffa9f7289bd000  ->  PA 0x0000000042bbd000
   x8   0xffffa9f7289ca730  (__primary_switched)  ->  PA 0x0000000042bca730
```

It does VA->PA one direction only — `_is_va` (all top bits 1) is an unambiguous decision, so it does not mistake a control/ID register
holding a large value (`PMCR_EL0`, `ID_MMFR1`, `cpsr` etc.) for a pointer. Only a twin that falls inside the physical window is shown,
so it prints no stray address even at a moment when the KASLR slide is undetermined, and when there is no physical twin or it is a **virtual stop
(the address is already virtual-correct)** this line does not appear at all and stays quiet. Measured (3 arches): arm64 `x8->PA` shown, riscv
the same, x86 quiet because its transition is `jmp *ptr` and no VA is held in a register (normal). In the all-in-one walk it keeps the window
complete with 0 errors.

### Keep kernel-version detection from killing `context` (`install_kernel_guards`)

**Symptom.** Right after attaching, stopping at the **earliest start_kernel (init/main.c:915)** with `b start_kernel; c` and then drawing the
context gives `Exception occurred: context: Linux version tuple not found`, and **the whole context is not drawn.**
Yet at `vfs_write`·`ip_local_out` a little further along it is fine. Being intermittent makes it more confusing.

**Cause.** In the context, pwndbg tries to learn the kernel version by reading `linux_banner` (a .rodata string) and parsing it with
`krelease()`. `krelease()` **throws an exception rather than returning None** (pwndbg code) when `kversion()` gives a **non-empty**
string that is not `Linux version X.Y`. At the moment the high virtual map has just come up, the banner read is still unstable and may return
a short piece of garbage, and then the exception aborts the whole context. Since `krelease` is `cache_until("start")`, it is recomputed on every
`continue`, so once userspace is up the banner reads cleanly and it returns to normal — which is why it looks like "only at start_kernel,
sometimes". **Unrelated to multicore** (CPU0 alone at that moment).

**Handling.** It wraps `krelease()` (and `kversion()`) to **return None instead of an exception on failure**. Not yet being able to read the
version is an "unknown (None)" situation, not a fatal error, and pwndbg's own callers already treat `krelease() is None` as "version unknown".
So even if the banner cannot be read, **the context is drawn to the end**. In the normal case where the banner reads, it returns the real version
tuple as-is, so nothing is lost. It does not touch the display features. Definitive check: forcing kversion to garbage at start_kernel, the original
`krelease` throws (reproduced), and the wrapped one returns None with `context` rendered to the end.

> Honest limitation: the instability of the earliest-boot banner read itself (gdbstub/early-mapping timing) is avoided (guarded), not fixed at the
> root. In this case pwndbg does not learn the kernel version (= None), but there is no impact on the context or on early-boot debugging.

## 10.4 `kearly where` — "what is my situation right now" as a one-line command

To take stock at the spot you stopped, you used to have to type four separate commands: `kearly status` (calibration),
`kearly mmu` (MMU), `sym $pc` (where you are), `kearly kaslr status` (slide). The values themselves were already
rendered in the pwndbg panel at every stop; what was missing was **a way to ask**.

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

`twin` is the opposite-side address of the current pc (physical↔virtual). `phase` says whether you are before the reset vector,
at the kernel entry point, past the entry but still physical, or after the virtual scheme is up. `next` is the command you are most
likely to type next in the current situation.

**It is read-only.** It writes no register, sets no probe, and resumes no CPU. So it is safe to type in any regime.

## 10.5 `kearly regimes` — this build's MMU stop points

To know "where exactly the MMU is turned on in this kernel", you used to have to disassemble vmlinux outside gdb and count offsets.
Now the tool scans the running image and answers directly — with not a single per-version constant.

```
(gdb) kearly regimes
[kgdb] early-boot MMU regimes for this build
  entry     PHYS   link 0xffff800080000000  PA 0x0000000040200000
            kernel entry, MMU off, PC physical  -- _text
  mmuon     PHYS   link 0xffff8000829b84a8  PA 0x0000000042bb84a8
            translation turned on, PC still physical  -- __enable_mmu+0x30: msr sctlr_el1, x0  (M=1 turns the MMU on)
  crossing  PHYS   link 0xffff8000829b8518  PA 0x0000000042bb8518
            the phys->high-VA transfer instruction  -- __primary_switch: br -> __primary_switched
  virtual   VIRT   link 0xffff8000829ca730  PA 0x0000000042bca730
            first instruction at a true high VA  -- landing of the transfer (__primary_switched)
  start     VIRT   link 0xffff8000829c0bd8  PA 0x0000000042bc0bd8
            start_kernel, steady state  -- start_kernel
```

`mmuon` is found by the new architecture hook `find_mmu_enable` via an **opcode scan**: arm64 is
`msr sctlr_el1, xN` (0xD5181000 | Rt), riscv is `csrw satp` (0x18001073 | rs1<<15), x86 is
`mov %rXX,%cr3` (0f 22 d?). It is found without knowing the register number or the kernel version.

`kearly regimes walk` arms all five points, so afterwards simply repeating `continue` passes the MMU transitions in order.
Measured (arm64 6.12):

```
0x42bb84a8  ->  0x42bb8518  ->  0xffffa33cc9fca730  ->  0xffffa33cc9fc0bd8
  msr sctlr      br x8            __primary_switched      start_kernel+8
```

**It uses exactly 1 HW slot per stop point.** head.S code never executes at the high-VA map and `start_kernel` never executes physically,
so this command, knowing each point's regime, arms only one of each twin (`kb`'s new `sides` argument). Arming both would use 8 slots for
5 points, three of which would be positions that never match.

riscv shows only four points. One `csrw satp` is both "the instruction that turns translation on" and "the physical→virtual transition
instruction", so the two entries merge into the same address — it does not make a nonexistent stop point look like it exists.

`kearly regimes stop <id>` runs straight to one point.

## 10.6 `kx` — physical memory examine that bypasses translation

`x` always interprets an address **through the current page tables**. So in the instant when "the PC is a physical value but translation
is already on", it cannot read even the spot it stopped at.

riscv creates exactly that spot. The fetch after `csrw satp, a0` in `relocate_enable_mmu` is designed to trap immediately and land at
`stvec` (a virtual address). Stopping at that boundary, `$pc` is the physical value `0x80201048`, but that value is not a valid VA in the new
mapping:

```
(gdb) printf "%#lx\n", $pc
0x80201048
(gdb) x/16xb $pc
0x80201048 <_start+4168>:	Cannot access memory at address 0x80201048
(gdb) kx/16xb $pc
0x0000000080201048:	0x17 0x05 0x00 0x00 0x13 0x05 0x45 0x07 0x73 0x10 0x55 0x10 0x97 0xc1 0x57 0x02
```

The 16 bytes read match exactly the contents of vmlinux's `0xffffffff80001048`
(`auipc a0,0x0` / `addi a0,a0,116` / `csrw stvec,a0` / `auipc gp,0x257c`).

`kx` puts QEMU HMP's `xp` (examine physical) through the gdbstub monitor path to skip translation entirely.
It is the same path that lets the page-table walkers (`kpt` / `kpthex`) read table pages even after the MMU is on;
this time that path is exposed as a user command.

Stopped at that spot, the tool tells you first — because a feature with no discoverability might as well not exist:

```
[kgdb] note: $pc 0x0000000080201048 is physical and translation is on, so `x` cannot read it.
       Use `kx/16xb $pc` (physical examine) or `cfgdis` here.
```

The decision is made not by guessing but by **actually trying the command the user would type** (whether `x/1xb $pc` fails).
At the idmap stop on arm64·x86, VA==PA so `x` works fine and this line does not appear.

Note the memory itself is read from the target — gdb's Python `read_memory` returns the correct bytes at the same address.
What refuses is the `x` command that tries to translate through the current page tables.

The syntax follows `x` exactly — `kx/16xb $pc`, `kx/8gx 0x40200000`. The default is `/16xb`.
If the argument is a kernel VA, it converts it to a physical address, reads, and prints that conversion too, so `kx $pc` is correct in any
regime. It does not touch gdb's `x`.

---

## 11. The crossing catcher — "it catches wherever you set it"

On a KASLR-on cold frozen boot, setting `b start_kernel` at the head.S entry used to **quietly miss**.
At that point the kernel has not yet computed its own virtual base, so the only address gdb can arm is the link VA, and the
relocated kernel never executes that address. Without a stop or a diagnostic, the guest boots all the way to the login prompt.
It was a problem reproduced independently on all four trees.

Now, **if you set a breakpoint/watchpoint aimed at a high VA while the slide is unknown**, the tool automatically arms a catcher on that arch's
physical→high-VA crossing. The moment execution reaches the crossing it reads the slide, relocates the symbols, and the catcher retires itself.
The user types no further command.

```
(gdb) b start_kernel
Breakpoint 5 at 0x42bc0bd8: start_kernel. (2 locations)
[kgdb] kaslr: that breakpoint targets a high VA but the slide is still unknown -- armed a silent
       catcher on the MMU-crossing (phys 0x42bb8518); the slide is read and applied in passing,
       without stopping.
(gdb) continue
[kgdb] KASLR slide = 0x3de518400000 applied: all symbols relocated to runtime VAs
Thread 1 hit Breakpoint 5.2, start_kernel () at init/main.c:915
915	{
```

arm64 · riscv64 · x86_64 all pass **without stopping (silently)** — because the crossing landing address is obtained by a **physical read only**,
from a register (arm64 `x8`/`x27`), a global (`kernel_map.virt_addr`), or an indirect-jump slot (the target qword of x86's `jmp *0f(%rip)`),
so it does not move the CPU.

It does not collapse even if a user breakpoint/watchpoint fires **before** the crossing. In that case the catcher stays persistent,
respecting the user's stop, and applies later when execution reaches the crossing:

```
Thread 1 hit Hardware watchpoint 2: *(unsigned long long *)0x43a56000
preserve_boot_args () at arch/arm64/kernel/head.S:174
[kgdb] kaslr: another breakpoint stopped first (pc=0x42bca710) -- left a PERSISTENT catcher [bp 5]
       on the crossing (phys 0x42bb8518).  Keep debugging: the slide is read and applied
       automatically the moment execution reaches it.
```

### x86_64 has one more layer

x86 randomizes even the physical load address (arm64/riscv only the virtual), so at the cold frozen point the main kernel is not even in RAM
yet. The tool sees that `$pc` is below the decompressor load address (`0x100000`), i.e. at the reset vector, confirms the cold frozen state,
and first recovers the random physical base via the decompressor chain. **No environment variable or flag is needed.**

```
[kgdb] x86 KASLR: extract_kernel reached; decompressing kernel (finish) ...
[kgdb] x86 KASLR: recovered main-kernel phys base 0x0000000039e00000 via the decompressor
[kgdb] KASLR slide = 0x13e00000 applied
Thread 1 hit Breakpoint 5.2, start_kernel () at init/main.c:915
```

### Measured (4 trees, KASLR on, armed at R0)

Cross-validated **independently of the tool** using the difference between the ELF link value (`nm vmlinux`) and the live landing address.

| tree | auto-applied slide | live `start_kernel` − ELF link value | match |
|---|---|---|---|
| arm64-v6.12 | `0x3de518400000` | `0x3de518400000` | ✓ |
| arm64-v4.6 (EOL) | `0x192229c00000` | `0x192229c00000` | ✓ |
| riscv64-v6.12 | `0x1fe00000` | `0x1fe00000` | ✓ |
| x86_64-v6.12 | `0x3e00000` | `0x3e00000` | ✓ |

### What the exhaustive combination sweep revealed (2026-07-19)

Sweeping arm-time (reset vector / MMU-off entry / mid head.S / half-enabled / on the crossing / fully virtual) ×
probe kind (`b` / `kb` / `watch` / `kw` / `b *ADDR` / `b FILE:LINE` / `hbreak` / `kw -r` / `kw -a`) ×
target regime × KASLR on/off across four trees revealed that **the catcher initially worked only for the `b SYM` form**.
The cause was deciding "does this probe aim at a high VA" by parsing the `N.M  y  0xADDR` line of a multi-location breakpoint —
a watchpoint has no address column at all, and a single-location `b *ADDR` has no such line, so both quietly dropped out of the decision.
Now it makes no such distinction and **arms the catcher regardless of probe kind whenever the slide is unknown**
(using one breakpoint that retires itself at the crossing).

Also fixed in the same sweep:

- deleting the catcher with `delete` left a `_kaslr_pending` record that **permanently blocked** any later re-arm. It now checks
  whether the catcher breakpoint survives, and if it is gone, discards the record and re-arms.
- setting a probe while already standing on the crossing PA returned early, so the slide was never applied. It now reads and applies
  right there.
- a probe set at the reset vector (before the kernel entry, uncalibrated) now gets a catcher too (it tries calibration first).
- **x86 intermittent defect**: calibration/shadow created during the decompressor stage lingered and polluted the calculation after
  recovering the random base (the offset came out relative to the nokaslr default `0x1000000`). It reproduced about 1 in 3–4 runs.
  On recovering the base it now clears the offset·slide·shadow·pending and re-fixes them all.

A literal address means "exactly this address", so the tool **moving** it would betray the user's instruction.
So the literal is left in place and a regime-aware sibling location is set **alongside** it (§11.5).

### What the regime cross-validation revealed (2026-07-20)

The previous sweep swept the arm *time*, but the target was almost always `start_kernel` — a symbol that only executes after the
virtual address scheme is fully up. This time the target side was moved into head.S, **crossing** the five regimes taken from each tree's
vmlinux (MMU off / idmap / the transition instruction itself / the first virtual instruction / start_kernel) against each other.
The decision uses an oracle the tool is not involved in: it reads guest memory at the stopped `$pc` and compares against the bytes
`objdump` extracted from the ELF.

Found and fixed:

- **a deleted probe came back to life.** The group created by `kb` / `kw` / adopt stayed on the books after `delete`, and the moment the
  slide was fixed at the crossing, `_rearm_kb` **re-created it** at `linkVA + slide`.
  On arm64 v4.6, `kb __mmap_switched; continue; delete; kb start_kernel; continue` was found to stop not at start_kernel but at the deleted
  `__mmap_switched`. Now, when all breakpoints a group owns are gone, the group is discarded too. It also tidies up the sibling breakpoints
  attached to a user's `b`, but since touching a breakpoint inside gdb's delete callback kills gdb, it defers to the next safe point.
- **a single-location probe got no sibling.** `_bp_locations` parsed only the multi-location row (`N.M  y  0xADDR`), so it always returned an
  empty list for single-location probes like `b *0xLINKVA` / `b FILE:LINE`, and adopt returned early ahead of that. It now recognizes both forms.
- **on x86, adopt did not engage at all.** `phys_window` was pinned to `0x100000..0x10000000` (1MB~256MB), but x86 KASLR randomizes even the
  **physical** base — the measured boots came up at `0x52a00000`, `0x7ba00000`. arm64·riscv fix the physical base via QEMU `-kernel` so the narrow
  window fits, but x86 does not. The window was widened, and adopt now asks "is this address inside the kernel image" directly against
  `_text`..`_end`.
- **at the riscv trap boundary the standing spot could not be read.** The fetch after `csrw satp` is designed to fault, and QEMU stops **at the
  faulting fetch, before the trap is delivered**. So `$pc` is a physical value that is not a valid VA in the new mapping, and `x` fails. This state
  cannot be removed — it is a real machine state — so instead `kx` was made to view memory there (§10.6).

### 11.5 Literal link address — not moved, set alongside

Analyzing head.S by reading it with `objdump`, what catches the eye is the **link address**. Typing it directly is the most natural action:

```
(gdb) b *0xffff8000829b80a8
Breakpoint 2 at 0xffff8000829b80a8
[kgdb] note: 0xffff8000829b80a8 is a LINK address and this kernel is KASLR-relocated, so that
       exact byte will not be executed once the slide is known.  Its physical twin has been
       armed alongside, so a probe here still fires while the MMU is off.

(gdb) info breakpoints
2   breakpoint     keep y   0xffff8000829b80a8 <primary_entry+8>
3   hw breakpoint  keep y   0x0000000042bb80a8 <primary_entry+8>      <- the added sibling
```

The literal the user typed (#2) stays in place. A physical twin (#3) is attached alongside, and once the slide is fixed at the crossing
the IMG sibling is re-armed at `linkVA + slide`. Measured: a physical-regime target fires #3, and a virtual-regime target like `start_kernel`
fires the re-armed IMG sibling.

The slot cost is at most 2 per literal, the same as `kb`. A `b SYM` that already has two locations (multi-location thanks to the shadow) has
its candidates already covered, so it **adds nothing**.

### Why the catcher is an internal breakpoint

The catcher is set as a gdb **internal breakpoint**. It does not appear in `info breakpoints`, and above all **`delete` cannot remove it**.
Even if the user deletes all their breakpoints, sets only a watchpoint, and continues, the slide is still applied.

This structure is needed because of a gdb internal constraint. gdb's `watch_command_1` asserts, while creating a watchpoint, that the end of
the breakpoint chain must be that watchpoint. So **creating a breakpoint inside a watchpoint-creation event kills gdb with an internal-error and
dumps core** — regardless of the method (CLI or Python API), it is a matter of timing. Conversely, during an ordinary breakpoint creation it is
safe.

So the arming rule is this:

- if the probe being created is a **watchpoint, do not arm** (only record the request). Creating one there kills gdb.
- otherwise, create the internal catcher there.
- also handle a pending request at safe points like calibration, the stop hook, and the gdb prompt.

In the normal flow the catcher is already set at `kearly bootbreak`'s calibration, so it is ready whatever the user sets first. That is why
setting a watchpoint first is not a problem.

### Why the validation is not circular

Checking against `expected = link value + slide` is **an identity, not a measurement** — the breakpoint fires at the address it was armed at,
so "observed == expected" holds even if the slide is wrong. Two witnesses outside the tool are needed.

1. **The guest memory bytes at the stop point match the ELF original.** If the slide were wrong, there would be different code at that address.
   On arm64-v6.12 / arm64-v4.6 / riscv64 the first 16 bytes of `start_kernel` were confirmed to match the `objdump` value exactly
   (e.g. arm64-v4.6 `fd7bbba9 c0220090 00002491 fd030091`).
2. **An address the kernel printed itself.** x86 prints `Kernel Offset: 0x… from 0xffffffff81000000`, and
   arm64-v4.6·riscv64 print the memory layout in the boot log. On arm64-v6.12 that output was removed upstream, so 1 stands in for it.

### Known limitations

- **riscv needs `--cpu max`.** The default `rv64` model has no Zkr SEED CSR, and the DTB QEMU makes has no
  `/chosen/kaslr-seed`, so the kernel finds no entropy and the slide **is silently 0**. You end up testing a state where nothing is randomized
  while believing KASLR is on, so beware of this case.
- **x86 cannot set kernel symbols before the decompression point.** With `--earliest` (reset vector) or
  `--no-calibrate` attached, if you set a probe like `b start_kernel` / `watch system_state`,
  at that moment only the bzImage decompressor is in memory and the kernel is still compressed data — that symbol's address exists
  nowhere in the machine, so no debugger can set it. Instead of quietly missing, the tool states the reason and the remedy:

  ```
  [kgdb] kaslr: the kernel is still compressed at this point, so there is nothing to
         calibrate against yet -- run `kearly bootbreak` first (it recovers the
         randomized base), then re-arm.
  ```

  Once `kearly bootbreak` recovers the random physical base via the decompressor chain, **a probe you already set follows on its own** —
  no need to set it again. Measured (`--earliest`, x86 KASLR): setting `b start_kernel` at the reset vector creates the breakpoint at the
  link address, and the moment `kearly bootbreak` recovers the base `0x48200000`, gdb re-resolves it into the relocated symbol, it becomes
  `<MULTIPLE>`, and the following `continue` catches at the relocated `0xffffffffaaf4ea60`. That is, it is done in three commands (`b` → `bootbreak` →
  `continue`). The only unavoidable thing is the fact that "it cannot fire while the kernel is not in RAM". arm64·riscv do not have this limitation —
  QEMU loads the whole kernel into RAM with `-kernel`, so the location is known even at the reset vector, and both architectures actually pass this
  case. So it is a physical difference of the architecture, not an implementation gap.

  Automatically running the decompressor recovery was an option, but it was not taken. `--earliest` and
  `--no-calibrate` are an instruction to "not advance the CPU", and the recovery has to run through `extract_kernel`,
  so it would violate that instruction.

- **arm64 6.12's `.idmap.text` region has no source line info.** `primary_entry` / `__enable_mmu` /
  `__primary_switch` — that is, exactly the region where the MMU is "half on". The cause is that the
  `.section ".idmap.text","a"` declaration in `arch/arm64/kernel/head.S` has no execute (`x`) flag, so the assembler generates no DWARF line info
  for that section (`head.o`'s `.rela.debug_line` has no entry for the section at all). Since no build artifact has the info, a debugger cannot
  restore it — follow it with `cfgdis`'s symbol+offset disassembly and `stepi`.
  On arm64 v4.6 the same code is in `.text` so line info is normal (head.S:772/788/811).

- **pwndbg's own `context` can abort gdb at a post-early-boot kernel-thread stop (e.g. `kernel_init`) on some gdb/pwndbg builds.**
  At such a stop, pwndbg's register-context render trips gdb's `inferior_thread` assertion (`current_thread_ != nullptr`) and aborts gdb
  (core dumped). It reproduces with pwndbg alone (this plugin disabled) and with the running thread explicitly selected, so it is an upstream
  pwndbg-vs-gdb issue, not this tool; being a C-level assertion it cannot be caught from Python, so this tool cannot guard it the way it guards
  the QEMU debug-read SEGV or the version-tuple exception. gdbtools' own views (the `kgdb`/`flow` context sections, `kearly where`, `kcensus`,
  `mmview`) and plain gdb (`p`/`x`/`bt`/`info`) all work at those stops. Workaround: narrow pwndbg's sections
  (`set context-sections 'kgdb flow'`) or use the tool's commands there. Measured on mainline v7.2 (gdb 17.2); early boot up to and including
  `start_kernel` renders normally, and the whole memory lifecycle (head.S -> MMU enable -> start_kernel -> setup_arch -> mm_core_init ->
  kmem_cache_init/SLUB -> kernel_init) walks in a single session on arm64, riscv64 and x86_64 with `kb`/`kw` and the tool's own views.

---

## Cross-validation (direct boot, measured)

| architecture | paging | levels | validation |
|---|---|---|---|
| arm64 v4.6 | 4KB/48-bit | 4 | kpt (initial 2MB block · runtime 4KB page both kv2p MATCH), kpgd, mmview, kcensus(88), panel, chaindepth |
| x86_64 v6.12 (LA57) | 5-level | 5 | kpt/mmview 5-level, kernel filter |
| x86_64 v6.12 (`no5lvl`) | 4-level | 4 | kpt PML4→PDPT→PD, kv2p MATCH |
| riscv64 v6.12 | Sv57 | 5 | kpt L4→L1 BLOCK kv2p MATCH, mmview, kcensus(21 CSR) |

All pass without a crash, using pwndbg as a library only (unmodified).

---

## Design principles (summary)

- **pwndbg unmodified** — used as a library only. Works in plain text even without it.
- **physical reads after MMU on** — `monitor xp` (HMP, qRcmd tunnel). gdb `x`/`hexdump` are translated through the PT of that moment and fail.
- **session inviolable** — every gdb call goes through the safe layer and is a no-op on failure. Telescopes, page walks, and enumerators are
  all finite (depth cap / level counter / node·leaf cap), so infinite recursion is impossible.
- **additive only, no removal** — existing commands and behavior are preserved and only features are added.
