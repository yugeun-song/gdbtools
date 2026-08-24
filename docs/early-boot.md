# gdbtools — head.S(부팅 극초기) 커널 디버깅 도구

`gdbtools.py`는 QEMU gdbstub에 붙은 호스트 gdb(+pwndbg) 위에서 동작하는 커스텀
플러그인이다. `source` 대상은 이 파일 하나 그대로이고, 구현은 옆의 `kgdb/` 패키지에 들어 있다
(`runtime` → `physmem` → `pwndbg_glue`/`dtb`/`target` → `arch_*` → `session` → `commands`/`cfgdis`
→ `bootstrap` 순의 의존 그래프; `state`가 헬퍼↔세션 순환을 끊는다). MMU가 켜지기 전 `head.S` 구간에서는 `$pc`·포인터가 **물리주소**라, 가상주소로
링크된 gdb 심볼표로는 아무것도 안 풀린다(`info symbol`·pwndbg `telescope`/`context` 무력화).
이 도구는 런타임에 phys↔virt 오프셋을 **보정(calibration)** 해 물리주소를 다시 심볼로 풀고,
페이지테이블 워크·메모리 레이아웃·레지스터 전수조사 같은 커널 전용 편의 기능을 얹는다.

- pwndbg는 **라이브러리로만** 쓰고 **개조하지 않는다**. pwndbg가 없어도 평문으로 그대로 동작한다.
- arm64 · x86_64 · riscv64 3종, 커널 버전 무관. 모든 명령이 **MMU 꺼진 물리단계부터 런타임까지** 동작한다.
- 어떤 gdb 호출이 실패해도 no-op/None으로 degrade해 **메인 gdb·리모트 세션을 절대 깨지 않는다**.

이 문서의 모든 출력은 QEMU를 실제로 부팅·접속해 **직접 캡처한 실측 텍스트**다(색상코드 제거).

---

## 실행 방법

이 도구는 gdb 안에서 도는 파이썬 확장이다. VM을 띄우는 스크립트나 gdb를 대신
실행해 주는 런처는 여기에 들어 있지 않다. 필요한 것은 `gdbtools.py`를 `source`
하는 것뿐이고, `setup.sh`를 한 번 돌려두면 gdb가 시작할 때 알아서 읽는다.

```bash
# 터미널 1: 프리즈된 VM (-S, gdbstub 대기)
qemu-system-aarch64 -M virt -cpu cortex-a72 -kernel Image -S -gdb tcp::1235 ...

# 터미널 2
aarch64-linux-gnu-gdb vmlinux
(gdb) target remote :1235
(gdb) kearly on
(gdb) kearly bootbreak
(gdb) kearly status
```

매번 치기 싫으면 gdb를 띄우기 전에 `GDBTOOLS_AUTO=1`을 내보내면 된다. 접속
시점에 위 세 줄이 자동으로 돌고, stop hook과 shadow 심볼, MMU 전환 안내가 함께
켜진다. 커널이 아닌 타깃에서는 아무 일도 일어나지 않는다.

머신 정보가 필요한 보드(QEMU가 아닌 실물 등)는 `$GDBTOOLS_PROFILE`로 JSON
프로파일을, `$GDBTOOLS_DTB`로 DTB를 지정한다. 세션 도중에는 `kearly profile
FILE` / `kearly dtb FILE`로도 된다.

**`kearly bootbreak`가 하는 일**

5. **접속 + 엔트리 진행 + 캘리브레이션** — `target remote :PORT` 후 기본으로 `kearly bootbreak`(리셋/펌웨어를
   지나 커널 엔트리까지 진행 + phys↔virt 오프셋 보정) → `kearly status`를 자동 실행.
6. **자동 훅 활성** — `$GDBTOOLS_AUTO`를 세팅해 stop hook·shadow 심볼·MMU on/off 전환 안내가 켜진다
   (plain `gdb vmlinux`에는 절대 자동부착하지 않는다 — 이 신호가 있을 때만).

접속 직후 배너가 전체 명령을 나열한다:

```
[kgdb] early-boot symbolizer loaded (commands: kearly | kp2v | kv2p | sym |
       stackscan | ksr | ksregs | kcensus | kpt | kpgd | koff | mmview/memlayout | kfin | chain | cfgdis | kdtb)
```

**안전 계약** — ① 아무 것도 죽이지 않는다(no pkill/fuser, 떠 있는 VM·세션 불가침). ② 스텁이 없으면
접속을 강행해 gdb를 매달지 않고, 심볼·도구만 로드한 채 **살아있는 인터랙티브 프롬프트로 떨어진다**
(나중에 `target remote :기본포트`를 수동으로 치면 됨). ③ 전역 gdb/pwndbg 설정은 건드리지 않는다.

**주요 옵션**

| 옵션 | 효과 |
|---|---|
| `target remote :PORT` | gdbstub 접속 |
| `-p, --port N` | gdbstub 포트 강제 |
| `--gdb BIN` | gdb 바이너리 강제 |
| `--no-connect` | 심볼·도구만 로드, 접속 안 함 |
| `--no-calibrate` | 접속만, `kearly bootbreak` 생략 |
| `--earliest` (`--raw`) | head.S 앞(리셋 벡터/펌웨어)에 멈춤 — 나중에 `kearly bootbreak`로 진행 |
| `-x, --ex CMD` | 접속 후 임의 gdb 명령 실행(반복 가능) |
| `--preset NAME` | 부팅 조합 프리셋(arm64-uefi, x86-pvh, riscv-uefi …) |
| `--entry-pa` / `--anchor` / `--break-kind` / `--ram-base` / `--scan` | 자동탐지 안 되는 조합 수동 지정 |
| `--profile FILE.json` / `--dtb FILE` | 비-QEMU 보드 머신 기술자 주입 |

> 요약: **프리즈된 VM에 붙어 `kearly bootbreak` 한 줄** 이면, 엔트리 진행부터
> vmlinux+도구 로드, 엔트리까지 진행, 캘리브레이션, 자동 훅까지 끝난다. 그 다음부터 아래 명령들을 친다.

---

## 명령 오버뷰

| 명령 | 한 줄 요약 |
|---|---|
| `kearly bootbreak` | 커널 엔트리까지 진행 + phys↔virt 오프셋 캘리브레이션 ($GDBTOOLS_AUTO 이면 자동 실행) |
| `kearly status` / `kearly mmu` | arch·오프셋·맵·MMU on/off·설정 상태 |
| `kearly overmmu [SYM]` | MMU-enable 경계를 안전하게 통과(가상 랜딩에 임시 bp + continue) |
| `kearly steplock on\|off\|auto` | MMU off 동안 싱글스텝 시 다른 코어 동결(SMP 소음 제거) |
| `kearly saferender warn\|on\|off\|auto` | arm64 pwndbg 에뮬레이션 디스어셈 SIGABRT 가드(`on/auto`=`set emulate off`, `kearly off` 시 복원). **기본 `auto`**가 arm64에서 자동 차단; `off`=즉시 복원, `warn`=경고만 |
| `kearly bpfix <on\|off>` | dual 물리+가상 브레이크 정리(선택): **가상 위치는 항상 켜둠**(MMU-on 코드가 발화), MMU-on일 때 잠자는 물리 위치만 끔. **기본 off** — QEMU SW 브레이크는 가상 PC 매칭이라 네이티브 dual로도 걸림 |
| `kearly kaslr [auto\|off\|status\|<hex>]` | KASLR 슬라이드 자동 감지 후 `symbol-file -o`로 전 심볼을 런타임 VA로 재배치 → `b SYM`이 KASLR에서도 걸림. `auto`: 이미 읽을 수 있으면 전역(`kimage_voffset`/`kernel_map.virt_addr`) 리드, 아니면(콜드 프로즌) **arch별 물리→고VA 크로싱 앵커**까지 진행해 전이 레지스터에서 slide를 읽는다(start_kernel 이전에 정지 → 이어서 `b start_kernel`이 걸림). `$GDBTOOLS_X86_KASLR=1`이면 자동 실행. **CPU를 움직이는 건 `auto`뿐** — 인자 없는 `kearly kaslr`은 usage와 현재 slide만 출력하고 아무것도 재개하지 않는다. `auto`는 이미 크로싱 위에 정지해 있어도 재진입 안전(계속 진행하지 않고 그 자리에서 slide를 읽는다). **대개 직접 칠 필요가 없다** — slide 미상일 때 고VA를 겨냥한 브레이크/워치포인트를 걸면 툴이 크로싱에 캐처를 자동 무장해, `b start_kernel` + `continue`만으로 걸린다(아래 11절) |
| `kb SYM \| *ADDR \| FILE:LINE` | **regime 인지 브레이크(whitelist 없음)**: 심볼을 불변 물리주소 `PA(S)=linkVA+offset`과 런타임 VA `IMG(S)=linkVA+slide` 양쪽에 HW 브레이크로 건다. MMU-off/idmap 실행(head.S·pi·secondary·cpu_resume)은 PA가, 고VA 실행(start_kernel·정상가동 코드)은 IMG가 발화 — 실행 regime이 맞는 쪽만 걸리고 반대편은 사문(死文)이라 안 맞는다. slide가 나중에 알려지면 IMG는 자동 재무장 |
| `kw [-r\|-a] SYM \| *ADDR [SIZE]` | **regime 인지 워치포인트** — `kb`의 데이터판. 커널 전역은 MMU-off/idmap에서는 물리주소로, 고VA 가동 뒤에는 `linkVA+slide`로 접근되므로 `watch SYM` 하나로는 크로싱 반대편이 사각이 된다. `kw`는 `PA(S)`와 `IMG(S)` 양쪽에 HW 워치포인트를 걸고, slide가 확정되면 IMG를 자동 재무장한다. `-r`=rwatch, `-a`=awatch. **HW 슬롯을 2개 소비** — 실기 arm64 코어는 보통 4개뿐이고 QEMU TCG는 더 너그럽다(6개 실측 수용). 슬롯을 채우는 건 목적이 아니므로 필요한 만큼만 걸 것 |
| `kearly census off\|compact\|full` | 아래 `kcensus`를 매 stop 패널에 상주 표시할지 토글 |
| `kearly chaindepth N` | 텔레스코프(체인) 깊이 조절 — 항상 유한·순환감지 |
| `kp2v ADDR` / `kv2p ADDR` | 물리↔가상 변환 |
| `sym ADDR` | 물리·가상 주소 → 커널 심볼 |
| `stackscan [N]` | 스택에서 코드 포인터를 찾아 심볼화(backtrace 죽은 head.S용) |
| `ksr NAME` / `ksregs` | sysreg 1개 / 핵심 sysreg 일괄 덤프(+디코드) |
| **`kcensus`** | **head.S+호출체인이 건드리는 모든 제어/시스템 레지스터**를 값·디코드와 함께 전수 나열 |
| **`kpt [VA] [hex]`** | **하드웨어 페이지테이블 워크** — L0~L3 / PML4~PT / Sv39-57 (`hex`=각 레벨 디스크립터의 raw LE 바이트도 표시) |
| **`kpgd [PA] [N]`** | 최상위(또는 지정) 페이지 디렉토리의 비어있지 않은 엔트리 덤프 |
| **`kpthex [PA] [N\|full]`** | 페이지테이블 엔트리를 **바이트 단위 hex 뷰**로(엔트리별 8바이트 분해; `full`=4KB xxd 덤프). 물리 리드라 MMU on 뒤에도 동작 |
| **`koff [SYM]`** | **왜 런타임 주소 ≠ vmlinux ELF(nm) 값** — MMU on/off를 가르는 CPU 플래그·레지스터·`$pc`를 단서로, ELF값-vs-현재주소 offset 요약 |
| **`mmview` / `memlayout [all\|noidmap]`** | **커널용 vmmap** — 심볼 랜드마크 + 라이브 ptdump |
| `kfin` | CFI 없는 head.S용 `finish` 대체 |
| `chain [ADDR] [N]` | N워드 텔레스코프(물리/가상 인지, 심볼화) |
| **`cfgdis [ascii\|mono] [WHAT]`** | **분기 화살표 디스어셈블** — radare2 `pdf`처럼 화면 안 점프마다 좌측 여백에 중첩 화살표(출발·도착 길이 정렬). arch 자동 판별, 호출 제외, 물리·가상 모두 동작. run-gdb 접속 시 context에 `flow` 섹션 자동 |
| **`kdtb [옵션] [ADDR]`** | **라이브 FDT 전체 덤프** — 헤더·메모리 예약 블록·모든 노드·모든 속성을 DTS 형태로, 잘라내기 없이. 주소는 `initial_boot_params`에서 자동 탐색(MMU 상태별 후보를 순서대로 매직 검사). 옵션: `--header` `--rsv` `--tree` `--path P` `--grep RE` `--hex` `--terse` `--phys` `--save FILE` `--stats`. 외부 도구 없이 gdb 안에서 `dtc -I dtb -O dts`와 같은 결과 |

> 순수 gdb 명령어만 쓰는 버전은 별도 파일 `fdt.gdb`에 있다(`source fdt.gdb` → `fdt` / `fdt-header` / `fdt-rsv` / `fdt-tree`). python도 플러그인도 필요 없으므로 stock gdb에서 그대로 동작한다.

---

## 1. 준비 — `kearly`

### `kearly bootbreak` / `kearly status`

`$GDBTOOLS_AUTO`가 설정되어 있으면 접속 시 `kearly bootbreak`가 돌아 QEMU 리셋/펌웨어를 지나 커널
엔트리까지 진행하고 오프셋을 잡는다. 이후 상태:

```
(gdb) kearly status
[kgdb] arch=arm64  enabled=True  offset(PA-VA)=0x0001000038000000
      map=virtual  MMU=on [pc=VA]  steplock=auto  census=off  chaindepth=8
      preset=(default)  anchor=_text  break=sw
      target=(arch defaults)
      vmlinux=.../arm64-v4.6/kernel/vmlinux  shadow=0x0000000040080000
```

- `offset(PA-VA)` — 물리=가상+offset. 여기선 `0x0001000038000000`.
- `map` / `MMU` — 지금 물리(physical)인지 가상(virtual)인지, MMU on/off.
- `shadow` — 물리주소도 심볼로 풀리도록 얹은 phys-shifted 심볼 파일 주소.

### `kearly mmu` — MMU 상태 상세

```
(gdb) kearly mmu
[kgdb] MMU=off [ctrl-reg]  map=physical  pc=0x0000000040080000  SCTLR_EL1.M=0
      pre-MMU: $pc/pointers are PHYSICAL; shadow symbols active.
```

MMU가 켜진 뒤:

```
[kgdb] MMU=on [ctrl-reg]  map=physical  pc=0x00000000408b003c  SCTLR_EL1.M=1
      MMU on: kernel VAs resolve natively; kp2v/kv2p translate either way.
```

### `kearly overmmu` — MMU 경계 통과

`__enable_mmu`를 `stepi`로 넘으면 QEMU gdbstub가 그 지점에서 싱글스텝을 흘려 CPU가 폭주한다.
대신 가상 랜딩(예: `start_kernel`)에 임시 브레이크를 걸고 `continue`로 넘는다:

```
(gdb) kearly overmmu start_kernel
[kgdb] over_mmu: continue to virtual landing {start_kernel} ...
[kgdb] >>> MMU ON: $pc now VIRTUAL 0xffff000008c365f0 -- native kernel symbolization active
[kgdb] landed pc=0xffff000008c365f0 start_kernel in section .init.text  (MMU on)
```

---

## 2. 주소 변환·심볼화 — `kp2v` / `kv2p` / `sym` / `stackscan`

물리↔가상 변환과 심볼화. MMU on 이후엔 양방향 다 동작한다(실측, 런타임 `$pc`=`cpu_do_idle+8`):

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

`stackscan [N]` — backtrace가 죽는 head.S에서 스택 워드 중 커널 포인터를 찾아 심볼화한다.
물리(PA)·가상(VA)을 구분해 표기한다(실측 발췌):

```
(gdb) stackscan 24
  [sp+0x008] 0xffff000008109a7c  VA  cpu_startup_entry + 644 in section .text of …/vmlinux
  [sp+0x028] 0xffff0000088a3600  VA  rest_init + 136 in section .text of …/vmlinux
  [sp+0x070] 0xffff000008081198  VA  __mmap_switched in section .head.text of …/vmlinux
  [sp+0x078] 0x00000000408b0054  PA  __enable_mmu + 84 in section .text of …/vmlinux
  [sp+0x088] 0xffff000008c36968  VA  start_kernel + 888 in section .init.text of …/vmlinux
```

---

## 3. 시스템 레지스터 — `ksr` / `ksregs`

`ksregs`는 핵심 sysreg를 값·디코드와 함께 일괄 덤프한다(실측, arm64 런타임):

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

`ksr NAME`은 1개만 읽는다(예: `ksr CurrentEL`). 읽기 경로는 pstate 유도 → gdb 레지스터 →
QEMU monitor 폴백 순이라, 스텁이 숨기는 레지스터도 최대한 값을 잡는다.

---

## 4. `kcensus` — head.S 레지스터 전수조사

**무엇을 하나** — `head.S`와 그것이 (호출체인 전체를 따라) 도달하는 모든 파일에서 **한 번이라도
read/write에 관여되는 모든 시스템/제어 레지스터**를 카테고리별로, 현재 값·필드 디코드·용도와 함께
나열한다. pwndbg의 REGISTERS 패널이 안 보여주는 바로 그 레지스터들이다(범용 x0~x30은 제외).
arm64 88개 / x86 CR·MSR·세그먼트 / riscv CSR.

**어떻게 치나**

```
(gdb) kcensus
```

**실측 출력 (arm64, 발췌 — 총 88개)**

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

- `RW`/`R`/`W` = head.S가 그 레지스터를 어떻게 쓰는지.
- `?` = 지금 EL/시점에서 gdbstub/monitor가 못 내주는 것(예: EL1에 있는데 EL2 레지스터). **정직하게 `?`** 로 표기.
- `[6.12]`/`[4.6]`/`[M-mode]` = 버전·모드 한정 레지스터.

**실측 출력 (riscv, 전체 — 21 CSR)**

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

**패널 상주** — `kearly census compact`를 켜면 매 stop마다 pwndbg context(또는 자동 라인)에
카테고리별 한 줄로 붙는다:

```
 translation:     TTBR0_EL1=0x6d0000b7f34000  TTBR1_EL1=0x41200000  TCR_EL1=0x34b5103510
 memory-attr:     MAIR_EL1=0xbbff440c0400
 system-control:  SCTLR_EL1=0x34d5d91d  CPACR_EL1=0x300000  DAIF=0x7
 el-transition:   CurrentEL=0x4  SPSR_EL1=0x145  ELR_EL1=0xffff000008086844  SP_EL0=0xffff000009080000
 feature-id:      CTR_EL0=0x8444c004  ID_AA64MMFR0_EL1=0x1124  ID_AA64DFR0_EL1=0x10305106
```

---

## 5. `kpt` — 하드웨어 페이지테이블 워크

**무엇을 하나** — 한 VA를 하드웨어처럼 걸어(L0~L3 arm64 / PML4~PT x86 / Sv39·48·57 riscv),
각 레벨의 raw descriptor·타입(table/block/page/invalid)·다음테이블 또는 출력 PA·리프 속성을
보여준다. **핵심**: MMU가 켜진 뒤에는 gdb `x`/pwndbg `hexdump`가 물리주소를 "지금 페이지테이블로
번역"해 읽으므로 PT 원본을 못 읽는다(`Cannot access memory`). `kpt`는 QEMU HMP `monitor xp`
(물리 examine)로 읽어 **MMU on 이후에도 정확**하다.

**어떻게 치나** — `kpt [VA]` (VA 생략 시 `$pc`, 표현식 가능: `kpt &_stext`)

**실측 (arm64 런타임, 4KB 페이지로 매핑된 커널 텍스트)**

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

- 각 레벨: `[인덱스] @그 엔트리의 물리주소  desc=raw값  타입 -> 다음/출력`.
- 리프 속성: `AF`(access) `RO-`(읽기전용, 커널텍스트) `AttrIdx`(MAIR 인덱스) `ISh`(inner share) `UXN`(EL0 실행금지).
- `=> LEAF` = 최종 물리주소 + 심볼. `MATCH` = 소프트웨어 kv2p 값과 하드웨어 워크 결과가 일치(정합성 확인).

**실측 (arm64 부팅 극초기 — 초기 스와퍼가 2MB 블록으로 매핑)**

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

> 같은 `_stext`인데 초기엔 **2MB BLOCK**(L2에서 종료), 부팅 후엔 **4KB PAGE**(L3까지) — 커널이
> `paging_init`에서 세분 매핑으로 다시 까는 과정을 그대로 관찰할 수 있다.

**실측 (미매핑을 정직하게 보고)**

```
(gdb) kpt &_text
  ...
  L3/PTE  [128] @PA 0xbeffc400   desc=0x0000000000000000  INVALID / not-present
  => NOT MAPPED (no valid leaf descriptor)
```

> `_text`(efi/head 페이지)나 `start_kernel`(부팅 후 해제된 `.init.text`)은 실제로 안 매핑돼 있고,
> `kpt`는 그 사실을 그대로 보고한다.

**실측 (MMU 꺼진 상태에서는 깔끔하게 거절)**

```
(gdb) kpt &_stext
[kgdb] cannot walk VA 0xffff000008082000 -- page-table base unreadable, or paging is off
       (MMU/satp/CR0.PG). Try after MMU-enable.
```

**실측 (riscv Sv57, 5단계)**

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

**실측 (x86, 4단계와 5단계 모두)**

```
# 기본(LA57): 5단계
VA ...   CR3 (5-level)   [5-level paging (LA57 5-level)]

# no5lvl 부팅: 4단계
VA 0xffffffff821132cf   CR3 (4-level)   [4-level paging (4-level)]
  PML4    [511] @PA 0x4cfeff8    desc=0x0000000003231067  table -> 0x3231000  (level3_kernel_pgt)
  PDPT    [510] @PA 0x3231ff0    desc=0x0000000003232063  table -> 0x3232000  (level2_kernel_pgt)
  => LEAF PA 0x21132cf  (pv_native_safe_halt + 15)
     (kv2p(VA)=0x21132cf  MATCH)
```

> 레벨 수는 하드웨어 설정 레지스터(x86 `CR4.LA57` / arm64 `TCR` T0SZ·T1SZ / riscv `satp` MODE)에서
> 런타임 계산하므로 3/4/5단계에 자동 적응한다. 페이지테이블 페이지도 `level3_kernel_pgt`처럼 심볼화된다.

---

## 6. `kpgd` — 페이지 디렉토리 덤프

**무엇을 하나** — 최상위 페이지 디렉토리(또는 지정한 테이블 PA)의 **비어있지 않은 엔트리**를
인덱스·raw값·타입·출력PA(+심볼)와 함께 덤프한다. `kpt`가 준 `table -> 0x...` PA를 넘겨 하위
레벨을 파고들 수도 있다.

**어떻게 치나** — `kpgd [PA] [N]` (생략 시 `$pc` 레짐의 최상위, N=표시 상한)

**실측 (arm64 런타임, 최상위 L0/PGD)**

```
(gdb) kpgd
top table L0/PGD @PA 0x41200000   regime TTBR1_EL1 (kernel/high)   (non-zero of 512 entries)
  [  0] 0x00000000beffe003  table   -> 0xbeffe000
  [247] 0x00000000bedf2003  table   -> 0xbedf2000
  [255] 0x00000000411bd003  table   -> 0x411bd000    (bm_pud)
  [256] 0x00000000beff7003  table   -> 0xbeff7000
```

> 512개 중 4개만 유효 — 커널 이미지/선형맵/fixmap 영역에 해당. `bm_pud`처럼 심볼도 붙는다.

### `kpthex` — 엔트리를 진짜 바이트 단위로 (hex 뷰)

**무엇을 하나** — `kpgd`가 64비트 디스크립터를 한 덩어리로 보여주는 것과 달리, 각 엔트리를
**메모리에 실제로 놓인 리틀엔디언 바이트 8개로 쪼개어** raw 값·디코드와 나란히 보여준다.
`full`을 주면 4KB 페이지 전체를 xxd식(16바이트/줄 + ASCII)으로 덤프한다. 물리 메모리를 QEMU
monitor(`xp`)로 읽으므로 **MMU가 켜진 뒤에도** 동작한다(gdb `x`/pwndbg `hexdump`가 물리
페이지테이블 주소에서 실패하는 바로 그 상황).

**어떻게 치나** — `kpthex [TABLE_PA] [N | full]` (생략 시 `$pc` 레짐 최상위, N=비어있지 않은 엔트리 상한 64)

**실측 (arm64-v4.6 런타임, 커널 L0/PGD)**

```
(gdb) kpthex
page-table page @PA 0x41200000   regime TTBR1_EL1 (kernel/high)   little-endian, as stored in RAM
   idx  @PA           b0 b1 b2 b3 b4 b5 b6 b7   value (LE)          decode
  [  0] 0x41200000     03 e0 ff be 00 00 00 00   0x00000000beffe003   TABLE -> 0xbeffe000
  [255] 0x412007f8     03 d0 1b 41 00 00 00 00   0x00000000411bd003   TABLE -> 0x411bd000  (bm_pud)
```

> 값 `0x…beffe003`이 메모리에는 `03 e0 ff be 00 00 00 00`로 놓인다(LE). `kpt VA hex`를 쓰면 워크의
> 각 레벨 디스크립터에도 `[03 e0 ff be 00 00 00 00]`처럼 바이트가 붙고, `kpthex 0x… full`은 그
> 테이블 페이지 4KB를 통째로 xxd식으로 찍는다.

---

## 6.5 `koff` — 왜 런타임 주소가 vmlinux ELF(nm) 값과 다른가

`nm`/`readelf`가 보여주는 심볼 주소(= vmlinux에 링크된 VA)와, 지금 그 심볼이 실제로 놓인 주소는
regime에 따라 **서로 다른 이유로** 다르다. `koff [SYM]`(SYM 생략 시 이미지 베이스)은 그 이유를
**서술이 아니라, 그걸 직접 규정하는 CPU 플래그·제어 레지스터·`$pc` 값**을 단서로 요약한다.
regime은 MMU 플래그가 아니라 **실제 `$pc`가 물리인지 가상인지**(`which_map`)로 가른다 — x86처럼
페이징이 늘 켜져 있어도 초기엔 identity/저주소로 도는 경우를 정확히 잡기 위해서다.

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

단서는 arch별로: **arm64** SCTLR_EL1.M / TTBR1_EL1 / kimage_voffset, **x86** CR0.PG / CR3 / CR4.PAE /
EFER.LMA / phys_base, **riscv** satp.MODE(Bare/Sv39-57) / satp.PPN. 공통으로 `$pc`(고반부 VA인지
물리/저주소인지)와 cmdline의 `nokaslr` 표지를 얹는다. KASLR 슬라이드: **`kearly kaslr`를 적용했다면**
그 slide를 반영해 **진짜 링크 VA**(심볼값 − 적용 slide)·**런타임 VA**·**slide**를 정확히 찍는다. 아직
적용 전이면 cmdline에 `nokaslr`가 있으면 `0`(확정), 없으면 `kearly kaslr`로 측정하라고 안내한다(koff
단독으로는 재배치된 심볼표만 보므로 slide를 직접 못 잰다). 런타임에
붙어 offset이 아직 없으면 조용히 `calibrate`를 시도한다.

---

## 7. `mmview` / `memlayout` — 커널용 vmmap

**무엇을 하나** — pwndbg `vmmap`은 커널 타겟을 못 읽으므로 그 자리를 대체한다. 두 부분으로 구성:

1. **심볼 랜드마크(VA→PA)** — 심볼표+캘리브레이션만 필요 → **MMU 이전 물리단계에서도 동작**.
2. **라이브 ptdump** — 페이지테이블을 걸어 연속 리전을 병합하고 권한·`kernel image` 라벨을 붙임.

MMU가 꺼져 있으면 라이브 매핑 대신 **물리 배치 + RAM**을 보여준다. 통합 루트(x86 CR3 / riscv satp)는
유저+커널이 섞이므로 기본은 **커널 절반만** (`mmview all`로 유저 포함, `noidmap`으로 arm64 TTBR0 생략).

**어떻게 치나** — `mmview` 또는 별칭 `memlayout` (옵션: `all` / `noidmap`)

**실측 (arm64, MMU 꺼진 극초기 — 물리 배치 표시)**

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

**실측 (arm64, MMU 켜진 직후 초기 스와퍼 — 리전 병합)**

```
live mappings: kernel  TTBR1_EL1  root@PA 0x41200000   (1 regions)   [4KB granule, 4-level (L0..L3), 9-bit index/level]
  0xffff000008000000-0xffff0000093fffff    20M -> 0x40000000    block AF=1 RW- AttrIdx=4 ISh kernel image {_text,_stext,_etext+}
```

> 초기 스와퍼가 이미지 영역 20MB를 2MB 블록들로 매핑한 것을 **하나의 리전으로 병합**해 보여준다.

**실측 (x86, 커널 공간만 필터 — 유저 474개 숨김)**

```
live mappings: kernel+user  CR3  root@PA 0x4714000   (14161/14635 regions)   [5-level paging (LA57 5-level)]
  (474 user/low-half regions hidden -- 'mmview all' to include)
  0xff11000000000000-0xff11000000097fff   608K -> 0x0           page  W S A D G NX
  0xff1100000009b000-0xff11000000ffffff 15764K -> 0x9b000       mixed W S A D G NX
  0xff11000001000000-0xff110000031f4fff 34772K -> 0x1000000     mixed R S A G NX
  0xffa0000000000000-0xffa0000000003fff    16K -> 0x7dc02000    page  W S A D G NX
  ...
```

> `0xff11...` = LA57 선형맵(직접 매핑), `0xffa0...` = vmalloc/ioremap(디바이스 `0xfed00000` 등),
> `R/W S A D G NX` = x86 PTE 플래그. 유저 프로세스 매핑은 숨겨 커널 지도에 집중한다.

**실측 (riscv Sv57)**

```
live mappings: kernel  satp  root@PA 0x838bf000   (112/564 regions)   [Sv57, 5-level, 4KB pages]
  (452 user/low-half regions hidden -- 'mmview all' to include)
  0xff1bfffffec00000-0xff1bfffffeffffff     4M -> 0xffe00000    block RW- S G A D
  0xff1c000000000000-0xff1c000001ffffff    32M -> 0xfce00000    block RW- S G A D
  0xff20000000000000-0xff20000000003fff    16K -> 0x825dc000    page  RW- S G A D
  ...
```

---

## 8. 텔레스코프와 `kearly chaindepth`

주소형 sysreg(TTBR/VBAR/ELR/SP 등)은 패널에서 **텔레스코프**(→ 체인)로 렌더된다. 단, pwndbg의
기본 체인을 **그대로 쓰지 않는다**: TTBR 같은 페이지테이블 베이스를 주면 pwndbg가 그 값을 포인터로
착각해 PGD→PUD→PMD… **테이블 트리 전체를 따라가다 gdb의 C 스택을 오버플로해 세션(과 QEMU)을 죽인다**.
그래서 자체 구현 `safe_chain`(항상 유한 깊이 + 순환감지)로 렌더하며, TTBR은 **물리읽기로 PGD→PUD→PMD
베이스만 안전하게** 따라간다.

**실측 (패널의 TTBR 텔레스코프 — 안전하지만 그대로 유지)**

```
 TTBR1_EL1  0x41200000  PTbase 0x41200000  ->  0xbeffe000  ->  0xbeffd000  ->  0x0
 TTBR0_EL1  0x6d0000b7f34000  PTbase 0xb7f34000  ->  0x0  ASID 0x6d
```

**깊이를 명령창에서 라이브로 조절** — `kearly chaindepth N`

```
(gdb) kearly chaindepth 2
[kgdb] telescope depth = 2 hops  (safe_chain: bounded, cycle-guarded; ...)
# -> TTBR1_EL1  0x41200000  PTbase 0x41200000  ->  0xbeffe000        (2홉에서 멈춤)

(gdb) kearly chaindepth 8       # 기본값
# -> TTBR1_EL1  0x41200000  PTbase 0x41200000  ->  0xbeffe000  ->  0xbeffd000  ->  0x0
```

`chain [ADDR] [N]`도 같은 안전 텔레스코프를 쓴다. `kfin`은 CFI 없는 head.S에서 `finish` 대체로,
복귀주소를 `lr`/`ra`/스택톱에서 잡아 그 지점까지 실행한다.

---

## 9. `cfgdis` — 분기 화살표 디스어셈블

radare2의 `pdf`처럼, 디스어셈블 좌측 여백에 함수 내부 점프의 **제어흐름 화살표**를 그린다.
화면에 보이는 명령을 타깃으로 하는 직접 점프마다 엣지를 만들고, 겹치지 않는 세로 트랙에
(넓은 span이 바깥쪽) 쌓아 코너·세로선·교차(`┌│└─┼┬┴`)로 그린다. **출발점과 도착점의 가로선
길이를 맞춰**(둘 다 같은 트랙 열에서 시작해 주소 열까지 뻗음) 도착점 끝에 화살촉 `>`, 출발점
끝에 평선 `─`를 찍는다.

- **`WHAT`은 gdb `disassemble` 인자 그대로** — 생략 시 현재 함수(프레임이 함수 밖이면 `$pc,+0x60`),
  심볼/주소/범위(`cfgdis start_kernel`, `cfgdis 0x80200000, +0x80`, `cfgdis __memset, __memset+0x40`).
  표시 수식어 `/r`·`/s`·`/m`은 무시한다(kdis가 자체 컬럼을 그리므로).
- **조건분기 + 무조건 점프만** 화살표 대상 — 호출(`jal ra`/`bl`/`callq`)·복귀·간접점프는 제외(radare2 선형 뷰와 동일).
  arch별 mnemonic 자동 판별(riscv `b*`/`j`, x86 `jcc`/`jmp`/`loop`, arm64 `b`/`b.cond`/`cbz`/`tbz`).
- **레짐 무관** — gdb의 `disassemble`를 그대로 몰기 때문에 물리 조기부팅 주소든 MMU 켜진 뒤의
  가상 주소(16자리 커널 VA)든 동일하게 동작한다. MMU가 켜져 가상 주소가 되어도 계속 쓴다.
- 옵션 `ascii`(비-UTF 터미널용 ASCII 글리프), `mono`(색 끔; `$GDBTOOLS_NO_COLOR`로도 끔). 색은 기본 on.

실측(riscv64 런타임, 커널 VA — 출발·도착 가로선이 주소 열까지 같은 길이로 정렬):

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

> **pwndbg 창과 mnemonic 일치** — gdb/binutils와 Capstone(pwndbg)은 일부 니모닉 철자가 다르다
> (arm64 조건분기: binutils `b.cc`/`b.cs` ↔ Capstone `b.lo`/`b.hs`). `cfgdis`/`flow`는 표시할 때
> `Arch.MNEM_ALIASES`로 **Capstone 철자로 정규화**해 pwndbg의 `[ DISASM ]` 창과 니모닉이 그대로
> 맞는다. 아울러 binutils가 붙이는 `// b.none` 같은 별칭 주석은 표시에서 떼되(pwndbg엔 없음),
> `tbz w0, #0x1f, <타깃>`의 `#imm`처럼 실제 피연산자는 보존한다.

### 자동 context 섹션 — `$GDBTOOLS_AUTO` 전용 (`flow` = radare2 화살표 창, pwndbg disasm과 병렬)

`$GDBTOOLS_AUTO`로 접속하면 도구는 pwndbg에 **섹션 두 개(`kgdb`·`flow`)만 추가**한다 —
**pwndbg 기본은 하나도 제거·변경하지 않는다.** 그래서 **두 disasm 창이 나란히, 각자 독립적으로** 뜬다:

- **`[ DISASM / … / set emulate on ]`** — pwndbg 자신의 창. 완전히 손대지 않으므로 에뮬레이션(`X3 => 4`·
  `CPSR` flags·`✔`/`✘` 분기예측·telescope)·색상 전부 그대로. hang-prone 지점(`_text` 등)은 pwndbg의
  자체 섹션 렌더링이 알아서 처리한다.
- **`[ DISASM + ARROWS ]`** (우리 `flow`) — **radare2식 분기 화살표** 뷰. `cfgdis`와 같은 **자체
  gdb+python 렌더러**로 그린다(gdb `disassemble` → 정확한 hex 타깃 → `┌│└─┬>` 화살표). pwndbg 창과
  겹치지 않는 별개 관점이라, 순수 gdb+python이라 **절대 hang·crash하지 않는다.**

```
[ DISASM / aarch64 / set emulate on ]        [ DISASM + ARROWS ]  (우리 flow)
 ► 0x…13d8 <memset+24>  cmp x2,#0xf           =>      0x…13d8  cmp   x2, #0xf
   0x…14b0 cmp … CPSR => 0x20000000 [ … C … ] ┌───    0x…13dc  b.hi  0x…1404 <+68>
                                              │┌──    0x…13e0  tbz   w2,#3,0x…13e8
                                              │└┬>    0x…13e8  tbz   w2,#2,0x…13f0
                                              └──>    0x…1404  neg   x4, x8
```

이전에는 `flow`가 pwndbg 라인을 재활용하려다 (1) pwndbg 창과 거의 판박이가 되고 (2) pwndbg가 분기
타깃을 심볼명으로 찍는 경우 화살표가 안 그려지는 문제가 있었다. 지금은 **자체 렌더러**라 두 창이
확실히 갈린다: pwndbg = 리치 주석, 우리 = 화살표.

> **arm64-v4.6 참고 (SIGABRT 가드)**: pwndbg의 *자체* disasm 창은 이 EOL 커널의 일부 명령에서
> 에뮬레이션(Unicorn) 세그폴트할 수 있다(pwndbg 고유 버그, 도구와 무관). 대표 사례가 **세컨더리 CPU
> 극초기 stop** — `b __secondary_switched`(`head.S:722`, `sp`/`x29`가 아직 미초기화)에서 pwndbg가 그
> 지점부터 앞으로 에뮬레이트하다 폴트를 내 **gdb 프로세스 자체가 SIGABRT(core dumped)**로 죽는다
> (`----- Backtrace -----`에 찍히는 건 커널이 아니라 gdb의 crash dump다). 네이티브 세그폴트라 파이썬
> 예외로는 못 잡는다(첫 stop이 곧바로 크래시면 손쓸 틈도 없다 — 접속 직후 `cpu_do_idle` 같은 지점).
> 그래서 도구는 **기본 `auto`**로 arm64 접속 시 도구의 stop 훅이 pwndbg 컨텍스트 렌더링보다 **먼저**
> 돌며 `emulate`를 자동으로 꺼 크래시를 원천 차단하고(1줄 안내 출력), `kearly off`/`saferender off` 시
> 복원한다 — 즉 **별도 조작 없이 안 죽는다**. 에뮬레이션을 그대로 쓰려면 `kearly saferender off`(즉시
> 복원)나 `warn`(경고만, 설정 불변). 우리 `flow`(별도 gdb+python 화살표 창)는 어느 커널에서도 안
> 깨진다. 일반 `gdb vmlinux`는 pwndbg를 안 건드리고 수동 `cfgdis`만 남긴다.

> **shadow 브레이크포인트 (`kearly bpfix`, 기본 off)**: MMU-off 심볼화를 위해 물리 주소에 shadow
> 심볼표를 얹는 부작용으로, `b start_kernel` 같은 이름 브레이크가 **물리(0x40c365f0) + 가상
> (0xffff000008c365f0) 두 위치**로 잡힌다(프롬프트엔 물리가 primary로 표시). 하지만 **QEMU의 SW 브레이크는
> 가상 PC로 매칭**하므로, MMU-on 심볼은 `continue`하면 **가상 위치가 알아서 발화**한다(실측:
> `b start_kernel; c` → `Breakpoint 2.2, start_kernel` clean hit). 즉 **네이티브 dual 브레이크로도 그냥
> 걸리며, `bpfix`는 필수가 아니다.**
>
> `bpfix on`은 선택적 정리용이다: **가상 위치는 항상 켜두고**(MMU-on 코드가 발화하는 위치), MMU-on일 때
> 잠자는 물리 위치만 끈다. 가상 위치는 절대 끄지 않는다(초기 버전은 MMU-off에서 가상 위치를 꺼
> `b start_kernel`이 안 걸리는 회귀가 있었다 — 수정됨). 기본 off인 이유: 네이티브가 이미 걸리므로.

> **KASLR 디버깅(물리 크로싱 앵커)**: KASLR가 켜지면 gdb 심볼(링크 VA) ≠ 런타임 VA(링크+슬라이드)라
> `b SYM`이 안 걸린다. 슬라이드는 relocation(각 arch의 조기 asm) 이후에만 정해지는데, **콜드 프로즌 부팅에는
> relocation과 start_kernel 사이에 자연스러운 정지점이 없다**(chicken/egg). 그래서 슬라이드 비의존 **물리
> 크로싱 앵커**를 쓴다: relocation 직후·start_kernel 이전에, MMU가 idmap/물리로 켜진 채 실행되는 "물리→고VA
> 전이 명령"에 HW 브레이크를 건다(그 주소는 VA==PA라 slide 없이도 발화). 전이 레지스터에서 착지 심볼의 런타임
> VA를 읽어 `slide = 런타임VA − 링크VA`를 확정한다.
>
> | arch | 크로싱 앵커 | slide 획득 |
> |---|---|---|
> | arm64 6.12 | `__primary_switch`의 `br x8` → `__primary_switched` | `x8 − linkVA(__primary_switched)` |
> | arm64 4.6 | `__enable_mmu`의 `br x27` → `__mmap_switched` | `x27 − linkVA(__mmap_switched)` (= x23) |
> | riscv 6.12 | `relocate_enable_mmu` 진입 (setup_vm 이후·MMU-off) | `kernel_map.virt_addr − linkVA(_start)` |
> | x86 6.12 | `startup_64`의 `jmp *0f` (CR3 로드 후) → `common_startup_64` | stepi 후 `$pc − linkVA(common_startup_64)` |
>
> 크로싱 명령은 함수의 물리 바이트를 opcode 스캔(arm64 `br xN`=`0xD61F0000|N<<5`, `ret`에서 정지)하거나
> disasm(x86 `jmp *..(%rip)` — AT&T·Intel 양쪽 문법)으로 찾는다 → 버전별 주소 하드코딩 없음. nokaslr에서도
> 레지스터가 링크 VA를 담아 slide=0으로 정확히 착지한다.
>
> **`kearly kaslr auto`** (권장): bootbreak 후 크로싱까지 진행해 slide를 읽고
> `symbol-file -o`로 전 심볼을 런타임 VA로 재배치한다. **start_kernel 이전**에 멈추므로 이어서
> `b start_kernel; continue`가 걸린다. 실측(직접 부팅, snapshot): arm64 6.12 `0x4de1aec00000` · arm64 4.6
> `0x2c4cf5c00000` · riscv 6.12 `0x38c00000` — 모두 **크로싱 레지스터 값 == kimage_voffset/kernel_map 독립
> 검출값**으로 교차검증 일치, start_kernel clean hit. `kearly kaslr <hex>`로 명시 슬라이드도 적용 가능.
>
> **x86 KASLR — 디컴프레서 물리 베이스 복구**: x86은 물리 KASLR이 bzImage 디컴프레서에서 커널을 **랜덤 물리
> 주소**로 배치한다(arm64/riscv은 물리 로드 고정 → 물리 앵커가 항상 유효). 그래서 콜드 프로즌엔 `startup_64`의
> 로드 PA를 미리 알 수 없어, `--kaslr`가 x86에서는 먼저 **디컴프레서**를 앵커로 그 랜덤 베이스를 복구한다(디컴프
> 레서는 KASLR 무관하게 `0x100000`에 고정 적재):
>
> 1. 디컴프레서 진입(`0x100000`)에 HW 브레이크 → 2. `startup_64`의 self-relocation `jmp *%rax`에서 `%rax`를 읽어
> 이동 베이스 `rbx`(= `%rax − IMM`) 확보 → 3. `extract_kernel`(rbx+off)에서 `finish` → `%rax` = 압축해제된 메인
> 커널 물리 진입점(= 랜덤 KASLR 베이스). 이 베이스를 entry로 잡으면 이후는 위 크로싱 앵커가 그대로 가상 slide를
> 확정한다. 오프셋은 `arch/x86/boot/compressed/vmlinux`를 `nm`/`objdump`로 읽어 버전 무관하게 도출한다(빌드시
> 자동 생성; 없으면 `--entry-pa`로 폴백). 실측: 부팅마다 다른 랜덤 베이스(`0x52600000`·`0x28a00000`·`0x0ca00000`
> …)를 매번 복구, slide(`0x25600000`·`0x27400000` …) 교차검증 일치, start_kernel clean hit. x86은 조기부팅 HW
> 브레이크 결정성을 위해 QEMU를 TCG로 띄운다.
>
> 참고: MMU-off/idmap head.S와 pi 코드는 **재배치 없이** 물리/idmap 주소로 그냥 걸린다(`kb`의 PA 위치) —
> relocation이 필요한 건 재배치 고VA에서 도는 start_kernel 이후 코드뿐이다.

---

## 10. `kw` — regime 인지 워치포인트

브레이크포인트와 같은 문제가 **데이터 쪽**에도 있다. head.S는 `__bss`·부트 인자·`kernel_map`·자기가
만드는 페이지테이블을 **물리주소로** 쓰고, 고VA 가동 뒤의 코드는 같은 전역을 `linkVA+slide`로 쓴다.
gdb의 `watch SYM`은 **입력한 그 순간 심볼이 가리키던 주소 하나만** 감시하므로 크로싱 반대편이 사각이
된다. `kw`는 `kb`와 동일하게 `PA(S)`·`IMG(S)` 양쪽을 걸고, slide가 확정되면 IMG를 자동 재무장한다.

```
# MMU off (head.S 진입), slide 아직 미상 상태에서 무장
(gdb) kw kimage_voffset
[kgdb] kw 'kimage_voffset'  linkVA=0xffff800082148000  watch  8-byte
        watch @ 0x0000000042348000  PA  MMU-off/idmap  (head.S data writes, page tables)  [wp 2]
        watch @ 0xffff800082148000  IMG high kernel map (start_kernel & steady state)  [wp 3]
        (IMG auto-re-arms to linkVA+slide the moment the KASLR slide is known)

(gdb) kearly kaslr auto
[kgdb] KASLR slide = 0x253005a00000 applied: ...

(gdb) info watchpoints          # IMG가 linkVA+slide 로 이동해 있다
2       hw watchpoint  keep y   *(unsigned long long *)0x42348000
5       hw watchpoint  keep y   *(unsigned long long *)0xffffa53087b48000

(gdb) continue                  # 재배치된 VA 쪽 기록에서 발화
Thread 1 hit Hardware watchpoint 5: *(unsigned long long *)0xffffa53087b48000
Old value = 0x0
New value = 0xffffa53045800000
__primary_switched () at arch/arm64/kernel/head.S:234
```

PA 쪽 발화도 대칭으로 동작한다 — `kw boot_args` 뒤 `continue`하면 MMU가 아직 꺼진
`preserve_boot_args`(head.S:174)에서 걸리며 QEMU가 넘긴 DTB 포인터 저장을 그대로 잡는다.

```
Thread 1 hit Hardware watchpoint 3: *(unsigned long long *)0x43a56000
Old value = 0x0
New value = 0x48000000
preserve_boot_args () at arch/arm64/kernel/head.S:174
[kgdb] MMU=off [ctrl-reg]  map=physical  pc=0x0000000042bca710  SCTLR_EL1.M=0
```

`-r`(rwatch)·`-a`(awatch)와 `kw *ADDR [SIZE]`(SIZE ∈ {1,2,4,8})도 같은 방식으로 걸린다.
**HW 워치포인트 슬롯을 항목당 2개 소비**한다. 실기 arm64 코어는 보통 4개뿐이라 두 개만 걸어도
포화되지만, QEMU TCG는 더 너그럽다(`kw` 3개 = 6워치포인트가 모두 무장되는 것을 실측). 어느 쪽이든
슬롯을 채우는 것 자체가 목적이 아니므로 필요한 지점에만 걸고, 무장에 실패하면 `kw`가 아무것도
걸지 못했음을 명시적으로 알린다.

---

## 10.2 상태 패널의 KASLR 칸

pwndbg `kgdb` 섹션(및 `kearly where`)의 `KASLR=` 칸은 **알 수 있는 값이면 언제나 숫자**를 보인다.
패널을 보는 이유가 그것이기 때문이다 — 슬라이드 0은 "없음"이 아니라 하나의 정보다.

```
KASLR=0x4ca043800000                  KASLR 켜짐, 크로싱에서 확정된 값
KASLR=0  (KASLR 비활성화)              nokaslr -- 리셋 벡터에서부터 확정
KASLR=? (undecided until the crossing -- still physical, MMU off)
```

`nokaslr` 판정은 DTB의 `/chosen/bootargs`에서 읽는다. QEMU가 arm64·riscv에 cmdline을 그 경로로
넘기므로 커널이 아직 아무것도 파싱하지 않은 리셋 벡터에서도 답할 수 있다(x86은 DTB가 없어
`start_kernel` 이후에야 확정된다). 커널 전역(`saved_command_line`)은 fallback이다.

KASLR을 켠 채 크로싱 이전이면 `?`다. 그 시점에는 슬라이드가 **어디에도 존재하지 않으므로**
0을 지어내지 않고 무엇을 기다리는지 말한다.

## 10.3 레짐이 안 맞으면 답하지 않고, 이유를 말한다

한쪽 주소 체계를 가정하는 명령을 반대쪽 레짐에서 실행하면 **조용히 틀린 답이 나오는 것**이 가장
나쁘다. 실제로 그랬다 — MMU가 켜지기 전 head.S에서 `kv2p $pc`는 `$pc`가 물리 주소인데도 가상으로
가정해 `0x0000800000400000` 같은 그럴듯한 무의미한 값을 돌려줬다. 지금은 거절하고 이유를 말한다.

```
(gdb) kv2p $pc
[kgdb] kv2p: 0x0000000040200000 is not a kernel virtual address -- it looks PHYSICAL.
      Right now: MMU off, so addresses here are PHYSICAL.
      Use `kp2v` for this direction, or `sym` which accepts either.
```

거절 문구는 어디서나 같은 세 가지를 말한다: **명령이 무엇을 가정했는지 / 지금 실제로는 어떤
상태인지 / 대신 무엇을 쓰면 되는지**. 가운데 한 줄은 `Session.regime_phrase()`가 공급하므로
표현이 갈라지지 않는다.

같은 이유로 고친 것들:

- `kp2v`에 이미 가상인 주소를 주면 거절한다(반대 방향 안내).
- `kfin`은 링크 레지스터가 0인 진입 시점에 **CPU를 진행시키지 않는다**. 예전에는 주소 0으로
  달려가 게스트를 날려버렸고, 그 뒤 명령이 전부 "target is running"으로 실패했다.
- `stackscan`은 "no symbolizable pointers"가 아니라 `$sp`가 아직 0이라는 사실과, arm64 head.S가
  `__primary_switch`의 `adrp x1, early_init_stack`에서야 sp를 세운다는 것을 알린다.

나머지 명령들은 이미 이유를 밝히고 있다 — 전수 조사로 확인했다: `kpt`는 "paging is off",
`kpgd`/`kpthex`는 "cannot read the page-table base (paging off / stub)", `ksr`는 stub이 못 주는
레지스터를 `mrs` 단일 스텝으로 얻는 법, `koff`/`mmview`/`kearly mmu`는 현재 레짐을 머리에 달고
출력한다.

## 10.35 `kearly safemem` — pwndbg 탐침이 QEMU를 죽이는 것 막기

**증상.** KASLR 커널에서 `vfs_write` 같은 syscall 경로 함수에 멈춘 뒤 pwndbg가 컨텍스트를
그리면 **QEMU가 SIGSEGV로 죽고** 이어서 gdb가 abort한다. 재현율 100%였다(4/4, 3/3, 3/3).

**원인.** pwndbg는 커널 타깃에 `/proc/<pid>/maps`가 없으니 메모리 맵을 **탐침으로 추정**한다 —
페이지 정렬 주소에 1바이트 읽기를 렌더당 약 170회. 대부분은 조용히 실패한다. 그런데 그 시점은
유저 프로세스의 syscall 문맥이라 TTBR0가 그 프로세스 페이지테이블을 가리키고, 탐침 주소가
RAM 밖으로 번역되면 QEMU가 디바이스 모델로 디스패치하다 죽는다. 코어 스택이 그대로 말해준다:

```
gdb_read_byte -> cpu_memory_rw_debug -> flatview_read_continue
              -> memory_region_dispatch_read -> SEGV
```

**귀속.** 이 툴이 아니다. pwndbg만 올리고 이 플러그인을 **로드하지 않은** 상태에서도 죽었고,
반대로 순정 gdb(`-nx`)는 같은 조건에서 멀쩡했다. 세 조건(KASLR + syscall 문맥 + 풀 컨텍스트
렌더)이 겹쳐야 하며, 하나만 빠져도 나지 않는다 — `nokaslr`이면 안 나고, 브레이크만 걸고
컨텍스트를 안 그리면 안 나고, head.S 구간에서도 안 난다.

**대처.** pwndbg의 모든 읽기가 지나는 단일 통로(`pwndbg/aglib/memory.py`의 `read`)를 감싼다.
읽기 전에 `monitor gva2gpa`로 그 페이지가 매핑됐는지 묻고, `Unmapped`면 QEMU에 요청하지 않고
**pwndbg가 이미 처리할 줄 아는 평범한 읽기 실패**로 돌려준다. `gva2gpa`는 어떤 입력에도
안전하다 — 실제로 크래시를 낸 그 주소에 대해서도 `Unmapped`를 정상 반환한다.

```
kearly safemem status      installed / 차단한 탐침 수(blocked) / monitor로 되살린 읽기 수(rescued)
kearly safemem on|off|auto (기본 auto: 커널 타깃 + 번역 활성일 때만)
```

pwndbg를 수정하지 않는다. 가장 낮은 단일 통로(gdb 백엔드의 `GDBProcess.read_memory`)를 감싼다 —
레지스터 인핸서·telescope·스택 덤프가 모두 이 아래로 내려오므로 그보다 낮게 새는 경로가 없다.
원본 읽기는 보관하고 위험한 주소만 걸러내며, 판정이 불가능하면 그냥 통과시킨다. 페이지 단위로
캐시하고 정지마다 비운다.

근본 결함은 QEMU에 있다. 어떤 주소를 물어보든 디버그 읽기가 SEGV로 죽어선 안 된다. 여기서 한
것은 **유발하지 않도록 회피**한 것이지 고친 것이 아니다. 회귀는 크래시 가드 테스트로 잡는다.

### 초기-부트에서도 pwndbg 특유의 수려한 TUI 유지 (두 가지 보강)

**(1) pagescan 경고 스팸 제거.** pwndbg의 `auto-explore-pages`는 커널 타깃(맵을 모름)에서
정지마다 정크 레지스터값을 telescope할 때 `Avoided exploring ... / Likely a pagescan bug,
please report`를 수십 줄 쏟아내 레지스터 telescope를 뒤덮는다. 이 플러그인은 커널 타깃에서
활성화되는 동안 이 값을 `no`로 두고(정지마다 확인함), `kearly off`에서 **사용자의 이전 값으로
원복**한다. 실측: arm64 v6.12 KASLR의 `__enable_mmu`(MMU off, 물리) 정지에서 레지스터 telescope와
색상은 켜든 끄든 **완전히 동일**하고, 차이는 오직 정지당 약 11줄의 경고 유무뿐이다. telescope /
역참조 / 심볼화 같은 실제 표시 기능은 손대지 않는다 — 오직 잡음 발생 휴리스틱 하나만 끈다.

**(2) 읽기 되살리기(rescue) — regime 무관.** CPU들이 서로 다른 번역 regime에 동시에 놓이면
(이차 코어가 `__enable_mmu` 물리 코드에 있는데 다른 코어는 MMU on으로 커널을 돌리거나, riscv SMP에서
**정상 가상 정지인데** 형제 hart가 부팅 중이거나) QEMU gdbstub가 그 읽기를 서비스하지 못해 gdb
`Inferior.read_memory`가 `MemoryError`로 실패한다 — CPU가 바로 그 자리에서 실행 중인데도. 그러면
pwndbg telescope는 화살표가 사라지고 네이티브 DISASM은 `Invalid address`를 찍는다. 반면 HMP
`monitor xp`는 어떤 코어의 regime과도 무관한 물리 경로라 **여전히 읽힌다**. safemem 가드는 라이브
읽기가 실패하면, 실패한 주소를 물리주소로 바꿔 `monitor xp`로 되살린다:

* 물리(저)주소는 그대로 쓰고,
* 가상주소는 게스트 페이지테이블(`monitor gva2gpa`)로 번역하되, **그 stop에서 실행 중인 코어(=gdb가
  선택한 스레드의 hart)의 페이지테이블 기준으로** 번역한다. HMP `gva2gpa`는 기본으로 HMP-현재 코어를
  쓰는데, riscv는 **부팅 hart가 매 부팅마다 랜덤**이라 기본 코어(cpu 0)가 Bare(MMU off) 이차 hart일
  때가 있고, 그러면 gva2gpa가 입력 VA를 **그대로 되돌려준다**(identity, 번역 아님). 그래서 먼저
  `monitor cpu <선택코어>`로 맞추고, identity·여전히-고VA인 응답은 거부하며, 필요하면 코어를 훑어
  실제 물리주소를 얻는다. 어느 코어에도 아직 매핑이 없는 VA(예: 상위 맵 생성 전)는 거짓 PA를 주지
  않고 그냥 사양한다.

그 물리 대상이 **실제 게스트 RAM**일 때만 읽는다. RAM 여부는 하드코딩한 창이 아니라 **QEMU에 직접
물어본다** — `monitor gpa2hva`가 RAM이면 `Host virtual address ... (pc.ram) is 0x..`, 디바이스면
`is not RAM`, 빈 곳이면 `No memory is mapped`로 답하므로 디바이스 모델은 절대 건드리지 않는다(구형
QEMU로 명령이 없으면 아치별 `phys_window` 프리셋으로 폴백). 실측: arm64 이차 `__enable_mmu` 정지에서
전체 `context`가 rescue 수백 회로도 **0.1초 안**에 telescope·색상·DISASM이 모두 살아나고, riscv의
`Invalid address` 3건(형제 hart 타이밍 의존)도 0으로 닫힌다. 되살린 횟수는 `kearly safemem status`의
`rescued`. 원래 크래시 경로(가상 정지의 **매핑 안 된** 정크 포인터)는 위쪽 zero-fill 가드가 먼저
차단하므로 rescue까지 오지 않아 `crashguard`는 그대로 통과한다(arm64·x86·riscv 실측 확인). 이 되살리기는
**아키텍처 무관**이며, 애초에 라이브 읽기가 되는 상황에서는 아무 일도 하지 않는다 — 필요한 곳에서만 발동.

> 정정(실측으로 바로잡음): 예전에 "MMU off인 이차 코어에 멈추면 높은 가상주소를 읽는 건 원리상
> 불가능"이라고 적었는데, **이는 틀렸다.** 실측 결과, 그런 동시-regime 정지에서 gdbstub 읽기는
> 흔히 MMU on인 다른 코어의 문맥으로 라우팅되므로 커널 고VA(`vfs_write` 등)는 순정 gdb로도 잘
> 읽히고(정작 실패하던 쪽은 그 이차 코어의 **물리 pc**였다), 설령 읽기가 이차 코어로 라우팅돼
> 고VA가 실패해도 rescue의 `gva2gpa`가 **HMP 기준 코어(대개 MMU on인 CPU0)**로 번역하므로 되살린다.
> 커널 고VA는 부팅 후 모든 코어의 상위 매핑에 들어있어 항상 번역된다. 진짜로 못 읽는 경우는 **아직
> 어느 코어에도 그 매핑이 없는** 극초기(상위 맵 생성 전)뿐이며, 그건 매핑이 실제로 없으니 옳게
> 사양한다. 즉 물리·가상 어느 쪽으로 라우팅되든 rescue가 덮는다.
>
> 코어(스레드) 전환도 그대로 성립한다: regime 판정은 **현재 선택된 스레드의 pc/레지스터**로 하므로,
> `thread N`으로 코어를 바꾸면 KGDB 패널·telescope가 그 코어의 실행 맥락(MMU on/off, 물리/가상)에
> 맞춰 자동으로 바뀐다. 실측: 한 정지에서 이차(MMU off)는 `PHYS`, 주 코어(MMU on)는 `VIRT`로,
> 양쪽 다 완전한 telescope 렌더.

### cross-regime 레지스터 twin (물리 정지에서 VA의 물리 twin 병기)

물리/전환 regime에 멈추면 어떤 레지스터가 아직 **닿을 수 없는 커널 가상주소**를 담고 있을 수 있다.
대표적 예: phys->virt 전환 순간(arm64 `br x8`)의 `x8 = __primary_switched` — 상위 맵이 아직 이 코어에
활성화되지 않아 그 VA로는 지금 접근이 안 된다. KGDB 패널은 **pwndbg 네이티브 REGISTERS는 그대로 두고**,
tool 자체 패널에 그 VA의 **지금 닿을 수 있는 물리 twin**을 병기한다:

```
 cross-regime regs (VA -> reachable PA twin):
   x5   0xffffa9f7289bd000  ->  PA 0x0000000042bbd000
   x8   0xffffa9f7289ca730  (__primary_switched)  ->  PA 0x0000000042bca730
```

VA->PA 한 방향만 한다 — `_is_va`(상위 비트 전부 1)는 애매하지 않은 판정이라, 큰 값을 담은 제어/ID
레지스터(`PMCR_EL0`, `ID_MMFR1`, `cpsr` 등)를 포인터로 오인하지 않는다. 물리 window 안에 드는 twin만
보이므로 KASLR 슬라이드가 미확정인 순간에도 엉뚱한 주소를 찍지 않고, 물리 twin이 없거나 **가상 정지(주소가
이미 가상-정확)**이면 이 줄은 아예 안 나와 조용하다. 실측(3아치): arm64 `x8->PA` 병기, riscv 동일, x86은
전환이 `jmp *ptr`이라 레지스터에 VA가 안 담겨 조용(정상). all-in-one walk에서 창 완전·에러 0 유지.

### 커널 버전 탐지가 `context`를 죽이지 않게 (`install_kernel_guards`)

**증상.** 붙자마자 `b start_kernel; c`로 **극초기 start_kernel(init/main.c:915)**에 멈춘 뒤 context를
그리면 `Exception occurred: context: Linux version tuple not found`로 **context 전체가 안 그려진다.**
그런데 조금 더 진행한 `vfs_write`·`ip_local_out` 등에선 멀쩡하다. 간헐적이라 더 헷갈린다.

**원인.** pwndbg는 context에서 커널 버전을 알려고 `linux_banner`(.rodata 문자열)를 읽어
`krelease()`로 파싱한다. `krelease()`는 `kversion()`이 **비어있지 않은데 `Linux version X.Y`가 아닌**
문자열을 주면 **None이 아니라 예외를 던진다**(pwndbg 코드). 상위 가상 맵이 막 켜진 그 순간엔 배너 읽기가
아직 불안정해 짧은 쓰레기가 나올 수 있고, 그러면 예외가 나 context가 통째로 중단된다. `krelease`는
`cache_until("start")`라 `continue`마다 재계산되므로, 유저스페이스가 뜬 뒤엔 배너가 깨끗이 읽혀 정상으로
돌아온다 — 그래서 "start_kernel만, 가끔" 처럼 보인다. **멀티코어와는 무관**(그 시점 CPU0 단독).

**대처.** `krelease()`(및 `kversion()`)를 감싸 **실패 시 예외 대신 None**을 돌려준다. 버전을 아직 못 읽는
것은 "미상(None)" 상황이지 치명적 오류가 아니며, pwndbg 자신의 호출자들도 `krelease() is None`을
"버전 미상"으로 이미 처리한다. 그래서 배너가 못 읽혀도 **context는 끝까지 그려진다**. 배너가 읽히는
평상시엔 실제 버전 튜플을 그대로 돌려주므로 잃는 것도 없다. 표시 기능은 손대지 않는다. 결정적 검증:
start_kernel에서 kversion을 강제로 쓰레기로 만들어 원본 `krelease`는 예외(재현), 감싼 것은 None을 내고
`context`가 끝까지 렌더됨을 확인.

> 정직한 한계: 극초기의 배너 읽기 불안정 자체(gdbstub/초기 매핑 타이밍)는 회피(가드)한 것이지 근본을
> 고친 게 아니다. 이 경우 pwndbg가 커널 버전을 모르게 되지만(=None), context·초기부트 디버깅에는
> 영향이 없다.

## 10.4 `kearly where` — "지금 내 상황이 뭐냐"를 한 줄 명령으로

멈춘 자리에서 상황을 파악하려면 예전에는 `kearly status`(캘리브레이션), `kearly mmu`(MMU),
`sym $pc`(어디인지), `kearly kaslr status`(슬라이드) 네 개를 따로 쳐야 했다. 값 자체는 이미
매 정지마다 pwndbg 패널에 렌더링되고 있었고, 없던 건 **물어볼 방법**이었다.

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

`twin`은 현재 pc의 반대편 주소(물리↔가상)다. `phase`는 리셋 벡터 이전인지, 커널 진입점인지,
진입 후 아직 물리인지, 가상 체계가 선 뒤인지를 말한다. `next`는 지금 상황에서 다음에 칠 가능성이
가장 높은 명령이다.

**읽기 전용이다.** 레지스터를 쓰지 않고, 프로브를 걸지 않고, CPU를 재개하지 않는다. 그래서 어떤
레짐에서 쳐도 안전하다.

## 10.5 `kearly regimes` — 이 빌드의 MMU 정지점

"이 커널에서 MMU는 정확히 어디서 켜지나"를 알려면 gdb 밖에서 vmlinux를 디스어셈블하고 오프셋을
세야 했다. 이제 툴이 실행 이미지를 스캔해 직접 답한다 — 버전별 상수는 하나도 없다.

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

`mmuon`은 새 아키텍처 훅 `find_mmu_enable`이 **opcode 스캔**으로 찾는다: arm64는
`msr sctlr_el1, xN`(0xD5181000 | Rt), riscv는 `csrw satp`(0x18001073 | rs1<<15), x86은
`mov %rXX,%cr3`(0f 22 d?). 레지스터 번호도 커널 버전도 모른 채 찾아진다.

`kearly regimes walk` 은 다섯 지점을 전부 무장해서, 이후 그냥 `continue`만 반복하면 MMU 전이를
순서대로 통과한다. 실측 (arm64 6.12):

```
0x42bb84a8  ->  0x42bb8518  ->  0xffffa33cc9fca730  ->  0xffffa33cc9fc0bd8
  msr sctlr      br x8            __primary_switched      start_kernel+8
```

**HW 슬롯은 정지점당 정확히 1개만 쓴다.** head.S 코드는 고VA 맵에서 실행될 일이 없고
`start_kernel`은 물리에서 실행될 일이 없으므로, 각 지점의 레짐을 알고 있는 이 명령은 쌍둥이 중
한쪽만 무장한다(`kb`의 새 `sides` 인자). 양쪽을 다 걸면 5개 지점에 8개를 쓰게 되는데, 그중 셋은
영원히 매치되지 않는 자리였다.

riscv는 네 지점만 나온다. `csrw satp` 하나가 "번역을 켜는 명령"이자 "물리→가상 전이 명령"이라
두 항목이 같은 주소로 합쳐지기 때문이다 — 없는 정지점을 있는 것처럼 보이게 하지 않는다.

`kearly regimes stop <id>` 는 한 지점까지 바로 달린다.

## 10.6 `kx` — 번역을 우회하는 물리 메모리 examine

`x`는 항상 **현재 페이지테이블을 통해** 주소를 해석한다. 그래서 "PC는 물리값인데 번역은 이미 켜진"
찰나에는 자기가 멈춰 선 자리조차 읽지 못한다.

riscv가 정확히 그 지점을 만든다. `relocate_enable_mmu`의 `csrw satp, a0` 다음 페치는 곧바로
트랩되어 `stvec`(가상 주소)로 착지하도록 설계돼 있다. 그 경계에서 멈추면 `$pc`는 물리값
`0x80201048`인데, 그 값은 새 매핑에서 유효한 VA가 아니다:

```
(gdb) printf "%#lx\n", $pc
0x80201048
(gdb) x/16xb $pc
0x80201048 <_start+4168>:	Cannot access memory at address 0x80201048
(gdb) kx/16xb $pc
0x0000000080201048:	0x17 0x05 0x00 0x00 0x13 0x05 0x45 0x07 0x73 0x10 0x55 0x10 0x97 0xc1 0x57 0x02
```

읽힌 16바이트는 vmlinux의 `0xffffffff80001048` 내용과 정확히 일치한다
(`auipc a0,0x0` / `addi a0,a0,116` / `csrw stvec,a0` / `auipc gp,0x257c`).

`kx`는 QEMU HMP의 `xp`(examine physical)를 gdbstub monitor 통로로 태워 번역을 통째로 건너뛴다.
페이지테이블 워커(`kpt` / `kpthex`)가 MMU가 켜진 뒤에도 테이블 페이지를 읽을 수 있는 것과 같은
경로이며, 이번에 그 경로를 사용자 명령으로 노출한 것이다.

그 자리에 멈추면 툴이 먼저 알려준다 — 발견성이 없으면 있는 기능도 없는 것과 같기 때문이다:

```
[kgdb] note: $pc 0x0000000080201048 is physical and translation is on, so `x` cannot read it.
       Use `kx/16xb $pc` (physical examine) or `cfgdis` here.
```

판정은 추측이 아니라 **사용자가 칠 명령을 그대로 시험**해서 한다(`x/1xb $pc`가 실패하는지).
arm64·x86의 idmap 정지에서는 VA==PA라 `x`가 정상 동작하므로 이 줄은 뜨지 않는다.

참고로 메모리 자체는 타깃에서 읽힌다 — gdb의 파이썬 `read_memory`는 같은 주소에서 올바른
바이트를 돌려준다. 거부하는 것은 현재 페이지테이블로 번역을 시도하는 `x` 명령 쪽이다.

문법은 `x`를 그대로 따른다 — `kx/16xb $pc`, `kx/8gx 0x40200000`. 기본값은 `/16xb`.
인자가 커널 VA이면 물리 주소로 변환한 뒤 읽고 그 변환을 함께 출력하므로, 어느 레짐에서든
`kx $pc`가 옳다. gdb의 `x`는 건드리지 않는다.

---

## 11. 크로싱 캐처 — "아무 지점에 걸어도 걸린다"

KASLR을 켠 콜드 프로즌 부팅에서 `b start_kernel`을 head.S 진입점에서 걸면, 예전에는 **조용히 빗나갔다**.
그 시점의 커널은 아직 자기 가상 베이스를 계산하지 않았으므로 gdb가 무장할 수 있는 주소는 링크 VA뿐이고,
재배치된 커널은 그 주소를 영원히 실행하지 않기 때문이다. 정지도 진단도 없이 게스트가 로그인 프롬프트까지
부팅해 버린다. 4개 트리 모두에서 독립적으로 재현된 문제였다.

지금은 **slide가 미상인 상태에서 고VA를 겨냥한 브레이크/워치포인트를 걸면**, 툴이 그 arch의 물리→고VA
크로싱에 캐처를 자동으로 무장한다. 실행이 크로싱에 닿는 순간 slide를 읽어 심볼을 재배치하고 캐처는 스스로
회수된다. 사용자는 아무 명령도 더 치지 않는다.

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

arm64 · riscv64 · x86_64 모두 **정지 없이(무음)** 통과한다 — 크로싱 착지 주소를 레지스터(arm64 `x8`/`x27`),
전역(`kernel_map.virt_addr`), 또는 간접점프 슬롯(x86 `jmp *0f(%rip)`의 타깃 qword)에서 **물리 읽기로만**
얻기 때문에 CPU를 움직이지 않는다.

사용자가 건 브레이크·워치포인트가 크로싱보다 **먼저** 발화해도 무너지지 않는다. 그 경우 캐처는 지속형으로
남아 사용자의 정지를 존중하고, 나중에 실행이 크로싱에 닿을 때 적용된다:

```
Thread 1 hit Hardware watchpoint 2: *(unsigned long long *)0x43a56000
preserve_boot_args () at arch/arm64/kernel/head.S:174
[kgdb] kaslr: another breakpoint stopped first (pc=0x42bca710) -- left a PERSISTENT catcher [bp 5]
       on the crossing (phys 0x42bb8518).  Keep debugging: the slide is read and applied
       automatically the moment execution reaches it.
```

### x86_64는 한 겹 더

x86은 물리 로드 주소까지 랜덤화되므로(arm64/riscv은 가상만) 콜드 프로즌 시점엔 메인 커널이 아직 RAM에도
없다. 툴은 `$pc`가 디컴프레서 적재 주소(`0x100000`) 아래, 즉 리셋 벡터에 있는 것을 보고 콜드 프로즌임을
확정하고 디컴프레서 체인으로 랜덤 물리 베이스를 먼저 복구한다. **환경변수나 플래그가 필요 없다.**

```
[kgdb] x86 KASLR: extract_kernel reached; decompressing kernel (finish) ...
[kgdb] x86 KASLR: recovered main-kernel phys base 0x0000000039e00000 via the decompressor
[kgdb] KASLR slide = 0x13e00000 applied
Thread 1 hit Breakpoint 5.2, start_kernel () at init/main.c:915
```

### 실측 (4개 트리, KASLR on, R0에서 무장)

ELF 링크값(`nm vmlinux`)과 라이브 착지 주소의 차이로 **툴과 독립적으로** 교차검증했다.

| 트리 | 자동 적용 slide | 라이브 `start_kernel` − ELF 링크값 | 일치 |
|---|---|---|---|
| arm64-v6.12 | `0x3de518400000` | `0x3de518400000` | ✓ |
| arm64-v4.6 (EOL) | `0x192229c00000` | `0x192229c00000` | ✓ |
| riscv64-v6.12 | `0x1fe00000` | `0x1fe00000` | ✓ |
| x86_64-v6.12 | `0x3e00000` | `0x3e00000` | ✓ |

### 전수 조합 검증에서 드러난 것 (2026-07-19)

무장 시점(리셋 벡터 / MMU-off 진입 / head.S 중간 / 절반 활성화 / 크로싱 위 / 완전 가상) ×
프로브 종류(`b` / `kb` / `watch` / `kw` / `b *ADDR` / `b FILE:LINE` / `hbreak` / `kw -r` / `kw -a`) ×
대상 regime × KASLR on·off 를 4개 트리에서 훑은 결과, **캐처가 처음에는 `b SYM` 형태에서만
동작**하고 있었다. 원인은 "이 프로브가 고VA를 겨냥하는가"를 다중 위치 브레이크의 `N.M  y  0xADDR`
행을 파싱해 판정한 것이었다 — 워치포인트는 주소 열 자체가 없고 단일 위치 `b *ADDR`은 그 행이 없어,
둘 다 판정에서 조용히 탈락했다. 지금은 판별을 하지 않고 **slide가 미상이면 프로브 종류를 불문하고**
캐처를 무장한다(브레이크 1개를 쓰고 크로싱에서 스스로 회수된다).

같은 스윕에서 함께 고친 것:

- `delete` 로 캐처를 지우면 `_kaslr_pending` 기록이 남아 이후 재무장을 **영구 차단**했다. 캐처
  브레이크의 생존 여부를 확인해, 사라졌으면 기록을 버리고 다시 건다.
- 크로싱 PA 위에 이미 서 있는 상태에서 프로브를 걸면 조기 반환해 slide가 영영 적용되지 않았다.
  그 자리에서 바로 읽어 적용한다.
- 리셋 벡터(커널 진입 이전, 미캘리브레이션)에서 건 프로브도 이제 캐처를 받는다(먼저 캘리브레이션을
  시도한다).
- **x86 간헐 결함**: 디컴프레서 단계에서 만들어진 캘리브레이션·shadow가 남아, 랜덤 베이스를 복구한
  뒤의 계산을 오염시켰다(offset이 nokaslr 기본값 `0x1000000` 기준으로 나옴). 3~4회 중 1회꼴로
  재현됐다. 베이스를 복구하면 offset·slide·shadow·pending을 모두 비우고 다시 잡는다.

리터럴 주소는 "정확히 이 주소"라는 뜻이라 툴이 그것을 **옮기는** 것은 사용자 지시를 배신한다.
그래서 리터럴은 그 자리에 그대로 두고, 옆에 regime 인지 형제 위치를 **추가로** 건다(§11.5).

### 레짐 교차 검증에서 드러난 것 (2026-07-20)

앞의 스윕은 무장 *시점*을 훑었지만 대상은 거의 `start_kernel` — 이미 가상 주소 체계가 다 선 뒤에만
실행되는 심볼 — 이었다. 이번에는 대상 쪽을 head.S 안으로 옮겨, 각 트리의 vmlinux에서 뽑은 다섯
레짐(MMU off / idmap / 전이 명령 그 자체 / 첫 가상 명령 / start_kernel)을 **서로 교차**시켰다.
판정은 툴이 관여하지 않는 오라클로 한다: 정지한 `$pc`에서 게스트 메모리를 읽어 `objdump`가 ELF에서
뽑은 바이트와 대조한다.

발견하여 고친 것:

- **삭제한 프로브가 되살아났다.** `kb` / `kw` / adopt가 만든 그룹은 `delete` 후에도 장부에 남아,
  크로싱에서 slide가 확정되는 순간 `_rearm_kb`가 그것을 `linkVA + slide`에 **다시 만들었다**.
  arm64 v4.6에서 `kb __mmap_switched; continue; delete; kb start_kernel; continue` 가
  start_kernel이 아니라 지운 `__mmap_switched`에 멈추는 것으로 드러났다. 이제 그룹이 소유한
  브레이크포인트가 모두 사라지면 그룹도 버린다. 사용자가 만든 `b`에 딸린 형제 브레이크포인트도
  함께 정리하되, gdb의 삭제 콜백 안에서 브레이크포인트를 건드리면 gdb가 죽으므로 다음 안전 지점까지
  미룬다.
- **단일 위치 프로브는 형제를 못 받았다.** `_bp_locations`가 다중 위치 행(`N.M  y  0xADDR`)만
  파싱해서 `b *0xLINKVA` / `b FILE:LINE` 같은 단일 위치 프로브에는 언제나 빈 목록을 돌려줬고,
  adopt가 그 앞에서 조기 반환했다. 두 형태를 모두 인식한다.
- **x86에서는 adopt가 아예 걸리지 않았다.** `phys_window`가 `0x100000..0x10000000`(1MB~256MB)로
  박혀 있었는데, x86 KASLR은 **물리** 베이스까지 랜덤화한다 — 실측 부팅은 `0x52a00000`,
  `0x7ba00000`에 올라갔다. arm64·riscv는 QEMU `-kernel`이 물리 베이스를 고정하므로 좁은 창이
  맞지만 x86은 아니다. 창을 넓히고, adopt는 "이 주소가 커널 이미지 안인가"를 `_text`..`_end`로
  직접 묻도록 바꿨다.
- **riscv 트랩 경계에서는 서 있는 자리를 읽을 수 없었다.** `csrw satp` 다음 페치는 폴트하도록
  설계돼 있고 QEMU는 **트랩이 전달되기 전, 폴팅 페치 시점**에 멈춘다. 그래서 `$pc`가 물리값인데
  그 값은 새 매핑에서 유효한 VA가 아니고 `x`가 실패한다. 이 상태를 없앨 수는 없으므로 — 실재하는
  기계 상태다 — 대신 그 자리에서 메모리를 볼 수 있게 `kx`를 만들었다(§10.6).

### 11.5 리터럴 링크 주소 — 옮기지 않고, 옆에 건다

head.S를 `objdump`로 읽으며 분석하면 눈에 들어오는 것은 **링크 주소**다. 그것을 그대로 치는 것이
가장 자연스러운 동작이다:

```
(gdb) b *0xffff8000829b80a8
Breakpoint 2 at 0xffff8000829b80a8
[kgdb] note: 0xffff8000829b80a8 is a LINK address and this kernel is KASLR-relocated, so that
       exact byte will not be executed once the slide is known.  Its physical twin has been
       armed alongside, so a probe here still fires while the MMU is off.

(gdb) info breakpoints
2   breakpoint     keep y   0xffff8000829b80a8 <primary_entry+8>
3   hw breakpoint  keep y   0x0000000042bb80a8 <primary_entry+8>      <- 추가된 형제
```

사용자가 친 리터럴(2번)은 그 자리에 그대로 있다. 옆에 물리 트윈(3번)이 붙고, 크로싱에서 slide가
확정되면 IMG 형제가 `linkVA + slide`로 재무장된다. 실측: 물리 레짐 대상은 3번이, `start_kernel`
같은 가상 레짐 대상은 재무장된 IMG 형제가 각각 발화한다.

슬롯 비용은 리터럴당 최대 2개로 `kb`와 같다. 이미 두 위치를 가진 `b SYM`(shadow 덕에 다중 위치)은
후보가 이미 덮여 있으므로 **아무것도 추가하지 않는다**.

### 캐처는 왜 internal 브레이크포인트인가

캐처는 gdb의 **internal 브레이크포인트**로 걸린다. `info breakpoints`에 나타나지 않고, 무엇보다
**`delete`가 지우지 못한다**. 사용자가 자기 브레이크포인트를 전부 지운 뒤 워치포인트만 걸고 이어가도
slide는 여전히 적용된다.

이 구조가 필요한 이유는 gdb 내부 제약 때문이다. gdb의 `watch_command_1`은 워치포인트를 만드는 도중
브레이크포인트 체인의 끝이 그 워치포인트여야 한다고 단정(assert)한다. 그래서 **워치포인트 생성 이벤트
안에서 브레이크포인트를 만들면 gdb가 internal-error로 죽고 코어를 덤프한다** — 방식(CLI냐 Python
API냐)과 무관하게 시점의 문제다. 반대로 일반 브레이크포인트 생성 중에는 안전하다.

그래서 무장 규칙은 이렇다:

- 생성되는 프로브가 **워치포인트이면 무장하지 않는다**(요청만 기록). 그 자리에서 만들면 gdb가 죽는다.
- 그 외에는 그 자리에서 internal 캐처를 만든다.
- 캘리브레이션·정지 훅·gdb 프롬프트 같은 안전한 지점에서도 미처리 요청을 처리한다.

정상 흐름에서는 `kearly bootbreak`의 캘리브레이션 시점에 이미 캐처가 걸리므로, 사용자가 무엇을 먼저
걸든 이미 준비돼 있다. 워치포인트를 맨 처음 거는 경우가 문제되지 않는 것도 이 때문이다.

### 검증이 순환적이지 않다는 근거

`기대값 = 링크값 + slide` 로 맞춰보는 것은 **항등식이지 측정이 아니다** — 브레이크는 무장한 주소에서
발화하므로, slide가 틀렸어도 "관측 == 기대"는 성립한다. 툴 바깥의 증인이 두 개 필요하다.

1. **정지 지점의 게스트 메모리 바이트가 ELF 원본과 일치**한다. slide가 틀렸다면 그 주소에는 다른
   코드가 있다. arm64-v6.12 / arm64-v4.6 / riscv64 에서 `start_kernel` 첫 16바이트가 `objdump` 값과
   정확히 일치함을 확인했다(예: arm64-v4.6 `fd7bbba9 c0220090 00002491 fd030091`).
2. **커널이 스스로 출력한 주소**. x86은 `Kernel Offset: 0x… from 0xffffffff81000000` 을,
   arm64-v4.6·riscv64는 부팅 로그의 메모리 레이아웃을 찍는다. arm64-v6.12는 상류에서 그 출력이
   제거되어 1번으로 대신한다.

### 알려진 제약

- **riscv은 `--cpu max`가 필요하다.** 기본 `rv64` 모델에는 Zkr SEED CSR이 없고 QEMU가 만드는 DTB에는
  `/chosen/kaslr-seed`가 없어, 커널이 엔트로피를 못 찾고 slide가 **조용히 0**이 된다. KASLR을 켰다고
  믿은 채 아무것도 랜덤화되지 않은 상태를 시험하게 되므로, 이 경우를 조심한다.
- **x86은 압축 해제 이전 시점에 커널 심볼을 걸 수 없다.** `--earliest`(리셋 벡터) 또는
  `--no-calibrate`로 붙은 상태에서 `b start_kernel` / `watch system_state` 같은 프로브를 걸면,
  그 순간 메모리에는 bzImage 디컴프레서만 있고 커널은 아직 압축된 데이터다 — 그 심볼의 주소가
  기계 어디에도 존재하지 않으므로 어떤 디버거로도 걸 수 없다. 툴은 조용히 빗나가는 대신 이유와
  대처법을 알린다:

  ```
  [kgdb] kaslr: the kernel is still compressed at this point, so there is nothing to
         calibrate against yet -- run `kearly bootbreak` first (it recovers the
         randomized base), then re-arm.
  ```

  `kearly bootbreak`가 디컴프레서 체인으로 랜덤 물리 베이스를 복구하면 **이미 걸어둔 프로브가
  스스로 따라간다** — 다시 걸 필요가 없다. 실측(`--earliest`, x86 KASLR): 리셋 벡터에서
  `b start_kernel`을 걸면 브레이크포인트가 링크 주소에 생기고, `kearly bootbreak`가 베이스
  `0x48200000`을 복구하는 순간 gdb가 재배치된 심볼로 다시 풀어 `<MULTIPLE>`이 되며, 이어지는
  `continue`가 재배치된 `0xffffffffaaf4ea60`에 걸린다. 즉 명령 3개(`b` → `bootbreak` →
  `continue`)로 끝난다. 불가피한 것은 "커널이 RAM에 없는 동안에는 발화할 수 없다"는 사실뿐이다. arm64·riscv에는 이 제약이 없다 — QEMU가 `-kernel`로 커널을 통째로 RAM에
  올리므로 리셋 벡터에서도 위치를 알 수 있고, 두 아키텍처 모두 이 케이스를 실제로 통과한다.
  즉 아키텍처의 물리적 차이이지 구현 미비가 아니다.

  자동으로 디컴프레서 복구를 돌려버리는 선택지도 있었지만 택하지 않았다. `--earliest`와
  `--no-calibrate`는 "CPU를 진행시키지 말라"는 지시이고, 복구는 `extract_kernel`까지 실행해야
  하므로 그 지시를 어기게 된다.

- **arm64 6.12의 `.idmap.text` 구간에는 소스 라인 정보가 없다.** `primary_entry` / `__enable_mmu` /
  `__primary_switch` — 즉 MMU가 "절반만 켜진" 바로 그 구간이다. 원인은 `arch/arm64/kernel/head.S`의
  `.section ".idmap.text","a"` 선언에 실행(`x`) 플래그가 없어 어셈블러가 그 섹션에 DWARF 라인 정보를
  생성하지 않는 것이다(`head.o`의 `.rela.debug_line`에 해당 섹션 항목이 아예 없다). 어떤 빌드 산물에도
  정보가 없으므로 디버거로는 복원할 수 없다 — `cfgdis`의 심볼+오프셋 디스어셈블과 `stepi`로 따라간다.
  arm64 v4.6은 같은 코드가 `.text`에 있어 라인 정보가 정상이다(head.S:772/788/811).

---

## 교차 검증 (직접 부팅·실측)

| 아키텍처 | 페이징 | 단수 | 검증 |
|---|---|---|---|
| arm64 v4.6 | 4KB/48-bit | 4 | kpt(초기 2MB block·런타임 4KB page 모두 kv2p MATCH), kpgd, mmview, kcensus(88), 패널, chaindepth |
| x86_64 v6.12 (LA57) | 5-level | 5 | kpt/mmview 5단계, 커널 필터 |
| x86_64 v6.12 (`no5lvl`) | 4-level | 4 | kpt PML4→PDPT→PD, kv2p MATCH |
| riscv64 v6.12 | Sv57 | 5 | kpt L4→L1 BLOCK kv2p MATCH, mmview, kcensus(21 CSR) |

모두 pwndbg를 라이브러리로만 쓴 채(미개조) 크래시 없이 통과.

---

## 설계 원칙 (요약)

- **pwndbg 미개조** — 라이브러리로만 사용. 없어도 평문으로 동작.
- **MMU on 이후 물리 읽기** — `monitor xp`(HMP, qRcmd 터널). gdb `x`/`hexdump`는 그 시점 PT로 번역돼 실패.
- **세션 불가침** — 모든 gdb 호출은 safe 레이어를 통과, 실패해도 no-op. 텔레스코프·페이지워크·열거자는
  전부 유한(깊이 상한/레벨 카운터/노드·리프 상한)이라 무한재귀 불가.
- **추가만, 삭제 없음** — 기존 명령·동작은 보존하고 기능만 얹었다.
