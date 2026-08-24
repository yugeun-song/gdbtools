"""part of gdbtools; see the package docstring."""


# ----------------------------------------------------------------------------
# Boot-combination presets.  The DEFAULT per arch is the verified lab env and
# changes nothing; the others adapt the anchor symbol / breakpoint kind for a
# different firmware/boot-protocol.  `anchor=None` means "use the arch's image
# base symbol" (_text / _start / startup_64); a non-None anchor breaks at that
# symbol's physical address instead (e.g. UEFI enters primary_entry, not _text).
# `verified` marks combos actually live-tested in this lab.  Anything not covered
# is reachable with the the $GDBTOOLS_ENTRY_PA / _ANCHOR / _RAM_BASE / _BREAK_KIND overrides,
# or fully described by a --profile JSON / --dtb for a non-QEMU board.
# ----------------------------------------------------------------------------
PRESETS = {
    # x86_64
    "x86-default": {"arch": "x86_64", "anchor": None, "break_kind": None, "verified": True,
                    "desc": "-M pc/q35 + -kernel bzImage + SeaBIOS, nokaslr (lab default)"},
    "x86-pvh": {"arch": "x86_64", "anchor": "pvh_start_xen", "break_kind": "sw", "verified": False,
                "desc": "-kernel vmlinux PVH boot; needs CONFIG_PVH=y so pvh_start_xen exists"},
    "x86-uefi": {"arch": "x86_64", "anchor": None, "break_kind": "hw", "verified": False,
                 "desc": "OVMF/EFI-stub; if the kernel relocates off 0x1000000 pass --entry-pa"},
    "x86-grub": {"arch": "x86_64", "anchor": None, "break_kind": "hw", "verified": False,
                 "desc": "GRUB multiboot/EFI chainload; load addr varies -> pass --entry-pa"},
    # arm64
    "arm64-default": {"arch": "arm64", "anchor": None, "break_kind": None, "verified": True,
                      "desc": "-M virt + -kernel Image + QEMU boot stub (lab default)"},
    "arm64-uefi": {"arch": "arm64", "anchor": "primary_entry", "break_kind": "sw", "verified": False,
                   "desc": "edk2/EFI-stub enters primary_entry, skipping the _text header"},
    "arm64-uboot": {"arch": "arm64", "anchor": None, "break_kind": "sw", "verified": False,
                    "desc": "u-boot booti; like default, supply --dtb/--ram-base for the load addr"},
    "arm64-atf": {"arch": "arm64", "anchor": None, "break_kind": "sw", "verified": False,
                  "desc": "ATF/TF-A BL31 -> kernel at EL1; same image base, use --dtb for RAM base"},
    # riscv64
    "riscv-default": {"arch": "riscv64", "anchor": None, "break_kind": None, "verified": True,
                      "desc": "-M virt + OpenSBI fw_jump/fw_dynamic (lab default)"},
    "riscv-uefi": {"arch": "riscv64", "anchor": "_start_kernel", "break_kind": "sw", "verified": False,
                   "desc": "EFI-stub enters _start_kernel, skipping _start"},
    "riscv-uboot": {"arch": "riscv64", "anchor": None, "break_kind": "sw", "verified": False,
                    "desc": "u-boot booti after SBI; supply --dtb/--ram-base for the load addr"},
    "riscv-mmode": {"arch": "riscv64", "anchor": None, "break_kind": "sw", "verified": False,
                    "desc": "M-mode/nommu; satp stays 0 -- set --ram-base 0x80000000"},
}


__all__ = ['PRESETS']
