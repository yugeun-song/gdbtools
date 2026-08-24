"""Kernel-side architecture classes.

Importing this module registers them over the target-independent ones, so
`gdbtools.common.arch.detect_arch()` starts returning the full class.
"""
from ...common.arch import register
from .base import KernelArch
from .x86_64 import X86_64
from .arm64 import Arm64
from .riscv64 import Riscv64

for _cls in (X86_64, Arm64, Riscv64):
    register(_cls)

ARCHES = [X86_64, Arm64, Riscv64]

__all__ = ["KernelArch", "X86_64", "Arm64", "Riscv64", "ARCHES"]
