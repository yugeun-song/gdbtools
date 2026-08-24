"""Linux kernel half of gdbtools: early-boot (pre-MMU) symbolization.

Before head.S switches the MMU to the kernel's high mapping, $pc and pointers
hold PHYSICAL addresses while gdb's symbol table is linked at VIRTUAL ones, so
symbolization is dead exactly where it is needed most.  This half calibrates the
per-boot phys<->virt offset from a head.S anchor -- measured at runtime, never a
constant, so it survives KASLR, a different load address and a different kernel
version -- and loads a phys-shifted shadow symbol file, which revives stock gdb
and pwndbg alike without patching either.

Everything here is inert until a kernel target is actually loaded.
"""
