"""`sym` -- what is at this address."""
import gdb

from .runtime import *
from .symbolize import resolve


class Sym(gdb.Command):
    """sym ADDR : name the symbol at ADDR.

With a calibrated kernel session ADDR may be physical or virtual and the answer
says which, translating a physical address to its kernel virtual one first.
Otherwise the address is looked up as given."""

    def __init__(self, name="sym"):
        super(Sym, self).__init__(name, gdb.COMMAND_USER)

    @safe()
    def invoke(self, arg, from_tty):
        addr = evi(arg)
        if addr is None:
            print("usage: sym ADDR")
            return
        res = resolve(addr)
        if res is None:
            print("[%s] cannot resolve %s" % (NAME, fmt(addr)))
            return
        kind, out, text = res
        if kind == "PA":
            print("%s (PHYS) -> VA %s  %s" % (fmt(addr), fmt(out), text or "<no sym>"))
        elif kind == "VA":
            print("%s (VA)  %s" % (fmt(addr), text or "<no sym>"))
        else:
            print("%s  %s" % (fmt(addr), text or "<no sym>"))


__all__ = ["Sym"]
