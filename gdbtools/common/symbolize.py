"""Address -> symbol, without assuming the target is a kernel."""
from .runtime import MASK, safe, execstr
from . import state


@safe(default=None)
def info_symbol(addr):
    """What gdb's own symbol table says about `addr`, or None."""
    out = (execstr("info symbol 0x%x" % (addr & MASK)) or "").strip()
    if not out or "No symbol matches" in out:
        return None
    return out


def resolve(addr):
    """(kind, addr, text|None), kind in {"VA", "PA", "ADDR"}, or None.

    Asked of the kernel session when one is loaded, so a calibrated kernel still
    gets its phys<->virt answer.  Otherwise gdb's symbol table answers directly
    and the result is reported as "ADDR": with no map established there is no
    basis for calling an address physical or virtual.
    """
    if addr is None:
        return None
    s = state.session()
    if s is not None:
        r = s.symbolize(addr)
        if r is not None:
            return r
    return ("ADDR", addr & MASK, info_symbol(addr))


def short(text):
    """The symbol name alone, with gdb's ` in section ...` tail removed."""
    return text.split(" in section")[0].strip() if text else None


__all__ = ["info_symbol", "resolve", "short"]
