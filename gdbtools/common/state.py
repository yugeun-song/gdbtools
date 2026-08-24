"""Late-bound singleton registry.

The single-file layout let helpers defined near the top of the file reach the
Session instance created ~4000 lines below, because the name was only resolved
at call time.  Splitting into modules turns that into a real import cycle
(physmem -> session -> physmem).  This module owns the binding instead: it
imports nothing, so it sits at the very bottom of the graph and every layer can
depend on it.  session.py publishes the instance here at construction time.
"""

_SESSION = None


def set_session(s):
    global _SESSION
    _SESSION = s


def session():
    """The live Session, or None before bootstrap.  Callers must tolerate None --
    the same contract the old deferred-name-lookup had when SESSION did not exist
    yet."""
    return _SESSION
