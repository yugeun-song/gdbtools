"""Target-independent half of gdbtools.

Nothing here needs the debuggee to be a kernel: it works against an ordinary
process, a core file or a bare-metal target alike.  Imports run one way only --
`common` never reaches into `linux_kernel`; where a richer answer exists when the
kernel side happens to be loaded, it is reached through the late-bound
`state.session()` handle, which is None when it is not.
"""
