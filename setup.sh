#!/usr/bin/env bash
# Wire this checkout into gdb, and record where it is so other tools can find it.
#
# Nothing is written into the repository: clone it anywhere, run this, and the
# one machine-specific path lives in your gdb init file, generated rather than
# hand-written.
set -euo pipefail

REPO="$(cd -P "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
LOADER="${REPO}/gdbtools.py"
CONF="${XDG_CONFIG_HOME:-$HOME/.config}/gdbtools"
BEGIN="# >>> gdbtools >>>"
END="# <<< gdbtools <<<"
MODE="install"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check)     MODE="check"; shift ;;
        --uninstall) MODE="uninstall"; shift ;;
        -h|--help)
            cat <<USAGE
usage: setup.sh [--check] [--uninstall]

  (no option)  write the loader line into the gdb init file gdb actually reads
  --check      report the current state and change nothing
  --uninstall  remove what this script added; the checkout is left alone
USAGE
            exit 0 ;;
        *) echo "setup.sh: unknown option '$1'" >&2; exit 2 ;;
    esac
done

say()  { printf '  %s\n' "$*"; }
warn() { printf '  [!] %s\n' "$*" >&2; }

# Which file does gdb actually read?  Asked, not assumed.  gdb reads exactly ONE
# user init file: if ~/.config/gdb/gdbinit exists it is used and ~/.gdbinit is
# ignored entirely, so creating the XDG file on a machine that has ~/.gdbinit
# would silently drop every line in it, pwndbg included.
gdb_init_file() {
    local f
    if command -v gdb >/dev/null 2>&1; then
        f="$(gdb --help 2>/dev/null | sed -n 's/^ *\* user-specific init file: *//p' | head -1)"
        [[ -n "$f" ]] && { printf '%s\n' "$f"; return 0; }
    fi
    f="${XDG_CONFIG_HOME:-$HOME/.config}/gdb/gdbinit"
    [[ -f "$f" ]] && { printf '%s\n' "$f"; return 0; }
    printf '%s\n' "$HOME/.gdbinit"
}

INIT="$(gdb_init_file)"

block() {
    cat <<BLOCK
${BEGIN}
# gdb extensions: control-flow graphs, arrowed disassembly, address
# symbolization, and early-boot Linux kernel symbolization.  Silent and inert
# until a target needs it.  Written by setup.sh -- edit the path only if the
# checkout moved, and keep this block BELOW any pwndbg line.
source ${LOADER}
${END}
BLOCK
}

has_block()   { [[ -f "$INIT" ]] && grep -qF "$BEGIN" "$INIT"; }
strip_block() {
    [[ -f "$INIT" ]] || return 0
    awk -v b="$BEGIN" -v e="$END" '
        index($0,b){skip=1} !skip{print} index($0,e){skip=0}' "$INIT" > "${INIT}.gdbtools.tmp"
    mv "${INIT}.gdbtools.tmp" "$INIT"
}

if [[ "$MODE" == "check" ]]; then
    echo "gdbtools doctor"
    say "repo          ${REPO}"
    say "loader        $([[ -f "$LOADER" ]] && echo "$LOADER" || echo "MISSING $LOADER")"
    say "gdb init file ${INIT}"
    if has_block; then
        say "loader line   present"
        if grep -q 'source .*pwndbg' "$INIT" 2>/dev/null; then
            if [[ "$(grep -n 'source .*pwndbg' "$INIT" | head -1 | cut -d: -f1)" \
                  -lt "$(grep -n "$BEGIN" "$INIT" | head -1 | cut -d: -f1)" ]]; then
                say "pwndbg order  ok (pwndbg first)"
            else
                warn "pwndbg is sourced AFTER this block; move the block below it"
            fi
        fi
    else
        warn "loader line absent from ${INIT} -- run setup.sh"
    fi
    say "root pointer  $([[ -r "${CONF}/root" ]] && cat "${CONF}/root" || echo '(unset)')"
    if command -v gdb >/dev/null 2>&1; then
        if gdb -q -batch -ex 'python import gdbtools' >/dev/null 2>&1; then
            say "gdb import    ok"
        else
            warn "gdb cannot import the package"
        fi
    fi
    exit 0
fi

if [[ "$MODE" == "uninstall" ]]; then
    strip_block && say "removed the loader block from ${INIT}"
    rm -rf "$CONF" && say "removed ${CONF}"
    say "the checkout at ${REPO} was left alone"
    exit 0
fi

echo "installing gdbtools from ${REPO}"
mkdir -p "$(dirname "$INIT")"
strip_block
# Appended, never prepended.  pwndbg refuses to load over a command another
# extension already registered and aborts its whole command set, so anything of
# ours that shares a name has to come second.
block >> "$INIT"
say "gdb init file ${INIT}  (loader line written)"

mkdir -p "$CONF"
printf '%s\n' "$REPO" > "${CONF}/root"
say "root pointer  ${CONF}/root"

echo
"${REPO}/setup.sh" --check
