#!/usr/bin/env bash
# Record where this checkout is, so the tools that start gdb (kbuildlab, the nvim
# adapter, `gdbtools gdb`) can source it.  A plain gdb stays stock: nothing goes
# into the gdb init file unless --global asks for it.
#
# Nothing is written into the repository: clone it anywhere and run this.
set -euo pipefail

REPO="$(cd -P "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
LOADER="${REPO}/gdbtools.py"
CONF="${XDG_CONFIG_HOME:-$HOME/.config}/gdbtools"
BEGIN="# >>> gdbtools >>>"
END="# <<< gdbtools <<<"
MODE="library"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check)              MODE="check"; shift ;;
        --uninstall)          MODE="uninstall"; shift ;;
        --library|--no-global) MODE="library"; shift ;;
        --global)             MODE="install"; shift ;;
        -h|--help)
            cat <<'USAGE'
usage: setup.sh [--global] [--check] [--uninstall]

  (no option)  record the root pointer only, and take any loader line this
               script wrote out of the gdb init file: a plain gdb stays stock,
               and kbuildlab, the nvim adapter and `gdbtools gdb` source
               gdbtools.py themselves
  --global     also write the loader line into the gdb init file gdb reads,
               so every gdb loads gdbtools
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
# Rewritten in place (cat >), never replaced (mv): a symlinked init file stays a
# symlink and keeps its mode.  Untouched when there is no block to remove.
strip_block() {
    has_block || return 0
    local tmp
    tmp="$(mktemp "${TMPDIR:-/tmp}/gdbtools-init.XXXXXX")"
    if ! awk -v b="$BEGIN" -v e="$END" '
            index($0,b){skip=1} !skip{print} index($0,e){skip=0}' "$INIT" > "$tmp"; then
        rm -f "$tmp"
        return 1
    fi
    cat "$tmp" > "$INIT"
    rm -f "$tmp"
}

if [[ "$MODE" == "check" ]]; then
    echo "gdbtools doctor"
    say "repo          ${REPO}"
    say "loader        $([[ -f "$LOADER" ]] && echo "$LOADER" || echo "MISSING $LOADER")"
    say "gdb init file ${INIT}"
    if has_block; then
        say "loader line   present (global source)"
        if grep -q 'source .*pwndbg' "$INIT" 2>/dev/null; then
            if [[ "$(grep -n 'source .*pwndbg' "$INIT" | head -1 | cut -d: -f1)" \
                  -lt "$(grep -n "$BEGIN" "$INIT" | head -1 | cut -d: -f1)" ]]; then
                say "pwndbg order  ok (pwndbg first)"
            else
                warn "pwndbg is sourced AFTER this block; move the block below it"
            fi
        fi
    elif [[ -r "${CONF}/root" ]]; then
        say "loader line   absent (library mode: kbuildlab, nvim and \`gdbtools gdb\` source it)"
    else
        warn "no root pointer and no loader line -- run setup.sh"
    fi
    say "root pointer  $([[ -r "${CONF}/root" ]] && cat "${CONF}/root" || echo '(unset)')"
    if command -v gdb >/dev/null 2>&1; then
        # gdb -batch exits non-zero when its LAST command fails; `help cmdinfo` only
        # succeeds if the loader got as far as registering the commands.
        if gdb -q -nx -batch -ex "source $LOADER" -ex 'help cmdinfo' >/dev/null 2>&1; then
            say "gdb load      ok"
        else
            warn "gdb cannot load the package: gdb -nx -batch -ex 'source $LOADER'"
        fi
    fi
    exit 0
fi

if [[ "$MODE" == "library" ]]; then
    echo "installing gdbtools (library mode) from ${REPO}"
    if has_block; then
        strip_block
        say "gdb init file ${INIT}  (the global source line was removed)"
    else
        say "gdb init file ${INIT}  (not touched)"
    fi
    mkdir -p "$CONF"
    printf '%s\n' "$REPO" > "${CONF}/root"
    say "root pointer  ${CONF}/root"
    say "gdb stays stock; a caller sources ${LOADER}"
    echo
    "${REPO}/setup.sh" --check
    exit 0
fi

if [[ "$MODE" == "uninstall" ]]; then
    # Only what setup.sh writes: the init-file block and ${CONF}/root.  Anything
    # else in ${CONF} (an env file, profiles) is the user's and stays.
    if has_block; then
        strip_block
        say "removed the loader block from ${INIT}"
    fi
    if [[ -e "${CONF}/root" ]]; then
        rm -f "${CONF}/root"
        say "removed ${CONF}/root"
    fi
    if rmdir "$CONF" 2>/dev/null; then
        say "removed ${CONF} (it was empty)"
    fi
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
