#!/usr/bin/env bash
# Put the `gdbtools` command on PATH and record this checkout for kbuildlab and
# the nvim adapter.  The command is a symlink into this checkout, so a `git pull`
# here updates it.
#
#   ./install.sh                  ~/.local/bin (XDG_BIN_HOME), for this user
#   ./install.sh --system         /usr/local/bin, for every user (run with sudo)
#   ./install.sh --prefix DIR     DIR/bin
#   ./install.sh --global         also load gdbtools in every gdb (setup.sh --global)
#   ./install.sh --check | --uninstall
#
# Both default directories are on PATH on Debian, Ubuntu, Fedora, RHEL and
# openSUSE once they exist; on Arch and Void ~/.local/bin is added by the
# user's shell setup, and this says how when it is missing.  Shell files are
# never edited.
set -euo pipefail
REPO="$(cd -P "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
NAME=gdbtools
MODE=install; WHERE=user; PREFIX=""; GLOBAL=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --user) WHERE=user; shift ;;
        --system) WHERE=system; shift ;;
        --prefix) WHERE=prefix; PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
        --global) GLOBAL=1; shift ;;
        --check) MODE=check; shift ;;
        --uninstall) MODE=uninstall; shift ;;
        -h|--help) awk 'NR > 1 && !/^#/ {exit} NR > 1 {sub(/^# ?/, ""); print}' "$0"; exit 0 ;;
        *) echo "install.sh: unknown option '$1'" >&2; exit 2 ;;
    esac
done

if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != dumb ]]; then
    G=$'\e[32m' R=$'\e[31m' C=$'\e[36m' D=$'\e[2m' N=$'\e[0m'
else G="" R="" C="" D="" N=""; fi
case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
    *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*) OKM="✓" NOM="✗" ;; *) OKM="+" NOM="x" ;;
esac
ok()  { printf '  %s%s%s %s\n' "$G" "$OKM" "$N" "$*"; }
bad() { printf '  %s%s%s %s\n' "$R" "$NOM" "$N" "$*"; }
say() { printf '  %s%-12s%s %s\n' "$C" "$1" "$N" "${*:2}"; }

case "$WHERE" in
    user)   BIN="${XDG_BIN_HOME:-$HOME/.local/bin}" ;;
    system) BIN=/usr/local/bin ;;
    prefix) BIN="${PREFIX%/}/bin" ;;
esac
LINK="$BIN/$NAME"
TARGET="$REPO/bin/$NAME"

on_path() { case ":$PATH:" in *":$1:"*) return 0 ;; esac; return 1; }

path_hint() {
    on_path "$BIN" && return 0
    bad "$BIN is not on PATH; add it in your shell's startup file:"
    printf '      bash, zsh:  export PATH="%s:$PATH"\n' "$BIN"
    printf '      fish:       fish_add_path %s\n' "$BIN"
}

# Root's config is not the user's: the record kbuildlab and nvim read is the
# user's own, written by `gdbtools install` run as that user.
as_user_setup() {
    if [[ "$(id -u)" -eq 0 ]]; then
        say next "as yourself, not root: gdbtools install$([[ $GLOBAL -eq 1 ]] && echo ' --global')"
        return 0
    fi
    if [[ $GLOBAL -eq 1 ]]; then "$REPO/setup.sh" --global; else "$REPO/setup.sh"; fi
}

# Whether a user other than the owner can reach PATH (every directory on the
# way needs its others-execute bit).
others_reach() {
    local d="$1"
    while [[ "$d" != / && -n "$d" ]]; do
        [[ "$(stat -c %A "$d" 2>/dev/null)" == *[xt] ]] || return 1
        d="$(dirname "$d")"
    done
}

case "$MODE" in
    check)
        if [[ -L "$LINK" && "$(readlink -f "$LINK")" == "$TARGET" ]]; then ok "$LINK -> $TARGET"
        else bad "$LINK is not this checkout's $NAME"; fi
        path_hint
        "$REPO/setup.sh" --check ;;
    uninstall)
        if [[ -L "$LINK" && "$(readlink -f "$LINK")" == "$TARGET" ]]; then
            rm -f "$LINK" && ok "removed $LINK"
        else
            say kept "$LINK (it is not a link to this checkout)"
        fi
        [[ "$(id -u)" -eq 0 ]] || "$REPO/setup.sh" --uninstall ;;
    install)
        if [[ ! -d "$BIN" ]]; then
            mkdir -p "$BIN" 2>/dev/null || { bad "cannot create $BIN$([[ $WHERE == system ]] && echo ' -- run with sudo')"; exit 1; }
        fi
        [[ -w "$BIN" ]] || { bad "$BIN is not writable$([[ $WHERE == system ]] && echo ' -- run with sudo')"; exit 1; }
        if [[ -e "$LINK" && ! -L "$LINK" ]]; then
            bad "$LINK exists and is not a symlink; remove it first"; exit 1
        fi
        if [[ -L "$LINK" && -e "$LINK" && "$(readlink -f "$LINK")" != "$TARGET" ]]; then
            bad "$LINK points at $(readlink -f "$LINK"), another checkout; remove it first"; exit 1
        fi
        [[ -L "$LINK" && ! -e "$LINK" ]] && say replaced "$LINK (it pointed at $(readlink "$LINK"), which is gone)"
        ln -sfn "$TARGET" "$LINK"
        ok "$LINK -> $TARGET"
        if [[ "$WHERE" == system ]] && ! others_reach "$REPO/bin"; then
            bad "other users cannot reach $REPO, so the link works only for its owner"
        fi
        as_user_setup
        path_hint
        printf '  %snext: gdbtools doctor%s\n' "$D" "$N" ;;
esac
