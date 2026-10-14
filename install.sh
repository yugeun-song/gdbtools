#!/usr/bin/env bash
# Put the `gdbtools` command on PATH and record this checkout for kbuildlab and
# the nvim adapter.  The command is a symlink into this checkout, so a `git pull`
# here updates it.
#
#   ./install.sh                  ~/.local/bin (XDG_BIN_HOME), for this user
#   ./install.sh --system         /usr/local/bin, for every user who can read
#                                 this checkout; run it as yourself and it asks
#                                 sudo for the link only, then records as you
#   ./install.sh --prefix DIR     DIR/bin (through sudo too when you cannot write it)
#   ./install.sh --sudo CMD       what asks for root: sudo, else doas, else run0
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
MODE=install; WHERE=user; PREFIX=""; GLOBAL=0; SUDO_CMD=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --user) WHERE=user; shift ;;
        --system) WHERE=system; shift ;;
        --prefix) WHERE=prefix; PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
        --global) GLOBAL=1; shift ;;
        --sudo) SUDO_CMD="${2:?--sudo needs a command}"; shift 2 ;;
        --check) MODE=check; shift ;;
        --uninstall) MODE=uninstall; shift ;;
        -h|--help) awk 'NR > 1 && !/^#/ {exit} NR > 1 {sub(/^# ?/, ""); print}' "$0"; exit 0 ;;
        *) echo "install.sh: unknown option '$1'" >&2; exit 2 ;;
    esac
done

if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != dumb ]]; then
    G=$'\e[32m' R=$'\e[31m' Y=$'\e[33m' C=$'\e[36m' D=$'\e[2m' N=$'\e[0m'
else G="" R="" Y="" C="" D="" N=""; fi
case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
    *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*) OKM="✓" NOM="✗" ;; *) OKM="+" NOM="x" ;;
esac
ok()  { printf '  %s%s%s %s\n' "$G" "$OKM" "$N" "$*"; }
bad() { printf '  %s%s%s %s\n' "$R" "$NOM" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
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
    warn "$BIN is not on PATH; add it in your shell's startup file:"
    printf '      bash, zsh:  export PATH="%s:$PATH"\n' "$BIN"
    printf '      fish:       fish_add_path %s\n' "$BIN"
}

# Root's config is not the user's: the record kbuildlab and nvim read is the
# user's own, written by `gdbtools install` run as that user.
as_user_setup() {
    if [[ "$(id -u)" -eq 0 ]]; then
        say next "as yourself: gdbtools install$([[ $GLOBAL -eq 1 ]] && echo ' --global'), then gdbtools doctor"
        return 0
    fi
    if [[ $GLOBAL -eq 1 ]]; then "$REPO/setup.sh" --global; else "$REPO/setup.sh"; fi
}

# A link into a directory this user cannot write (--system, or a root-owned
# --prefix) goes through sudo, asked once before anything changes; the record
# stays this user's.  Never for ~/.local/bin: a root-owned link there is wrong.
declare -a ELEVATE=()
ask_root() {
    local d="$BIN" cmd
    [[ "$(id -u)" -ne 0 && "$WHERE" != user ]] || return 0
    while [[ ! -d "$d" ]]; do d="$(dirname "$d")"; done
    [[ -w "$d" ]] && return 0
    if [[ -n "$SUDO_CMD" ]]; then
        read -ra ELEVATE <<<"$SUDO_CMD"
    else
        for cmd in sudo doas run0; do command -v "$cmd" >/dev/null 2>&1 && { ELEVATE=("$cmd"); break; }; done
    fi
    if [[ ${#ELEVATE[@]} -eq 0 ]]; then
        bad "cannot write $d, and none of sudo, doas, run0 is installed; --sudo CMD names another"; exit 1
    fi
    command -v "${ELEVATE[0]}" >/dev/null 2>&1 || { bad "--sudo: ${ELEVATE[0]} is not installed"; exit 1; }
    say root "cannot write $d; asking ${ELEVATE[0]##*/} for the link only"
    if [[ "${ELEVATE[0]}" == sudo ]]; then
        "${ELEVATE[@]}" -v || { bad "sudo did not authenticate; nothing was changed"; exit 1; }
    fi
}
as_root() { "${ELEVATE[@]+"${ELEVATE[@]}"}" "$@"; }

# The first directory on the way to this checkout that other users cannot enter.
reach_block() {
    local d="$REPO/bin"
    while [[ "$d" != / && -n "$d" ]]; do
        [[ "$(stat -c %A "$d" 2>/dev/null)" == *[xt] ]] || { printf '%s\n' "$d"; return 0; }
        d="$(dirname "$d")"
    done
    return 1
}
reach_warn() {
    local blk
    [[ "$WHERE" != user ]] && blk="$(reach_block)" || return 0
    warn "other users cannot enter $blk ($(stat -c %A "$blk")), so the link works only for $(stat -c %U "$REPO")"
}

case "$MODE" in
    check)
        if [[ -L "$LINK" && "$(readlink -f "$LINK")" == "$TARGET" ]]; then ok "$LINK -> $TARGET"
        else bad "$LINK is not this checkout's $NAME"; fi
        reach_warn
        path_hint
        "$REPO/setup.sh" --check ;;
    uninstall)
        if [[ -L "$LINK" && "$(readlink -f "$LINK")" == "$TARGET" ]]; then
            ask_root
            as_root rm -f -- "$LINK" || { bad "could not remove $LINK"; exit 1; }
            ok "removed $LINK"
        else
            say kept "$LINK (it is not a link to this checkout)"
        fi
        [[ "$(id -u)" -eq 0 ]] || "$REPO/setup.sh" --uninstall ;;
    install)
        if ! [[ -L "$LINK" && "$(readlink -f "$LINK")" == "$TARGET" ]]; then
            if [[ -e "$LINK" && ! -L "$LINK" ]]; then
                bad "$LINK exists and is not a symlink; remove it first"; exit 1
            fi
            if [[ -L "$LINK" && -e "$LINK" ]]; then
                bad "$LINK points at $(readlink -f "$LINK"), another checkout; remove it first"; exit 1
            fi
            [[ -L "$LINK" ]] && say replaced "$LINK (it pointed at $(readlink "$LINK"), which is gone)"
            ask_root
            as_root sh -c 'mkdir -p "$(dirname "$2")" && ln -sfn "$1" "$2"' sh "$TARGET" "$LINK" \
                || { bad "could not link $LINK"; exit 1; }
        fi
        ok "$LINK -> $TARGET"
        reach_warn
        as_user_setup
        if [[ "$(id -u)" -ne 0 ]]; then
            path_hint
            printf '  %snext: gdbtools doctor%s\n' "$D" "$N"
        fi ;;
esac
