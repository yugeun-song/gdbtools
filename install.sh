#!/usr/bin/env bash
# Put the `gdbtools` command on PATH with its bash and zsh completions, and
# record this checkout for kbuildlab and the nvim adapter.  The command and the
# completions are symlinks into this checkout, so a `git pull` here updates them.
#
#   ./install.sh                  ~/.local/bin (XDG_BIN_HOME), for this user
#   ./install.sh --system         /usr/local/bin, for every user who can read
#                                 this checkout; run it as yourself and it asks
#                                 sudo for the links only, then records as you
#   ./install.sh --prefix DIR     DIR/bin (through sudo too when you cannot write it)
#   ./install.sh --sudo CMD       what asks for root: sudo, else doas, else run0
#   ./install.sh --global         also load gdbtools in every gdb (setup.sh --global)
#   ./install.sh --check | --uninstall
#
# Both default directories are on PATH on Debian, Ubuntu, Fedora, RHEL and
# openSUSE once they exist; on Arch and Void ~/.local/bin is added by the
# user's shell setup, and this says how when it is missing.  The completions go
# where bash-completion and zsh look: share/bash-completion/completions and
# share/zsh/site-functions under /usr/local or DIR, or under XDG_DATA_HOME for
# this user (zsh reads that one only once it is on $fpath, and this says how).
# Shell files are never edited.
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
    user)   BIN="${XDG_BIN_HOME:-$HOME/.local/bin}"; SHARE="${XDG_DATA_HOME:-$HOME/.local/share}"
            BASHC="${BASH_COMPLETION_USER_DIR:-$SHARE/bash-completion}/completions" ;;
    system) BIN=/usr/local/bin; SHARE=/usr/local/share; BASHC="$SHARE/bash-completion/completions" ;;
    prefix) BIN="${PREFIX%/}/bin"; SHARE="${PREFIX%/}/share"; BASHC="$SHARE/bash-completion/completions" ;;
esac
ZSHC="$SHARE/zsh/site-functions"
LINK="$BIN/$NAME"
TARGET="$REPO/bin/$NAME"
# What is linked where, as SOURCE DEST pairs: the command, then its completions.
PAIRS=("$TARGET" "$LINK" "$REPO/completions/gdbtools.bash" "$BASHC/$NAME"
       "$REPO/completions/_gdbtools" "$ZSHC/_$NAME")
placed() { [[ -L "$2" && "$(readlink -f "$2")" == "$(readlink -f "$1")" ]]; }

on_path() { case ":$PATH:" in *":$1:"*) return 0 ;; esac; return 1; }

path_hint() {
    on_path "$BIN" && return 0
    warn "$BIN is not on PATH; add it in your shell's startup file:"
    printf '      bash, zsh:  export PATH="%s:$PATH"\n' "$BIN"
    printf '      fish:       fish_add_path %s\n' "$BIN"
}

# zsh reads a completion only from a directory on $fpath.  The system and the
# usual prefixes are on the default one; a user's XDG directory is on it only if
# their startup files put it there, which is looked for, never written.
zsh_hint() {
    command -v zsh >/dev/null 2>&1 || return 0
    zsh -fc 'print -rl -- $fpath' 2>/dev/null | grep -qxF "$ZSHC" && return 0
    local rc="${ZDOTDIR:-$HOME}/.zshrc" short="${ZSHC/#$HOME/\~}"
    [[ -r "$rc" ]] && grep -qF -e "$ZSHC" -e "$short" "$rc" && return 0
    warn "zsh completes from $ZSHC only once it is on \$fpath; in ${rc/#$HOME/\~}, before compinit"
    printf '      (or before oh-my-zsh is sourced):  fpath=(%s $fpath)\n' "$short"
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
ask_root() {   # ask_root DEST...: elevate when any of them cannot be written
    local d="" p cmd
    [[ "$(id -u)" -ne 0 && "$WHERE" != user ]] || return 0
    for p in "$@"; do
        p="$(dirname "$p")"
        while [[ ! -d "$p" ]]; do p="$(dirname "$p")"; done
        [[ -w "$p" ]] || { d="$p"; break; }
    done
    [[ -n "$d" ]] || return 0
    if [[ -n "$SUDO_CMD" ]]; then
        read -ra ELEVATE <<<"$SUDO_CMD"
    else
        for cmd in sudo doas run0; do command -v "$cmd" >/dev/null 2>&1 && { ELEVATE=("$cmd"); break; }; done
    fi
    if [[ ${#ELEVATE[@]} -eq 0 ]]; then
        bad "cannot write $d, and none of sudo, doas, run0 is installed; --sudo CMD names another"; exit 1
    fi
    command -v "${ELEVATE[0]}" >/dev/null 2>&1 || { bad "--sudo: ${ELEVATE[0]} is not installed"; exit 1; }
    say root "cannot write $d; asking ${ELEVATE[0]##*/} for the links only"
    # sudo and doas ask on the controlling terminal; with none (an editor, a pipe)
    # only a cached or password-free grant can work, so say what to do instead.
    case "${ELEVATE[0]##*/}" in
        sudo|doas)
            if ! { : </dev/tty; } 2>/dev/null && ! "${ELEVATE[@]}" -n true 2>/dev/null; then
                bad "${ELEVATE[0]##*/} needs a password and there is no terminal to ask on; run this in a terminal"
                exit 1
            fi ;;
    esac
    if [[ "${ELEVATE[0]##*/}" == sudo ]]; then
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
        for ((i = 0; i < ${#PAIRS[@]}; i += 2)); do
            if placed "${PAIRS[i]}" "${PAIRS[i+1]}"; then ok "${PAIRS[i+1]}"
            else bad "${PAIRS[i+1]} is not this checkout's"; fi
        done
        reach_warn
        path_hint
        [[ "$WHERE" == user ]] && zsh_hint
        "$REPO/setup.sh" --check ;;
    uninstall)
        declare -a gone=()
        for ((i = 0; i < ${#PAIRS[@]}; i += 2)); do
            if placed "${PAIRS[i]}" "${PAIRS[i+1]}"; then gone+=("${PAIRS[i+1]}")
            elif [[ -e "${PAIRS[i+1]}" || -L "${PAIRS[i+1]}" ]]; then say kept "${PAIRS[i+1]} (not this checkout's)"; fi
        done
        if [[ ${#gone[@]} -gt 0 ]]; then
            ask_root "${gone[@]}"
            as_root rm -f -- "${gone[@]}" || { bad "could not remove what was installed"; exit 1; }
            for d in "${gone[@]}"; do ok "removed $d"; done
        fi
        [[ "$(id -u)" -eq 0 ]] || "$REPO/setup.sh" --uninstall ;;
    install)
        if [[ -e "$LINK" && ! -L "$LINK" ]]; then
            bad "$LINK exists and is not a symlink; remove it first"; exit 1
        fi
        if [[ -L "$LINK" && -e "$LINK" && "$(readlink -f "$LINK")" != "$TARGET" ]]; then
            bad "$LINK points at $(readlink -f "$LINK"), another checkout; remove it first"; exit 1
        fi
        declare -a todo=() dests=()
        for ((i = 0; i < ${#PAIRS[@]}; i += 2)); do
            s="${PAIRS[i]}" d="${PAIRS[i+1]}"
            if placed "$s" "$d"; then ok "$d"; continue; fi
            if [[ -L "$d" && ! -e "$d" ]]; then
                say replaced "$d (it pointed at $(readlink "$d"), which is gone)"
            elif [[ -e "$d" || -L "$d" ]]; then
                bad "$d is not this checkout's; skipped"; continue
            fi
            todo+=("$s" "$d"); dests+=("$d")
        done
        if [[ ${#todo[@]} -gt 0 ]]; then
            ask_root "${dests[@]}"
            as_root sh -c 'while [ $# -gt 0 ]; do mkdir -p "$(dirname "$2")" && ln -sfn "$1" "$2" || exit; shift 2; done' \
                sh "${todo[@]}" || { bad "could not install into $BIN and $SHARE"; exit 1; }
            for d in "${dests[@]}"; do ok "$d"; done
        fi
        reach_warn
        as_user_setup
        if [[ "$(id -u)" -ne 0 ]]; then
            path_hint
            zsh_hint
            printf '  %snext: gdbtools doctor; a new shell completes gdbtools with Tab%s\n' "$D" "$N"
        fi ;;
esac
