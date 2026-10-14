# bash completion for gdbtools.  It asks gdbtools itself (`gdbtools __complete`)
# what may come next; after `gdbtools gdb` it completes as gdb does.

_gdbtools() {
    local cur words cword
    if declare -F _comp_get_words >/dev/null 2>&1; then
        _comp_get_words cur words cword
    elif declare -F _get_comp_words_by_ref >/dev/null 2>&1; then
        _get_comp_words_by_ref cur words cword
    else
        cur=${COMP_WORDS[COMP_CWORD]} words=("${COMP_WORDS[@]}") cword=$COMP_CWORD
    fi
    local line tag rest
    local -a cands=()
    while IFS= read -r line; do
        tag=${line%%$'\t'*} rest=${line#*$'\t'}
        if [[ $tag == @gdb ]]; then
            if declare -F _comp_command_offset >/dev/null 2>&1; then _comp_command_offset 1
            elif declare -F _command_offset >/dev/null 2>&1; then _command_offset 1
            else COMPREPLY=($(compgen -f -- "$cur")); compopt -o filenames 2>/dev/null; fi
            return 0
        fi
        [[ -n $tag ]] && cands+=("${rest%%$'\t'*}")
    done < <("${words[0]}" __complete "${words[@]:1:cword-1}" "$cur" 2>/dev/null)
    local IFS=$'\n'
    COMPREPLY=($(compgen -W "${cands[*]}" -- "$cur"))
    return 0
}
complete -F _gdbtools gdbtools
