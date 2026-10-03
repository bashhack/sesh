# bash completion for sesh.
# Load it in ~/.bashrc with:  eval "$(sesh completion bash)"
_sesh() {
    local line="${COMP_LINE:0:COMP_POINT}"
    local -a words
    read -r -a words <<< "$line"
    # After a space, the word being completed is a new, empty one.
    [[ $line == *[[:space:]] ]] && words+=("")
    local cur="${words[${#words[@]}-1]}"
    # Readline replaces only the part of --flag=value after the "=" (when
    # "=" is in COMP_WORDBREAKS, as it is by default), whatever COMP_WORDS
    # says: bash 3.2 keeps the word whole there, later versions split it.
    local keep=""
    [[ $COMP_WORDBREAKS == *=* && $cur == *=* ]] && keep="${cur%"${cur##*=}"}"
    # Sliced before IFS changes: bash 3.2 joins "${a[@]:1}" when IFS lacks a space.
    local -a args=("${words[@]:1}")

    local IFS=$'\n'
    local -a out
    out=($(command sesh __complete "${args[@]}" 2>/dev/null | cut -f1))
    if [[ ${out[0]} == ":files" ]]; then
        type compopt >/dev/null 2>&1 && compopt -o filenames
        COMPREPLY=($(compgen -f -- "${cur#"$keep"}"))
        return
    fi
    local c
    COMPREPLY=()
    for c in "${out[@]}"; do
        COMPREPLY+=("${c#"$keep"}")
    done
}
complete -F _sesh sesh
