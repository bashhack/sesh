# bash completion for sesh.
# Load it in ~/.bashrc with:  eval "$(sesh completion bash)"
_sesh() {
    # The words up to the cursor, from bash's own parse, which keeps a quoted
    # path whole. bash 4+ also splits --flag=value at "=", so the pieces are
    # joined back; bash 3.2 keeps them whole.
    local -a args=()
    local i n w glue=0
    for (( i = 1; i <= COMP_CWORD; i++ )); do
        w=${COMP_WORDS[i]}
        n=${#args[@]}
        if (( n > 0 )) && { (( glue )) || [[ $w == "=" ]]; }; then
            args[n-1]="${args[n-1]}$w"
            [[ $w == "=" ]] && glue=1 || glue=0
        else
            args[n]=$w
            glue=0
        fi
    done
    # Drop the quoting a word still carries: "My Backup/ba, 'x, My\ Backup.
    for (( i = 0; i < ${#args[@]}; i++ )); do
        w=${args[i]}
        case $w in
            \"*) w=${w#\"}; w=${w%\"} ;;
            \'*) w=${w#\'}; w=${w%\'} ;;
            *) w=${w//\\ / } ;;
        esac
        args[i]=$w
    done
    local cur=${args[${#args[@]}-1]}
    # Readline replaces only the part of --flag=value after the "=" (when
    # "=" is in COMP_WORDBREAKS, as it is by default).
    local keep=""
    [[ $COMP_WORDBREAKS == *=* && $cur == *=* ]] && keep="${cur%"${cur##*=}"}"

    local IFS=$'\n'
    local -a out
    out=($(command sesh __complete "${args[@]}" 2>/dev/null | cut -f1))
    if [[ ${out[0]} == ":files" ]]; then
        type compopt >/dev/null 2>&1 && compopt -o filenames 2>/dev/null
        COMPREPLY=($(compgen -f -- "${cur#"$keep"}"))
        return
    fi
    local c
    COMPREPLY=()
    for c in "${out[@]}"; do
        COMPREPLY+=("${c#"$keep"}")
    done
}
# Paths need readline's filename quoting. bash 4+ turns it on per Tab
# (compopt); bash 3.2 can only turn it on for every completion of sesh.
if type compopt >/dev/null 2>&1; then
    complete -F _sesh sesh
else
    complete -o filenames -F _sesh sesh
fi
