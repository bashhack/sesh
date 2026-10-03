#compdef sesh
# zsh completion for sesh.
# Load it in ~/.zshrc, after compinit, with:  eval "$(sesh completion zsh)"
# or save it as _sesh in a directory on $fpath.
_sesh() {
    local out line
    local -a cands
    out=$(command sesh __complete "${(@)words[2,CURRENT]}" 2>/dev/null) || return 1
    if [[ $out == :files ]]; then
        # For --flag=path, complete only the part after the "=".
        [[ ${words[CURRENT]} == -*=* ]] && compset -P '*='
        _files
        return
    fi
    for line in "${(@f)out}"; do
        [[ -z $line ]] && continue
        if [[ $line == *$'\t'* ]]; then
            cands+=("${${line%%$'\t'*}//:/\\:}:${line#*$'\t'}")
        else
            cands+=("${line//:/\\:}")
        fi
    done
    (( ${#cands} )) && _describe -t sesh sesh cands
}
if [[ $funcstack[1] == _sesh ]]; then
    _sesh "$@"
else
    compdef _sesh sesh
fi
