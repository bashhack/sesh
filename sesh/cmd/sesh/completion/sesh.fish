# fish completion for sesh.
# Load it with:  sesh completion fish | source
# or save it as ~/.config/fish/completions/sesh.fish
function __sesh_complete
    set -l words (commandline -opc) (commandline -ct)
    set -l out (command sesh __complete $words[2..-1] 2>/dev/null)
    if test "$out" = ":files"
        # For --flag=path, complete the part after the "=" and keep the flag.
        set -l tok (commandline -ct)
        set -l pre (string match -r -- '^-[^=]*=' $tok)
        for p in (__fish_complete_path (string replace -r -- '^-[^=]*=' '' $tok))
            printf '%s%s\n' "$pre" $p
        end
        return
    end
    printf '%s\n' $out
end
complete -c sesh -f -a '(__sesh_complete)'
