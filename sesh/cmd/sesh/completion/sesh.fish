# fish completion for sesh.
# Load it with:  sesh completion fish | source
# or save it as ~/.config/fish/completions/sesh.fish
function __sesh_complete
    # The words before the cursor come unquoted; the one being typed doesn't,
    # so drop an opening quote and escaped spaces from it ("pa, My\ Backup,
    # --format="j).
    set -l cur (commandline -ct | string replace -r -- '^["\']' '' | string replace -r -- '^(-[^=]*=)["\']' '$1' | string replace -a -- '\\ ' ' ')
    set -l words (commandline -opc) $cur
    set -l out (command sesh __complete $words[2..-1] 2>/dev/null)
    if test "$out" = ":files"
        # For --flag=path, complete the part after the "=" and keep the flag.
        set -l pre (string match -r -- '^-[^=]*=' $cur)
        for p in (__fish_complete_path (string replace -r -- '^-[^=]*=' '' $cur))
            printf '%s%s\n' "$pre" $p
        end
        return
    end
    printf '%s\n' $out
end
complete -c sesh -f -a '(__sesh_complete)'
