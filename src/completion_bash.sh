
# Registration of the bash completion for wgd. Same protocol as the script
# clap_complete generates (the candidates come from the completer called with
# `-- words` and the clap protocol variables), plus one thing it does not do: bash cuts
# COMP_WORDS at `=` and `:` (COMP_WORDBREAKS), which would cut the value of
# `connection config --link ANCHOR=PREFIX[,PREFIX...]` into pieces. This
# function joins such pieces again before asking wgd, and gives bash back only
# what follows the last `=` or `:` of the word, which is the part bash replaces.
# It reads the word breaks from COMP_WORDBREAKS and never changes them, and it
# does not need the bash-completion package. Runs on bash 3.2 too.
_clap_complete_@NAME@() {
    local IFS=$'\013'
    local _CLAP_COMPLETE_INDEX
    local _CLAP_COMPLETE_COMP_TYPE=${COMP_TYPE}
    if compopt +o nospace 2> /dev/null; then
        local _CLAP_COMPLETE_SPACE=false
    else
        local _CLAP_COMPLETE_SPACE=true
    fi

    # Only the word-break characters this function repairs, and only when
    # bash really breaks at them.
    local breaks=
    [[ $COMP_WORDBREAKS == *=* ]] && breaks=${breaks}=
    [[ $COMP_WORDBREAKS == *:* ]] && breaks=${breaks}:

    # Join a word that consists only of break characters with the words next
    # to it when the line has no whitespace between them, and so does every
    # word that follows such a break word without whitespace.
    local -a words=() starts=()
    local i n=${#COMP_WORDS[@]} pos=0 prev_end=-1 prev_break=false is_break start w
    local k=-1 cword=0
    for (( i = 0; i < n; i++ )); do
        w=${COMP_WORDS[i]}
        while [[ ${COMP_LINE:pos:1} == [[:space:]] ]]; do
            pos=$(( pos + 1 ))
        done
        start=$pos
        pos=$(( pos + ${#w} ))
        is_break=false
        if [[ -n $breaks && -n $w && -z ${w//[$breaks]/} ]]; then
            is_break=true
        fi
        if (( k >= 0 && start == prev_end )) && { $is_break || $prev_break; }; then
            words[k]=${words[k]}$w
        else
            k=$(( k + 1 ))
            words[k]=$w
            starts[k]=$start
        fi
        prev_break=$is_break
        prev_end=$pos
        if (( i == COMP_CWORD )); then
            cword=$k
        fi
    done

    # The word under the cursor ends at the cursor.
    local cur=${words[cword]}
    local cur_start=${starts[cword]}
    if (( COMP_POINT >= cur_start && COMP_POINT - cur_start < ${#cur} )); then
        cur=${COMP_LINE:cur_start:COMP_POINT-cur_start}
    fi
    words[cword]=$cur
    _CLAP_COMPLETE_INDEX=$cword

    COMPREPLY=( $( \
        _CLAP_IFS="$IFS" \
        _CLAP_COMPLETE_INDEX="$_CLAP_COMPLETE_INDEX" \
        _CLAP_COMPLETE_COMP_TYPE="$_CLAP_COMPLETE_COMP_TYPE" \
        _CLAP_COMPLETE_SPACE="$_CLAP_COMPLETE_SPACE" \
        @VAR@="bash" \
        @COMPLETER@ -- "${words[@]}" \
    ) )
    if [[ $? != 0 ]]; then
        unset COMPREPLY
        return
    fi

    # bash replaces the text after the last break character of the word, so
    # the candidates must start there, not at the start of the joined word.
    if [[ -n $breaks ]]; then
        local prefix=${cur%"${cur##*[$breaks]}"} j
        if [[ -n $prefix ]]; then
            for j in "${!COMPREPLY[@]}"; do
                if [[ ${COMPREPLY[j]} == "$prefix"* ]]; then
                    COMPREPLY[j]=${COMPREPLY[j]#"$prefix"}
                fi
            done
        fi
    fi

    if [[ $_CLAP_COMPLETE_SPACE == false ]] && [[ "${COMPREPLY-}" =~ [=/:]$ ]]; then
        compopt -o nospace
    fi
}
if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -o nospace -o bashdefault -o nosort -F _clap_complete_@NAME@ @BIN@
else
    complete -o nospace -o bashdefault -F _clap_complete_@NAME@ @BIN@
fi
