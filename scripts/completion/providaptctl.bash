# ProvidAPT CLI bash completion
# Install: source <(providaptctl completion bash)
# Or:     providaptctl completion bash > /etc/bash_completion.d/providaptctl

_providaptctl_complete() {
    local cur prev words cword
    _init_completion -n = || return

    # Define all flags (long form only, matching the Go flag package)
    local flags=(
        -status -stop -restart -reload -diagnose -bpf -verify -purge -audit
        -replay -archive -genrules -profile -report -dashboard
        -config -json
        -diagnose-out -purge-mode -purge-cutoff -purge-maxbytes -purge-dry-run
        -audit-cat -audit-since -audit-limit
        -verify -repair
        -replay-input -replay-max
        -archive-dir -archive-age -archive-dry-run
        -genrules-out
        -report-out
    )

    local purge_modes="time capacity compliance"
    local audit_cats="security admin system integrity all"
    local bool_flags="-status -stop -restart -reload -diagnose -bpf -verify -purge -audit -replay -archive -genrules -profile -report -dashboard -json -repair -purge-dry-run -archive-dry-run"

    case $prev in
        -config|-diagnose-out|-replay-input|-archive-dir|-genrules-out|-report-out)
            _filedir -d
            return
            ;;
        -purge-mode)
            COMPREPLY=($(compgen -W "$purge_modes" -- "$cur"))
            return
            ;;
        -purge-cutoff)
            # RFC3339 hint
            COMPREPLY=($(compgen -W "2026-01-01T00:00:00Z" -- "$cur"))
            return
            ;;
        -purge-maxbytes)
            COMPREPLY=($(compgen -W "104857600 1073741824 5368709120" -- "$cur"))
            return
            ;;
        -audit-cat)
            COMPREPLY=($(compgen -W "$audit_cats" -- "$cur"))
            return
            ;;
        -audit-since)
            COMPREPLY=($(compgen -W "1h 6h 24h 7d 30d" -- "$cur"))
            return
            ;;
        -audit-limit)
            COMPREPLY=($(compgen -W "10 50 100 500 1000" -- "$cur"))
            return
            ;;
        -archive-age)
            COMPREPLY=($(compgen -W "1 7 14 30 90" -- "$cur"))
            return
            ;;
        -replay-max)
            COMPREPLY=($(compgen -W "100 1000 10000 100000" -- "$cur"))
            return
            ;;
    esac

    # If current word starts with -, suggest flags
    if [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "${flags[*]}" -- "$cur"))
        return
    fi

    # Default: suggest flags if no input
    if [[ "$cur" == "" ]]; then
        COMPREPLY=($(compgen -W "${flags[*]}" -- "$cur"))
    fi
}

complete -F _providaptctl_complete providaptctl
