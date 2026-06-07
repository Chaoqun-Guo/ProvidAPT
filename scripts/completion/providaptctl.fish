# ProvidAPT CLI fish completion
# Install: providaptctl completion fish > ~/.config/fish/completions/providaptctl.fish

complete -c providaptctl -f

# Action commands (mutually exclusive)
complete -c providaptctl -s status   -d "Query daemon status"
complete -c providaptctl -s stop     -d "Stop the daemon"
complete -c providaptctl -s restart  -d "Restart the daemon"
complete -c providaptctl -s reload   -d "Trigger config reload via daemon API"
complete -c providaptctl -s diagnose -d "Collect diagnostic bundle"
complete -c providaptctl -s bpf      -d "Inspect eBPF state"
complete -c providaptctl -s verify   -d "Verify store consistency"
complete -c providaptctl -s purge    -d "Purge stored data"
complete -c providaptctl -s audit    -d "Query audit log"
complete -c providaptctl -s replay   -d "Replay events from NDJSON logs"
complete -c providaptctl -s archive  -d "Archive old event logs"
complete -c providaptctl -s genrules -d "Generate Prometheus alert rules"
complete -c providaptctl -s profile  -d "Collect performance profile"
complete -c providaptctl -s report   -d "Generate MITRE ATTACK heatmap report"
complete -c providaptctl -s dashboard -d "Live terminal dashboard"

# Common flags
complete -c providaptctl -l config    -d "Config file path" -r -F
complete -c providaptctl -s json     -d "Output in JSON format"
complete -c providaptctl -l json     -d "Output in JSON format"

# Diagnose flags
complete -c providaptctl -l diagnose-out -d "Diagnostic output directory" -r -F

# Purge flags
complete -c providaptctl -l purge-mode    -d "Purge mode" -r -xa "time\t'Purge by cutoff time' capacity\t'Purge by max bytes' compliance\t'Full compliance wipe'"
complete -c providaptctl -l purge-cutoff  -d "Purge cutoff time (RFC3339)" -r
complete -c providaptctl -l purge-maxbytes -d "Target remaining bytes" -r
complete -c providaptctl -l purge-dry-run -d "Preview purge without deleting"

# Audit flags
complete -c providaptctl -l audit-cat   -d "Audit category" -r -xa "security\t'Security events' admin\t'Admin operations' system\t'System events' integrity\t'Integrity events' all\t'All categories'"
complete -c providaptctl -l audit-since -d "Show entries since" -r -xa "1h\t'Last hour' 6h\t'Last 6 hours' 24h\t'Last 24 hours' 7d\t'Last 7 days' 30d\t'Last 30 days'"
complete -c providaptctl -l audit-limit -d "Max audit entries" -r -xa "10\t'10 entries' 50\t'50 entries' 100\t'100 entries' 500\t'500 entries'"

# Verify flags
complete -c providaptctl -l repair -d "Repair fixable issues (used with -verify)"

# Replay flags
complete -c providaptctl -l replay-input -d "Input directory with NDJSON files" -r -F
complete -c providaptctl -l replay-max   -d "Max events to replay" -r

# Archive flags
complete -c providaptctl -l archive-dir     -d "Input directory with NDJSON files" -r -F
complete -c providaptctl -l archive-age     -d "Archive files older than N days" -r -xa "1\t'1 day' 7\t'7 days' 14\t'14 days' 30\t'30 days' 90\t'90 days'"
complete -c providaptctl -l archive-dry-run -d "Preview archive without archiving"

# Genrules flags
complete -c providaptctl -l genrules-out -d "Output path for rules file" -r -F

# Report flags
complete -c providaptctl -l report-out -d "Report output path" -r -F
