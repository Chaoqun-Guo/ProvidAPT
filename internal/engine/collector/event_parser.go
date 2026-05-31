package collector

// event_parser.go — Post-processing of raw events.
// Adds enrichment (e.g., resolve UID to username, resolve IP to DNS).

// Enrich adds cross-referenced metadata to a raw event.
func (e *Event) Enrich() {
	// TODO: resolve UID -> /etc/passwd username (lazy lookup with cache)
	// TODO: resolve binary path from /proc/<pid>/exe
	// TODO: resolve IP addresses to hostnames (optional, rate-limited)
}
