package version

import "fmt"

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func String() string {
	return fmt.Sprintf("ProvidAPT v%s [commit %s, built %s]", Version, Commit, Date)
}
