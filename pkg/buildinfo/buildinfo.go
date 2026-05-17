package buildinfo

import "fmt"

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

func String(name string) string {
	return fmt.Sprintf("%s %s (%s, %s)", name, Version, Commit, Date)
}
