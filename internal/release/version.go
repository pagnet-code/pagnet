package release

import (
	"regexp"
	"strings"
)

var semverPattern = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// ValidVersion accepts SemVer with Pagnet's conventional optional v prefix.
// A bare commit hash, development label, or path is never a release
// identity. Numeric prerelease identifiers cannot have leading zeroes.
func ValidVersion(version string) bool {
	if !semverPattern.MatchString(version) {
		return false
	}
	core := strings.SplitN(strings.TrimPrefix(version, "v"), "+", 2)[0]
	_, pre, found := strings.Cut(core, "-")
	if !found {
		return true
	}
	for _, id := range strings.Split(pre, ".") {
		numeric := true
		for _, r := range id {
			if r < '0' || r > '9' {
				numeric = false
				break
			}
		}
		if numeric && len(id) > 1 && id[0] == '0' {
			return false
		}
	}
	return true
}
