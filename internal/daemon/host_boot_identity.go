package daemon

import (
	"net/url"

	"github.com/pagnet-code/pagnet/internal/proc"
)

// setHostBootIdentity omits recovery evidence on read failure while preserving
// ordinary host registration. Configured URL parameters cannot supply evidence.
func setHostBootIdentity(query url.Values, read func() (proc.BootIdentity, error)) {
	for _, key := range []string{"os_boot_identity", "os_boot_source", "os_boot_quality"} {
		query.Del(key)
	}
	identity, err := read()
	if err != nil || identity.ID == "" || identity.Source == "" || identity.Quality == "" {
		return
	}
	query.Set("os_boot_identity", identity.ID)
	query.Set("os_boot_source", identity.Source)
	query.Set("os_boot_quality", identity.Quality)
}
