//go:build linux || darwin

package daemon

import (
	"net/url"
	"strings"
)

func (d *Daemon) managedDirectCredentialReady() bool {
	return d.ManagedDirectCredentialEnabled && managedDirectCredentialServerOrigin(d.ServerURL) != "" && d.managedEndpointPoPReady() && d.managedDirectCredential != nil && d.managedDirectCredential.ready()
}

// Reserved offers are configuration hints only; they never become native
// worker origin authority. Reject malformed or unrelated query parameters.
func managedDirectCredentialServerOrigin(value string) string {
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.User != nil || strings.Contains(value, "#") {
		return ""
	}
	query, err := url.ParseQuery(endpoint.RawQuery)
	if err != nil {
		return ""
	}
	for _, key := range []string{"managed_endpoint_prepare", "managed_endpoint_pop", "managed_direct_credential"} {
		query.Del(key)
	}
	for _, key := range directManagedSourceQueryKeys {
		query.Del(key)
	}
	query.Del("direct_endpoint_wake")
	if len(query) != 0 {
		return ""
	}
	endpoint.RawQuery = ""
	endpoint.ForceQuery = false
	return managedPrepareServerOrigin(endpoint.String())
}
