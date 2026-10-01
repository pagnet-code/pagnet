package domain

import "regexp"

var runtimeProfileNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,47}$`)

func ValidRuntimeProfileName(name string) bool { return runtimeProfileNamePattern.MatchString(name) }
func RuntimeProfileCapability(runtime RuntimeName, name string) string {
	return "profile:" + string(runtime) + ":" + name
}

// RuntimeProfileInstallation contains only public host-local profile metadata.
type RuntimeProfileInstallation struct {
	Name      string `json:"name"`
	Runtime   string `json:"runtime"`
	Available bool   `json:"available"`
}
