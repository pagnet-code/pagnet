package runtime

// profileNativeDirs keeps per-profile native state grants isolated from the
// default account directory. Defaults remain unchanged without a profile.
func profileNativeDirs(configured, defaults []string) []string {
	if len(configured) > 0 {
		return append([]string(nil), configured...)
	}
	return defaults
}
