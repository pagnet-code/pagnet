package main

import (
	"encoding/hex"
	"github.com/pagnet-code/pagnet/internal/release"
	"runtime/debug"
)

// Release builds stamp version explicitly. `go install module@version`
// retains its module version; unstamped source builds remain valid SemVer
// while identifying their source revision, rather than printing a bare hash.
func init() {
	if version != "" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		version = "v0.0.0-dev+source"
		return
	}
	version = unstampedVersion(info)
}

func unstampedVersion(info *debug.BuildInfo) string {
	if release.ValidVersion(info.Main.Version) {
		return info.Main.Version
	}
	revision, dirty := "", false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			dirty = setting.Value == "true"
		}
	}
	if len(revision) >= 12 {
		if _, err := hex.DecodeString(revision); err == nil {
			suffix := ""
			if dirty {
				suffix = ".dirty"
			}
			return "v0.0.0-dev+g" + revision[:12] + suffix
		}
	}
	return "v0.0.0-dev+source"
}
