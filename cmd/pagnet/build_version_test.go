package main

import (
	"runtime/debug"
	"testing"
)

func TestUnstampedBuildVersionRetainsModuleAndSourceIdentity(t *testing.T) {
	cases := []struct {
		name string
		info debug.BuildInfo
		want string
	}{
		{name: "module install", info: debug.BuildInfo{Main: debug.Module{Version: "v0.5.1"}}, want: "v0.5.1"},
		{name: "pseudo version", info: debug.BuildInfo{Main: debug.Module{Version: "v0.5.1-0.20260930120000-abcdef123456"}}, want: "v0.5.1-0.20260930120000-abcdef123456"},
		{name: "source archive", want: "v0.0.0-dev+source"},
		{name: "source revision", info: debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abcdef1234560000000000000000000000000000"}}}, want: "v0.0.0-dev+gabcdef123456"},
		{name: "dirty source", info: debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abcdef1234560000000000000000000000000000"}, {Key: "vcs.modified", Value: "true"}}}, want: "v0.0.0-dev+gabcdef123456.dirty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := unstampedVersion(&tc.info); got != tc.want {
				t.Fatalf("version=%q,want%q", got, tc.want)
			}
		})
	}
}
