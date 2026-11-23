package senderipc

import (
	"runtime"
	"testing"
)

func TestSupportedPlatforms(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows", "freebsd", "openbsd", "netbsd", "plan9"} {
		want := goos == "linux" || goos == "darwin"
		if supportedOS(goos) != want {
			t.Fatal("insecure peer platform enabled", goos)
		}
	}
	if Supported() != supportedOS(runtime.GOOS) {
		t.Fatal("platform support does not match kernel peer implementation")
	}
}

func TestRequestRejectsNonRFCAsk(t *testing.T) {
	if canonicalID("00000000-0000-7000-0000-000000000001", true) {
		t.Fatal("non-RFC supplied ASK identity accepted")
	}
}
