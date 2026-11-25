//go:build linux || darwin

package daemon

import (
	"context"
	"net/url"
	"os"
	"testing"

	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/internal/session"
)

func TestDirectManagedSourceV2RuntimeGate(t *testing.T) {
	_, _, d, _, _ := sourceCredentialAuthorityFixtureV2(t)
	lock, err := os.CreateTemp(t.TempDir(), "lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	d.serveLockFile = lock
	d.ServerURL = "https://example.test"
	d.sessions = session.NewManager()
	d.sessions.RegisterDriver(agentruntime.NewQwenPersistent(""))
	d.initDirectManagedSourceV2()
	if d.directManagedSourcePrepareV2 != nil || d.directManagedSourcePoPV2 != nil || d.directManagedSourceCredentialV2 != nil {
		t.Fatal("default activated V2")
	}
	for _, reason := range []string{"exact", "inherited", "unrelated", "malformed", "worker-support", "custody", "off"} {
		t.Run(reason, func(t *testing.T) {
			d.DirectManagedSourceV2Enabled = true
			d.ServerURL = "https://example.test"
			switch reason {
			case "inherited":
				d.ServerURL += "?direct_managed_source_prepare=bad&direct_managed_source_prepare=bad&direct_managed_source_pop=bad&direct_managed_source_credential=bad"
			case "unrelated":
				d.ServerURL += "?unrelated=value"
			case "malformed":
				d.ServerURL += "?direct_managed_source_prepare=%zz"
			case "worker-support":
				d.directManagedSourcePrepare = &directSourcePrepareLaneExecutor{available: true}
				defer func() { d.directManagedSourcePrepare = nil }()
				saved := d.sessions
				d.sessions = nil
				defer func() { d.sessions = saved }()
			case "off":
				d.DirectManagedSourceV2Enabled = false
			}
			d.initDirectManagedSourceV2()
			if reason == "custody" {
				saved := d.directManagedSourcePoPV2
				d.directManagedSourcePoPV2 = nil
				defer func() { d.directManagedSourcePoPV2 = saved }()
			}
			endpoint, err := url.Parse(d.wsURL(context.Background()))
			if err != nil {
				t.Fatal(err)
			}
			want := reason == "exact" || reason == "inherited"
			for i, key := range directManagedSourceQueryKeys {
				values := endpoint.Query()[key]
				if want {
					if len(values) != 1 || values[0] != directManagedSourceProtocolsV2[i] {
						t.Fatalf("incorrect exact offer %s: %v", key, values)
					}
				} else if len(values) != 0 {
					t.Fatalf("unready suite offered %s: %v", key, values)
				}
			}
			if want && d.nativeConnection(nil).serverURL != "https://example.test" {
				t.Fatal("query became origin authority")
			}
		})
	}
}
