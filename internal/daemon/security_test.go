package daemon

// §72 negative tests (daemon scope): launch payloads with malformed
// instance ids must be rejected before they can steer filesystem paths.

import (
	"strings"
	"testing"

	"pagnet/internal/domain"
	"pagnet/internal/transport"
)

// SEC-407: the instance id becomes path components under the daemon state
// dir and the repository (worktrees/<id>). A non-UUID value — from a
// buggy or compromised control plane — must be refused, not resolved
// into a path.
func TestDoLaunch_RejectsNonUUIDInstanceID(t *testing.T) {
	d, err := New(Config{StateDir: t.TempDir(), AllowedRoots: []string{t.TempDir()}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.adapters[domain.RuntimeFake] = stubAdapter{}
	t.Cleanup(func() { d.Close() })

	repo := t.TempDir()
	gitInitRepo(t, repo)

	for _, bad := range []string{"inst-1", "../../etc/passwd", "a/b", "..", "x/../y", ""} {
		err := d.doLaunch(nil, transport.LaunchAgentPayload{
			InstanceID:    bad,
			WorkspacePath: repo,
			AgentName:     "evil",
			Access:        domain.AccessReadWrite,
			Runtime:       string(domain.RuntimeFake),
		})
		if err == nil {
			t.Fatalf("doLaunch accepted non-UUID instance id %q", bad)
		}
		if !strings.Contains(err.Error(), "invalid instance id") {
			t.Fatalf("doLaunch(%q) → %v, want invalid-instance-id refusal", bad, err)
		}
	}
}
