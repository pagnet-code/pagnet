package runtime

import (
	"strings"
	"testing"
)

// TestValidateExtraEnvControlPlaneBlocklist pins the operator runtime-env
// blocklist and its two documented PAGNET_ exceptions: the PAGNET_FAKE_*
// simulation namespace and the daemon-rendered PAGNET_FABRIC_SIDEPORT
// (the fused node's static host socket, whose parent directory the
// sandboxed runtime bridge must open). Every other PAGNET_ key, plus the
// database connection-string keys, stays a hard error.
func TestValidateExtraEnvControlPlaneBlocklist(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pairs   []string
		wantErr bool
	}{
		{"clean pairs pass", []string{"FOO=bar", "OPENAI_API_KEY=k"}, false},
		{"fake namespace exception", []string{"PAGNET_FAKE_FULL_OUTPUT=1"}, false},
		{"fabric sideport exception", []string{"PAGNET_FABRIC_SIDEPORT=/h/.pagnet/run/fabric/local.sock"}, false},
		{"other PAGNET_ key blocked", []string{"PAGNET_MCP_CONFIG={}"}, true},
		{"PAGNET_ prefix sibling blocked", []string{"PAGNET_FABRIC_SIDEPORT_EXTRA=/x"}, true},
		{"turn marker blocked", []string{"PAGNET_TURN_ID=t-1"}, true},
		{"database url blocked", []string{"DATABASE_URL=postgres://x"}, true},
		{"postgres family blocked", []string{"POSTGRES_PASSWORD=x"}, true},
		{"malformed pair blocked", []string{"NO_EQUALS"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateExtraEnv(tc.pairs)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateExtraEnv(%v) = nil, want an error", tc.pairs)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateExtraEnv(%v) = %v, want nil", tc.pairs, err)
			}
			if tc.wantErr && err != nil && !strings.Contains(err.Error(), "control-plane keys cannot be injected") {
				t.Fatalf("unexpected error shape: %v", err)
			}
		})
	}
}
