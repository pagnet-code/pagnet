//go:build linux || darwin

package daemon

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestDirectManagedSourceVerifierExactNativeSubject(t *testing.T) {
	for _, mutation := range []string{"valid", "principal", "instance", "role", "source-principal", "native-session", "worker-replacement"} {
		t.Run(mutation, func(t *testing.T) {
			f := newManagedPrepareVerifierFixture(t)
			_, command, _ := directSourceStoreFixture(t)
			raw, err := json.Marshal(f.command.Subject)
			if err != nil || json.Unmarshal(raw, &command.Subject) != nil {
				t.Fatal("subject projection failed", err)
			}
			command.Subject.ProtocolVersion = transport.DirectManagedSourceBindingProtocol
			command.Subject.SourcePrincipalID = command.Subject.PrincipalID
			switch mutation {
			case "principal":
				command.Subject.PrincipalID = domain.NewID()
				command.Subject.SourcePrincipalID = command.Subject.PrincipalID
			case "instance":
				command.Subject.InstanceID = domain.NewID()
			case "role":
				command.Subject.Role = "T"
			case "source-principal":
				command.Subject.SourcePrincipalID = domain.NewID()
			case "native-session":
				command.Subject.NativeSessionID += "-other"
			}
			token, err := f.d.verifyDirectManagedSourcePrepareToken(context.Background(), f.captured, "https://example.test", command, func(_ context.Context, _ *NativeWorkerProxy, _ transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
				if mutation == "worker-replacement" {
					f.d.nativeWorkersMu.Lock()
					old := f.d.nativeWorkers[command.Subject.InstanceID.String()]
					f.d.nativeWorkers[command.Subject.InstanceID.String()] = &nativeWorkerLink{conn: old.conn, proxy: old.proxy, ownership: old.ownership}
					f.d.nativeWorkersMu.Unlock()
				}
				return &sessionworker.NativeOwnershipVerifyResult{Snapshot: f.snapshot}, nil
			})
			if mutation == "valid" {
				if err != nil || token == nil {
					t.Fatal("exact source worker rejected", err)
				}
			} else if err == nil || token != nil {
				t.Fatal("wrong source identity or superseded worker verified")
			}
		})
	}
}
