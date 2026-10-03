//go:build linux || darwin

package daemon

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeOwnershipBootstrapUsesOriginalConfigurationForLaterOperations(t *testing.T) {
	for _, operation := range []string{transport.MsgAttachTerminal, transport.MsgWakeAgent, transport.MsgRestartAgent, transport.MsgDeliverNetworkEvent} {
		t.Run(operation, func(t *testing.T) {
			d := newTestDaemon(t)
			d.adapters[domain.RuntimeFake].(*agentruntime.Fake).Binary = "/bin/true"
			registry, _, _ := nativeRegistryFixture(t)
			d.nativeRegistry = registry
			var connection *NativeObservationConnection
			var registered *transport.NativeOwnershipRegisterPayload
			connection, scope, _ := ownershipConnectionFixture(t, func(_ context.Context, typ string, payload any) error {
				if typ != transport.MsgNativeOwnershipRegister {
					t.Fatalf("preparation attempted execution: %s", typ)
				}
				p := payload.(transport.NativeOwnershipRegisterPayload)
				registered = &p
				// Stop at the real ownership RPC: preparation cannot execute a runtime
				// without a committed ownership receipt and a separate dispatch proof.
				connection.OwnershipDisposition(transport.NativeOwnershipRegisteredPayload{RequestID: p.RequestID, PublicError: "registration not committed", Retryable: true})
				return nil
			})
			conn := &websocket.Conn{}
			d.curConn, d.nativeConn = conn, connection
			d.ServerURL, d.HostID = scope.ServerURL, scope.HostID
			row := InstanceRow{InstanceID: scope.InstanceID, DefinitionID: domain.NewID().String(), AgentPrincipalID: domain.NewID().String(), Runtime: string(domain.RuntimeFake), Workspace: t.TempDir(), Status: "hibernated", SessionID: "original-native-session", ConfigFingerprint: "original-configuration", Instruction: "Keep the current standing instructions", AgentName: "Original assistant", Kind: "representative", Access: domain.AccessReadWrite}
			if err := d.state.UpsertInstance(row); err != nil {
				t.Fatal(err)
			}
			before, _, err := d.state.GetInstance(row.InstanceID)
			if err != nil {
				t.Fatal(err)
			}
			launch := transport.LaunchAgentPayload{CommandID: domain.NewID().String(), InstanceID: row.InstanceID, DefinitionID: row.DefinitionID, AgentPrincipalID: row.AgentPrincipalID, Runtime: row.Runtime, WorkspacePath: "/historical-folder-no-longer-present", AgentMD: "historical instruction", Mission: "Do not execute this old first task"}
			prep := transport.NativeOwnershipPreparePayload{SourceCommandID: domain.NewID().String(), SourceCommandType: operation, InstanceID: row.InstanceID, Runtime: row.Runtime, Launch: &launch}
			for _, mismatch := range []string{"instance", "runtime", "profile", "launch identity", "fresh launch", "network", "definition", "principal"} {
				bad := prep
				badLaunch := launch
				bad.Launch = &badLaunch
				switch mismatch {
				case "instance":
					badLaunch.InstanceID = domain.NewID().String()
				case "runtime":
					badLaunch.Runtime = string(domain.RuntimeCodex)
				case "profile":
					badLaunch.Profile = "foreign-profile"
				case "launch identity":
					badLaunch.CommandID = "not-a-command-id"
				case "fresh launch":
					bad.SourceCommandType = transport.MsgLaunchAgent
				case "network":
					badLaunch.NetworkID = domain.NewID().String()
				case "definition":
					badLaunch.DefinitionID = domain.NewID().String()
				case "principal":
					badLaunch.AgentPrincipalID = domain.NewID().String()
				}
				if err := d.prepareNativeOwnership(conn, bad); !errors.Is(err, ErrNativeObservationConflict) {
					t.Fatalf("%s mismatch did not fail closed: %v", mismatch, err)
				}
				if registered != nil || registry.Owns(row.InstanceID) {
					t.Fatalf("%s mismatch reserved or registered ownership", mismatch)
				}
			}
			if err := d.prepareNativeOwnership(conn, prep); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
				t.Fatalf("wanted pending ownership receipt, got %v", err)
			}
			if registered == nil || registered.InstanceID != row.InstanceID || registered.Runtime != row.Runtime {
				t.Fatal("later operation never reached original ownership registration")
			}
			record, err := registry.Lookup(row.InstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if record.Spec.InitialNativeSessionID != row.SessionID || record.Spec.Workspace != row.Workspace || !strings.Contains(record.Spec.StandingInstructions, row.Instruction) || strings.Contains(record.Spec.StandingInstructions, launch.Mission) {
				t.Fatal("bootstrap replayed stale launch instead of existing configuration")
			}
			after, _, err := d.state.GetInstance(row.InstanceID)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("bootstrap changed existing session/configuration: %v", err)
			}
			if prep.SourceCommandID == prep.Launch.CommandID || prep.Launch.CommandID != launch.CommandID {
				t.Fatal("source identity rewritten to historical launch")
			}
		})
	}
}
