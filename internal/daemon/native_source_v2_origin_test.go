//go:build linux || darwin

package daemon

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeSourceV2BootstrapUsesTrustedOrigin(t *testing.T) {
	d := newTestDaemon(t)
	d.DirectManagedSourceV2Enabled = true
	d.adapters[domain.RuntimeFake].(*agentruntime.Fake).Binary = "/bin/true"
	registry, _, _ := nativeRegistryFixture(t)
	d.nativeRegistry = registry
	var native *NativeObservationConnection
	registered := false
	native, scope, _ := ownershipConnectionFixture(t, func(_ context.Context, typ string, payload any) error {
		if typ != transport.MsgNativeOwnershipRegister {
			t.Fatalf("unexpected runtime effect: %s", typ)
		}
		request := payload.(transport.NativeOwnershipRegisterPayload)
		registered = true
		native.OwnershipDisposition(transport.NativeOwnershipRegisteredPayload{RequestID: request.RequestID, PublicError: "registration not committed", Retryable: true})
		return nil
	})
	socket := &websocket.Conn{}
	d.curConn, d.nativeConn = socket, native
	d.ServerURL = scope.ServerURL + "?direct_managed_source_prepare=inherited&direct_managed_source_prepare=duplicate&direct_managed_source_pop=inherited&direct_managed_source_credential=inherited"
	d.HostID = scope.HostID
	if d.nativeConnection(nil).serverURL != scope.ServerURL {
		t.Fatal("admission used inherited query as origin")
	}
	row := InstanceRow{InstanceID: scope.InstanceID, DefinitionID: domain.NewID().String(), AgentPrincipalID: domain.NewID().String(), Runtime: string(domain.RuntimeFake), Workspace: t.TempDir(), Status: "hibernated", SessionID: "original-native-session", Kind: "representative", Access: domain.AccessReadWrite}
	if err := d.state.UpsertInstance(row); err != nil {
		t.Fatal(err)
	}
	launch := transport.LaunchAgentPayload{CommandID: domain.NewID().String(), InstanceID: row.InstanceID, DefinitionID: row.DefinitionID, AgentPrincipalID: row.AgentPrincipalID, Runtime: row.Runtime}
	prepare := transport.NativeOwnershipPreparePayload{SourceCommandID: domain.NewID().String(), SourceCommandType: transport.MsgWakeAgent, InstanceID: row.InstanceID, Runtime: row.Runtime, Launch: &launch}
	if err := d.prepareNativeOwnership(socket, prepare); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
		t.Fatalf("ownership registration: %v", err)
	}
	record, err := registry.Lookup(row.InstanceID)
	if err != nil || record.Scope.ServerURL != scope.ServerURL || !registered {
		t.Fatalf("worker did not reserve canonical origin: %v", err)
	}
	if record.LaunchState != "reserved" || len(d.nativeWorkers) != 0 {
		t.Fatal("preparation started a native worker")
	}
}

func TestNativeSourceV2RejectsRetainedOriginMismatch(t *testing.T) {
	for _, retainedOrigin := range []string{"https://example.test?direct_managed_source_prepare=inherited", "https://foreign.test"} {
		t.Run(retainedOrigin, func(t *testing.T) {
			d := newTestDaemon(t)
			d.DirectManagedSourceV2Enabled = true
			registry, _, _ := nativeRegistryFixture(t)
			d.nativeRegistry = registry
			native, scope, spec := ownershipConnectionFixture(t, func(context.Context, string, any) error {
				t.Fatal("mismatched identity reached ownership RPC")
				return nil
			})
			d.ServerURL = scope.ServerURL + "?direct_managed_source_prepare=inherited"
			d.HostID = scope.HostID
			scope.ServerURL = retainedOrigin
			record, err := registry.Reserve(scope, spec, "", "")
			if err != nil {
				t.Fatal(err)
			}
			socket := &websocket.Conn{}
			d.curConn, d.nativeConn = socket, native
			if err := d.connectNativeWorker(socket, native, record); !errors.Is(err, ErrNativeObservationConflict) {
				t.Fatalf("retained identity accepted: %v", err)
			}
			retained, err := registry.Lookup(scope.InstanceID)
			if err != nil || !reflect.DeepEqual(retained, record) || len(d.nativeWorkers) != 0 {
				t.Fatalf("persisted identity was rewritten or restarted: %v", err)
			}
		})
	}
}

func TestNativeSourceV2OriginGateOffPreservesV1(t *testing.T) {
	raw := "https://example.test?direct_managed_source_prepare=inherited"
	d := &Daemon{Config: Config{ServerURL: raw}}
	if d.nativeServerURL() != raw || d.nativeConnection(nil).serverURL != raw {
		t.Fatal("default-off rewrote V1 origin identity")
	}
}
