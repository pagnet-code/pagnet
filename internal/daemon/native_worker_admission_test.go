package daemon

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeWorkerActivationAdapterKeepsOriginalAuthorityWithFreshController(t *testing.T) {
	for _, scenario := range []string{"shared_network", "transplanted_account", "different_state_directory", "old_current_admission", "wrong_network_tenant"} {
		t.Run(scenario, func(t *testing.T) {
			scope := sessionworker.Scope{ServerURL: "https://example.test", TenantID: domain.NewID().String(), AccountID: domain.NewID().String(), HostID: domain.NewID().String(), InstanceID: domain.NewID().String(), Generation: domain.NewID().String()}
			network, networkTenant := domain.NewID().String(), domain.NewID().String()
			session := transport.HostSessionPayload{NativeAdmissionID: domain.NewID().String(), HostID: scope.HostID, RunnerID: domain.NewID().String(), RunnerEpoch: time.Now().UTC(), BootID: domain.NewID().String(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol}}
			source := sessionworker.Admission{NativeAdmissionID: domain.NewID().String(), Scope: scope, TenantID: scope.TenantID, NetworkID: network, Kind: "worker", RunnerID: domain.NewID().String(), RunnerEpoch: session.RunnerEpoch.Add(-time.Minute), BootID: domain.NewID().String()}
			sent := 0
			var connection *NativeObservationConnection
			connection = NewNativeObservationConnection(scope.HostID, session.BootID, func(_ context.Context, typ string, p any) error {
				sent++
				request := p.(transport.NativeOriginRegisterPayload)
				if typ != transport.MsgNativeOriginRegister || request.NativeAdmissionID != source.NativeAdmissionID {
					t.Fatal("fresh controller rewrote original source authority")
				}
				tenant := networkTenant
				if scenario == "wrong_network_tenant" {
					tenant = scope.TenantID
				}
				connection.OriginRegistered(transport.NativeOriginRegisteredPayload{RequestID: request.RequestID, Origin: &transport.NativeObservationOrigin{NativeAdmissionID: source.NativeAdmissionID, ID: domain.NewID().String(), CommandID: request.CommandID, TenantID: tenant, HostID: scope.HostID, InstanceID: scope.InstanceID, Runtime: request.Runtime, NativeGeneration: request.NativeGeneration, RunnerID: source.RunnerID, RunnerEpoch: source.RunnerEpoch, BootID: source.BootID, CreatedAt: time.Now().Add(-time.Minute)}})
				return nil
			})
			if err := connection.Admit(session); err != nil {
				t.Fatal(err)
			}
			current, err := connection.NativeWorkerAdmission(scope, network, "worker")
			if err != nil {
				t.Fatal(err)
			}
			request := sessionworker.ActivationRequest{ID: domain.NewID().String(), Scope: scope, SourceCommandID: domain.NewID().String(), NativeGeneration: "actual-native-generation", ActualRuntime: "qwen-code", NetworkID: network, NetworkTenantID: networkTenant, Admission: source, CurrentAdmission: current}
			switch scenario {
			case "transplanted_account":
				request.Scope.AccountID = domain.NewID().String()
			case "different_state_directory":
				request.Admission.Scope.Generation = domain.NewID().String()
			case "old_current_admission":
				request.CurrentAdmission = source
			}
			result, err := connection.AuthorizeNativeWorkerActivation(t.Context(), scope, request)
			if scenario != "shared_network" {
				if err == nil {
					t.Fatal("mismatched authority accepted", scenario)
				}
				if scenario != "wrong_network_tenant" && sent != 0 {
					t.Fatal("wrong local worker reached server")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var origin transport.NativeObservationOrigin
			if err := json.Unmarshal(result.Origin, &origin); err != nil {
				t.Fatal(err)
			}
			if result.ID != request.ID || result.NativeGeneration != request.NativeGeneration || origin.NativeAdmissionID != source.NativeAdmissionID || origin.RunnerID != source.RunnerID || origin.TenantID != networkTenant {
				t.Fatal("admission adapter lost source scope")
			}
		})
	}
}
