//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func recoveryProtocolFixture(t *testing.T) (*Daemon, *NativeObservationConnection, transport.NativeWorkerRecoveryState, *[]transport.NativeWorkerRecoveryAck, string) {
	t.Helper()
	registry, scope, spec := nativeRegistryFixture(t)
	local, err := registry.Reserve(scope, spec, "", "")
	if err != nil {
		t.Fatal(err)
	}
	acknowledgements := []transport.NativeWorkerRecoveryAck{}
	c := NewNativeObservationConnection(scope.ServerURL, scope.HostID, "daemon-boot", func(_ context.Context, typ string, payload any) error {
		if typ != transport.MsgNativeWorkerRecoveryAck {
			t.Fatalf("synthetic source ACK: %s", typ)
		}
		ack, ok := payload.(transport.NativeWorkerRecoveryAck)
		if !ok {
			t.Fatal("untyped recovery acknowledgement")
		}
		record, err := registry.LookupRecovery(ack.RecoveryID)
		if err != nil || record.Phase != ack.LocalPhase {
			t.Fatalf("ack preceded durable phase: %+v %v", record, err)
		}
		acknowledgements = append(acknowledgements, ack)
		return nil
	})
	session := transport.HostSessionPayload{HostID: scope.HostID, TenantID: scope.TenantID, AccountID: scope.AccountID, OwnershipScope: "personal", BootID: "daemon-boot", NativeAdmissionID: domain.NewID().String(), RunnerID: domain.NewID().String(), RunnerEpoch: time.Now().UTC(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol, transport.NativeWorkerRecoveryProtocol}}
	if err = c.Admit(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	d := &Daemon{Config: Config{ServerURL: scope.ServerURL, HostID: scope.HostID}, nativeRegistry: registry, nativeConn: c}
	original := recoveryBoot("11111111-1111-4111-8111-111111111111")
	p := transport.NativeWorkerRecoveryState{RecoveryID: domain.NewID().String(), InstanceID: scope.InstanceID, DefinitionID: domain.NewID().String(), HostID: scope.HostID, TenantID: scope.TenantID, AccountID: scope.AccountID, OwnershipID: domain.NewID().String(), OwnershipGeneration: scope.Generation, Action: "replace", State: "prepared", OriginalBoot: &original, PrepareBoot: original, LastDispatchSequence: 4, RetiredFloor: 1}
	return d, c, p, &acknowledgements, local.Dir
}

func bootReader(boot transport.KernelBootEvidence) func() (transport.KernelBootEvidence, error) {
	return func() (transport.KernelBootEvidence, error) { return boot, nil }
}

func TestNativeWorkerRecoveryStateLogging(t *testing.T) {
	for _, unexpected := range []bool{false, true} {
		name := "same-boot-deferred"
		if unexpected {
			name = "unexpected-error"
		}
		t.Run(name, func(t *testing.T) {
			d, _, p, acks, _ := recoveryProtocolFixture(t)
			boot, err := CollectKernelBootEvidence()
			if err != nil {
				t.Fatal(err)
			}
			p.PrepareBoot, p.OriginalBoot = boot, &boot
			if unexpected {
				p.HostID = domain.NewID().String()
			}
			var output bytes.Buffer
			d.Log = slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
			d.instQueues = make(map[string]*instQueue)
			t.Cleanup(func() { d.finishQueue(p.InstanceID) })
			env, err := transport.NewEnvelope(transport.MsgNativeWorkerRecoveryState, p)
			if err != nil {
				t.Fatal(err)
			}
			for range 3 {
				d.handleCommand(nil, env)
			}
			done := make(chan struct{})
			if !d.enqueueInstance(p.InstanceID, func() { close(done) }) {
				t.Fatal("completion barrier enqueue failed")
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("recovery state handling did not finish")
			}
			level, category := "DEBUG", ErrNativeOriginAdmissionDeferred
			if unexpected {
				level, category = "WARN", ErrNativeObservationConflict
			}
			if got := strings.Count(output.String(), "level="+level); got != 3 {
				t.Fatalf("%s entries = %d, want 3: %s", level, got, output.String())
			}
			if !unexpected && strings.Contains(output.String(), "level=WARN") {
				t.Fatalf("same-boot retry warned: %s", output.String())
			}
			if !strings.Contains(output.String(), category.Error()) {
				t.Fatalf("missing actual error: %s", output.String())
			}
			if len(*acks) != 0 {
				t.Fatal("deferred or invalid recovery state acknowledged")
			}
		})
	}
}

func TestNativeWorkerRecoveryProtocolDurableFenceBeforeAck(t *testing.T) {
	d, _, p, acks, _ := recoveryProtocolFixture(t)
	first := p.PrepareBoot
	if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(first)); !errors.Is(err, ErrNativeOriginAdmissionDeferred) {
		t.Fatalf("same boot accepted: %v", err)
	}
	if len(*acks) != 0 {
		t.Fatal("prepared ACK without reboot")
	}
	record, err := d.nativeRegistry.LookupRecovery(p.RecoveryID)
	if err != nil || record.FenceBoot != first || record.Phase != "prepared" {
		t.Fatalf("fence not durable before reboot: %+v %v", record, err)
	}
	reopened, err := OpenNativeWorkerRegistry(filepath.Dir(d.nativeRegistry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	d.nativeRegistry = reopened
	next := recoveryBoot("22222222-2222-4222-8222-222222222222")
	if err = d.handleNativeWorkerRecoveryState(nil, p, bootReader(next)); err != nil {
		t.Fatal(err)
	}
	if len(*acks) != 1 || (*acks)[0].LocalFenceBoot != first || (*acks)[0].OwnershipGeneration != p.OwnershipGeneration {
		t.Fatalf("incorrect durable fence evidence: %+v", *acks)
	}
	changed := p
	changed.Action = "delete"
	if err = d.handleNativeWorkerRecoveryState(nil, changed, bootReader(next)); err == nil {
		t.Fatal("immutable action changed")
	}
	changed = p
	changed.LastDispatchSequence++
	if err = d.handleNativeWorkerRecoveryState(nil, changed, bootReader(next)); err == nil {
		t.Fatal("dispatch evidence changed")
	}
	changed = p
	changed.OriginalBoot = &next
	if err = d.handleNativeWorkerRecoveryState(nil, changed, bootReader(next)); err == nil {
		t.Fatal("original boot evidence changed")
	}
	if len(*acks) != 1 {
		t.Fatal("identity mutation acknowledged")
	}
}

func TestNativeWorkerRecoveryProtocolCollectionPreservesEvidence(t *testing.T) {
	d, _, p, acks, dir := recoveryProtocolFixture(t)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	evidence := []byte("original dispatch outcome unknown; retain journal")
	if err := os.WriteFile(filepath.Join(dir, "intents.sqlite"), evidence, 0600); err != nil {
		t.Fatal(err)
	}
	_ = d.handleNativeWorkerRecoveryState(nil, p, bootReader(p.PrepareBoot))
	next := recoveryBoot("22222222-2222-4222-8222-222222222222")
	if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(next)); err != nil {
		t.Fatal(err)
	}
	p.State = "committed"
	if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(p.PrepareBoot)); err == nil {
		t.Fatal("committed state bypassed reboot proof")
	}
	if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(next)); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(d.nativeRegistry.root, "recovery-"+p.RecoveryID, "intents.sqlite")
	if got, err := os.ReadFile(archive); err != nil || string(got) != string(evidence) {
		t.Fatalf("original journal altered or lost: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("original launch directory still available")
	}
	if _, err := d.nativeRegistry.Lookup(p.InstanceID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("exact registry row not collected")
	}
	if !d.nativeOwned(p.InstanceID) {
		t.Fatal("collected instance fell through to legacy execution")
	}
	if len(*acks) != 2 || (*acks)[1].LocalPhase != "collected" {
		t.Fatalf("collection acknowledgement missing: %+v", *acks)
	}
	if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(next)); err != nil {
		t.Fatal("committed retry failed", err)
	}
	reopened, err := OpenNativeWorkerRegistry(filepath.Dir(d.nativeRegistry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	d.nativeRegistry = reopened
	d.resumeNativeWorkerRecoveryAcks(nil)
	if len(*acks) != 4 {
		t.Fatal("lost collected ACK not resumed on reconnect")
	}
	p.State = "cleaned"
	if err := d.handleNativeWorkerRecoveryState(nil, p, func() (transport.KernelBootEvidence, error) {
		t.Fatal("cleaned state requested new boot proof")
		return transport.KernelBootEvidence{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	d.resumeNativeWorkerRecoveryAcks(nil)
	if len(*acks) != 4 {
		t.Fatal("server cleaned confirmation did not stop retries")
	}
	fenced, err := d.nativeRegistry.RecoveryTombstoned(p.InstanceID, p.OwnershipGeneration)
	if err != nil || !fenced {
		t.Fatal("cleanup removed launch fence")
	}
	if got, err := os.ReadFile(archive); err != nil || string(got) != string(evidence) {
		t.Fatal("cleanup confirmation erased archive")
	}
}

func TestNativeWorkerRecoveryProtocolRejectsForeignAndUnnegotiatedState(t *testing.T) {
	for _, kind := range []string{"foreign-host", "foreign-tenant", "foreign-account", "unnegotiated", "replaced", "missing-prepare", "missing-boot"} {
		t.Run(kind, func(t *testing.T) {
			d, c, p, acks, _ := recoveryProtocolFixture(t)
			switch kind {
			case "foreign-host":
				p.HostID = domain.NewID().String()
			case "foreign-tenant":
				p.TenantID = domain.NewID().String()
			case "foreign-account":
				p.AccountID = domain.NewID().String()
			case "unnegotiated":
				c.session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol}
			case "replaced":
				d.curConn = &websocket.Conn{}
			case "missing-prepare":
				p.State = "committed"
			}
			boot := p.PrepareBoot
			if kind == "missing-boot" {
				boot = transport.KernelBootEvidence{}
			}
			if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(boot)); err == nil {
				t.Fatal("invalid state accepted")
			}
			if len(*acks) != 0 {
				t.Fatal("invalid state acknowledged")
			}
			if _, err := d.nativeRegistry.LookupRecovery(p.RecoveryID); !errors.Is(err, sql.ErrNoRows) {
				t.Fatal("invalid state mutated registry")
			}
		})
	}
}

func TestNativeWorkerRecoveryProtocolLegacyMissingWorker(t *testing.T) {
	d, _, p, acks, _ := recoveryProtocolFixture(t)
	if _, err := d.nativeRegistry.db.Exec(`DELETE FROM native_workers WHERE instance_id=?`, p.InstanceID); err != nil {
		t.Fatal(err)
	}
	p.OwnershipID = ""
	p.OwnershipGeneration = ""
	p.LastDispatchSequence = 0
	p.RetiredFloor = 0
	p.OriginalBoot = nil
	_ = d.handleNativeWorkerRecoveryState(nil, p, bootReader(p.PrepareBoot))
	next := recoveryBoot("22222222-2222-4222-8222-222222222222")
	if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(next)); err != nil {
		t.Fatal(err)
	}
	p.State = "committed"
	if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(next)); err != nil {
		t.Fatal(err)
	}
	if len(*acks) != 2 || (*acks)[1].OwnershipGeneration != "" {
		t.Fatal("invented legacy generation")
	}
	if fenced, err := d.nativeRegistry.RecoveryTombstoned(p.InstanceID, domain.NewID().String()); err != nil || !fenced {
		t.Fatal("legacy collection lost wildcard fence")
	}
}

func TestNativeWorkerRecoveryProtocolArchiveReplayAfterRename(t *testing.T) {
	d, _, p, _, dir := recoveryProtocolFixture(t)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	_ = d.handleNativeWorkerRecoveryState(nil, p, bootReader(p.PrepareBoot))
	// Crash after rename but before the transaction collecting the registry row.
	if err := d.nativeRegistry.AdvanceRecoveryPhase(p.RecoveryID, "prepared", "committed"); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(d.nativeRegistry.root, "recovery-"+p.RecoveryID)
	if err := os.Rename(dir, archive); err != nil {
		t.Fatal(err)
	}
	p.State = "committed"
	next := recoveryBoot("22222222-2222-4222-8222-222222222222")
	if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(next)); err != nil {
		t.Fatal("rename replay failed", err)
	}
}

func TestNativeWorkerRecoveryProtocolNegotiation(t *testing.T) {
	d, _, _, _, _ := recoveryProtocolFixture(t)
	d.ServerURL += "?native_worker_recovery=injected"
	parsed, err := url.Parse(d.wsURL(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("native_worker_recovery") != transport.NativeWorkerRecoveryProtocol || parsed.Query().Get("native_observations") != transport.NativeObservationReceiptProtocol {
		t.Fatal("recovery protocol not advertised with native observations")
	}
	d.nativeRegistry = nil
	parsed, err = url.Parse(d.wsURL(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Has("native_worker_recovery") {
		t.Fatal("configured URL enabled recovery without durable registry")
	}
}

func TestNativeWorkerRecoveryProtocolRefusesMissingLaunchedEvidence(t *testing.T) {
	d, _, p, acks, _ := recoveryProtocolFixture(t)
	if _, err := d.nativeRegistry.db.Exec(`UPDATE native_workers SET launch_state='launched' WHERE instance_id=?`, p.InstanceID); err != nil {
		t.Fatal(err)
	}
	_ = d.handleNativeWorkerRecoveryState(nil, p, bootReader(p.PrepareBoot))
	p.State = "committed"
	next := recoveryBoot("22222222-2222-4222-8222-222222222222")
	if err := d.handleNativeWorkerRecoveryState(nil, p, bootReader(next)); err == nil {
		t.Fatal("missing launched journals treated as collected")
	}
	if len(*acks) != 0 {
		t.Fatal("missing original evidence acknowledged as collected")
	}
	if _, err := d.nativeRegistry.Lookup(p.InstanceID); err != nil {
		t.Fatal("lost original registry authority")
	}
	record, err := d.nativeRegistry.LookupRecovery(p.RecoveryID)
	if err != nil || record.Phase != "committed" {
		t.Fatal("failed collection lost durable commit phase")
	}
}
