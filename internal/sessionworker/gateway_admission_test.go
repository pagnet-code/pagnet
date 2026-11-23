//go:build linux || darwin

package sessionworker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/managedgateway"
)

func gatewayFixture() managedgateway.GatewayAdmission {
	h := strings.Repeat("a", 64)
	return managedgateway.GatewayAdmission{Source: managedgateway.SourceGateway, OperationID: "operation", OwnerID: "account", TenantID: "tenant", HostID: "host", InstallationID: "installation", InstallationGeneration: "1", ExecutableGrantID: "grant", ExecutableGrantVersion: "1", V2ProjectID: "project", PolicyHash: h, ServiceID: "service", SenderID: "sender", ASKID: "ask", ASKWireDigest: h, InputDigest: h, TargetDefinitionID: "definition", TargetDefinitionRevision: "1", TargetDefinitionFingerprint: h, WorkerInstanceID: "instance", WorkerIncarnation: "generation", ConfigurationFingerprint: h, IsolationFingerprint: h, Deadline: time.Now().UTC().Add(time.Hour), MaxInputBytes: 1024, MaxResultBytes: 1024, MaxConcurrency: 1}
}

func TestGatewayAdmissionCapabilityAndBinding(t *testing.T) {
	j, _ := testJournal(t)
	a := gatewayFixture()
	c, err := j.installGatewayAdmissionCapability(a)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = j.admitGateway(context.Background(), nil, a, time.Now()); !errors.Is(err, ErrFenced) {
		t.Fatalf("missing capability: %v", err)
	}
	forged := *c
	if _, _, err = j.admitGateway(context.Background(), &forged, a, time.Now()); !errors.Is(err, ErrFenced) {
		t.Fatalf("copied capability: %v", err)
	}
	for _, mutate := range []func(*managedgateway.GatewayAdmission){
		func(a *managedgateway.GatewayAdmission) { a.Source = "cloud" },
		func(a *managedgateway.GatewayAdmission) { a.WorkerInstanceID = "other" },
		func(a *managedgateway.GatewayAdmission) { a.WorkerIncarnation = "other" },
		func(a *managedgateway.GatewayAdmission) { a.InstallationGeneration = "2" },
		func(a *managedgateway.GatewayAdmission) { a.IsolationFingerprint = strings.Repeat("b", 64) },
	} {
		changed := a
		mutate(&changed)
		if _, _, err = j.admitGateway(context.Background(), c, changed, time.Now()); err == nil {
			t.Fatal("changed pin admitted")
		}
	}
	if _, inserted, err := j.admitGateway(context.Background(), c, a, time.Now()); err != nil || !inserted {
		t.Fatalf("admit: %v %v", inserted, err)
	}
	for _, mutate := range []func(*managedgateway.GatewayAdmission){
		func(a *managedgateway.GatewayAdmission) { a.InputDigest = strings.Repeat("b", 64) },
		func(a *managedgateway.GatewayAdmission) { a.ASKWireDigest = strings.Repeat("b", 64) },
		func(a *managedgateway.GatewayAdmission) { a.OperationID = "other" },
		func(a *managedgateway.GatewayAdmission) { a.ASKID = "other" },
	} {
		changed := a
		mutate(&changed)
		if _, _, err = j.admitGateway(context.Background(), c, changed, time.Now()); !errors.Is(err, ErrConflict) {
			t.Fatalf("changed request: %v", err)
		}
	}
	if _, inserted, err := j.admitGateway(context.Background(), c, a, a.Deadline.Add(time.Hour)); err != nil || inserted {
		t.Fatalf("expired replay: %v %v", inserted, err)
	}
	if _, err = j.installGatewayAdmissionCapability(a); err != nil {
		t.Fatal(err)
	}
	if _, _, err = j.admitGateway(context.Background(), c, a, time.Now()); !errors.Is(err, ErrFenced) {
		t.Fatalf("replaced capability: %v", err)
	}
}

func TestGatewayAdmissionConcurrentReplayAndRecovery(t *testing.T) {
	j, dir := testJournal(t)
	a := gatewayFixture()
	c, err := j.installGatewayAdmissionCapability(a)
	if err != nil {
		t.Fatal(err)
	}
	var count atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			_, inserted, err := j.admitGateway(context.Background(), c, a, time.Now())
			if err != nil {
				t.Error(err)
			}
			if inserted {
				count.Add(1)
			}
		})
	}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatalf("inserted %d times", count.Load())
	}
	var cloudCount int
	if err = j.db.QueryRow(`SELECT COUNT(*) FROM worker_intent`).Scan(&cloudCount); err != nil || cloudCount != 0 {
		t.Fatalf("gateway fabricated cloud intent: %d %v", cloudCount, err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := OpenExistingJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if _, _, err = recovered.admitGateway(context.Background(), c, a, time.Now()); !errors.Is(err, ErrFenced) {
		t.Fatalf("old process capability: %v", err)
	}
	fresh, err := recovered.installGatewayAdmissionCapability(a)
	if err != nil {
		t.Fatal(err)
	}
	out, inserted, err := recovered.admitGateway(context.Background(), fresh, a, time.Now())
	if err != nil || inserted || out.State != "unknown" {
		t.Fatalf("recovered replay: %+v %v %v", out, inserted, err)
	}
}

func TestGatewayAdmissionDeadlineAndCloudBoundary(t *testing.T) {
	j, _ := testJournal(t)
	a := gatewayFixture()
	c, err := j.installGatewayAdmissionCapability(a)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = j.admitGateway(context.Background(), c, a, a.Deadline); !errors.Is(err, ErrFenced) {
		t.Fatalf("expired: %v", err)
	}
	// A gateway reservation neither creates a Cloud command nor alters its lease,
	// sequence or original admission proof requirements.
	if _, _, err = j.admitGateway(context.Background(), c, a, time.Now()); err != nil {
		t.Fatal(err)
	}
	out, run, err := j.Admit(context.Background(), lease(t, j), 1, "real-cloud-command", "input", []byte(`{}`))
	if err != nil || !run || out.Sequence != 1 {
		t.Fatalf("cloud history changed: %+v %v %v", out, run, err)
	}
}

func TestGatewayAdmissionInstallationScopeAndRetirement(t *testing.T) {
	j, _ := testJournal(t)
	a := gatewayFixture()
	for _, mutate := range []func(*managedgateway.GatewayAdmission){
		func(a *managedgateway.GatewayAdmission) { a.OwnerID = "other" },
		func(a *managedgateway.GatewayAdmission) { a.HostID = "other" },
		func(a *managedgateway.GatewayAdmission) { a.TenantID = "other" },
		func(a *managedgateway.GatewayAdmission) { a.WorkerInstanceID = "other" },
		func(a *managedgateway.GatewayAdmission) { a.WorkerIncarnation = "other" },
	} {
		changed := a
		mutate(&changed)
		if _, err := j.installGatewayAdmissionCapability(changed); !errors.Is(err, ErrFenced) {
			t.Fatalf("wrong installation scope: %v", err)
		}
	}
	c, err := j.installGatewayAdmissionCapability(a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = j.db.Exec(`INSERT INTO worker_ownership_retirement(singleton,payload) VALUES(1,'{}')`); err != nil {
		t.Fatal(err)
	}
	if _, _, err = j.admitGateway(context.Background(), c, a, time.Now()); !errors.Is(err, ErrRetired) {
		t.Fatalf("retired admission: %v", err)
	}
}
