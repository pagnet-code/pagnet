package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/transport"
)

// turnCapturingAdapter is a stub runtime adapter that records the turn
// specs it receives and completes each turn immediately (no process is
// spawned). It lets the launch tests assert what the mission turn was
// given without a real runtime.
type turnCapturingAdapter struct {
	specs []agentruntime.TurnSpec
}

func (a *turnCapturingAdapter) Name() domain.RuntimeName { return domain.RuntimeFake }
func (a *turnCapturingAdapter) StartTurn(ctx context.Context, spec agentruntime.TurnSpec, events chan agentruntime.TurnEvent) error {
	a.specs = append(a.specs, spec)
	events <- agentruntime.TurnEvent{Type: agentruntime.EventTurnCompleted}
	close(events)
	return nil
}
func (a *turnCapturingAdapter) Stop(string) error          { return nil }
func (a *turnCapturingAdapter) Available() bool            { return true }
func (a *turnCapturingAdapter) BinaryPath() (string, bool) { return "stub", true }
func (a *turnCapturingAdapter) PID(string) *int            { return nil }
func (a *turnCapturingAdapter) InteractiveCmd(agentruntime.TurnSpec) (*exec.Cmd, error) {
	return nil, errors.New("stub adapter has no interactive process")
}

// newLaunchCryptoDaemon builds a daemon (fresh temp state dir, repo as the
// allowed root) with a network keyring (one active epoch) for a fresh
// network id, and registers the turn-capturing fake adapter. It returns
// the daemon, the network id, and the active epoch id.
func newLaunchCryptoDaemon(t *testing.T, repo string) (*Daemon, string, string) {
	t.Helper()
	d, err := New(Config{StateDir: t.TempDir(), AllowedRoots: []string{repo}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	d.adapters[domain.RuntimeFake] = &turnCapturingAdapter{}

	networkID := string(domain.NewID())
	kr := crypto.NewKeyring(networkID)
	epoch, err := kr.Activate(time.Now().UTC())
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if err := crypto.SaveKeyring(d.StateDir, kr); err != nil {
		t.Fatalf("SaveKeyring: %v", err)
	}
	return d, networkID, epoch.ID
}

// encryptDefinition mirrors the CONSOLE-side sender for the test: the
// mission + standing instruction are ONE protected document
// {"mission","instruction"} encrypted under the network's active epoch
// with an agent_definition AAD bound to a fresh object id (the definition
// id). It returns the single envelope + AAD the server relays verbatim in
// BOTH launch envelope fields.
func encryptDefinition(t *testing.T, d *Daemon, networkID, mission, instruction string) (e2ee.EncryptedPayloadV1, e2ee.AAD) {
	t.Helper()
	doc, err := json.Marshal(map[string]string{"mission": mission, "instruction": instruction})
	if err != nil {
		t.Fatalf("marshal doc: %v", err)
	}
	kr, err := crypto.LoadKeyring(d.StateDir, networkID)
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	epoch, err := kr.ActiveEpoch()
	if err != nil {
		t.Fatalf("ActiveEpoch: %v", err)
	}
	key, err := epoch.KeyArray()
	if err != nil {
		t.Fatalf("KeyArray: %v", err)
	}
	aad, err := buildAAD("tenant-1", networkID, e2ee.ObjectTypeAgentDefinition, newObjectID(), "operator", "", epoch.ID)
	if err != nil {
		t.Fatalf("buildAAD: %v", err)
	}
	env, err := e2ee.Encrypt(doc, key, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return env, aad
}

// TestResolveLaunchContent_EnvelopeRoundTrip is the W-H1 focused unit
// test: the mission + standing instruction encrypted as ONE combined
// agent_definition document (fresh CEK, epoch key from a test keyring,
// canonical AAD) round-trip through the daemon's launch decrypt helper —
// both fields recovered from the single envelope the server mirrors in
// both wire slots.
func TestResolveLaunchContent_EnvelopeRoundTrip(t *testing.T) {
	repo := t.TempDir()
	d, networkID, _ := newLaunchCryptoDaemon(t, repo)

	mission := "ship the release notes"
	instruction := "always run the test suite before committing"
	env, aad := encryptDefinition(t, d, networkID, mission, instruction)

	missionPlain, agentMDPlain, err := d.resolveLaunchContent(transport.LaunchAgentPayload{
		NetworkID:           networkID,
		MissionEnvelope:     &env,
		MissionAAD:          &aad,
		InstructionEnvelope: &env,
		InstructionAAD:      &aad,
	})
	if err != nil {
		t.Fatalf("resolveLaunchContent: %v", err)
	}
	if missionPlain != mission {
		t.Fatalf("mission = %q, want %q", missionPlain, mission)
	}
	if agentMDPlain != instruction {
		t.Fatalf("agentMD = %q, want %q", agentMDPlain, instruction)
	}
}

// TestResolveLaunchContent_PlaintextPassesThrough pins the additive
// contract: a launch without envelopes passes its plaintext fields
// through unchanged (pre-W-H1 behavior).
func TestResolveLaunchContent_PlaintextPassesThrough(t *testing.T) {
	repo := t.TempDir()
	d, networkID, _ := newLaunchCryptoDaemon(t, repo)

	missionPlain, agentMDPlain, err := d.resolveLaunchContent(transport.LaunchAgentPayload{
		NetworkID: networkID,
		Mission:   "plain mission",
		AgentMD:   "plain instruction",
	})
	if err != nil {
		t.Fatalf("resolveLaunchContent: %v", err)
	}
	if missionPlain != "plain mission" || agentMDPlain != "plain instruction" {
		t.Fatalf("got (%q, %q), want the plaintext fields unchanged", missionPlain, agentMDPlain)
	}
}

// TestResolveLaunchContent_ContractViolations pins the fail-closed
// contract: an envelope REPLACES its plaintext fields. A plaintext field
// set alongside its envelope, or an envelope without its AAD, is a
// control-plane bug and is refused.
func TestResolveLaunchContent_ContractViolations(t *testing.T) {
	repo := t.TempDir()
	d, networkID, _ := newLaunchCryptoDaemon(t, repo)
	env, aad := encryptDefinition(t, d, networkID, "mission", "instruction")

	cases := []struct {
		name string
		p    transport.LaunchAgentPayload
	}{
		{
			name: "plaintext mission AND mission envelope",
			p: transport.LaunchAgentPayload{
				NetworkID: networkID, Mission: "plain",
				MissionEnvelope: &env, MissionAAD: &aad,
			},
		},
		{
			name: "plaintext instruction AND instruction envelope",
			p: transport.LaunchAgentPayload{
				NetworkID: networkID, AgentMD: "plain",
				InstructionEnvelope: &env, InstructionAAD: &aad,
			},
		},
		{
			name: "mission envelope without its AAD",
			p: transport.LaunchAgentPayload{
				NetworkID: networkID, MissionEnvelope: &env,
			},
		},
		{
			name: "instruction envelope without its AAD",
			p: transport.LaunchAgentPayload{
				NetworkID: networkID, InstructionEnvelope: &env,
			},
		},
	}
	for _, tc := range cases {
		if _, _, err := d.resolveLaunchContent(tc.p); err == nil {
			t.Fatalf("%s: accepted, want refusal", tc.name)
		}
	}
}

// TestResolveLaunchContent_TamperedAAD_Fails is the W-H1 negative: the
// server altered a bound AAD field, so the reconstructed AAD differs from
// the one used at encryption and GCM authentication must fail.
func TestResolveLaunchContent_TamperedAAD_Fails(t *testing.T) {
	repo := t.TempDir()
	d, networkID, _ := newLaunchCryptoDaemon(t, repo)

	env, aad := encryptDefinition(t, d, networkID, "ship the release notes", "instruction")
	badAAD := aad
	badAAD.ObjectID = "tampered" // a bound field the server must relay verbatim

	if _, _, err := d.resolveLaunchContent(transport.LaunchAgentPayload{
		NetworkID:       networkID,
		MissionEnvelope: &env,
		MissionAAD:      &badAAD,
	}); err == nil {
		t.Fatal("tampered AAD accepted, want GCM authentication failure")
	}
}

// TestResolveLaunchContent_MalformedDocument_Fails pins the parse gate:
// an envelope whose plaintext is NOT the combined agent_definition JSON
// (a buggy or hostile encryptor) fails the launch clean — the daemon never
// guesses by treating the raw plaintext as the mission.
func TestResolveLaunchContent_MalformedDocument_Fails(t *testing.T) {
	repo := t.TempDir()
	d, networkID, _ := newLaunchCryptoDaemon(t, repo)

	// Encrypt RAW mission text (not the combined document) — the pre-fix
	// wire shape. The daemon must refuse it, not launch with the raw text
	// misread as the mission.
	kr, err := crypto.LoadKeyring(d.StateDir, networkID)
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	epoch, err := kr.ActiveEpoch()
	if err != nil {
		t.Fatalf("ActiveEpoch: %v", err)
	}
	key, err := epoch.KeyArray()
	if err != nil {
		t.Fatalf("KeyArray: %v", err)
	}
	aad, err := buildAAD("tenant-1", networkID, e2ee.ObjectTypeAgentDefinition, newObjectID(), "operator", "", epoch.ID)
	if err != nil {
		t.Fatalf("buildAAD: %v", err)
	}
	env, err := e2ee.Encrypt([]byte("raw mission, not a document"), key, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, _, err := d.resolveLaunchContent(transport.LaunchAgentPayload{
		NetworkID:       networkID,
		MissionEnvelope: &env,
		MissionAAD:      &aad,
	}); err == nil {
		t.Fatal("non-document plaintext accepted, want clean parse failure")
	}
}

// TestResolveLaunchContent_UnknownEpoch_Fails pins the availability
// failure: the envelope was encrypted under an epoch the local keyring
// does not hold (a rotation whose key package has not landed). The launch
// fails clean — never a fallback to another epoch.
func TestResolveLaunchContent_UnknownEpoch_Fails(t *testing.T) {
	repo := t.TempDir()
	d, networkID, _ := newLaunchCryptoDaemon(t, repo)

	// A foreign network's keyring holds the epoch the envelope was
	// encrypted under; the daemon's keyring for networkID does not.
	fkr := crypto.NewKeyring(string(domain.NewID()))
	fepoch, err := fkr.Activate(time.Now().UTC())
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	fkey, err := fepoch.KeyArray()
	if err != nil {
		t.Fatalf("KeyArray: %v", err)
	}
	aad, err := buildAAD("tenant-1", networkID, e2ee.ObjectTypeAgentDefinition, newObjectID(), "operator", "", fepoch.ID)
	if err != nil {
		t.Fatalf("buildAAD: %v", err)
	}
	env, err := e2ee.Encrypt([]byte("secret mission"), fkey, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, _, err := d.resolveLaunchContent(transport.LaunchAgentPayload{
		NetworkID:       networkID,
		MissionEnvelope: &env,
		MissionAAD:      &aad,
	}); err == nil {
		t.Fatal("envelope under a foreign epoch accepted, want key_epoch_unavailable")
	}
}

// TestDoLaunch_EnvelopeContentDecryptsAndRuns exercises the full launch
// path: the daemon decrypts the mission + instruction locally, registers
// the instance with the decrypted standing instruction, and runs the
// decrypted mission as the first turn — exactly as a plaintext launch
// would.
func TestDoLaunch_EnvelopeContentDecryptsAndRuns(t *testing.T) {
	repo := t.TempDir()
	d, networkID, _ := newLaunchCryptoDaemon(t, repo)
	ad := d.adapters[domain.RuntimeFake].(*turnCapturingAdapter)

	mission := "ship the release notes"
	instruction := "always run the test suite before committing"
	env, aad := encryptDefinition(t, d, networkID, mission, instruction)

	id := domain.NewID().String()
	err := d.doLaunch(nil, transport.LaunchAgentPayload{
		InstanceID:          id,
		WorkspacePath:       repo,
		AgentName:           "e2ee-launch",
		Access:              domain.AccessReadOnly,
		Runtime:             string(domain.RuntimeFake),
		NetworkID:           networkID,
		MissionEnvelope:     &env,
		MissionAAD:          &aad,
		InstructionEnvelope: &env,
		InstructionAAD:      &aad,
	})
	if err != nil {
		t.Fatalf("doLaunch: %v", err)
	}
	row, ok, _ := d.state.GetInstance(id)
	if !ok || row == nil {
		t.Fatal("missing instance row")
	}
	// The standing instruction was decrypted and materialized.
	if row.Instruction != instruction {
		t.Fatalf("row.Instruction = %q, want %q", row.Instruction, instruction)
	}
	if row.AgentMDPath == "" {
		t.Fatal("row.AgentMDPath empty, want the materialized instruction file")
	}
	// The mission was decrypted and run as the first turn.
	if len(ad.specs) != 1 {
		t.Fatalf("turns run = %d, want 1", len(ad.specs))
	}
	if !strings.Contains(ad.specs[0].Input, mission) {
		t.Fatal("turn input does not carry the decrypted mission")
	}
	if ad.specs[0].InputKind != "mission" {
		t.Fatalf("turn kind = %q, want mission", ad.specs[0].InputKind)
	}
}

// TestDoLaunch_TamperedAAD_FailsClean is the W-H1 negative at the launch
// path: a tampered AAD fails the launch with a clean error BEFORE any
// side effect — no instance row is registered, no turn is started, and
// the agent is never launched with a silently-empty mission.
func TestDoLaunch_TamperedAAD_FailsClean(t *testing.T) {
	repo := t.TempDir()
	d, networkID, _ := newLaunchCryptoDaemon(t, repo)

	env, aad := encryptDefinition(t, d, networkID, "ship the release notes", "instruction")
	badAAD := aad
	badAAD.NetworkID = "other-network" // the server altered a bound field

	id := domain.NewID().String()
	err := d.doLaunch(nil, transport.LaunchAgentPayload{
		InstanceID:    id,
		WorkspacePath: repo,
		AgentName:     "e2ee-bad",
		Access:        domain.AccessReadOnly,
		Runtime:       string(domain.RuntimeFake),
		NetworkID:     networkID,
		MissionEnvelope: &env,
		MissionAAD:      &badAAD,
	})
	if err == nil {
		t.Fatal("doLaunch with tampered AAD succeeded, want clean failure")
	}
	if _, ok, _ := d.state.GetInstance(id); ok {
		t.Fatal("instance row registered despite failed decrypt, want none")
	}
}
