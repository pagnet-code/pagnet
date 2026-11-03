package textbridge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
)

func snapshotApproval() SnapshotApproval {
	return SnapshotApproval{Profile: SnapshotProfileVersion, Target: SnapshotTarget{"10000000-0000-4000-8000-000000000001", 3, "sha256:" + strings.Repeat("ab", 32)}, OwnerApproved: true, ExternalInstructions: "PRIVATE approved external instructions", Provider: provider.Config{BaseURL: "https://provider.example", Model: "fixed-model", APIKey: "PRIVATE-credential"}, CallsPerDay: 9, CommitmentKey: []byte(strings.Repeat("K", 32))}
}
func resolveTestSnapshot(t *testing.T, a SnapshotApproval) *SnapshotPlan {
	t.Helper()
	p, err := ResolveSnapshot(a, a.Target)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestSnapshotDigestAndPrivacy(t *testing.T) {
	a := snapshotApproval()
	p := resolveTestSnapshot(t, a)
	changes := map[string]func(*SnapshotApproval){
		"commitment key": func(a *SnapshotApproval) { a.CommitmentKey = []byte(strings.Repeat("L", 32)) },
		"instructions":   func(a *SnapshotApproval) { a.ExternalInstructions += " changed" },
		"model":          func(a *SnapshotApproval) { a.Provider.Model += "-other" },
		"origin":         func(a *SnapshotApproval) { a.Provider.BaseURL = "https://other.example" },
		"target":         func(a *SnapshotApproval) { a.Target.AgentID = "10000000-0000-4000-8000-000000000002" },
		"revision":       func(a *SnapshotApproval) { a.Target.DefinitionRevision++ },
		"definition":     func(a *SnapshotApproval) { a.Target.DefinitionFingerprint = "sha256:" + strings.Repeat("cd", 32) },
		"allowance":      func(a *SnapshotApproval) { a.CallsPerDay++ },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := a
			change(&changed)
			if resolveTestSnapshot(t, changed).Descriptor().Digest == p.Descriptor().Digest {
				t.Fatal("changed semantics retained digest")
			}
		})
	}
	rotated := a
	rotated.Provider.APIKey = "OTHER-secret"
	q := resolveTestSnapshot(t, rotated)
	if q.Descriptor() != p.Descriptor() || q.credentialFingerprint == p.credentialFingerprint {
		t.Fatal("credential commitment must remain private")
	}
	raw, _ := json.Marshal(p.Descriptor())
	for _, secret := range []string{a.ExternalInstructions, a.Provider.APIKey, p.credentialFingerprint, a.Provider.BaseURL, a.Provider.Model, a.Target.AgentID, string(a.CommitmentKey)} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("public descriptor leaked private configuration")
		}
	}
	planJSON, _ := json.Marshal(p)
	if string(planJSON) != "{}" {
		t.Fatal("plan exposes serializable state")
	}
	// Value capture prevents caller mutation from changing the resolved request.
	a.ExternalInstructions = "mutated"
	a.Provider.Model = "mutated"
	a.CallsPerDay = 100
	if p.instructions != "PRIVATE approved external instructions" || p.config.Model != "fixed-model" || p.Limits().CallsPerDay != 9 || p.Limits().MaxConcurrent != 1 {
		t.Fatal("plan changed after resolution")
	}
	d := p.Descriptor()
	if d.ExecutionReady || d.MaxInputChars != 16000 || d.MaxOutputChars != 16000 || d.MaxResponseBytes != 128<<10 || d.RequestTimeoutSeconds != 30 || d.MaxTokens != 4096 || d.MaxConcurrent != 1 {
		t.Fatal("incorrect descriptor bounds")
	}
}
func TestSnapshotSelectionIdentityAndBounds(t *testing.T) {
	a := snapshotApproval()
	for name, change := range map[string]func(*SnapshotApproval){
		"unselected":          func(a *SnapshotApproval) { a.Profile = "" },
		"unapproved":          func(a *SnapshotApproval) { a.OwnerApproved = false },
		"agent":               func(a *SnapshotApproval) { a.Target.AgentID += "other" },
		"revision":            func(a *SnapshotApproval) { a.Target.DefinitionRevision++ },
		"fingerprint":         func(a *SnapshotApproval) { a.Target.DefinitionFingerprint += "other" },
		"no allowance":        func(a *SnapshotApproval) { a.CallsPerDay = 0 },
		"empty snapshot":      func(a *SnapshotApproval) { a.ExternalInstructions = " " },
		"oversized snapshot":  func(a *SnapshotApproval) { a.ExternalInstructions = strings.Repeat("界", 16001) },
		"missing commitment":  func(a *SnapshotApproval) { a.CommitmentKey = nil },
		"invalid origin utf8": func(a *SnapshotApproval) { a.Provider.BaseURL = "https://provider.example/\xff" },
		"invalid model utf8":  func(a *SnapshotApproval) { a.Provider.Model = "\xff" },
		"invalid utf8":        func(a *SnapshotApproval) { a.ExternalInstructions = "\xff" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := a
			change(&bad)
			if _, err := ResolveSnapshot(bad, a.Target); err == nil {
				t.Fatal("accepted invalid approval")
			}
		})
	}
	a.ExternalInstructions = strings.Repeat("界", 16000)
	resolveTestSnapshot(t, a)
}
func TestSnapshotProviderRequestUsesResolvedPlan(t *testing.T) {
	a := snapshotApproval()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if len(body) != 4 || string(body["model"]) != `"fixed-model"` || string(body["stream"]) != "false" || string(body["max_tokens"]) != "4096" {
			t.Errorf("unexpected request shape: %v", body)
		}
		var messages []struct{ Role, Content string }
		if err := json.Unmarshal(body["messages"], &messages); err != nil {
			t.Error(err)
		}
		if len(messages) != 2 || messages[0].Role != "system" || messages[0].Content != a.ExternalInstructions || messages[1].Role != "user" || messages[1].Content != "bounded user text" {
			t.Errorf("unexpected messages: %+v", messages)
		}
		if r.Header.Get("Authorization") != "Bearer "+a.Provider.APIKey {
			t.Error("credential mismatch")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"result"},"finish_reason":"stop"}]}`))
	}))
	defer server.Close()
	a.Provider.BaseURL = server.URL
	p := resolveTestSnapshot(t, a)
	client, err := p.newProvider()
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("resolving a plan sent a request")
	}
	if _, err = client.Complete(context.Background(), strings.Repeat("x", 16001)); err == nil {
		t.Fatal("oversized input accepted")
	}
	if calls != 0 {
		t.Fatal("invalid input sent a request")
	}
	got, err := client.Complete(context.Background(), "bounded user text")
	if err != nil || got != "result" || calls != 1 {
		t.Fatalf("completion: %q %v %d", got, err, calls)
	}
}
func snapshotBinding(target SnapshotTarget) SnapshotPreparationBinding {
	return SnapshotPreparationBinding{InstallationID: "10000000-0000-4000-8000-000000000010", ServiceID: "10000000-0000-4000-8000-000000000011", Generation: 1, TenantID: "10000000-0000-4000-8000-000000000012", HostID: "10000000-0000-4000-8000-000000000013", Target: target, RunnerID: "10000000-0000-4000-8000-000000000014", Epoch: "2026-11-03T10:00:00.123456Z", ServerAudience: "https://server.example", BootID: "boot", ServerChallenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ServerRevision: 1}
}
func TestSnapshotPreparedSignatureBindingsAndExpiry(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := resolveTestSnapshot(t, snapshotApproval())
	b := snapshotBinding(p.target)
	now := time.Unix(10000, 0)
	signed, err := PrepareSnapshotDescriptor(p, b, now, now.Add(time.Minute), private)
	if err != nil {
		t.Fatal(err)
	}
	expected := signed.Transcript
	if err := VerifySnapshotPreparation(signed, expected, now, public); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*SnapshotPreparedTranscript){
		"installation":           func(t *SnapshotPreparedTranscript) { t.Binding.InstallationID += "x" },
		"service":                func(t *SnapshotPreparedTranscript) { t.Binding.ServiceID += "x" },
		"generation":             func(t *SnapshotPreparedTranscript) { t.Binding.Generation++ },
		"tenant":                 func(t *SnapshotPreparedTranscript) { t.Binding.TenantID += "x" },
		"host":                   func(t *SnapshotPreparedTranscript) { t.Binding.HostID += "x" },
		"agent":                  func(t *SnapshotPreparedTranscript) { t.Binding.Target.AgentID += "x" },
		"definition revision":    func(t *SnapshotPreparedTranscript) { t.Binding.Target.DefinitionRevision++ },
		"definition fingerprint": func(t *SnapshotPreparedTranscript) { t.Binding.Target.DefinitionFingerprint += "x" },
		"profile":                func(t *SnapshotPreparedTranscript) { t.Profile.Digest += "x" },
		"runner":                 func(t *SnapshotPreparedTranscript) { t.Binding.RunnerID += "x" },
		"epoch":                  func(t *SnapshotPreparedTranscript) { t.Binding.Epoch = "2026-11-03T10:00:01.123456Z" },
		"boot":                   func(t *SnapshotPreparedTranscript) { t.Binding.BootID += "x" },
		"challenge":              func(t *SnapshotPreparedTranscript) { t.Binding.ServerChallenge += "x" },
		"server revision":        func(t *SnapshotPreparedTranscript) { t.Binding.ServerRevision++ },
		"expiry":                 func(t *SnapshotPreparedTranscript) { t.ExpiresAt++ },
		"ready":                  func(t *SnapshotPreparedTranscript) { t.Profile.ExecutionReady = true },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := signed
			mutate(&tampered.Transcript)
			if VerifySnapshotPreparation(tampered, tampered.Transcript, now, public) == nil {
				t.Fatal("accepted tampered signature")
			}
			if VerifySnapshotPreparation(signed, tampered.Transcript, now, public) == nil {
				t.Fatal("accepted wrong expected binding")
			}
		})
	}
	for _, when := range []time.Time{now.Add(-time.Second), now.Add(time.Minute), now.Add(2 * time.Minute)} {
		if VerifySnapshotPreparation(signed, expected, when, public) == nil {
			t.Fatal("accepted outside validity window")
		}
	}
	wrongKey, _, _ := ed25519.GenerateKey(rand.Reader)
	if VerifySnapshotPreparation(signed, expected, now, wrongKey) == nil {
		t.Fatal("accepted wrong host key")
	}
	for _, expiry := range []time.Time{now, now.Add(-time.Second), now.Add(MaxPreparedSnapshotLifetime + time.Second)} {
		if _, err := PrepareSnapshotDescriptor(p, b, now, expiry, private); err == nil {
			t.Fatal("accepted invalid lifetime")
		}
	}
	b.Target.DefinitionRevision++
	if _, err := PrepareSnapshotDescriptor(p, b, now, now.Add(time.Minute), private); err == nil {
		t.Fatal("signed different target")
	}
	raw, _ := json.Marshal(signed)
	for _, secret := range []string{p.instructions, p.config.APIKey, p.credentialFingerprint, p.config.BaseURL, p.config.Model} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("signed descriptor leaked private configuration")
		}
	}
}
