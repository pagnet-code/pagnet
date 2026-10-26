package textbridge

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
)

const profileTestService = "eb8a664b-f7b8-4712-a90e-670a20bf4e68"

func savedTestProfile(t *testing.T) (string, string, Profile) {
	t.Helper()
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := ProfileDirectory(state, profileTestService)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(state, "provider-key")
	if err := os.WriteFile(key, []byte("provider-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	config := provider.Config{BaseURL: "https://provider.example", Model: "fixed", APIKey: "provider-secret"}
	p := Profile{Service: profileTestService, Server: "https://control.example", Credential: "pgn_act_v1_local-secret", ProviderOrigin: config.BaseURL, Model: config.Model, KeyFile: key, Fingerprint: ProviderFingerprint(config), Limits: ledger.Limits{CallsPerDay: 2, MaxConcurrent: 1}}
	unlock, err := LockProfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := SaveProfile(dir, p); err != nil {
		t.Fatal(err)
	}
	store, err := ledger.Open(filepath.Join(dir, "ledger"), ledger.Binding{ServiceOrigin: p.Server, PrincipalID: p.Service}, p.Limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return state, dir, p
}

func TestResolveProfileSameOSOwner(t *testing.T) {
	state, dir, want := savedTestProfile(t)
	gotDir, got, err := ResolveProfile(state, want.Service)
	if err != nil {
		t.Fatal(err)
	}
	if gotDir != dir || got != want {
		t.Fatal("saved profile did not round trip")
	}
	info, err := os.Stat(filepath.Join(dir, "profile.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("profile was not saved privately")
	}
	if _, _, err := ResolveProfile(state, "../escape"); err == nil {
		t.Fatal("accepted path instead of service UUID")
	}
	if _, err := LoadProfile(dir, "90ef464b-3467-44d7-a70c-91258ec310ee"); err == nil {
		t.Fatal("accepted different service binding")
	}
}

func TestReadProfileStatusDisabledAndPrivate(t *testing.T) {
	state, dir, p := savedTestProfile(t)
	unlock, err := LockProfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenProfileLedger(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetEnabled(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	p.Disabled = true
	if err := SaveProfile(dir, p); err != nil {
		t.Fatal(err)
	}
	unlock()
	// Status must work without access to the provider key, including while the
	// responder's mutation lock is held.
	if err := os.Remove(p.KeyFile); err != nil {
		t.Fatal(err)
	}
	unlock, err = LockProfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	status, err := ReadProfileStatus(context.Background(), state, p.Service)
	if err != nil {
		t.Fatal(err)
	}
	if status.Service != p.Service || !status.Disabled || status.Budget.Enabled || status.Budget.Limits != p.Limits {
		t.Fatal("incorrect disabled status")
	}
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{p.Credential, p.KeyFile, p.ProviderOrigin, p.Model, p.Fingerprint, "provider-secret"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("status disclosed private configuration")
		}
	}
}

func TestResolveProfileRejectsMalformedAndNonPrivateFiles(t *testing.T) {
	for _, kind := range []string{"invalid JSON", "unknown field", "trailing JSON", "public file"} {
		t.Run(kind, func(t *testing.T) {
			state, dir, p := savedTestProfile(t)
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			mode := os.FileMode(0600)
			switch kind {
			case "invalid JSON":
				raw = []byte(`{"Credential":"private-marker",`)
			case "unknown field":
				raw = append(raw[:len(raw)-1], []byte(`,"Unknown":"private-marker"}`)...)
			case "trailing JSON":
				raw = append(raw, []byte(` {"extra":"private-marker"}`)...)
			case "public file":
				mode = 0644
			}
			path := filepath.Join(dir, "profile.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			_, _, err = ResolveProfile(state, p.Service)
			if err == nil {
				t.Fatal("accepted malformed or non-private profile")
			}
			if strings.Contains(err.Error(), "private-marker") || strings.Contains(err.Error(), p.Credential) {
				t.Fatal("error disclosed private contents")
			}
			if _, err := ReadProfileStatus(context.Background(), state, p.Service); err == nil {
				t.Fatal("status accepted malformed or non-private profile")
			}
		})
	}
}

func TestReadProfileStatusDoesNotRecreateMissingLedger(t *testing.T) {
	state, dir, p := savedTestProfile(t)
	if err := os.RemoveAll(filepath.Join(dir, "ledger")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProfileStatus(context.Background(), state, p.Service); err == nil {
		t.Fatal("accepted missing saved ledger")
	}
	if _, err := os.Stat(filepath.Join(dir, "ledger")); !os.IsNotExist(err) {
		t.Fatal("status recreated missing ledger")
	}
}
