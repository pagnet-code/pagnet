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

func TestProfileRegistrationLegacy(t *testing.T) {
	_, dir, p := savedTestProfile(t)
	raw, err := os.ReadFile(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["Registration"]; ok {
		t.Fatal("legacy profile gained registration metadata")
	}
	got, err := LoadProfile(dir, p.Service)
	if err != nil || got != p || got.Registration != nil {
		t.Fatal("legacy profile did not load unchanged")
	}
}

func testProfileRegistration() ProfileRegistration {
	return ProfileRegistration{
		InstallationID: "6e6cb40a-72d4-4a64-8ed5-32db95d2cb60",
		HostID:         "b8fc428b-e874-4aaf-8ada-f50decd99b60",
		Role:           "responder", ProfileVersion: 1, Pending: true,
	}
}

func TestProfileRegistrationRoundTrip(t *testing.T) {
	for _, state := range []string{"pending", "pending enabled", "enabled", "disabled"} {
		t.Run(state, func(t *testing.T) {
			_, dir, p := savedTestProfile(t)
			r := testProfileRegistration()
			if state != "pending" {
				r.TenantID = profileTestService
				r.OwnerUserID = "90ef464b-3467-44d7-a70c-91258ec310ee"
				r.Generation = 2
				r.DesiredState = "enabled"
				r.Pending = state == "pending enabled"
				if state == "disabled" {
					r.DesiredState = "disabled"
				}
			}
			p.Registration = &r
			if err := SaveProfile(dir, p); err != nil {
				t.Fatal(err)
			}
			got, err := LoadProfile(dir, p.Service)
			if err != nil {
				t.Fatal(err)
			}
			if got.Registration == nil || *got.Registration != r {
				t.Fatal("registration metadata did not round trip")
			}
			got.Registration = p.Registration
			if got != p {
				t.Fatal("registration changed profile fields")
			}
		})
	}
}

func TestProfileRegistrationRejectsMalformed(t *testing.T) {
	cases := map[string]func(*ProfileRegistration){
		"missing installation":      func(r *ProfileRegistration) { r.InstallationID = "" },
		"nil installation":          func(r *ProfileRegistration) { r.InstallationID = "00000000-0000-0000-0000-000000000000" },
		"noncanonical installation": func(r *ProfileRegistration) { r.InstallationID = strings.ToUpper(r.InstallationID) },
		"invalid host":              func(r *ProfileRegistration) { r.HostID = "host" },
		"nil host":                  func(r *ProfileRegistration) { r.HostID = "00000000-0000-0000-0000-000000000000" },
		"noncanonical host":         func(r *ProfileRegistration) { r.HostID = strings.ReplaceAll(r.HostID, "-", "") },
		"invalid role":              func(r *ProfileRegistration) { r.Role = "owner" },
		"missing version":           func(r *ProfileRegistration) { r.ProfileVersion = 0 },
		"unknown version":           func(r *ProfileRegistration) { r.ProfileVersion = 2 },
		"unconfirmed nonpending":    func(r *ProfileRegistration) { r.Pending = false },
		"partial tenant":            func(r *ProfileRegistration) { r.TenantID = profileTestService },
		"partial owner":             func(r *ProfileRegistration) { r.OwnerUserID = profileTestService },
		"partial generation":        func(r *ProfileRegistration) { r.Generation = 1 },
		"partial state":             func(r *ProfileRegistration) { r.DesiredState = "enabled" },
		"negative generation":       func(r *ProfileRegistration) { r.Generation = -1 },
	}
	for _, field := range []string{"tenant", "owner", "generation", "state"} {
		for _, pending := range []bool{false, true} {
			name := field
			if pending {
				name += " pending"
			}
			cases[name] = func(r *ProfileRegistration) {
				r.TenantID, r.OwnerUserID = profileTestService, profileTestService
				r.Generation, r.DesiredState, r.Pending = 1, "enabled", pending
				switch field {
				case "tenant":
					r.TenantID = strings.ToUpper(r.TenantID)
				case "owner":
					r.OwnerUserID = "00000000-0000-0000-0000-000000000000"
				case "generation":
					r.Generation = 0
				case "state":
					r.DesiredState = "unknown"
				}
			}
		}
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, dir, p := savedTestProfile(t)
			r := testProfileRegistration()
			mutate(&r)
			p.Registration = &r
			if err := SaveProfile(dir, p); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadProfile(dir, p.Service); err == nil {
				t.Fatal("accepted invalid registration metadata")
			}
		})
	}
}

func TestProfileRegistrationRejectsUnknownFields(t *testing.T) {
	for _, field := range []string{"Credential", "ProviderOrigin", "Unknown"} {
		t.Run(field, func(t *testing.T) {
			_, dir, p := savedTestProfile(t)
			r := testProfileRegistration()
			p.Registration = &r
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw[:len(raw)-2], []byte(`,"`+field+`":"private-marker"}}`)...)
			if err := os.WriteFile(filepath.Join(dir, "profile.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadProfile(dir, p.Service); err == nil || strings.Contains(err.Error(), "private-marker") {
				t.Fatal("accepted unknown registration field or disclosed its contents")
			}
		})
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

func TestSavePrivateJSONRejectsPaths(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside.json")
	const original = "unchanged"
	if err := os.WriteFile(outside, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", ".", "..", "../outside.json", "nested/../../outside.json", "nested/profile.json", "profile.json/", `..\outside.json`, `nested\profile.json`, outside, "bad\x00name"} {
		t.Run(name, func(t *testing.T) {
			if err := SavePrivateJSON(dir, name, map[string]string{"value": "replacement"}); err == nil {
				t.Fatal("accepted a filename containing a path")
			}
			raw, err := os.ReadFile(outside)
			if err != nil || string(raw) != original {
				t.Fatal("modified file outside private directory")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatal("invalid filename created a file in private directory")
			}
		})
	}
}

func TestSavePrivateJSONLocalFilename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, []byte("old profile"), 0600); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"value": "saved"}
	if err := SavePrivateJSON(dir, "profile.json", want); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(raw, &got); err != nil || got["value"] != want["value"] {
		t.Fatal("valid filename did not save JSON")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("saved file is not private")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "profile.json" {
		t.Fatal("save left temporary files")
	}
}

func TestSenderProfileCompatibilityAndProviderRejection(t *testing.T) {
	state, _, _ := savedTestProfile(t)
	dir, err := ProfileDirectoryForRole(state, profileTestService, "sender")
	if err != nil {
		t.Fatal(err)
	}
	legacy := struct{ Service, Server, Credential string }{profileTestService, "https://example.com", "pgn_act_v1_test"}
	if err := SavePrivateJSON(dir, "profile.json", legacy); err != nil {
		t.Fatal(err)
	}
	p, err := LoadProfile(dir, profileTestService)
	if err != nil || p.ServiceRole() != "sender" || p.ProviderOrigin != "" {
		t.Fatalf("legacy sender: %+v %v", p, err)
	}
	for _, mutate := range []func(*Profile){
		func(p *Profile) { p.ProviderOrigin = "https://provider.example" },
		func(p *Profile) { p.Model = "model" },
		func(p *Profile) { p.KeyFile = "/key" },
		func(p *Profile) { p.Fingerprint = "fingerprint" },
		func(p *Profile) { p.Limits.CallsPerDay = 1 },
		func(p *Profile) { p.Role = "other" },
	} {
		bad := p
		mutate(&bad)
		if err := SaveProfile(dir, bad); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadProfile(dir, profileTestService); err == nil {
			t.Fatal("accepted invalid sender provider/role configuration")
		}
	}
}

func TestProfileExplicitProjectContract(t *testing.T) {
	for _, contract := range []string{"", SharingProjectContract, OwnerTextProjectContract, "unknown"} {
		t.Run(contract, func(t *testing.T) {
			_, dir, p := savedTestProfile(t)
			p.ProjectContract = contract
			if err := SaveProfile(dir, p); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadProfile(dir, p.Service)
			if contract == "unknown" {
				if err == nil {
					t.Fatal("unknown contract loaded")
				}
				return
			}
			if err != nil || loaded.ProjectContract != contract {
				t.Fatal("contract not preserved")
			}
			if contract == OwnerTextProjectContract {
				if loaded.validateProjectContract() == nil {
					t.Fatal("unregistered owner profile allowed runtime startup")
				}
				registration := testProfileRegistration()
				loaded.Registration = &registration
				if err := SaveProfile(dir, loaded); err != nil {
					t.Fatal(err)
				}
				if _, err := LoadProfile(dir, p.Service); err != nil {
					t.Fatal("pending registration cannot be loaded for retry")
				}
				if loaded.validateProjectContract() == nil {
					t.Fatal("pending owner registration allowed runtime startup")
				}
			}
		})
	}
}
