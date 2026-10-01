//go:build unix

package externalprofile

import (
	"github.com/pagnet-code/pagnet/domain"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExternalProfilePrivateStorageAndPolicy(t *testing.T) {
	state := t.TempDir()
	path, err := Path(state, "work")
	if err != nil {
		t.Fatal(err)
	}
	p := Profile{Version: 1, Principal: domain.NewID().String(), Network: domain.NewID().String(), Server: "https://app.pagnet.dev", Credential: "pgn_act_v1_local-secret"}
	if err := SaveNew(path, p); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || got.Principal != p.Principal || got.Credential != p.Credential {
		t.Fatal("private profile not preserved")
	}
	if err := SaveNew(path, p); err == nil {
		t.Fatal("overwrote existing profile")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("profile public")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("accepted public credential")
	}
	os.Chmod(path, 0600)
	link := filepath.Join(filepath.Dir(path), "link.json")
	os.Symlink(path, link)
	if _, err := Load(link); err == nil {
		t.Fatal("accepted credential symlink")
	}
	bad := p
	bad.Credential = "account-user-token-secret"
	if err := bad.Validate(); err == nil || strings.Contains(err.Error(), bad.Credential) {
		t.Fatal("wrong credential accepted or disclosed")
	}
	bad = p
	bad.Server = "https://secret:password@app.pagnet.dev"
	if err := bad.Validate(); err == nil || strings.Contains(err.Error(), "password") {
		t.Fatal("credential-bearing URL accepted or disclosed")
	}
	if _, err := Path(state, "../../escape"); err == nil {
		t.Fatal("profile name traversal")
	}
}
