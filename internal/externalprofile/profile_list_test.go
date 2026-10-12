package externalprofile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListProfiles(t *testing.T) {
	dir := t.TempDir()
	names, err := List(dir)
	if err != nil || len(names) != 0 {
		t.Fatalf("empty state: names=%v err=%v", names, err)
	}
	p := Profile{Version: 1, Principal: "01900000-0000-7000-8000-000000000002", Network: "01900000-0000-7000-8000-000000000001", Server: "https://app.pagnet.dev", Credential: "pgn_act_v1_test"}
	for _, name := range []string{"beta", "alpha"} {
		path, err := Path(dir, name)
		if err != nil {
			t.Fatal(err)
		}
		if err := SaveNew(path, p); err != nil {
			t.Fatal(err)
		}
	}
	// State dirs and stray files are not profiles.
	if err := os.MkdirAll(filepath.Join(dir, "external-profiles", "alpha.state"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "external-profiles", "notes.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	names, err = List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != "alpha" || names[1] != "beta" {
		t.Fatalf("list=%v", names)
	}
}
