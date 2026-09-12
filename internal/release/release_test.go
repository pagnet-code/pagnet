package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// TestReleaseTarballShape is the one-binary packaging contract:
// `make release` for one target produces a tarball containing EXACTLY
// the unified pagnet executable plus the non-binary members (LICENSE,
// README.md) — no pagnetd, no MCP bridge binaries, no fake runtime. It
// builds one target (linux/amd64) into a scratch dir and inspects the
// members, so a regression that ships a second executable (or drops the
// unified binary) fails here instead of on an installed host.
func TestReleaseTarballShape(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make not available")
	}
	// The Makefile lives at the repo root (two levels up from this
	// package).
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "Makefile")); err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	out := t.TempDir()
	cmd := exec.Command("make", "-C", root, "release",
		"RELEASE_DIR="+out, "RELEASE_TARGETS=linux/amd64", "VERSION=shapetest")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("make release: %v\n%s", err, stderr.String())
	}
	tarPath := filepath.Join(out, "pagnet-shapetest-linux-amd64.tar.gz")
	f, err := os.Open(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var (
		names      []string
		pagnetMode os.FileMode
	)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		names = append(names, filepath.Base(hdr.Name))
		if filepath.Base(hdr.Name) == BinaryName {
			pagnetMode = hdr.FileInfo().Mode()
		}
	}
	sort.Strings(names)
	want := []string{"LICENSE", "README.md", BinaryName}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("tarball members = %v, want exactly %v", names, want)
	}
	if pagnetMode&0o111 == 0 {
		t.Fatalf("the pagnet member is not executable: %v", pagnetMode)
	}
}
