package release

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionValidationMatchesReleaseBuildPolicy(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "version.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		value string
		valid bool
	}{
		{"v0.5.1", true}, {"0.5.1", true}, {"v0.5.0-dev.23+geec961f.dirty", true}, {"v1.2.3-rc.1", true}, {"v1.2.3-0", true},
		{"eec961f", false}, {"dev", false}, {"v0.5", false}, {"v01.2.3", false}, {"v1.2.3-01", false}, {"v1.2.3-rc..1", false}, {"v1.2.3+", false}, {"../v1.2.3", false}, {"v1.2.3\ninjected=1", false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%q", tc.value), func(t *testing.T) {
			if ValidVersion(tc.value) != tc.valid {
				t.Fatalf("Go validation=%v,want%v", ValidVersion(tc.value), tc.valid)
			}
			err := exec.Command("sh", script, "--validate", tc.value).Run()
			if (err == nil) != tc.valid {
				t.Fatalf("build validation=%v,want%v", err, tc.valid)
			}
			if !tc.valid && SignManifest(&Manifest{Version: tc.value}, make([]byte, ed25519.SeedSize)) == nil {
				t.Fatal("invalid version signed")
			}
		})
	}
}

func TestGitBuildVersionIgnoresRollingAndMalformedTags(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "version.sh"))
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("config", "user.name", "Build Test")
	git("config", "user.email", "build@example.invalid")
	git("config", "core.hooksPath", t.TempDir())
	file := filepath.Join(repo, "source.txt")
	commit := func(contents string) {
		t.Helper()
		if err := os.WriteFile(file, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		git("add", "source.txt")
		git("commit", "-qm", contents)
	}
	check := func(want string) {
		t.Helper()
		out, err := exec.Command("sh", script, repo).CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != want {
			t.Fatalf("version=%q,%v;want%q", out, err, want)
		}
	}
	commit("initial")
	sha := git("rev-parse", "--short=12", "HEAD")
	check("v0.0.0-dev.1+g" + sha)
	git("tag", "v0.5.0")
	git("tag", "dev")
	check("v0.5.0")
	commit("next")
	sha = git("rev-parse", "--short=12", "HEAD")
	git("tag", "-f", "dev")
	git("tag", "v99.0.0bad")
	git("tag", "v99.0.0-rc.1")
	expected := "v0.5.0-dev.1+g" + sha
	check(expected)
	if err := os.WriteFile(file, []byte("dirty"), 0600); err != nil {
		t.Fatal(err)
	}
	check(expected + ".dirty")
	git("tag", "v0.5.1")
	check("v0.5.1-dev.0+g" + sha + ".dirty")
	git("checkout", "--", "source.txt")
	check("v0.5.1")
}

func TestFailedReleasePreservesPreviouslyPublishedAssets(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, tc := range []struct{ name, version, target string }{
		{"invalid version", "eec961f", "linux/amd64"},
		{"failed crossbuild", "v0.5.1", "linux/not-an-architecture"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			previous := []string{"pagnet-v0.5.0-linux-amd64.tar.gz", "pagnet-latest-linux-amd64.tar.gz", "pagnet-release-manifest-latest.json"}
			for _, name := range previous {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("previous signed release"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("make", "-C", root, "release", "RELEASE_DIR="+dir, "RELEASE_TARGETS="+tc.target, "VERSION="+tc.version)
			if out, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("failed release unexpectedly succeeded: %s", out)
			}
			for _, name := range previous {
				data, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || string(data) != "previous signed release" {
					t.Fatalf("previous asset %s changed: %q,%v", name, data, err)
				}
			}
		})
	}
}
