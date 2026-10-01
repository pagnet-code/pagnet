package daemon

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
)

func TestSessionGuidanceIsPrivateScopedAndRemovedWithoutWorkLoss(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	d := &Daemon{StateDir: filepath.Join(home, ".pagnet"), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	row := &InstanceRow{InstanceID: domain.NewID().String(), Instruction: "Keep operator instructions", NetworkID: domain.NewID().String()}
	_, standing, err := d.writeStandingDocument(row)
	if err != nil {
		t.Fatal(err)
	}
	skill := filepath.Join(d.StateDir, "sessions", row.InstanceID, ".pagnet", "skills", "pagnet-coordination", "SKILL.md")
	data, err := os.ReadFile(skill)
	if err != nil || string(data) != coordinationSkill {
		t.Fatalf("skill materialization: %v", err)
	}
	info, _ := os.Stat(skill)
	if info.Mode().Perm() != 0600 {
		t.Fatal("guidance not private")
	}
	if !strings.Contains(standing, skill) || !strings.Contains(standing, row.Instruction) {
		t.Fatal("native standing instructions did not include skill and operator context")
	}
	for _, vendor := range []string{".claude", ".qwen", ".codex", ".config/opencode"} {
		if _, err := os.Stat(filepath.Join(home, vendor)); !os.IsNotExist(err) {
			t.Fatalf("global runtime home changed: %s", vendor)
		}
	}
	work := filepath.Join(d.StateDir, "sessions", row.InstanceID, "work-product.txt")
	if err := os.WriteFile(work, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	d.removeSessionGuidance(row.InstanceID)
	if _, err := os.Stat(skill); !os.IsNotExist(err) {
		t.Fatal("skill survived instance cleanup")
	}
	if data, err := os.ReadFile(work); err != nil || string(data) != "keep" {
		t.Fatal("cleanup removed work")
	}
}

func TestSessionGuidanceRejectsDirectoryEscapeAndReplacesFileSymlink(t *testing.T) {
	d := &Daemon{StateDir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	row := &InstanceRow{InstanceID: domain.NewID().String()}
	path, err := d.writeSessionGuidance(row)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := d.writeSessionGuidance(row); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(secret)
	if string(data) != "untouched" {
		t.Fatal("skill write followed file symlink")
	}
	if err := os.RemoveAll(filepath.Join(d.StateDir, "sessions", row.InstanceID, ".pagnet")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(d.StateDir, "sessions", row.InstanceID, ".pagnet")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.writeSessionGuidance(row); err == nil {
		t.Fatal("accepted escaping directory symlink")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 1 {
		t.Fatal("wrote outside session")
	}
}
