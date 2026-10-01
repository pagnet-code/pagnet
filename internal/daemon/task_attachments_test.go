package daemon

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
)

func TestPrivateTaskAttachmentMaterialization(t *testing.T) {
	d := &Daemon{Config: Config{StateDir: t.TempDir()}}
	row := &InstanceRow{InstanceID: domain.NewID().String()}
	raw, err := domain.EncodeTaskContent(domain.TaskContent{Objective: "inspect attachment", Attachments: []domain.TaskAttachment{{Name: "report.txt", MIME: "text/plain", Data: base64.StdEncoding.EncodeToString([]byte("private data"))}}})
	if err != nil {
		t.Fatal(err)
	}
	prompt, err := d.materializeTaskContent(row, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prompt, "inspect attachment") || strings.Contains(prompt, "cHJpdmF0ZSBkYXRh") {
		t.Fatal("invalid attachment prompt")
	}
	files, err := filepath.Glob(filepath.Join(d.StateDir, "sessions", row.InstanceID, "task-input-*", "attachment-1"))
	if err != nil || len(files) != 1 {
		t.Fatalf("files %v %v", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil || string(data) != "private data" {
		t.Fatal("attachment mismatch")
	}
	info, err := os.Stat(files[0])
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("attachment not private")
	}
	outside := t.TempDir()
	other := &InstanceRow{InstanceID: domain.NewID().String()}
	if err := os.Symlink(outside, filepath.Join(d.StateDir, "sessions", other.InstanceID)); err != nil {
		t.Skip(err)
	}
	if _, err := d.materializeTaskContent(other, raw); err == nil {
		t.Fatal("followed unsafe session symlink")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal("wrote outside session")
	}
}
