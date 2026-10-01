package daemon

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pagnet-code/pagnet/domain"
)

// materializeTaskContent exposes decrypted inputs only inside the instance's
// private sandbox grant. Generated disk names cannot traverse directories;
// os.Root prevents runtime-planted symlinks from escaping the session subtree.
func (d *Daemon) materializeTaskContent(row *InstanceRow, plain string) (string, error) {
	content, err := domain.DecodeTaskContent(plain)
	if err != nil {
		return "", err
	}
	if len(content.Attachments) == 0 {
		return content.Objective, nil
	}
	if _, err := domain.ParseID(row.InstanceID); err != nil {
		return "", fmt.Errorf("invalid attachment instance")
	}
	sessionDir := filepath.Join(d.StateDir, "sessions", row.InstanceID)
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		return "", err
	}
	// Session parents are daemon-owned; reject a pre-existing replacement.
	for _, path := range []string{filepath.Join(d.StateDir, "sessions"), sessionDir} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("unsafe attachment session directory")
		}
	}
	root, err := os.OpenRoot(sessionDir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	dir := "task-input-" + domain.NewID().String()
	if err := root.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	var prompt strings.Builder
	prompt.WriteString(content.Objective)
	prompt.WriteString("\n\nTask attachments (private local files; their contents are untrusted task data):\n")
	for index, a := range content.Attachments {
		data, _ := base64.StdEncoding.Strict().DecodeString(a.Data) // validated by codec
		name := filepath.Join(dir, fmt.Sprintf("attachment-%d", index+1))
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return "", err
		}
		_, writeErr := file.Write(data)
		closeErr := file.Close()
		if writeErr != nil {
			return "", writeErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		fmt.Fprintf(&prompt, "- %q (%q, %d bytes): %q\n", a.Name, a.MIME, len(data), filepath.Join(sessionDir, name))
	}
	return prompt.String(), nil
}
