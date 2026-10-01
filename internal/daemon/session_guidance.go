package daemon

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pagnet-code/pagnet/domain"
)

//go:embed skills/pagnet-coordination/SKILL.md
var coordinationSkill string

// This is an explicitly loaded session reference, not an installation into a
// vendor's global skill search path. os.Root confines runtime-planted links.
func (d *Daemon) writeSessionGuidance(row *InstanceRow) (string, error) {
	if _, err := domain.ParseID(row.InstanceID); err != nil {
		return "", fmt.Errorf("invalid guidance instance")
	}
	sessionDir := filepath.Join(d.StateDir, "sessions", row.InstanceID)
	if err := os.MkdirAll(sessionDir, 0700); err != nil {
		return "", err
	}
	for _, path := range []string{filepath.Join(d.StateDir, "sessions"), sessionDir} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("unsafe guidance session directory")
		}
	}
	root, err := os.OpenRoot(sessionDir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	const dir = ".pagnet/skills/pagnet-coordination"
	if err := root.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	temporary := filepath.Join(dir, ".skill-"+domain.NewID().String())
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	defer root.Remove(temporary)
	_, writeErr := file.WriteString(coordinationSkill)
	closeErr := file.Close()
	if writeErr != nil {
		return "", writeErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err := root.Rename(temporary, filepath.Join(dir, "SKILL.md")); err != nil {
		return "", err
	}
	return filepath.Join(sessionDir, dir, "SKILL.md"), nil
}

func coordinationSkillBody() string {
	_, rest, _ := strings.Cut(coordinationSkill, "---\n")
	_, body, _ := strings.Cut(rest, "---\n")
	return strings.TrimSpace(body)
}

func (d *Daemon) removeSessionGuidance(instanceID string) {
	if _, err := domain.ParseID(instanceID); err != nil {
		return
	}
	root, err := os.OpenRoot(d.StateDir)
	if err != nil {
		return
	}
	defer root.Close()
	// Remove only the managed resource; preserve runtime sessions/work products.
	_ = root.RemoveAll(filepath.Join("sessions", instanceID, ".pagnet", "skills", "pagnet-coordination"))
}
