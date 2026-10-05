//go:build linux || darwin

package localinstallation

import (
	"github.com/pagnet-code/pagnet/fabric/registry"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallationRejectsSymlinkAndBroadKeyPermissions(t *testing.T) {
	for _, mode := range []string{"broad-key", "symlink-key", "symlink-config", "broad-directory"} {
		t.Run(mode, func(t *testing.T) {
			value, dir, _ := installationFixture(t)
			value.Close()
			var e error
			switch mode {
			case "broad-key":
				e = os.Chmod(filepath.Join(dir, keyFilename), 0644)
			case "broad-directory":
				e = os.Chmod(dir, 0755)
			case "symlink-key", "symlink-config":
				name := keyFilename
				if mode == "symlink-config" {
					name = configFilename
				}
				original := filepath.Join(dir, name)
				target := filepath.Join(filepath.Dir(dir), "outside-private-file")
				e = os.Rename(original, target)
				if e == nil {
					e = os.Symlink(target, original)
				}
			}
			if e != nil {
				t.Fatal(e)
			}
			if opened, e := Load(t.Context(), dir, registry.Options{}); e == nil || opened != nil {
				if opened != nil {
					opened.Close()
				}
				t.Fatal("unsafe private installation accepted")
			}
		})
	}
}
