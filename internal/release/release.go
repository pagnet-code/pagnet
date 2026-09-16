// Package release implements the one-binary release format shared by the
// daemon's auto-update and the manual `pagnet update` command: download
// the platform's tarball from the control plane's public /download/
// endpoint, validate that it carries the unified pagnet binary, and
// atomically replace the installed binary (stage in the target's own
// directory + rename — the target is never left partial).
//
// A release tarball (pagnet-<version>-<os>-<arch>.tar.gz, flat) contains
// exactly ONE executable — `pagnet` (CLI, daemon and MCP bridges in a
// single binary; the daemon self-spawns its bridges from its own
// executable) — plus the non-binary members LICENSE and README.md.
package release

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// BinaryName is the single executable a release ships.
const BinaryName = "pagnet"

// DownloadTimeout bounds a release tarball download.
const DownloadTimeout = 5 * time.Minute

// ErrNoBinary is returned when a release tarball does not carry the
// unified pagnet binary: the artifact is not a pagnet release (an
// old-format or foreign tarball), and the update must fail cleanly —
// the caller keeps running its current build.
var ErrNoBinary = errors.New("pagnet binary not found in tarball")

// TarballName is the stable per-platform release artifact name served at
// /download/ (the pagnet-latest-* convention of `make release`).
func TarballName(goos, goarch string) string {
	return "pagnet-latest-" + goos + "-" + goarch + ".tar.gz"
}

// ExtractPagnet unpacks the release tarball (a flat pagnet-*.tar.gz)
// into dir and returns the path of the pagnet binary inside it. Only
// the binary is extracted: the non-binary members (LICENSE, README.md)
// are not needed by an update. A missing pagnet member is fatal —
// ErrNoBinary — so a wrong artifact can never be installed.
func ExtractPagnet(tarPath, dir string) (string, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var found string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != BinaryName {
			continue
		}
		dst := filepath.Join(dir, BinaryName)
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return "", err
		}
		if err := out.Close(); err != nil {
			return "", err
		}
		if found == "" {
			found = dst
		}
	}
	if found == "" {
		return "", ErrNoBinary
	}
	return found, nil
}

// ReplaceBinary atomically replaces dst with the bytes of src: the new
// content is staged in dst's OWN directory (same filesystem, so the
// final rename is atomic), fsynced, chmodded 0755, and renamed over
// dst. Readers of dst never observe a partial file, and on Linux the
// rename replaces even a RUNNING executable (the live process keeps its
// inode) — that is how the on-disk install is updated alongside the
// re-exec.
func ReplaceBinary(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".pagnet-update-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, dst)
}
