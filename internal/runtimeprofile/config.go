// Package runtimeprofile defines host-local execution settings. Nothing except
// profile name, canonical runtime and availability belongs in public inventory.
package runtimeprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pagnet-code/pagnet/domain"
)

const Filename = "runtime-profiles.json"

type Profile struct {
	Name       string             `json:"name"`
	Runtime    domain.RuntimeName `json:"runtime"`
	Executable string             `json:"executable,omitempty"`
	Args       []string           `json:"args,omitempty"`
	Env        map[string]string  `json:"env,omitempty"`
	NativeDirs []string           `json:"nativeDirs,omitempty"`
}
type File struct {
	Version  int       `json:"version"`
	Profiles []Profile `json:"profiles"`
}

var envPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

func Load(path string) (File, error) {
	data, err := readPrivate(path)
	if errors.Is(err, os.ErrNotExist) {
		return File{Version: 1}, nil
	}
	if err != nil {
		return File{}, err
	}
	var f File
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&f) != nil {
		return File{}, errors.New("invalid runtime profile configuration")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return File{}, errors.New("invalid runtime profile configuration")
	}
	if err := f.Validate(); err != nil {
		return File{}, err
	}
	return f, nil
}
func (f File) Validate() error {
	if f.Version != 1 || len(f.Profiles) > 32 {
		return errors.New("invalid runtime profile version or count")
	}
	names := map[string]bool{}
	for _, p := range f.Profiles {
		if !domain.ValidRuntimeProfileName(p.Name) || names[p.Name] {
			return errors.New("runtime profile names must be unique lowercase identifiers")
		}
		names[p.Name] = true
		switch p.Runtime {
		case domain.RuntimeClaudeCode, domain.RuntimeOpenCode, domain.RuntimeCodex, domain.RuntimeQwenCode:
		default:
			return errors.New("runtime profile requires a supported canonical runtime")
		}
		if len(p.Args) > 32 || len(p.Env) > 32 || len(p.NativeDirs) > 16 {
			return errors.New("runtime profile exceeds setting limits")
		}
		if p.Executable != "" && !filepath.IsAbs(ExpandHome(p.Executable)) {
			return errors.New("profile executable must be an absolute path; omit it to use the native CLI")
		}
		values := append([]string{p.Executable}, p.Args...)
		for k, v := range p.Env {
			upper := strings.ToUpper(k)
			if !envPattern.MatchString(k) || strings.HasPrefix(upper, "PAGNET_") || upper == "HOME" || upper == "USERPROFILE" || upper == "BASH_ENV" || upper == "ENV" || strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "DYLD_") {
				return errors.New("runtime profile contains a reserved or invalid environment key")
			}
			values = append(values, v)
		}
		for _, v := range values {
			if len(v) > 16*1024 || strings.ContainsRune(v, 0) {
				return errors.New("runtime profile contains an invalid setting")
			}
		}
		for _, dir := range p.NativeDirs {
			if !filepath.IsAbs(ExpandHome(dir)) || len(dir) > 4096 {
				return errors.New("profile native directories must be absolute host-local paths")
			}
		}
		for _, key := range []string{"CLAUDE_CONFIG_DIR", "CODEX_HOME"} {
			if v := p.Env[key]; v != "" && !filepath.IsAbs(ExpandHome(v)) {
				return errors.New("runtime configuration directory must be absolute")
			}
		}
	}
	return nil
}
func ExpandHome(value string) string {
	if strings.HasPrefix(value, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, value[2:])
		}
	}
	return value
}
func (p Profile) ResolvedExecutable() (string, bool) {
	binary := ExpandHome(p.Executable)
	if binary == "" {
		switch p.Runtime {
		case domain.RuntimeClaudeCode:
			binary = "claude"
		case domain.RuntimeOpenCode:
			binary = "opencode"
		case domain.RuntimeQwenCode:
			binary = "qwen"
		case domain.RuntimeCodex:
			binary = "codex"
		}
	}
	resolved, err := exec.LookPath(binary)
	if err != nil {
		return "", false
	}
	resolved, err = filepath.Abs(resolved)
	return resolved, err == nil
}
func (p Profile) Environment() []string {
	keys := make([]string, 0, len(p.Env))
	for k := range p.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, k := range keys {
		v := p.Env[k]
		if k == "CLAUDE_CONFIG_DIR" || k == "CODEX_HOME" {
			v = ExpandHome(v)
		}
		env = append(env, k+"="+v)
	}
	return env
}
func (p Profile) Directories() []string {
	dirs := append([]string(nil), p.NativeDirs...)
	if len(dirs) == 0 {
		if p.Runtime == domain.RuntimeClaudeCode && p.Env["CLAUDE_CONFIG_DIR"] != "" {
			dirs = []string{p.Env["CLAUDE_CONFIG_DIR"]}
		}
		if p.Runtime == domain.RuntimeCodex && p.Env["CODEX_HOME"] != "" {
			dirs = []string{p.Env["CODEX_HOME"]}
		}
	}
	for n, v := range dirs {
		dirs[n] = ExpandHome(v)
	}
	return dirs
}
func (p Profile) Digest() string {
	data, _ := json.Marshal(p)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func readPrivate(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 128*1024 {
		return nil, errors.New("runtime profile file must be a bounded regular file")
	}
	if err := validateOwner(info); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open runtime profile configuration")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(info, after) {
		return nil, errors.New("runtime profile file changed while opening")
	}
	if err := validateOwner(after); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(f, 128*1024+1))
}
func Save(path string, file File) error {
	if err := file.Validate(); err != nil {
		return err
	}
	if _, err := Load(path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".runtime-profiles-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if info, err := tmp.Stat(); err != nil {
		tmp.Close()
		return err
	} else if err := validateOwner(info); err != nil {
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
	return os.Rename(tmp.Name(), path)
}
