package runtime

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
)

// ErrExecutableUnavailable deliberately omits executable paths and environment.
var ErrExecutableUnavailable = errors.New("runtime executable or interpreter unavailable")

// ErrExecutableWorkspaceRequired means interpreter resolution depends on the
// eventual launch working directory. Admission must defer to the exact check.
var ErrExecutableWorkspaceRequired = errors.New("runtime interpreter requires launch workspace")

// PreflightExecutable checks a resolved executable and its shebang interpreters
// without executing code. env must be the effective runtime launch environment.
// workdir is the launch working directory; empty uses the controller working
// directory, as inventory and doctor do before a workspace has been selected.
// Inspection is bounded, including interpreter chains and the first line read.
func PreflightExecutable(binary string, env []string, workdir string) error {
	return preflightExecutableEnvironment(binary, env, workdir, true)
}

// PreflightExecutableBeforeWorkspace checks workspace-independent requirements.
// A relative interpreter lookup returns ErrExecutableWorkspaceRequired rather
// than treating the controller working directory as the launch workspace.
func PreflightExecutableBeforeWorkspace(binary string, env []string) error {
	return preflightExecutableEnvironment(binary, env, "", false)
}

func preflightExecutableEnvironment(binary string, env []string, workdir string, workspaceKnown bool) error {
	workdir, err := filepath.Abs(workdir)
	if err != nil {
		return ErrExecutableUnavailable
	}
	if !filepath.IsAbs(binary) {
		binary = filepath.Join(workdir, binary)
	}
	searchPath := "/bin:/usr/bin"
	for _, pair := range env {
		if value, ok := strings.CutPrefix(pair, "PATH="); ok {
			searchPath = value
			break
		}
	}
	return preflightExecutable(binary, searchPath, workdir, 0, workspaceKnown)
}

func preflightExecutable(binary, searchPath, workdir string, depth int, workspaceKnown bool) error {
	if depth >= 4 {
		return ErrExecutableUnavailable
	}
	info, err := os.Stat(binary)
	if err != nil || !info.Mode().IsRegular() || (goruntime.GOOS != "windows" && info.Mode().Perm()&0111 == 0) {
		return ErrExecutableUnavailable
	}
	file, err := os.Open(binary)
	if err != nil {
		return ErrExecutableUnavailable
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 4096))
	if err != nil {
		return ErrExecutableUnavailable
	}
	if !bytes.HasPrefix(data, []byte("#!")) {
		return nil
	}
	line, _, complete := bytes.Cut(data, []byte{'\n'})
	if !complete && len(data) == 4096 {
		return ErrExecutableUnavailable
	}
	fields := strings.FieldsFunc(string(line[2:]), func(r rune) bool { return r == ' ' || r == '\t' })
	if len(fields) == 0 || !filepath.IsAbs(fields[0]) {
		return ErrExecutableUnavailable
	}
	if err := preflightExecutable(fields[0], searchPath, workdir, depth+1, workspaceKnown); err != nil {
		return err
	}
	if filepath.Base(fields[0]) != "env" {
		return nil
	}
	args := fields[1:]
	if len(args) > 0 && args[0] == "-S" {
		// env -S has its own quoting, escaping and expansion grammar. Only
		// simple words are supported here; never approximate that grammar.
		if strings.ContainsAny(string(line[2:]), "\"'\\$#") {
			return ErrExecutableUnavailable
		}
		args = args[1:]
	} else if len(args) != 1 {
		// A kernel shebang supplies one optional argument. Multiple words
		// require env -S; do not claim an unlaunchable wrapper is available.
		return ErrExecutableUnavailable
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") || strings.Contains(args[0], "=") {
		return ErrExecutableUnavailable
	}
	interpreter := args[0]
	if strings.ContainsRune(interpreter, os.PathSeparator) {
		if !filepath.IsAbs(interpreter) {
			if !workspaceKnown {
				return ErrExecutableWorkspaceRequired
			}
			interpreter = filepath.Join(workdir, interpreter)
		}
		return preflightExecutable(interpreter, searchPath, workdir, depth+1, workspaceKnown)
	}
	dirs := filepath.SplitList(searchPath)
	if searchPath == "" {
		dirs = []string{""}
	}
	for _, dir := range dirs {
		if !filepath.IsAbs(dir) {
			if !workspaceKnown {
				return ErrExecutableWorkspaceRequired
			}
			dir = filepath.Join(workdir, dir)
		}
		candidate := filepath.Join(dir, interpreter)
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() && (goruntime.GOOS == "windows" || info.Mode().Perm()&0111 != 0) {
			return preflightExecutable(candidate, searchPath, workdir, depth+1, workspaceKnown)
		}
	}
	return ErrExecutableUnavailable
}
