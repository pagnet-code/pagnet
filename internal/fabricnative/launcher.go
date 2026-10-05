package fabricnative

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

type LauncherConfig struct {
	Checkpoints                *Checkpoints
	Peers                      *ManagedPeers
	Binary, AuthorityDirectory string
	StartupTimeout             time.Duration
	MaxWorkers                 int
}
type LaunchSpec struct {
	Directory             string
	Ownership             nativeauthority.Scope
	Native                sessionworker.NativeSpec
	ControlKey            []byte
	RuntimeEnvironment    []string
	Attempt, ControllerID string
}

// WorkerConnection contains private controller capabilities, never discovery or
// caller DTOs. Closing a controller does not stop the independent native owner.
type WorkerConnection struct {
	Client     *sessionworker.LocalClient
	Process    localpeer.ProcessSnapshot
	Ownership  nativeauthority.Scope
	Directory  string
	keyMu      sync.Mutex
	controlKey []byte
}

// KeyCopy returns an owned capability copy. Callers must clear it after use.
func (c *WorkerConnection) KeyCopy() []byte {
	if c == nil {
		return nil
	}
	c.keyMu.Lock()
	defer c.keyMu.Unlock()
	return bytes.Clone(c.controlKey)
}
func (c *WorkerConnection) clearKey() {
	c.keyMu.Lock()
	clear(c.controlKey)
	c.controlKey = nil
	c.keyMu.Unlock()
}

type launchProcess struct {
	done chan struct{}
	mu   sync.Mutex
	err  error
}

func (p *launchProcess) result() error { p.mu.Lock(); defer p.mu.Unlock(); return p.err }

type Launcher struct {
	config    LauncherConfig
	mu        sync.Mutex
	closed    bool
	slots     map[string]bool
	clients   map[string]*WorkerConnection
	processes map[string]*launchProcess
}

func launchDenied() error {
	return fabric.NewError(fabric.CodeTargetUnavailable, "Original local worker unavailable; authenticated adoption required")
}
func NewLauncher(c LauncherConfig) (*Launcher, error) {
	if !launcherSupported() {
		return nil, fabric.NewError(fabric.CodeTargetUnavailable, "Local worker kernel ownership is unsupported on this platform")
	}
	if c.Checkpoints == nil || c.Peers == nil || c.Checkpoints.store != c.Peers.store || !filepath.IsAbs(c.Binary) || filepath.Clean(c.Binary) != c.Binary || !filepath.IsAbs(c.AuthorityDirectory) || filepath.Clean(c.AuthorityDirectory) != c.AuthorityDirectory || c.StartupTimeout < time.Second || c.StartupTimeout > time.Minute || c.MaxWorkers < 1 || c.MaxWorkers > 4096 {
		return nil, launchDenied()
	}
	actualDirectory, err := c.Checkpoints.store.CurrentAuthorityDirectory(context.Background())
	if err != nil || actualDirectory != c.AuthorityDirectory {
		return nil, launchDenied()
	}
	stat, e := os.Stat(c.Binary)
	if e != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0111 == 0 {
		return nil, launchDenied()
	}
	return &Launcher{config: c, slots: map[string]bool{}, clients: map[string]*WorkerConnection{}, processes: map[string]*launchProcess{}}, nil
}
func (l *Launcher) reserve(directory string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.slots[directory] {
		return launchDenied()
	}
	// A directory is one physical slot whether it is launching, adopted, or
	// retains an uncertain/reaped spawn. Count the union before any FULL claim.
	count := len(l.processes)
	for dir := range l.clients {
		if l.processes[dir] == nil {
			count++
		}
	}
	for dir := range l.slots {
		if l.processes[dir] == nil && l.clients[dir] == nil {
			count++
		}
	}
	known := l.processes[directory] != nil || l.clients[directory] != nil
	if !known && count >= l.config.MaxWorkers {
		return launchDenied()
	}
	l.slots[directory] = true
	return nil
}
func (l *Launcher) release(directory string) { l.mu.Lock(); delete(l.slots, directory); l.mu.Unlock() }
func (l *Launcher) validate(s LaunchSpec) error {
	if l == nil || !filepath.IsAbs(s.Directory) || filepath.Clean(s.Directory) != s.Directory || len(s.ControlKey) != 32 || s.ControllerID == "" || len(s.ControllerID) > 256 || s.Attempt == "" || len(s.Attempt) > 256 || s.Native.MCPExecutable != l.config.Binary || s.Native.LocalAuthorityDirectory != l.config.AuthorityDirectory || s.Ownership.Validate() != nil {
		return launchDenied()
	}
	local, ok := s.Ownership.Local()
	if !ok || string(s.Native.Runtime) != local.ActualRuntime || sessionworker.LocalNativeProfileFingerprint(s.Native) != hex.EncodeToString(local.ProfileDigest[:]) {
		return launchDenied()
	}
	return sessionworker.ValidateLocalRuntimeEnvironment(s.Native, s.RuntimeEnvironment)
}

// Launch consumes one FULL launch claim before preparing/spawning the idle
// independent worker. Cancellation or spawn/readiness failure never resets it.
func (l *Launcher) Launch(ctx context.Context, s LaunchSpec) (*WorkerConnection, error) {
	if ctx == nil || l == nil {
		return nil, launchDenied()
	}
	// Own configuration and key bytes across blocking launch/recovery steps.
	envProfile := append([]string(nil), s.Native.Env...)
	raw, e := json.Marshal(s.Native)
	if e != nil || len(raw) > 128<<10 {
		return nil, launchDenied()
	}
	var native sessionworker.NativeSpec
	if fabric.DecodeJSONWithLimits(raw, &native, fabric.WireLimits{MaxBytes: 128 << 10, MaxDepth: 64, MaxMembers: 4096}) != nil {
		return nil, launchDenied()
	}
	native.Env = envProfile
	s.Native = native
	s.ControlKey = bytes.Clone(s.ControlKey)
	defer clear(s.ControlKey)
	s.RuntimeEnvironment = append([]string(nil), s.RuntimeEnvironment...)
	for _, pair := range s.RuntimeEnvironment {
		if !utf8.ValidString(pair) {
			return nil, launchDenied()
		}
	}
	if e := l.validate(s); e != nil {
		return nil, e
	}
	env, e := json.Marshal(s.RuntimeEnvironment)
	if e != nil || len(env) > 128<<10 {
		return nil, launchDenied()
	}
	defer clear(env)
	if e = l.reserve(s.Directory); e != nil {
		return nil, e
	}
	defer l.release(s.Directory)
	bounded, cancel := context.WithTimeout(ctx, l.config.StartupTimeout)
	defer cancel()
	ctx = bounded
	ticket, e := l.config.Checkpoints.BeginLaunch(ctx, s.Ownership, s.Attempt, s.Directory)
	if e != nil {
		return nil, e
	}
	var process localpeer.ProcessSnapshot
	var reaped *launchProcess
	e = ticket.Run(ctx, func(current context.Context) error {
		if e := sessionworker.PrepareLocalBootstrap(s.Directory, sessionworker.LocalBootstrap{Protocol: sessionworker.LocalProtocol, Authority: s.Ownership, Native: s.Native}, s.ControlKey); e != nil {
			return e
		}
		if e := current.Err(); e != nil {
			return e
		}
		reader, writer, e := os.Pipe()
		if e != nil {
			return e
		}
		defer reader.Close()
		command := exec.Command(l.config.Binary, sessionworker.Subcommand, "--state", s.Directory, "--env-fd", "3")
		command.Dir = s.Directory
		command.Env = []string{"PATH=/usr/bin:/bin"}
		command.ExtraFiles = []*os.File{reader}
		if e := detachWorker(command); e != nil {
			writer.Close()
			return e
		}
		if e = command.Start(); e != nil {
			writer.Close()
			return e
		}
		reader.Close()
		reaped = &launchProcess{done: make(chan struct{})}
		l.mu.Lock()
		l.processes[s.Directory] = reaped
		l.mu.Unlock()
		go func() {
			err := command.Wait()
			reaped.mu.Lock()
			reaped.err = err
			reaped.mu.Unlock()
			close(reaped.done)
		}()
		// No native intent can be admitted before this registration. If kernel
		// classification itself fails, kill only this unregistered idle child.
		process, e = localpeer.ReadProcess(command.Process.Pid)
		if e == nil {
			e = l.config.Peers.guard.Register(context.Background(), process)
		}
		if e != nil {
			writer.Close()
			_ = command.Process.Kill()
			return e
		}
		// Secrets are written only to the inherited FD. Wait for worker consumption,
		// child exit or caller cancellation; never kill it on request cancellation.
		written := make(chan error, 1)
		pipeBytes := bytes.Clone(env)
		go func() { _, e := writer.Write(pipeBytes); clear(pipeBytes); writer.Close(); written <- e }()
		select {
		case e = <-written:
			return e
		case <-reaped.done:
			writer.Close()
			<-written
			return launchDenied()
		case <-current.Done():
			writer.Close()
			<-written
			return current.Err()
		}
	})
	if e != nil {
		return nil, e
	}
	return l.connect(ctx, s.Directory, s.Ownership, s.ControlKey, s.ControllerID, &process, reaped)
}

// Adopt never launches or prepares bootstrap files. A missing/uncertain socket
// or mismatched retained claim remains unavailable; no reset/replacement occurs.
func (l *Launcher) Adopt(ctx context.Context, directory string, ownership nativeauthority.Scope, controller string) (*WorkerConnection, error) {
	if l == nil || ctx == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || ownership.Validate() != nil || controller == "" || len(controller) > 256 {
		return nil, launchDenied()
	}
	if e := l.reserve(directory); e != nil {
		return nil, e
	}
	defer l.release(directory)
	bootstrap, key, e := sessionworker.LoadLocalControllerBootstrap(directory, ownership)
	if e != nil {
		return nil, e
	}
	defer clear(key)
	if bootstrap.Native.MCPExecutable != l.config.Binary || bootstrap.Native.LocalAuthorityDirectory != l.config.AuthorityDirectory {
		return nil, launchDenied()
	}
	bounded, cancel := context.WithTimeout(ctx, l.config.StartupTimeout)
	defer cancel()
	return l.connect(bounded, directory, ownership, key, controller, nil, nil)
}
func (l *Launcher) connect(ctx context.Context, dir string, scope nativeauthority.Scope, key []byte, controller string, expected *localpeer.ProcessSnapshot, reaped *launchProcess) (*WorkerConnection, error) {
	socket, e := sessionworker.SocketPath(dir)
	if e != nil {
		return nil, e
	}
	delay := 5 * time.Millisecond
	for {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		if reaped != nil {
			select {
			case <-reaped.done:
				return nil, launchDenied()
			default:
			}
		}
		info, statErr := os.Lstat(socket)
		if statErr == nil {
			if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
				return nil, launchDenied()
			}
			break
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return nil, launchDenied()
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}
		if delay < 100*time.Millisecond {
			delay *= 2
		}
	}
	client, e := sessionworker.DialLocal(ctx, dir, scope, key, controller)
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			client.Close()
		}
	}()
	process, e := client.OwnerProcess()
	if e != nil {
		return nil, e
	}
	if expected != nil && process != *expected {
		return nil, launchDenied()
	}
	// Recovery is classified before claim observation and before any public owner
	// socket can be exposed. The claim only records real authenticated IPC birth.
	if e = l.config.Peers.guard.Register(ctx, process); e != nil {
		return nil, e
	}
	if _, e = l.config.Checkpoints.ObserveLaunched(ctx, scope, client); e != nil {
		return nil, e
	}
	if e = l.config.Peers.Register(ctx, client, scope); e != nil {
		return nil, e
	}
	privateKey := bytes.Clone(key)
	l.mu.Lock()
	if l.closed || l.clients[dir] == nil && len(l.clients) >= l.config.MaxWorkers {
		l.mu.Unlock()
		clear(privateKey)
		return nil, launchDenied()
	}
	connection := &WorkerConnection{Client: client, Process: process, Ownership: scope, Directory: dir, controlKey: privateKey}
	previous := l.clients[dir]
	l.clients[dir] = connection
	l.mu.Unlock()
	if previous != nil {
		previous.Client.Close()
		previous.clearKey()
	}
	success = true
	return connection, nil
}

// Close relinquishes controller connections and secrets; independently owned
// processes and their genuine journals/launch claims remain available for adopt.
func (l *Launcher) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	for dir, connection := range l.clients {
		connection.Client.Close()
		connection.clearKey()
		delete(l.clients, dir)
	}
	return nil
}
