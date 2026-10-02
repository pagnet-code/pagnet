package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
)

const Subcommand = "session-worker"

type Bootstrap struct {
	Protocol string     `json:"protocol"`
	Scope    Scope      `json:"scope"`
	Native   NativeSpec `json:"native"`
}

// RunMain is intercepted by the unified binary before account/login plumbing.
// Bootstrap and the control key are owner-local files; arbitrary vendor env
// overrides arrive only through an inherited private pipe, never a state file.
func RunMain(args []string, build string) int {
	if err := runMain(args, build); err != nil {
		fmt.Fprintln(os.Stderr, "pagnet session worker:", err)
		return 1
	}
	return 0
}
func runMain(args []string, build string) error {
	flags := flag.NewFlagSet(Subcommand, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dir := flags.String("state", "", "private worker state")
	envFD := flags.Int("env-fd", -1, "inherited memory-only runtime environment pipe")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !filepath.IsAbs(*dir) {
		return errors.New("invalid private session worker arguments")
	}
	if err := privateDirectory(*dir); err != nil {
		return err
	}
	raw, err := readPrivateFile(filepath.Join(*dir, "bootstrap.json"), 128<<10)
	if err != nil {
		return err
	}
	var bootstrap Bootstrap
	if err = decodeClosed(raw, &bootstrap); err != nil || bootstrap.Protocol != Protocol {
		return errors.New("invalid private worker bootstrap protocol")
	}
	key, err := readPrivateFile(filepath.Join(*dir, "control.key"), 32)
	if err != nil || len(key) != 32 {
		return errors.New("private worker control key unavailable")
	}
	defer clear(key)
	if *envFD != -1 {
		if *envFD < 3 || *envFD > 32 {
			return errors.New("invalid private runtime environment pipe")
		}
		f := os.NewFile(uintptr(*envFD), "runtime-env")
		info, err := f.Stat()
		if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			_ = f.Close()
			return errors.New("runtime environment must arrive through an inherited pipe")
		}
		data, err := io.ReadAll(io.LimitReader(f, (128<<10)+1))
		_ = f.Close()
		if err != nil || len(data) > 128<<10 {
			return errors.New("runtime environment exceeds bound")
		}
		if err = decodeClosed(data, &bootstrap.Native.Env); err != nil {
			clear(data)
			return errors.New("invalid private runtime environment")
		}
		clear(data)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, cancelWorker := workerSignals(ctx)
	defer cancelWorker()
	journal, err := OpenJournal(*dir, bootstrap.Scope)
	if err != nil {
		return err
	}
	defer journal.Close()
	owner, err := NewSessionOwner(ctx, journal, bootstrap.Native, key)
	if err != nil {
		return err
	}
	defer owner.Close()
	workerCtx := ctx
	ctx, cancelServers := context.WithCancel(workerCtx)
	defer cancelServers()
	bridgeReady := make(chan struct{})
	bridgeDone := make(chan error, 1)
	go func() { bridgeDone <- owner.serveBridge(ctx, bridgeReady) }()
	// Whole ownership is not advertised while its required native bridge is
	// absent. A permanent listener failure cannot leave a usable control socket.
	select {
	case err := <-bridgeDone:
		if workerCtx.Err() != nil {
			return nil
		}
		return fmt.Errorf("native bridge startup failed: %w", err)
	case <-workerCtx.Done():
		cancelServers()
		<-bridgeDone
		return nil
	case <-bridgeReady:
	}
	controlDone := make(chan error, 1)
	go func() { controlDone <- ServeOwner(ctx, owner, key, build) }()
	var cause error
	select {
	case cause = <-bridgeDone:
		cancelServers()
		<-controlDone
	case cause = <-controlDone:
		cancelServers()
		<-bridgeDone
	}
	if workerCtx.Err() != nil {
		return nil
	}
	select {
	case <-owner.retirement:
		return nil
	default:
	}
	if cause == nil {
		return errors.New("required worker listener terminated unexpectedly")
	}
	return fmt.Errorf("required worker listener failed: %w", cause)

}
func decodeClosed(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing private protocol data")
	}
	return nil
}

// PrepareBootstrap never overwrites an existing worker identity/key. Changes
// to execution profile require an explicit lifecycle transition, not an
// invisible native restart during controller upgrade.
func PrepareBootstrap(dir string, b Bootstrap, key []byte) error {
	if b.Protocol != Protocol || len(key) != 32 || b.Scope.AccountID == "" || b.Scope.HostID == "" || b.Scope.InstanceID == "" || b.Scope.Generation == "" {
		return errors.New("invalid worker bootstrap")
	}
	if err := privateDirectory(dir); err != nil {
		return err
	}
	ownership, err := acquireOwnership(dir)
	if err != nil {
		return err
	}
	defer ownership.Close()
	for _, name := range []string{"bootstrap.json", "control.key"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			return errors.New("worker bootstrap identity already exists or is unavailable")
		}
	}
	raw, err := json.Marshal(b)
	if err != nil || len(raw) > 128<<10 {
		return errors.New("worker bootstrap exceeds bound")
	}
	// The manifest is the final publication marker. In-process failures remove
	// only files created by this invocation; existing identities are untouched.
	created := []string{}
	published := false
	defer func() {
		if !published {
			for _, path := range created {
				_ = os.Remove(path)
			}
		}
	}()
	for _, entry := range []struct {
		Name string
		Data []byte
	}{{"control.key", key}, {"bootstrap.json", raw}} {
		f, err := os.OpenFile(filepath.Join(dir, entry.Name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		created = append(created, filepath.Join(dir, entry.Name))
		_, writeErr := f.Write(entry.Data)
		if writeErr == nil {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return err
	}
	published = true
	return nil
}
