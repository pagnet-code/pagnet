package sessionworker

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

type LocalBootstrap struct {
	Protocol           string         `json:"protocol"`
	Authority          AuthorityScope `json:"authority"`
	Native             NativeSpec     `json:"native"`
	ProfileEnvironment []string       `json:"profileEnvironment,omitempty"`
}

func PrepareLocalBootstrap(dir string, b LocalBootstrap, key []byte) error {
	if !filepath.IsAbs(dir) || b.Protocol != LocalProtocol || b.Authority.Kind() != nativeauthority.Local || b.Authority.Validate() != nil || len(key) != 32 || validateLocalEnvironment(b.Native, true) != nil {
		return ErrFenced
	}
	local, _ := b.Authority.Local()
	if b.Native.Kind != "local" || string(b.Native.Runtime) != local.ActualRuntime || LocalNativeProfileFingerprint(b.Native) != hex.EncodeToString(local.ProfileDigest[:]) {
		return ErrFenced
	}
	if len(b.ProfileEnvironment) > 0 && !sameLocalJSON(b.ProfileEnvironment, b.Native.Env) {
		return ErrFenced
	}
	b.ProfileEnvironment = append([]string(nil), b.Native.Env...)
	raw, e := json.Marshal(b)
	if e != nil || len(raw) > 128<<10 {
		return ErrFull
	}
	return prepareBootstrapFiles(dir, raw, key)
}
func LoadLocalControllerBootstrap(dir string, expected AuthorityScope) (LocalBootstrap, []byte, error) {
	var result LocalBootstrap
	if !filepath.IsAbs(dir) || expected.Kind() != nativeauthority.Local || expected.Validate() != nil {
		return result, nil, ErrFenced
	}
	for p := filepath.Clean(dir); ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (p == filepath.Clean(dir) && info.Mode().Perm() != 0700) {
			return result, nil, ErrFenced
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	raw, e := readPrivateFile(filepath.Join(dir, "bootstrap.json"), 128<<10)
	if e != nil {
		return result, nil, e
	}
	if decodeClosed(raw, &result) != nil || result.Protocol != LocalProtocol || result.Authority != expected {
		return LocalBootstrap{}, nil, ErrFenced
	}
	result.Native.Env = append([]string(nil), result.ProfileEnvironment...)
	if validateLocalEnvironment(result.Native, true) != nil {
		return LocalBootstrap{}, nil, ErrFenced
	}
	key, e := readPrivateFile(filepath.Join(dir, "control.key"), 32)
	if e != nil || len(key) != 32 {
		clear(key)
		return LocalBootstrap{}, nil, ErrFenced
	}
	return result, key, nil
}
func runLocalMain(raw []byte, dir string, envFD int, build string) error {
	var b LocalBootstrap
	if decodeClosed(raw, &b) != nil || b.Protocol != LocalProtocol || b.Authority.Kind() != nativeauthority.Local || b.Authority.Validate() != nil {
		return ErrFenced
	}
	b.Native.Env = append([]string(nil), b.ProfileEnvironment...)
	if validateLocalEnvironment(b.Native, true) != nil {
		return ErrFenced
	}
	key, e := readPrivateFile(filepath.Join(dir, "control.key"), 32)
	if e != nil || len(key) != 32 {
		return ErrFenced
	}
	defer clear(key)
	if envFD != -1 {
		if envFD < 3 || envFD > 32 {
			return ErrFenced
		}
		f := os.NewFile(uintptr(envFD), "runtime-env")
		info, e := f.Stat()
		if e != nil || info.Mode()&os.ModeNamedPipe == 0 {
			f.Close()
			return ErrFenced
		}
		raw, e := io.ReadAll(io.LimitReader(f, (128<<10)+1))
		f.Close()
		if e != nil || len(raw) > 128<<10 {
			return ErrFull
		}
		var inherited []string
		e = decodeClosed(raw, &inherited)
		clear(raw)
		if e != nil {
			return ErrFenced
		}
		b.Native.Env, e = mergeLocalRuntimeEnvironment(b.Native, inherited)
		if e != nil {
			return e
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, cancelWorker := workerSignals(ctx)
	defer cancelWorker()
	j, e := OpenAuthorityJournal(dir, b.Authority)
	if e != nil {
		return e
	}
	defer j.Close()
	owner, e := NewLocalSessionOwner(ctx, j, b.Native, key)
	if e != nil {
		return e
	}
	defer owner.Close()
	local, _ := b.Authority.Local()
	binder, err := nativeauthority.NewInputBinder(b.Native.InputBindingProfile, local.ProfileDigest)
	if err != nil {
		return err
	}
	e = ServeLocalOwner(ctx, owner, key, build, binder)
	if ctx.Err() != nil {
		return nil
	}
	if e == nil {
		return errors.New("local worker listener unexpectedly stopped")
	}
	return e
}
