package localinstallation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

func installationFixture(t *testing.T) (*Installation, string, Options) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "authority")
	options := Options{Settings: DefaultSettings(filepath.Join(filepath.Dir(dir), "fabric.sock"))}
	value, e := Bootstrap(t.Context(), dir, options)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { value.Close() })
	return value, dir, options
}
func TestExplicitInstallationStableKeyRootAndExactRepeatedInit(t *testing.T) {
	original, dir, options := installationFixture(t)
	if _, err := json.Marshal(original.Keys); err == nil {
		t.Fatal("private key provider serialized")
	}
	if _, err := json.Marshal(original); err == nil {
		t.Fatal("private installation serialized")
	}
	root := original.Store.AuthorityIdentity()
	actual, e := currentOperator()
	if e != nil || root.Owner != actual {
		t.Fatal("root not actual OS operator", e)
	}
	owner, e := original.Operator(t.Context())
	if e != nil || owner.AuthenticationEvidence() == nil {
		t.Fatal("missing actual operator capability", e)
	}
	secret := []byte("private application marker 9007199254740993")
	sealed, e := original.Keys.Seal([]byte("original-purpose"), secret)
	if e != nil {
		t.Fatal(e)
	}
	configBefore, e := os.ReadFile(filepath.Join(dir, configFilename))
	if e != nil {
		t.Fatal(e)
	}
	keyBefore, e := os.ReadFile(filepath.Join(dir, keyFilename))
	if e != nil {
		t.Fatal(e)
	}
	defer clear(keyBefore)
	if e = original.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = original.Keys.Open([]byte("original-purpose"), sealed); e == nil {
		t.Fatal("closed encryption key still works")
	}
	repeat, e := Bootstrap(t.Context(), dir, options)
	var existing *AlreadyInstalledError
	if repeat != nil || !errors.As(e, &existing) || existing.StoreID != root.StoreID {
		t.Fatal("repeat init recreated or failed to explain retained installation", e)
	}
	configAfter, _ := os.ReadFile(filepath.Join(dir, configFilename))
	keyAfter, _ := os.ReadFile(filepath.Join(dir, keyFilename))
	defer clear(keyAfter)
	if !bytes.Equal(configBefore, configAfter) || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("repeat init replaced original configuration/key")
	}
	reopened, e := Load(t.Context(), dir, registry.Options{})
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if reopened.Store.AuthorityIdentity().StoreID != root.StoreID || reopened.Keys.Reference() != original.Keys.Reference() {
		t.Fatal("identity or encryption key reference changed")
	}
	plain, e := reopened.Keys.Open([]byte("original-purpose"), sealed)
	if e != nil || !bytes.Equal(plain, secret) {
		t.Fatal("original key not restored", e)
	}
	if _, e = reopened.Keys.Open([]byte("substituted-purpose"), sealed); e == nil {
		t.Fatal("ciphertext accepted under another purpose")
	}
	if e = reopened.WithCurrentOperator(t.Context(), owner, func(context.Context) error { return nil }); e == nil {
		t.Fatal("old installation proof admitted under new loader")
	}
	files, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range files {
		if f.IsDir() || f.Name() == keyFilename || f.Name() == "genesis.key" {
			continue
		}
		data, e := os.ReadFile(filepath.Join(dir, f.Name()))
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(data, keyAfter) || bytes.Contains(data, secret) {
			t.Fatal("key/application payload leaked to public/config persistence", f.Name())
		}
	}
}
func TestInstallationMissingTamperedOrSubstitutedStateNeverRegenerates(t *testing.T) {
	for _, mode := range []string{"key-missing", "config-missing", "wrong-key", "changed-config", "changed-key-and-config", "retired-pin", "root-key-missing", "config-duplicate-key"} {
		t.Run(mode, func(t *testing.T) {
			value, dir, options := installationFixture(t)
			owner, e := value.Operator(t.Context())
			if e != nil {
				t.Fatal(e)
			}
			if mode == "retired-pin" {
				e = value.Store.WithNativeAuthority(t.Context(), owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error {
					r, e := tx.Get(pinKey)
					if e != nil {
						return e
					}
					_, e = tx.CAS(pinKey, r.Revision, r.Value, true)
					return e
				})
				if e != nil {
					t.Fatal(e)
				}
			}
			value.Close()
			switch mode {
			case "key-missing":
				e = os.Remove(filepath.Join(dir, keyFilename))
			case "config-missing":
				e = os.Remove(filepath.Join(dir, configFilename))
			case "root-key-missing":
				e = os.Remove(filepath.Join(dir, "genesis.key"))
			case "wrong-key", "changed-key-and-config":
				key := sha256.Sum256([]byte("replacement key forbidden"))
				e = os.WriteFile(filepath.Join(dir, keyFilename), key[:], 0600)
			case "config-duplicate-key":
				data, _ := os.ReadFile(filepath.Join(dir, configFilename))
				data = append([]byte(`{"version":"bad",`), data[1:]...)
				e = os.WriteFile(filepath.Join(dir, configFilename), data, 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			if mode == "changed-config" || mode == "changed-key-and-config" {
				c := value.Configuration()
				c.Settings.MaxWorkers++
				raw, _ := json.Marshal(c)
				if e = os.WriteFile(filepath.Join(dir, configFilename), raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
			keyBefore, _ := os.ReadFile(filepath.Join(dir, keyFilename))
			defer clear(keyBefore)
			configBefore, _ := os.ReadFile(filepath.Join(dir, configFilename))
			if opened, e := Load(t.Context(), dir, registry.Options{}); e == nil || opened != nil {
				if opened != nil {
					opened.Close()
				}
				t.Fatal("invalid original state was accepted")
			}
			retried, e := Bootstrap(t.Context(), dir, options)
			var incomplete *IncompleteInstallationError
			if e == nil || retried != nil || !errors.As(e, &incomplete) {
				if retried != nil {
					retried.Close()
				}
				t.Fatal("partial state repaired/reset instead of reported", e)
			}
			keyAfter, _ := os.ReadFile(filepath.Join(dir, keyFilename))
			defer clear(keyAfter)
			configAfter, _ := os.ReadFile(filepath.Join(dir, configFilename))
			if !bytes.Equal(keyBefore, keyAfter) || !bytes.Equal(configBefore, configAfter) {
				t.Fatal("failed load/init replaced state")
			}
		})
	}
}
func TestProtectedOperatorCapabilityAndCloseJoin(t *testing.T) {
	i, _, _ := installationFixture(t)
	owner, e := i.Operator(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	substituted, e := fabric.NewAuthenticatedContext(owner.PrincipalView(), owner.Audience(), []byte("generic historical/setup assertion"))
	if e != nil {
		t.Fatal(e)
	}
	if e = i.WithCurrentOperator(t.Context(), substituted, func(context.Context) error { t.Fatal("sameprincipal nil-evidence callback executed"); return nil }); e == nil {
		t.Fatal("principal equality qualified as actual operator")
	}
	fake, e := fabric.NewAuthenticatedContextWithEvidence(owner.PrincipalView(), owner.Audience(), []byte("changed original"), owner.AuthenticationEvidence())
	if e != nil {
		t.Fatal(e)
	}
	if e = i.WithCurrentOperator(t.Context(), fake, func(context.Context) error { t.Fatal("changed setup digest callback executed"); return nil }); e == nil {
		t.Fatal("altered setup bytes qualified")
	}
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		finished <- i.WithCurrentOperator(t.Context(), owner, func(context.Context) error { close(entered); <-release; return nil })
	}()
	<-entered
	bounded, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	e = i.CloseContext(bounded)
	cancel()
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("close fabricated join", e)
	}
	if _, e = i.Store.CurrentAuthorityIdentity(t.Context()); e != nil {
		t.Fatal("close released root while callback active", e)
	}
	if _, e = i.Operator(t.Context()); e == nil {
		t.Fatal("closing installation admits new operator")
	}
	close(release)
	<-finished
	if e = i.Close(); e != nil {
		t.Fatal(e)
	}
	if e = i.WithCurrentOperator(t.Context(), owner, func(context.Context) error { t.Fatal("closed proof callback executed"); return nil }); e == nil {
		t.Fatal("closed capability retained authority")
	}
}
func TestPrivateKeyProviderConcurrentClose(t *testing.T) {
	i, _, _ := installationFixture(t)
	var workers sync.WaitGroup
	for n := 0; n < 8; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for k := 0; k < 50; k++ {
				sealed, e := i.Keys.Seal([]byte("purpose"), []byte("payload"))
				if e == nil {
					_, _ = i.Keys.Open([]byte("purpose"), sealed)
				}
			}
		}()
	}
	i.Keys.Close()
	workers.Wait()
	if _, e := i.Keys.Seal(nil, []byte("new")); e == nil {
		t.Fatal("closed provider admitted encryption")
	}
	if i.Keys.key != ([32]byte{}) {
		t.Fatal("raw secret not cleared")
	}
}
