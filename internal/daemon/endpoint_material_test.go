//go:build linux || darwin

package daemon

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func endpointMaterialFenceOK(*sql.Conn) (func(), func() error, error) {
	return func() {}, func() error { return nil }, nil
}

func TestEndpointMaterialSourceV2(t *testing.T) {
	for _, kind := range []string{"live", "credential-expired", "budget-expired", "wrong-installation", "wrong-credential", "wrong-role", "wrong-use", "wrong-boot", "wrong-ownership", "wrong-runner", "missing", "corrupt", "key-missing", "key-corrupt", "unsafe-mode", "ack-tampered", "replay", "nil-fence", "nil-check", "nil-release", "nil-callback", "revoked", "stopped", "replaced", "cancel-after-use", "expire-after-use", "callback-error", "panic"} {
		t.Run(kind, func(t *testing.T) {
			keys, issue, session := directSourceCredentialFixtureV2(t)
			if _, err := keys.InstallCredential(issue, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err != nil {
				t.Fatal(err)
			}
			keys.now = func() time.Time { return issue.InstallExpiresAt.Add(time.Nanosecond) }
			scope := endpointMaterialScope{keys.installation, issue.CredentialID, "S", endpointMaterialLiveUse}
			fence := endpointMaterialFence(endpointMaterialFenceOK)
			called, released := false, false
			var secret, private []byte
			use := func(m endpointMaterial) error {
				called = true
				secret, private = m.secret, m.private
				if len(secret) != 32 || len(private) != 32 {
					t.Fatal("invalid material length")
				}
				for _, format := range []string{"%v", "%+v", "%#v"} {
					if got := fmt.Sprintf(format, m); got != "endpointMaterial{closed}" {
						t.Fatal("material formatting leaked")
					}
				}
				if kind == "expire-after-use" {
					keys.now = func() time.Time { return issue.CredentialExpiresAt }
				}
				if kind == "callback-error" {
					return errors.New(string(m.secret))
				}
				if kind == "panic" {
					panic("interrupted")
				}
				return nil
			}
			path := directSourceCredentialPathV2(keys, issue)
			switch kind {
			case "credential-expired":
				keys.now = func() time.Time { return issue.CredentialExpiresAt }
			case "budget-expired":
				keys.now = func() time.Time { return issue.BudgetExpiresAt }
			case "wrong-installation":
				scope.installation = domain.NewID()
			case "wrong-credential":
				scope.credential = domain.NewID()
			case "wrong-role":
				scope.role = "P"
			case "wrong-use":
				scope.use = "historical"
			case "wrong-boot":
				session.BootID = "replacement"
			case "wrong-ownership":
				session.OwnershipScope = "shared"
			case "wrong-runner":
				session.RunnerID = domain.NewID().String()
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			case "key-missing":
				if err := os.Remove(strings.TrimSuffix(path, ".credential.json") + ".json"); err != nil {
					t.Fatal(err)
				}
			case "key-corrupt":
				if err := os.WriteFile(strings.TrimSuffix(path, ".credential.json")+".json", []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unsafe-mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "ack-tampered":
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(raw)
				var record directManagedSourceCredentialFileV2
				if err := json.Unmarshal(raw, &record); err != nil {
					t.Fatal(err)
				}
				defer clear(record.Secret)
				ack, err := transport.DecodeDirectManagedSourceCredentialACKV2(record.ACK)
				if err != nil {
					t.Fatal(err)
				}
				ack.HostConfirmation = strings.Repeat("ab", 32)
				record.ACK, err = ack.CanonicalBytes()
				if err != nil {
					t.Fatal(err)
				}
				changed, err := json.Marshal(record)
				defer clear(changed)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, changed, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := keys.registry.db.Exec(`UPDATE native_direct_managed_source_v2_credentials SET ack=? WHERE credential_id=?`, record.ACK, issue.CredentialID); err != nil {
					t.Fatal(err)
				}

			case "replay":
				issue.CredentialID = domain.NewID()
				scope.credential = issue.CredentialID
			case "nil-fence":
				fence = nil
			case "nil-callback":
				use = nil
			}
			if kind == "revoked" || kind == "stopped" || kind == "replaced" || kind == "cancel-after-use" || kind == "nil-check" || kind == "nil-release" {
				fence = func(*sql.Conn) (func(), func() error, error) {
					release := func() { released = true }
					check := func() error {
						if kind != "cancel-after-use" || called {
							return errors.New("authority unavailable")
						}
						return nil
					}
					if kind == "nil-check" {
						check = nil
					}
					if kind == "nil-release" {
						release = nil
					}
					return release, check, nil
				}
			}
			var err error
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				err = keys.withDirectManagedSourceEndpointMaterialV2(issue, "https://example.test", session, scope, directSourceCredentialScopeOKV2, fence, use)
			}()
			if kind == "panic" {
				if recovered != "interrupted" {
					t.Fatal("missing callback panic")
				}
			} else if recovered != nil || (err == nil) != (kind == "live") {
				t.Fatalf("unexpected outcome: %v", err)
			}
			if err != nil && err != errDirectManagedSourceKeyV2 {
				t.Fatal("secret in error")
			}
			if len(secret) > 0 && (!bytes.Equal(secret, make([]byte, len(secret))) || !bytes.Equal(private, make([]byte, len(private)))) {
				t.Fatal("material not cleared")
			}
			wantCalled := kind == "live" || kind == "cancel-after-use" || kind == "expire-after-use" || kind == "callback-error" || kind == "panic"
			if called != wantCalled {
				t.Fatal("callback escaped authority validation")
			}
			if (kind == "revoked" || kind == "stopped" || kind == "replaced" || kind == "cancel-after-use" || kind == "nil-check") && !released {
				t.Fatal("authority guard not released")
			}
			if kind == "missing" {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("missing secret regenerated")
				}
			}
		})
	}
}

func TestEndpointMaterialTargetV1(t *testing.T) {
	for _, kind := range []string{"live", "credential-expired", "budget-expired", "wrong-installation", "wrong-credential", "wrong-role", "wrong-use", "wrong-boot", "wrong-ownership", "wrong-runner", "missing", "corrupt", "key-missing", "key-corrupt", "unsafe-mode", "ack-tampered", "replay", "nil-fence", "nil-check", "nil-release", "nil-callback", "revoked", "stopped", "replaced", "cancel-after-use", "expire-after-use", "callback-error", "panic"} {
		t.Run(kind, func(t *testing.T) {
			keys, issue, session, _ := managedCredentialStoreFixture(t)
			if _, err := keys.InstallCredential(issue, "https://example.test", session, managedCredentialScopeOK, managedCredentialFenceOK); err != nil {
				t.Fatal(err)
			}
			keys.now = func() time.Time { return issue.InstallExpiresAt.Add(time.Nanosecond) }
			scope := endpointMaterialScope{keys.installation, issue.CredentialID, "P", endpointMaterialLiveUse}
			fence := endpointMaterialFence(endpointMaterialFenceOK)
			called, released := false, false
			var secret, private []byte
			use := func(m endpointMaterial) error {
				called = true
				secret, private = m.secret, m.private
				if len(secret) != 32 || len(private) != 32 {
					t.Fatal("invalid material length")
				}
				for _, format := range []string{"%v", "%+v", "%#v"} {
					if got := fmt.Sprintf(format, m); got != "endpointMaterial{closed}" {
						t.Fatal("material formatting leaked")
					}
				}
				if kind == "expire-after-use" {
					keys.now = func() time.Time { return issue.CredentialExpiresAt }
				}
				if kind == "callback-error" {
					return errors.New(string(m.secret))
				}
				if kind == "panic" {
					panic("interrupted")
				}
				return nil
			}
			path := managedCredentialPath(keys, issue)
			switch kind {
			case "credential-expired":
				keys.now = func() time.Time { return issue.CredentialExpiresAt }
			case "budget-expired":
				keys.now = func() time.Time { return issue.Budget.ExpiresAt }
			case "wrong-installation":
				scope.installation = domain.NewID()
			case "wrong-credential":
				scope.credential = domain.NewID()
			case "wrong-role":
				scope.role = "S"
			case "wrong-use":
				scope.use = "historical"
			case "wrong-boot":
				session.BootID = "replacement"
			case "wrong-ownership":
				session.OwnershipScope = "shared"
			case "wrong-runner":
				session.RunnerID = domain.NewID().String()
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			case "key-missing":
				if err := os.Remove(filepath.Join(keys.registry.root, nativeManagedEndpointKeyNamespace, managedEndpointKeyScope(keys.installation, "https://example.test", issue.PoP.Prepare.Subject)+".json")); err != nil {
					t.Fatal(err)
				}
			case "key-corrupt":
				if err := os.WriteFile(filepath.Join(keys.registry.root, nativeManagedEndpointKeyNamespace, managedEndpointKeyScope(keys.installation, "https://example.test", issue.PoP.Prepare.Subject)+".json"), []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unsafe-mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "ack-tampered":
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(raw)
				var record directManagedSourceCredentialFileV2
				if err := json.Unmarshal(raw, &record); err != nil {
					t.Fatal(err)
				}
				defer clear(record.Secret)
				ack, err := transport.DecodeManagedDirectCredentialACK(record.ACK)
				if err != nil {
					t.Fatal(err)
				}
				ack.HostConfirmation = strings.Repeat("ab", 32)
				record.ACK, err = ack.CanonicalBytes()
				if err != nil {
					t.Fatal(err)
				}
				changed, err := json.Marshal(record)
				defer clear(changed)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, changed, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := keys.registry.db.Exec(`UPDATE native_managed_direct_v1_credentials SET ack=? WHERE credential_id=?`, record.ACK, issue.CredentialID); err != nil {
					t.Fatal(err)
				}

			case "replay":
				issue.CredentialID = domain.NewID()
				scope.credential = issue.CredentialID
			case "nil-fence":
				fence = nil
			case "nil-callback":
				use = nil
			}
			if kind == "revoked" || kind == "stopped" || kind == "replaced" || kind == "cancel-after-use" || kind == "nil-check" || kind == "nil-release" {
				fence = func(*sql.Conn) (func(), func() error, error) {
					release := func() { released = true }
					check := func() error {
						if kind != "cancel-after-use" || called {
							return errors.New("authority unavailable")
						}
						return nil
					}
					if kind == "nil-check" {
						check = nil
					}
					if kind == "nil-release" {
						release = nil
					}
					return release, check, nil
				}
			}
			var err error
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				err = keys.withManagedTargetEndpointMaterial(issue, "https://example.test", session, scope, managedCredentialScopeOK, fence, use)
			}()
			if kind == "panic" {
				if recovered != "interrupted" {
					t.Fatal("missing callback panic")
				}
			} else if recovered != nil || (err == nil) != (kind == "live") {
				t.Fatalf("unexpected outcome: %v", err)
			}
			if err != nil && err != errManagedEndpointKey {
				t.Fatal("secret in error")
			}
			if len(secret) > 0 && (!bytes.Equal(secret, make([]byte, len(secret))) || !bytes.Equal(private, make([]byte, len(private)))) {
				t.Fatal("material not cleared")
			}
			wantCalled := kind == "live" || kind == "cancel-after-use" || kind == "expire-after-use" || kind == "callback-error" || kind == "panic"
			if called != wantCalled {
				t.Fatal("callback escaped authority validation")
			}
			if (kind == "revoked" || kind == "stopped" || kind == "replaced" || kind == "cancel-after-use" || kind == "nil-check") && !released {
				t.Fatal("authority guard not released")
			}
			if kind == "missing" {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("missing secret regenerated")
				}
			}
		})
	}
}
