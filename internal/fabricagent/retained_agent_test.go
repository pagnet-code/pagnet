package fabricagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

func TestRetainedAgentCorruptOrRetiredConfigurationNeverRegenerates(t *testing.T) {
	for _, retire := range []bool{false, true} {
		t.Run(map[bool]string{false: "corrupt", true: "retired"}[retire], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			parent := t.TempDir()
			dir, socket := filepath.Join(parent, "authority"), filepath.Join(parent, "node.sock")
			installation, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
			if e != nil {
				t.Fatal(e)
			}
			defer installation.Close()
			owner, e := installation.Operator(ctx)
			if e != nil {
				t.Fatal(e)
			}
			store, e := NewRetainedAgentStore(ctx, installation.Store, owner, installation.Keys)
			if e != nil {
				t.Fatal(e)
			}
			ref, _ := fabric.NewEndpointRef(installation.Store.AuthorityIdentity().PublicKey)
			spec := sessionworker.NativeSpec{Kind: "local", Runtime: domain.RuntimeClaudeCode, Binary: "/operator/claude", MCPExecutable: "/operator/pagnet", Workspace: parent, LocalAuthorityDirectory: dir, LocalFabricSocket: socket}
			digest := sha256.Sum256([]byte("actual-private-setup"))
			unproved := spec
			unproved.InitialNativeSessionID = "asserted-old-session"
			if _, e = store.Reserve(ctx, ref, digest, unproved, filepath.Join(parent, "workers")); e == nil {
				t.Fatal("SID alone authorized local conversation adoption")
			}
			original, e := store.Reserve(ctx, ref, digest, spec, filepath.Join(parent, "workers"))
			if e != nil {
				t.Fatal(e)
			}
			key, _, e := store.key(ref)
			if e != nil {
				t.Fatal(e)
			}
			e = installation.Store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{MaxOperations: 2, Timeout: 5 * time.Second}, func(tx *registry.AuthorityTx) error {
				row, e := tx.Get(key)
				if e != nil {
					return e
				}
				value, _ := json.Marshal(agentCipher{Cipher: []byte("corrupt-ciphertext")})
				_, e = tx.CAS(key, row.Revision, value, retire)
				return e
			})
			if e != nil {
				t.Fatal(e)
			}
			if _, e = store.Get(ctx, ref); e == nil {
				t.Fatal("damaged retained profile accepted")
			}
			if _, e = store.Reserve(ctx, ref, digest, spec, filepath.Join(parent, "workers")); e == nil {
				t.Fatal("damaged profile regenerated original IDs")
			}
			// The actual signed replay row remains its second revision; failed reads
			// and setup retries perform no mutation or replacement authority.
			e = installation.Store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{MaxOperations: 1, Timeout: 5 * time.Second}, func(tx *registry.AuthorityTx) error {
				row, e := tx.Get(key)
				if e == nil && row.Revision != 2 {
					t.Fatal("failed setup changed signed replay state")
				}
				return e
			})
			if e != nil {
				t.Fatal(e)
			}
			if original.Instance.ID == "" || original.Definition.ID == "" || original.Profile.Worker.ProfileDigest == [32]byte{} || hex.EncodeToString(original.Profile.Worker.ProfileDigest[:]) != sessionworker.LocalNativeProfileFingerprint(spec) {
				t.Fatal("original private identities not genuinely retained")
			}
		})
	}
}
