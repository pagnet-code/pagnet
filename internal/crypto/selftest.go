package crypto

import (
	"bytes"
	"fmt"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
)

// selfTestObjectType is the AAD object type for the crypto self-test.
const selfTestObjectType = "e2ee_selftest"

// selfTestPlaintext is the fixed payload the self-test encrypts and verifies.
var selfTestPlaintext = []byte("pagnet-e2ee-selftest-v1")

// SelfTest performs a client-side crypto round trip (plan §11.6 step 6): it
// encrypts a self-test object under the current epoch and verifies that the
// (in-memory echoed) ciphertext decrypts correctly. The server-side echo is a
// follow-up; this validates the local encrypt/decrypt path end to end.
//
// A network's crypto must not be reported active (the state that lets content
// operations run) until this succeeds — the activation ack carries
// selfTestOk, and the control plane flips the network to "active" only when it
// is true. V2 networks are ALWAYS encrypted (plan D6): there is no
// plaintext/privacy-mode state left to flip.
func SelfTest(kr *Keyring, tenantID, hostID string, now time.Time) error {
	epoch, err := kr.ActiveEpoch()
	if err != nil {
		return err
	}
	epochKey, err := epoch.KeyArray()
	if err != nil {
		return err
	}
	aad := e2ee.AAD{
		ProtocolVersion: e2ee.AADVersion,
		TenantID:        tenantID,
		NetworkID:       kr.NetworkID,
		ObjectType:      selfTestObjectType,
		ObjectID:        string(domain.NewID()),
		Sender:          hostID,
		Recipient:       hostID,
		CreatedAt:       now.UTC().Format(time.RFC3339),
		KeyEpochID:      epoch.ID,
	}
	env, err := e2ee.Encrypt(selfTestPlaintext, epochKey, aad)
	if err != nil {
		return fmt.Errorf("crypto: self-test encrypt: %w", err)
	}
	// In-memory echo: decrypt the just-encrypted envelope.
	got, err := e2ee.Decrypt(env, epochKey, aad)
	if err != nil {
		return fmt.Errorf("crypto: self-test decrypt: %w", err)
	}
	if !bytes.Equal(got, selfTestPlaintext) {
		return fmt.Errorf("crypto: self-test round-trip mismatch")
	}
	return nil
}
