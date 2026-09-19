package main

// The CLI's client-side E2EE path (plan D6 / D10): `pagnet invoke` and
// `pagnet event publish` encrypt the protected content on this host before
// it crosses the boundary — reusing the DAEMON'S crypto path: the
// server-announced network state the daemon persists in its state DB
// (daemon.sqlite, the "netcrypto:<networkId>" row) plus the network
// keyring on disk. There is NO plaintext fallback: a network whose crypto
// is not active (provisioning / degraded / not announced) fails with the
// clear not-ready error, and the content is never sent unencrypted.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/daemon"
	"github.com/pagnet-code/pagnet/transport"
)

// ErrClientCryptoNotReady is the user-facing state for client-side
// encryption on a network that is not ready yet (plan D6: networks are
// ALWAYS encrypted — there is no plaintext mode to fall back to).
var ErrClientCryptoNotReady = errors.New("this network is still being secured — encryption is not active yet, so content cannot be sent (no plaintext mode)")

// clientCrypto returns the network's announced crypto state (from the
// daemon's state DB) + the local keyring when the network is ACTIVE with
// an announced epoch and the keyring is installed on this host.
func (c *cliCtx) clientCrypto(networkID string) (daemon.NetworkCryptoState, *crypto.Keyring, error) {
	stPath := filepath.Join(c.stateDir, "daemon.sqlite")
	if _, err := os.Stat(stPath); err != nil {
		return daemon.NetworkCryptoState{}, nil, fmt.Errorf("%w (no daemon state at %s — is the pagnet daemon running on this host?)",
			ErrClientCryptoNotReady, stPath)
	}
	db, err := daemon.OpenState(stPath)
	if err != nil {
		return daemon.NetworkCryptoState{}, nil, fmt.Errorf("open daemon state: %w", err)
	}
	defer db.Close()

	st, ok := db.LoadNetworkCrypto(networkID)
	if !ok {
		return daemon.NetworkCryptoState{}, nil, fmt.Errorf("%w (no announced encryption state for this network)", ErrClientCryptoNotReady)
	}
	if st.Status != "active" || st.EpochID == "" {
		return daemon.NetworkCryptoState{}, nil, fmt.Errorf("%w (network state: %q)", ErrClientCryptoNotReady, st.Status)
	}
	kr, err := crypto.LoadKeyring(c.stateDir, networkID)
	if err != nil {
		return daemon.NetworkCryptoState{}, nil, fmt.Errorf("%w (keyring not installed on this host: %v)", ErrClientCryptoNotReady, err)
	}
	if _, ok := kr.EpochByID(st.EpochID); !ok {
		return daemon.NetworkCryptoState{}, nil, fmt.Errorf("%w (the announced key epoch is not in this host's keyring yet)", ErrClientCryptoNotReady)
	}
	return st, kr, nil
}

// newClientObjectID mints a client-generated UUIDv7 for a protected
// object (same pattern as the daemon: the id's embedded timestamp is the
// AAD's CreatedAt — a single clock source).
func newClientObjectID() string {
	id, err := uuid.NewV7()
	if err != nil {
		id, _ = uuid.NewRandom()
	}
	return id.String()
}

// clientAAD builds the AAD for a CLI-encrypted object. Sender is "" (the
// CLI acts for the signed-in user; the server knows the caller from the
// bearer). ProtocolVersion is 2 (the V2 content protocol).
func clientAAD(st daemon.NetworkCryptoState, objectType, objectID, recipient string) e2ee.AAD {
	aad := e2ee.AAD{
		ProtocolVersion: transport.ProtocolVersion,
		TenantID:        st.TenantID,
		NetworkID:       st.NetworkID,
		ObjectType:      objectType,
		ObjectID:        objectID,
		Sender:          "",
		Recipient:       recipient,
		KeyEpochID:      st.EpochID,
	}
	if id, err := uuid.Parse(objectID); err == nil && id.Version() == 7 {
		ms := uint64(id[0])<<40 | uint64(id[1])<<32 | uint64(id[2])<<24 |
			uint64(id[3])<<16 | uint64(id[4])<<8 | uint64(id[5])
		aad.CreatedAt = time.UnixMilli(int64(ms)).UTC().Format(time.RFC3339)
	} else {
		aad.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	return aad
}

// encryptClientContent encrypts a protected content string under the
// announced current epoch (the binding epoch rule: always the announced
// one; a missing epoch fails clean). It returns the envelope + the AAD
// the REST body must carry (the server relays both verbatim).
func (c *cliCtx) encryptClientContent(st daemon.NetworkCryptoState, kr *crypto.Keyring,
	objectType, objectID, recipient, plaintext string) (e2ee.EncryptedPayloadV1, e2ee.AAD, error) {
	epoch, ok := kr.EpochByID(st.EpochID)
	if !ok {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, fmt.Errorf("%w (announced epoch %s not in local keyring)", ErrClientCryptoNotReady, st.EpochID)
	}
	key, err := epoch.KeyArray()
	if err != nil {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, err
	}
	aad := clientAAD(st, objectType, objectID, recipient)
	env, err := e2ee.Encrypt([]byte(plaintext), key, aad)
	if err != nil {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, err
	}
	return env, aad, nil
}

// decryptClientContent decrypts an envelope with the keyring's epoch for
// the envelope's key_epoch_id (used for synchronous invocation results).
func (c *cliCtx) decryptClientContent(kr *crypto.Keyring, env e2ee.EncryptedPayloadV1, aad e2ee.AAD) (string, error) {
	epoch, ok := kr.EpochByID(env.KeyEpochID)
	if !ok {
		return "", fmt.Errorf("crypto: the result's key epoch %s is not in this host's keyring", env.KeyEpochID)
	}
	key, err := epoch.KeyArray()
	if err != nil {
		return "", err
	}
	plain, err := e2ee.Decrypt(env, key, aad)
	if err != nil {
		return "", fmt.Errorf("decrypt result: %w", err)
	}
	return string(plain), nil
}

// readJSONContent reads a JSON document from a file path, or from stdin
// when path is "-". An empty path reads the default "{}". The result is
// the compact JSON bytes (validated as a JSON object or array).
func readJSONContent(path string) ([]byte, error) {
	if path == "" {
		return []byte("{}"), nil
	}
	var rd io.Reader
	if path == "-" {
		rd = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		rd = f
	}
	raw, err := io.ReadAll(bufio.NewReader(rd))
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return []byte("{}"), nil
	}
	if !json.Valid(trimmed) {
		return nil, fmt.Errorf("input is not valid JSON: %s", pathOrStdin(path))
	}
	// Compact (canonical-ish) form: the plaintext that gets encrypted is
	// deterministic for a given input document.
	compact, err := json.Marshal(json.RawMessage(trimmed))
	if err != nil {
		return nil, err
	}
	return compact, nil
}

func pathOrStdin(path string) string {
	if path == "-" {
		return "stdin"
	}
	return path
}
