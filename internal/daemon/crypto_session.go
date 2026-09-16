package daemon

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

// errCryptoSessionGone is the sentinel the daemon acks when a browser key
// session is unknown or expired (daemon restart, TTL expiry, or explicit
// end). The control plane maps it to HTTP 410 crypto_session_gone. It is a
// stable, sanitized string (no key material, no internal detail).
const errCryptoSessionGone = "crypto_session_gone"

// sessionValid returns the session for p's sessionId, refreshing its TTL. It
// is the shared authorization gate for the unwrap/wrap commands: an unknown,
// expired, or network-mismatched session is a clean crypto_session_gone.
func (d *Daemon) sessionValid(pNetworkID, pSessionID string) (*browserSession, error) {
	sess, ok := d.cryptoManager().sessions.get(pSessionID, time.Now().UTC())
	if !ok || sess.NetworkID != pNetworkID {
		return nil, fmt.Errorf("%s", errCryptoSessionGone)
	}
	return sess, nil
}

// doCryptoSessionStart records a browser key session (plan §13, p10). The
// host must hold the network keyring (an enrolled, crypto-ready host) — a
// host without it cannot unwrap/wrap CEKs. It returns the host's static
// X25519 public key (the browser wraps write CEKs to it). The session is
// in-memory: a daemon restart drops it.
func (d *Daemon) doCryptoSessionStart(p transport.CryptoSessionStartPayload) (any, error) {
	kr, err := crypto.LoadKeyring(d.StateDir, p.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("crypto: session start: %w", err)
	}
	id, err := d.cryptoManager().hostIdentity()
	if err != nil {
		return nil, err
	}
	epoch, err := kr.ActiveEpoch()
	if err != nil {
		return nil, err
	}
	d.cryptoManager().sessions.sweep(time.Now().UTC())
	d.cryptoManager().sessions.create(p.SessionID, p.UserID, p.NetworkID, p.BrowserPub, time.Now().UTC())
	return &transport.CryptoSessionStartResult{
		HostX25519: base64.StdEncoding.EncodeToString(id.X25519Pub),
		EpochID:    epoch.ID,
	}, nil
}

// doCryptoUnwrapCek is the read path (plan §13, p10): for each object, the
// daemon unwraps the CEK with the object's epoch key and re-wraps it to the
// browser's X25519 public key (HPKE base mode, fresh sender ephemeral per
// object). The browser then decrypts the object itself with its own AAD.
// Per-object errors are reported in the result (a single bad object does not
// fail the batch). The daemon NEVER returns the network keyring or an
// epoch key — only per-object CEKs re-wrapped to the browser.
func (d *Daemon) doCryptoUnwrapCek(p transport.CryptoUnwrapCekPayload) (any, error) {
	sess, err := d.sessionValid(p.NetworkID, p.SessionID)
	if err != nil {
		return nil, err
	}
	kr, err := crypto.LoadKeyring(d.StateDir, p.NetworkID)
	if err != nil {
		return nil, err
	}
	browserPub, err := base64.StdEncoding.DecodeString(sess.BrowserPub)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode browser pub: %w", err)
	}
	res := &transport.CryptoUnwrapCekResult{Results: make([]transport.CryptoUnwrapCekResultItem, 0, len(p.Objects))}
	for _, obj := range p.Objects {
		item := transport.CryptoUnwrapCekResultItem{ObjectID: obj.ObjectID}
		if w, err := unwrapCekToBrowser(kr, browserPub, p.NetworkID, p.SessionID, obj); err != nil {
			item.Error = err.Error()
		} else {
			item.WrappedCek = w
		}
		res.Results = append(res.Results, item)
	}
	return res, nil
}

// unwrapCekToBrowser opens one object's CEK with its epoch key (ANY known
// epoch — history) and re-wraps it to the browser's X25519 public key (HPKE
// base mode, fresh ephemeral, bound to network/session/object).
func unwrapCekToBrowser(kr *crypto.Keyring, browserPub []byte, networkID, sessionID string, obj transport.CryptoUnwrapCekObject) (*transport.CryptoHPKEWrap, error) {
	epoch, ok := kr.EpochByID(obj.Envelope.KeyEpochID)
	if !ok {
		return nil, fmt.Errorf("%s: epoch %s not in local keyring", errKeyEpochUnavailable, obj.Envelope.KeyEpochID)
	}
	key, err := epoch.KeyArray()
	if err != nil {
		return nil, err
	}
	wrapped, err := base64.StdEncoding.DecodeString(obj.Envelope.WrappedContentKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode wrapped CEK: %w", err)
	}
	cek, err := e2ee.UnwrapCEK(key, wrapped)
	if err != nil {
		return nil, fmt.Errorf("crypto: unwrap CEK: %w", err)
	}
	enc, ct, err := e2ee.HPKEWrap(browserPub, []byte(e2ee.HPKEInfoCekUnwrap),
		e2ee.BrowserSessionAAD(networkID, sessionID, obj.ObjectID), cek[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: hpke wrap CEK: %w", err)
	}
	return &transport.CryptoHPKEWrap{Enc: enc, Ciphertext: ct}, nil
}

// doCryptoWrapCek is the write path (plan §13, p10): the daemon unwraps the
// browser's HPKE-wrapped CEK (sealed to the host's static X25519 key) and
// re-wraps it under the CURRENT network epoch. The browser then fills the
// EncryptedPayloadV1 (ciphertext + the returned wrappedContentKey) and POSTs
// it through the normal protected-field write path (authorization enforced
// there).
func (d *Daemon) doCryptoWrapCek(p transport.CryptoWrapCekPayload) (any, error) {
	if _, err := d.sessionValid(p.NetworkID, p.SessionID); err != nil {
		return nil, err
	}
	id, err := d.cryptoManager().hostIdentity()
	if err != nil {
		return nil, err
	}
	cekPlain, err := e2ee.HPKEUnwrap(id.X25519Priv, p.WrappedCek.Enc,
		[]byte(e2ee.HPKEInfoCekWrap), e2ee.BrowserSessionAAD(p.NetworkID, p.SessionID, p.ObjectID),
		p.WrappedCek.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("crypto: hpke unwrap CEK: %w", err)
	}
	if len(cekPlain) != e2ee.CEKSize() {
		return nil, fmt.Errorf("crypto: CEK is %d bytes, want %d", len(cekPlain), e2ee.CEKSize())
	}
	kr, err := crypto.LoadKeyring(d.StateDir, p.NetworkID)
	if err != nil {
		return nil, err
	}
	// Wrap under the epoch the browser bound into the AAD (the announced
	// epoch from the session-start ack), so the envelope's key_epoch_id
	// matches the AAD the browser used to seal the payload. Fall back to the
	// active epoch when the AAD names none. An unknown named epoch is a clean
	// availability failure (the browser retries once the key package lands).
	var epoch crypto.KeyEpoch
	if p.AAD.KeyEpochID != "" {
		e, ok := kr.EpochByID(p.AAD.KeyEpochID)
		if !ok {
			return nil, fmt.Errorf("%s: epoch %s not in local keyring", errKeyEpochUnavailable, p.AAD.KeyEpochID)
		}
		epoch = e
	} else {
		e, err := kr.ActiveEpoch()
		if err != nil {
			return nil, err
		}
		epoch = e
	}
	key, err := epoch.KeyArray()
	if err != nil {
		return nil, err
	}
	var cek [32]byte
	copy(cek[:], cekPlain)
	wrapped, err := e2ee.WrapCEK(key, cek)
	if err != nil {
		return nil, err
	}
	return &transport.CryptoWrapCekResult{
		KeyEpochID:        epoch.ID,
		WrappedContentKey: base64.StdEncoding.EncodeToString(wrapped),
	}, nil
}

// doCryptoSessionEnd drops a browser key session (explicit teardown). It is
// idempotent: ending an unknown session is a clean no-op (the session may
// have already expired or been dropped by a restart).
func (d *Daemon) doCryptoSessionEnd(p transport.CryptoSessionEndPayload) (any, error) {
	d.cryptoManager().sessions.delete(p.SessionID)
	return nil, nil
}
