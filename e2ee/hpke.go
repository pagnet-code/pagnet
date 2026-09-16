package e2ee

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/hpke"
)

// This file exposes the FIXED HPKE parameter set used for browser key-session
// key transfer (plan §13, p10): HPKE base mode (RFC 9180) over
// X25519 / HKDF-SHA256 / AES-256-GCM — the audited
// github.com/cloudflare/circl implementation, the SAME suite the p8 key
// package uses (internal/crypto).
//
// The API is deliberately NOT generic-configurable: there is exactly one
// suite (the constants below) and two operations (Wrap = sender, Unwrap =
// receiver). A future stronger client (plan §13.5) implements the same
// BrowserCryptoProvider contract over its own primitives; it does not get a
// configurable crypto API here.
//
// hpkeSuite is the single fixed suite. It is a package-level var (not a
// func) so the suite is constructed once; circl's NewSuite is pure and
// thread-safe for concurrent use.
var hpkeSuite = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)

// HPKE info contexts for browser key-session CEK transfer. These are FIXED
// protocol constants (documented in PROTOCOL.md §3): the sender and receiver
// must use the same info for a given direction, and the two directions use
// DIFFERENT info so a wrap from one direction can never be opened by the
// other. A black-box browser implementation (the e2e double, p10b) uses the
// same strings; they are deliberately simple and stable.
const (
	// HPKEInfoCekUnwrap is the info for the daemon re-wrapping an object's
	// CEK to the browser (read path).
	HPKEInfoCekUnwrap = "pagnet/browser-session/cek-unwrap/v1"
	// HPKEInfoCekWrap is the info for the browser wrapping a CEK to the
	// daemon host (write path).
	HPKEInfoCekWrap = "pagnet/browser-session/cek-wrap/v1"
)

// BrowserSessionAAD builds the public HPKE AAD binding a browser-session CEK
// transfer to (networkID, sessionID, objectID), NUL-separated. It is public
// routing context (never secret) that prevents a CEK wrapped for one
// session/object from being replayed to another. The black-box browser
// double builds the identical bytes.
func BrowserSessionAAD(networkID, sessionID, objectID string) []byte {
	return []byte(networkID + "\x00" + sessionID + "\x00" + objectID)
}

// HPKEWrap seals plaintext to the recipient's X25519 public key using HPKE
// base mode with the fixed suite. It returns the encapsulated (ephemeral)
// key enc and the sealed ciphertext. info and aad are public context bound
// to the exchange (a different info/aad makes Unwrap fail). A fresh sender
// ephemeral is drawn per call (never reused).
func HPKEWrap(recipientPub, info, aad, plaintext []byte) (enc, ct []byte, err error) {
	pkR, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("e2ee: hpke recipient public key: %w", err)
	}
	sender, err := hpkeSuite.NewSender(pkR, info)
	if err != nil {
		return nil, nil, fmt.Errorf("e2ee: hpke sender: %w", err)
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("e2ee: hpke setup: %w", err)
	}
	ct, err = sealer.Seal(plaintext, aad)
	if err != nil {
		return nil, nil, fmt.Errorf("e2ee: hpke seal: %w", err)
	}
	return enc, ct, nil
}

// HPKEUnwrap opens an HPKE base-mode sealed value with the recipient's
// X25519 private key, using the fixed suite. info and aad must match what
// HPKEWrap used (a mismatch fails authentication).
func HPKEUnwrap(recipientPriv, enc, info, aad, ct []byte) ([]byte, error) {
	skR, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPrivateKey(recipientPriv)
	if err != nil {
		return nil, fmt.Errorf("e2ee: hpke recipient private key: %w", err)
	}
	receiver, err := hpkeSuite.NewReceiver(skR, info)
	if err != nil {
		return nil, fmt.Errorf("e2ee: hpke receiver: %w", err)
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, fmt.Errorf("e2ee: hpke open setup: %w", err)
	}
	return opener.Open(ct, aad)
}
