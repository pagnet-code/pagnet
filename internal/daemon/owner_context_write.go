package daemon

import (
	"encoding/base64"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

// Owner writes never borrow a network epoch or a locally uncommitted candidate.
// The session pins the exact authority and committed epoch admitted by the server.
func (d *Daemon) ownerWrap(p transport.CryptoWrapCekPayload) (any, error) {
	c := p.ProtectedContext
	if c == nil || c.Validate() != nil || c.HostID != d.stateID() || p.TenantID != c.TenantID || p.NetworkID != "" || !validOwnerProtocolID(p.SessionID) || !validOwnerProtocolID(p.ObjectID) || p.ObjectType != e2ee.ObjectTypeAgentTemplate || p.AAD.ObjectType != p.ObjectType || p.AAD.ObjectID != p.ObjectID || p.AAD.ValidateScope() != nil || p.AAD.ProtectedContext == nil || *p.AAD.ProtectedContext != *c || p.AAD.Sender != c.OwnerUserID || p.AAD.Recipient != c.OwnerUserID {
		return nil, errors.New("protected context write binding invalid")
	}
	gate := d.ownerContextGate(c.ID)
	if gate == nil {
		return nil, errors.New("protected context unavailable")
	}
	gate.RLock()
	defer gate.RUnlock()
	o := d.ownerCrypto()
	o.mu.Lock()
	s, ok := o.sessions[p.SessionID]
	if ok && time.Now().Before(s.ExpiresAt) && s.Context == *c && s.UserID == c.OwnerUserID && s.EpochID != "" && p.AAD.KeyEpochID == s.EpochID {
		s.ExpiresAt = time.Now().Add(ownerContextTTL)
		o.sessions[p.SessionID] = s
	} else {
		ok = false
	}
	o.mu.Unlock()
	if !ok {
		return nil, errors.New(errCryptoSessionGone)
	}
	ring, err := crypto.LoadContextKeyring(d.StateDir, *c)
	if err != nil {
		return nil, errors.New("protected context local key unavailable")
	}
	epoch, found := ring.EpochByID(s.EpochID)
	if !found || epoch.State == crypto.EpochRevoked {
		return nil, errors.New("protected context committed key epoch unavailable")
	}
	key, err := epoch.KeyArray()
	if err != nil {
		return nil, errors.New("protected context local key unavailable")
	}
	identity, err := d.cryptoManager().hostIdentity()
	if err != nil {
		return nil, err
	}
	plain, err := e2ee.HPKEUnwrap(identity.X25519Priv, p.WrappedCek.Enc, []byte(e2ee.HPKEInfoCekWrap), e2ee.BrowserSessionAAD(c.ID, p.SessionID, p.ObjectID), p.WrappedCek.Ciphertext)
	if err != nil || len(plain) != e2ee.CEKSize() {
		return nil, errors.New("protected context wrapped content key invalid")
	}
	var cek [32]byte
	copy(cek[:], plain)
	wrapped, err := e2ee.WrapCEK(key, cek)
	if err != nil {
		return nil, errors.New("protected context content key wrapping failed")
	}
	return &transport.CryptoWrapCekResult{KeyEpochID: epoch.ID, WrappedContentKey: base64.StdEncoding.EncodeToString(wrapped)}, nil
}
