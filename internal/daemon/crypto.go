package daemon

import (
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

// cryptoManager caches the host's stable E2EE identity and per-network NKA
// instances for the lifetime of the daemon process (plan §11.5/§11.7).
//
// The NKA is cached per network because it must stay ALIVE across an
// enrollment round-trip (issue challenge → verify proof): the challenge
// plaintexts are held in the NKA's memory, so a fresh NKA per command could
// not verify the proof. A daemon restart drops the cache (and any in-flight
// challenge); the documented recovery is re-enrollment (a fresh 5-leg relay).
//
// The NKA's in-memory keyring stays consistent with disk: Rotate/Activate
// mutate the same *Keyring the NKA holds and persist it, so no reload is
// needed across a rotation.
type cryptoManager struct {
	d *Daemon

	mu       sync.Mutex
	identity *crypto.HostIdentity
	nkas     map[string]*crypto.NKA // networkID -> NKA (this host acting as NKA)
	// netCrypto caches the server-announced E2EE lifecycle state per network
	// (host.network_crypto, plan §12). It is the daemon's input for the
	// customer-side encryption decision: whether to encrypt (status=active)
	// and under which epoch (epochId). Re-pushed on every (re)connect and on
	// state changes, so it is always current while the daemon is connected.
	netCrypto map[string]NetworkCryptoState
	// sessions is the in-memory browser key-session store (plan §13, p10).
	// It is per-daemon (not per-network) and NOT durable: a daemon restart
	// drops every session (a reused sessionId is a clean 410).
	sessions *sessionStore
}

// NetworkCryptoState is the daemon's cached view of one network's E2EE
// lifecycle state (from the control plane's host.network_crypto signal).
type NetworkCryptoState struct {
	NetworkID string
	TenantID  string
	Status    string // standard | activating | active
	EpochID   string // the announced current epoch ("" until active)
}

// cryptoManager returns the daemon's crypto manager, creating it on first use.
func (d *Daemon) cryptoManager() *cryptoManager {
	d.cryptoMu.Lock()
	defer d.cryptoMu.Unlock()
	if d.cryptoMgr == nil {
		d.cryptoMgr = &cryptoManager{
			d:         d,
			nkas:      map[string]*crypto.NKA{},
			netCrypto: map[string]NetworkCryptoState{},
			sessions:  newSessionStore(),
		}
	}
	return d.cryptoMgr
}

// SetNetworkCrypto caches the server-announced E2EE lifecycle state for a
// network (host.network_crypto). It is idempotent (a re-push overwrites).
func (m *cryptoManager) SetNetworkCrypto(networkID string, st NetworkCryptoState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st.NetworkID = networkID
	m.netCrypto[networkID] = st
}

// NetworkCrypto returns the cached E2EE lifecycle state for a network
// (ok=false when the daemon has not yet received a host.network_crypto for
// it — e.g. before the first connect-time push lands).
func (m *cryptoManager) NetworkCrypto(networkID string) (NetworkCryptoState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.netCrypto[networkID]
	return st, ok
}

// hostIdentity returns the host's stable E2EE identity, generating and
// persisting it on first use (idempotent, survives restarts — it is per HOST,
// not per Runner). Cached after the first call.
func (m *cryptoManager) hostIdentity() (*crypto.HostIdentity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.identity != nil {
		return m.identity, nil
	}
	id, err := crypto.EnsureHostIdentity(m.d.StateDir)
	if err != nil {
		return nil, err
	}
	m.identity = id
	return id, nil
}

// nka returns the NKA for a network, creating (and caching) it on first use.
// The keyring must already exist on disk (created by host.crypto_activate);
// otherwise NewNKA fails and the command acks the error.
func (m *cryptoManager) nka(tenantID, networkID string) (*crypto.NKA, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n, ok := m.nkas[networkID]; ok {
		return n, nil
	}
	n, err := crypto.NewNKA(m.d.StateDir, tenantID, networkID, m.d.stateID())
	if err != nil {
		return nil, err
	}
	m.nkas[networkID] = n
	return n, nil
}

// hostPublic returns the host's public E2EE identity as base64 keys (the
// private keys never leave the host).
func (m *cryptoManager) hostPublic(id *crypto.HostIdentity) transport.CryptoHostPublic {
	return transport.CryptoHostPublic{
		X25519:  base64.StdEncoding.EncodeToString(id.X25519Pub),
		Ed25519: base64.StdEncoding.EncodeToString(id.Ed25519Pub),
	}
}

// doCryptoActivate is the NKA host's side of Private Network activation
// (plan §11.6 step 4–6): create the first key epoch locally, run the crypto
// self-test, and report the public identity + epoch id. The control plane
// flips the network to active ONLY when the ack is clean AND selfTestOk is
// true; a failed self-test reports selfTestOk=false (a clean ack) so the
// server can decide, never a half-activated state.
func (d *Daemon) doCryptoActivate(p transport.CryptoActivatePayload) (any, error) {
	id, err := d.cryptoManager().hostIdentity()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	kr, err := crypto.ActivateNetwork(d.StateDir, p.TenantID, p.NetworkID, now)
	if err != nil {
		return nil, err
	}
	epoch, err := kr.ActiveEpoch()
	if err != nil {
		return nil, err
	}
	res := &transport.CryptoActivateResult{
		HostPub:    d.cryptoManager().hostPublic(id),
		EpochID:    epoch.ID,
		SelfTestOK: true,
	}
	if err := crypto.SelfTest(kr, p.TenantID, d.stateID(), now); err != nil {
		res.SelfTestOK = false
		// Sanitized: the self-test error is a generic crypto failure, never
		// key material.
		d.Log.Warn("crypto self-test failed", "network", p.NetworkID, "err", err)
	}
	return res, nil
}

// doCryptoKeyPackage is enrollment leg 1 (plan §11.7 step 5–6): the NKA host
// builds the HPKE key package sealed to the target host's X25519 public key.
// Only the target can open it; the control plane relays the opaque bytes.
func (d *Daemon) doCryptoKeyPackage(p transport.CryptoKeyPackagePayload) (any, error) {
	targetPub, err := base64.StdEncoding.DecodeString(p.TargetX25519Pub)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode target x25519 public key: %w", err)
	}
	n, err := d.cryptoManager().nka(p.TenantID, p.NetworkID)
	if err != nil {
		return nil, err
	}
	pkg, err := n.BuildKeyPackage(targetPub)
	if err != nil {
		return nil, err
	}
	return &transport.CryptoKeyPackageResult{KeyPackage: *pkg}, nil
}

// doCryptoInstallKeyPackage is enrollment leg 2 (plan §11.7 step 6): the
// target host opens the key package with its X25519 private key and stores
// the network keyring. A clean ack (no result) signals success.
func (d *Daemon) doCryptoInstallKeyPackage(p transport.CryptoInstallKeyPackagePayload) (any, error) {
	id, err := d.cryptoManager().hostIdentity()
	if err != nil {
		return nil, err
	}
	kr, err := crypto.OpenKeyPackage(&p.KeyPackage, id.X25519Priv)
	if err != nil {
		return nil, err
	}
	if err := crypto.SaveKeyring(d.StateDir, kr); err != nil {
		return nil, err
	}
	return nil, nil
}

// doCryptoChallenge is enrollment leg 3 (plan §11.7 step 7): the NKA host
// issues a decryption challenge for the target host. The NKA remembers the
// challenge plaintext (in memory) so it can verify the proof in leg 5.
func (d *Daemon) doCryptoChallenge(p transport.CryptoChallengePayload) (any, error) {
	n, err := d.cryptoManager().nka(p.TenantID, p.NetworkID)
	if err != nil {
		return nil, err
	}
	ch, err := n.IssueChallenge(p.TargetHostID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	return &transport.CryptoChallengeResult{Challenge: *ch}, nil
}

// doCryptoProve is enrollment leg 4 (plan §11.7 step 7): the target host
// decrypts the challenge with its keyring and returns the proof. Only a host
// holding the epoch key can produce a valid proof.
func (d *Daemon) doCryptoProve(p transport.CryptoProvePayload) (any, error) {
	kr, err := crypto.LoadKeyring(d.StateDir, p.NetworkID)
	if err != nil {
		return nil, err
	}
	proof, err := crypto.ComputeChallengeProof(kr, &p.Challenge)
	if err != nil {
		return nil, err
	}
	return &transport.CryptoProveResult{Proof: *proof}, nil
}

// doCryptoVerify is enrollment leg 5 (plan §11.7 step 8): the NKA host
// verifies the target host's proof against the remembered challenge
// plaintext. A clean ack (no result) marks the host crypto-ready.
func (d *Daemon) doCryptoVerify(p transport.CryptoVerifyPayload) (any, error) {
	n, err := d.cryptoManager().nka(p.TenantID, p.NetworkID)
	if err != nil {
		return nil, err
	}
	if err := n.VerifyChallenge(&p.Challenge, &p.Proof); err != nil {
		return nil, err
	}
	return nil, nil
}

// doCryptoRotate is key rotation (plan §11.8): the NKA host mints a new key
// epoch, marking the previous one rotated (retained customer-side to read
// history). The control plane records only the new epoch id.
func (d *Daemon) doCryptoRotate(p transport.CryptoRotatePayload) (any, error) {
	n, err := d.cryptoManager().nka(p.TenantID, p.NetworkID)
	if err != nil {
		return nil, err
	}
	epoch, err := n.Rotate(time.Now().UTC())
	if err != nil {
		return nil, err
	}
	return &transport.CryptoRotateResult{EpochID: epoch.ID}, nil
}
