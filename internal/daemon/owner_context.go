package daemon

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/transport"
)

const ownerContextLimit = 64
const ownerContextTTL = 15 * time.Minute

// A pending native permission retains its bounded private observation for the
// same lifetime as the durable permission, independently of browser sessions.
const ownerObservationTTL = 24 * time.Hour

type ownerObservation struct {
	protected *transport.InteractionEventPayload
	payload   transport.InteractionEventPayload
	summary   string
	native    json.RawMessage
	secret    []byte
	aad       e2ee.AAD
	expires   time.Time
}
type ownerContextManager struct {
	mu           sync.Mutex
	gates        map[string]*sync.RWMutex
	sessions     map[string]transport.ProtectedContextSessionBinding
	observations map[string]*ownerObservation
}

func (d *Daemon) ownerCrypto() *ownerContextManager {
	m := d.cryptoManager()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ownerContexts == nil {
		m.ownerContexts = &ownerContextManager{gates: map[string]*sync.RWMutex{}, sessions: map[string]transport.ProtectedContextSessionBinding{}, observations: map[string]*ownerObservation{}}
	}
	return m.ownerContexts
}

// A context gate spans proof verification through native delivery. Rotation
// cannot invalidate that inspection between the check and the native action.
func (d *Daemon) ownerContextGate(id string) *sync.RWMutex {
	o := d.ownerCrypto()
	o.mu.Lock()
	defer o.mu.Unlock()
	if gate := o.gates[id]; gate != nil {
		return gate
	}
	if len(o.gates) >= ownerContextLimit {
		return nil
	}
	gate := &sync.RWMutex{}
	o.gates[id] = gate
	return gate
}
func validOwnerProtocolID(raw string) bool          { _, err := domain.ParseID(raw); return err == nil }
func ownerContextBindingKey(instance string) string { return "protected-context-instance:" + instance }
func (d *Daemon) contextForInstance(instance string) (e2ee.ProtectedContext, bool) {
	raw, ok := d.state.KVGet(ownerContextBindingKey(instance))
	var c e2ee.ProtectedContext
	if !ok || json.Unmarshal([]byte(raw), &c) != nil || c.Validate() != nil || c.HostID != d.stateID() {
		return c, false
	}
	return c, true
}
func (d *Daemon) doPrepareProtectedContext(p transport.PrepareProtectedContextPayload) (any, error) {
	if p.Context.Validate() != nil || !validOwnerProtocolID(p.CommandID) || (p.InstanceID != "" && !validOwnerProtocolID(p.InstanceID)) || p.Context.HostID != d.stateID() {
		return nil, errors.New("protected context binding invalid")
	}
	if p.InstanceID != "" {
		row, ok, err := d.state.GetInstance(p.InstanceID)
		if err == nil && !ok && d.nativeRegistry != nil {
			return nil, ErrDeferred
		}
		if err != nil || !ok || row.NetworkID != "" {
			return nil, errors.New("protected context instance unavailable")
		}
		if existing, ok := d.contextForInstance(p.InstanceID); ok && existing != p.Context {
			return nil, errors.New("protected context instance binding changed")
		}
	} else if p.Rotate {
		return nil, errors.New("template context rotation requires explicit authority")
	}
	identity, err := d.cryptoManager().hostIdentity()
	if err != nil {
		return nil, errors.New("protected context host identity unavailable")
	}
	x := base64.StdEncoding.EncodeToString(identity.X25519Pub)
	ed := base64.StdEncoding.EncodeToString(identity.Ed25519Pub)
	if x != p.HostX25519 || ed != p.HostEd25519 {
		return nil, errors.New("protected context host identity changed")
	}
	gate := d.ownerContextGate(p.Context.ID)
	if gate == nil {
		return nil, errors.New("protected context limit reached")
	}
	gate.Lock()
	defer gate.Unlock()
	o := d.ownerCrypto()
	o.mu.Lock()
	defer o.mu.Unlock()
	bindingKey := ownerContextBindingKey(p.InstanceID)
	if p.InstanceID == "" {
		bindingKey = "protected-context-authority:" + p.Context.ID
	}
	bindingRaw, authorityBound := d.state.KVGet(bindingKey)
	if authorityBound {
		var bound e2ee.ProtectedContext
		if json.Unmarshal([]byte(bindingRaw), &bound) != nil || bound != p.Context {
			return nil, errors.New("protected context authority binding changed")
		}
	}
	ring, err := crypto.LoadContextKeyring(d.StateDir, p.Context)
	if os.IsNotExist(err) {
		if p.ExpectedEpochID != "" {
			return nil, errors.New("protected context local key lost")
		}
		if authorityBound {
			return nil, errors.New("protected context local key lost")
		}
		ring = &crypto.ContextKeyring{Context: p.Context}
	} else if err != nil {
		return nil, errors.New("protected context local key unavailable")
	}
	var epoch crypto.KeyEpoch
	alreadyPrepared := ring.LastPrepareCommandID == p.CommandID
	if alreadyPrepared {
		epoch, err = ring.ActiveEpoch()
	} else if p.ExpectedEpochID != "" {
		current, keyErr := ring.ActiveEpoch()
		if keyErr != nil || current.ID != p.ExpectedEpochID {
			return nil, errors.New("protected context key epoch changed")
		}
		if p.Rotate {
			epoch, err = ring.Rotate(time.Now().UTC())
		} else {
			epoch = current
		}
	} else if p.Rotate {
		epoch, err = ring.Rotate(time.Now().UTC())
	} else {
		epoch, err = ring.Activate(time.Now().UTC())
	}
	ring.LastPrepareCommandID = p.CommandID
	if err != nil || crypto.SaveContextKeyring(d.StateDir, ring) != nil {
		return nil, errors.New("protected context local key persistence failed")
	}
	raw, _ := json.Marshal(p.Context)
	if err = d.state.KVSet(bindingKey, string(raw)); err != nil {
		return nil, errors.New("protected context binding persistence failed")
	}
	// Rotation invalidates browser sessions and approvals bound to the old epoch.
	if p.Rotate {
		for id, s := range o.sessions {
			if s.Context.ID == p.Context.ID {
				delete(o.sessions, id)
			}
		}
		for _, record := range o.observations {
			if record.aad.ProtectedContext != nil && record.aad.ProtectedContext.ID == p.Context.ID {
				record.secret = nil
				record.aad = e2ee.AAD{}
				record.protected = nil
			}
		}
	}
	result := transport.ProtectedContextReadyPayload{CommandID: p.CommandID, InstanceID: p.InstanceID, Context: p.Context, EpochID: epoch.ID, HostX25519: x, HostEd25519: ed}
	result.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(identity.Ed25519Priv, result.SignatureBytes()))
	return result, nil
}
func (d *Daemon) observeOwnerInteraction(payload transport.InteractionEventPayload, ie *agentruntime.InteractionEvent) (transport.InteractionEventPayload, bool) {
	o := d.ownerCrypto()
	o.mu.Lock()
	defer o.mu.Unlock()
	now := time.Now().UTC()
	for id, r := range o.observations {
		if !now.Before(r.expires) {
			delete(o.observations, id)
		}
	}
	if payload.Resolved {
		delete(o.observations, payload.InteractionID)
		return payload, false
	}
	if len(ie.NativePayload) > 64<<10 || len(ie.Summary) > 4096 {
		return payload, false
	}
	record := o.observations[payload.InteractionID]
	if record != nil && (record.payload.InstanceID != payload.InstanceID || record.payload.SessionID != payload.SessionID || record.payload.NativeInteractionID != payload.NativeInteractionID || record.summary != ie.Summary || !bytes.Equal(record.native, ie.NativePayload) || !equalOwnerOptions(record.payload.Options, payload.Options)) {
		record = nil
		delete(o.observations, payload.InteractionID)
	}
	if record == nil {
		if len(o.observations) >= ownerContextLimit {
			return payload, false
		}
		record = &ownerObservation{payload: payload, summary: ie.Summary, native: append(json.RawMessage(nil), ie.NativePayload...), expires: now.Add(ownerObservationTTL)}
		o.observations[payload.InteractionID] = record
	}
	return d.encryptOwnerObservationLocked(record)
}
func equalOwnerOptions(a, b []domain.RuntimeInteractionOption) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func (d *Daemon) encryptOwnerObservationLocked(record *ownerObservation) (transport.InteractionEventPayload, bool) {
	p := record.payload
	c, ok := d.contextForInstance(p.InstanceID)
	if !ok {
		return p, false
	}
	ring, err := crypto.LoadContextKeyring(d.StateDir, c)
	if err != nil {
		return p, false
	}
	epoch, err := ring.ActiveEpoch()
	if err != nil {
		return p, false
	}
	if record.protected != nil && record.aad.KeyEpochID == epoch.ID {
		return *record.protected, true
	}
	if record.secret == nil {
		record.secret = make([]byte, 32)
		if _, err = rand.Read(record.secret); err != nil {
			record.secret = nil
			return p, false
		}
	}
	var native any
	if len(record.native) > 0 && json.Unmarshal(record.native, &native) != nil {
		return p, false
	}
	detail := transport.OwnerInteractionDetail{Format: "pagnet.owner_interaction.v1", Summary: record.summary, NativePayload: native, Inspection: transport.OwnerInspection{Secret: base64.StdEncoding.EncodeToString(record.secret), InstanceID: p.InstanceID, SessionID: p.SessionID, NativeInteractionID: p.NativeInteractionID}}
	plain, err := json.Marshal(detail)
	if err != nil || len(plain) > 64<<10 {
		return p, false
	}
	aad := e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: c.TenantID, NetworkID: "", ObjectType: e2ee.ObjectTypeRuntimeInteraction, ObjectID: p.InteractionID, Sender: p.InstanceID, Recipient: c.OwnerUserID, CreatedAt: time.Now().UTC().Format(time.RFC3339), KeyEpochID: epoch.ID, ProtectedContext: &c}
	key, err := epoch.KeyArray()
	if err != nil {
		return p, false
	}
	env, err := e2ee.Encrypt(plain, key, aad)
	if err != nil {
		return p, false
	}
	record.aad = aad
	p.DetailAAD = &aad
	p.DetailEnvelope = &env
	p.Summary = ""
	p.NativePayload = nil
	p.Answer = ""
	record.protected = &p
	return p, true
}
func (d *Daemon) replayOwnerObservations(conn *websocket.Conn, instance string) {
	o := d.ownerCrypto()
	o.mu.Lock()
	var replay []transport.InteractionEventPayload
	prepared, preparedOK := d.contextForInstance(instance)
	for _, r := range o.observations {
		bound, boundOK := d.contextForInstance(r.payload.InstanceID)
		if preparedOK && boundOK && bound == prepared && time.Now().Before(r.expires) {
			if p, ok := d.encryptOwnerObservationLocked(r); ok {
				replay = append(replay, p)
			}
		}
	}
	o.mu.Unlock()
	for _, p := range replay {
		_ = d.send(conn, transport.MsgInteractionStarted, p)
	}
}
func (d *Daemon) verifyOwnerApproval(p transport.ResolveRuntimeInteractionPayload) error {
	row, ok, err := d.state.GetInstance(p.InstanceID)
	if err != nil || !ok {
		return errors.New("native approval instance unavailable")
	}
	if row.NetworkID != "" {
		return nil
	}
	o := d.ownerCrypto()
	o.mu.Lock()
	defer o.mu.Unlock()
	r := o.observations[p.InteractionID]
	if r == nil || !time.Now().Before(r.expires) || r.payload.InstanceID != p.InstanceID || r.payload.SessionID != p.SessionID || r.payload.NativeInteractionID != p.NativeInteractionID {
		return errors.New("native permission inspection unavailable")
	}
	var kind string
	for _, opt := range r.payload.Options {
		if opt.ID == p.OptionID {
			kind = opt.Kind
		}
	}
	if kind == "reject_once" || kind == "reject_always" {
		return nil
	}
	if kind != "allow_once" && kind != "allow_always" {
		return errors.New("native permission option invalid")
	}
	if r.aad.ProtectedContext == nil {
		return errors.New("native permission inspection unavailable")
	}
	ring, keyErr := crypto.LoadContextKeyring(d.StateDir, *r.aad.ProtectedContext)
	if keyErr != nil {
		return errors.New("native permission inspection unavailable")
	}
	if _, valid := ring.EpochByID(r.aad.KeyEpochID); !valid {
		return errors.New("native permission inspection epoch revoked")
	}
	proof, err := base64.StdEncoding.DecodeString(p.InspectionProof)
	if err != nil || len(proof) != 32 {
		return errors.New("native permission inspection proof required")
	}
	expected, err := e2ee.ApprovalProof(r.secret, r.aad, p.InstanceID, p.SessionID, p.NativeInteractionID, p.OptionID)
	if err != nil || !hmac.Equal(expected, proof) {
		return errors.New("native permission inspection proof invalid")
	}
	return nil
}
func (d *Daemon) ownerSessionStart(p transport.CryptoSessionStartPayload) (any, error) {
	c := p.ProtectedContext
	if c == nil || c.Validate() != nil || !validOwnerProtocolID(p.SessionID) || p.NetworkID != "" || p.TenantID != c.TenantID || p.UserID != c.OwnerUserID || c.HostID != d.stateID() {
		return nil, errors.New("protected context session binding invalid")
	}
	pub, err := base64.StdEncoding.DecodeString(p.BrowserPub)
	if err != nil || len(pub) != 32 || bytes.Equal(pub, make([]byte, 32)) {
		return nil, errors.New("protected context browser key invalid")
	}
	gate := d.ownerContextGate(c.ID)
	if gate == nil {
		return nil, errors.New("protected context unavailable")
	}
	gate.RLock()
	defer gate.RUnlock()
	ring, err := crypto.LoadContextKeyring(d.StateDir, *c)
	if err != nil {
		return nil, errors.New("protected context local key unavailable")
	}
	epoch, found := ring.EpochByID(p.EpochID)
	if p.EpochID == "" || !found || epoch.State == crypto.EpochRevoked {
		return nil, errors.New("protected context committed key epoch unavailable")
	}
	identity, err := d.cryptoManager().hostIdentity()
	if err != nil {
		return nil, err
	}
	o := d.ownerCrypto()
	o.mu.Lock()
	defer o.mu.Unlock()
	for id, s := range o.sessions {
		if !time.Now().Before(s.ExpiresAt) {
			delete(o.sessions, id)
		}
	}
	if existing, exists := o.sessions[p.SessionID]; exists && (existing.Context != *c || existing.UserID != p.UserID || existing.BrowserPub != p.BrowserPub || existing.EpochID != p.EpochID) {
		return nil, errors.New("protected context session binding changed")
	}
	if _, exists := o.sessions[p.SessionID]; !exists && len(o.sessions) >= ownerContextLimit {
		return nil, errors.New("protected context session limit reached")
	}
	o.sessions[p.SessionID] = transport.ProtectedContextSessionBinding{EpochID: p.EpochID, Context: *c, SessionID: p.SessionID, UserID: p.UserID, BrowserPub: p.BrowserPub, ExpiresAt: time.Now().Add(ownerContextTTL)}
	return &transport.CryptoSessionStartResult{HostX25519: base64.StdEncoding.EncodeToString(identity.X25519Pub), EpochID: epoch.ID}, nil
}
func (d *Daemon) ownerUnwrap(p transport.CryptoUnwrapCekPayload) (any, error) {
	c := p.ProtectedContext
	if c == nil || c.Validate() != nil || !validOwnerProtocolID(p.SessionID) || p.NetworkID != "" || p.TenantID != c.TenantID || c.HostID != d.stateID() || len(p.Objects) == 0 || len(p.Objects) > 32 {
		return nil, errors.New("protected context unwrap binding invalid")
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
	if ok && time.Now().Before(s.ExpiresAt) && s.Context == *c {
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
	pub, _ := base64.StdEncoding.DecodeString(s.BrowserPub)
	result := &transport.CryptoUnwrapCekResult{Results: make([]transport.CryptoUnwrapCekResultItem, 0, len(p.Objects))}
	for _, obj := range p.Objects {
		item := transport.CryptoUnwrapCekResultItem{ObjectID: obj.ObjectID}
		epoch, found := ring.EpochByID(obj.Envelope.KeyEpochID)
		aad := p.AAD
		if obj.AAD != nil {
			aad = *obj.AAD
		}
		bound, boundOK := d.contextForInstance(aad.Sender)
		instanceBound := boundOK && bound == *c && (aad.ObjectType == e2ee.ObjectTypeRuntimeInteraction || aad.ObjectType == e2ee.ObjectTypeRuntimeTerminalSession)
		templateBound := aad.ObjectType == e2ee.ObjectTypeAgentTemplate && validOwnerProtocolID(obj.ObjectID) && aad.Sender == c.OwnerUserID
		valid := (instanceBound || templateBound) && aad.ProtectedContext != nil && *aad.ProtectedContext == *c && aad.ValidateScope() == nil && aad.ObjectID == obj.ObjectID && aad.KeyEpochID == obj.Envelope.KeyEpochID && aad.Recipient == c.OwnerUserID
		if !found || !valid {
			item.Error = "protected_context_binding_invalid"
			result.Results = append(result.Results, item)
			continue
		}
		key, err := epoch.KeyArray()
		wrapped, decodeErr := base64.StdEncoding.DecodeString(obj.Envelope.WrappedContentKey)
		if err != nil || decodeErr != nil {
			item.Error = "invalid_ciphertext"
			result.Results = append(result.Results, item)
			continue
		}
		// Authenticate the complete stored object before releasing its CEK.
		if _, authErr := e2ee.Decrypt(obj.Envelope, key, aad); authErr != nil {
			item.Error = "invalid_ciphertext"
			result.Results = append(result.Results, item)
			continue
		}
		cek, err := e2ee.UnwrapCEK(key, wrapped)
		if err != nil {
			item.Error = "invalid_ciphertext"
			result.Results = append(result.Results, item)
			continue
		}
		enc, ct, err := e2ee.HPKEWrap(pub, []byte(e2ee.HPKEInfoOwnerCEK), e2ee.OwnerBrowserSessionAAD(*c, p.SessionID, obj.ObjectID), cek[:])
		if err != nil {
			item.Error = "invalid_ciphertext"
		} else {
			item.WrappedCek = &transport.CryptoHPKEWrap{Enc: enc, Ciphertext: ct}
		}
		result.Results = append(result.Results, item)
	}
	return result, nil
}
func (d *Daemon) ownerSessionEnd(p transport.CryptoSessionEndPayload) (any, error) {
	if p.ProtectedContext == nil || p.ProtectedContext.Validate() != nil || !validOwnerProtocolID(p.SessionID) || p.NetworkID != "" || p.TenantID != p.ProtectedContext.TenantID || p.ProtectedContext.HostID != d.stateID() {
		return nil, errors.New("protected context session binding invalid")
	}
	o := d.ownerCrypto()
	o.mu.Lock()
	defer o.mu.Unlock()
	if s, ok := o.sessions[p.SessionID]; ok && s.Context != *p.ProtectedContext {
		return nil, errors.New("protected context session binding invalid")
	}
	delete(o.sessions, p.SessionID)
	return nil, nil
}
