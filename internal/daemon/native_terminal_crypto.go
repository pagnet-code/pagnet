package daemon

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/e2ee"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

type nativeTerminalWindow struct {
	mu                  sync.Mutex
	conn                *websocket.Conn
	proxy               *NativeWorkerProxy
	stream              *sessionworker.TerminalStream
	meta                transport.TerminalSessionKeyPayload
	aad                 e2ee.AAD
	outputKey, inputKey [32]byte
	inputSequence       uint64
	active, closed      bool
	size                lastSize
}
type terminalSessionSecret struct {
	Format              string `json:"format"`
	InstanceID          string `json:"instance_id"`
	SessionID           string `json:"session_id"`
	NativeGeneration    string `json:"native_generation"`
	SessionKeyID        string `json:"session_key_id"`
	SourceOriginID      string `json:"source_origin_id"`
	NativeSessionID     string `json:"native_session_id"`
	NativeStartIdentity string `json:"native_start_identity"`
	RealEpochID         string `json:"real_epoch_id"`
	OutputKey           string `json:"output_key"`
	InputKey            string `json:"input_key"`
}

// Each send/effect checks the real epoch again. An ephemeral channel key never
// grants authority after current network or original owner context changes.
func (d *Daemon) nativeTerminalEpoch(p *NativeWorkerProxy) (e2ee.AAD, [32]byte, error) {
	var empty [32]byte
	spec := p.bootstrap.Native
	if spec.ProtectedContext != nil {
		context := *spec.ProtectedContext
		bound, ok := d.contextForInstance(p.scope.InstanceID)
		if !ok || bound != context || spec.NetworkID != "" || context.HostID != p.scope.HostID || context.TenantID != p.scope.TenantID {
			return e2ee.AAD{}, empty, ErrNativeObservationConflict
		}
		gate := d.ownerContextGate(context.ID)
		if gate == nil {
			return e2ee.AAD{}, empty, errors.New("terminal protected context unavailable")
		}
		gate.RLock()
		defer gate.RUnlock()
		ring, err := hostcrypto.LoadContextKeyring(d.StateDir, context)
		if err != nil {
			return e2ee.AAD{}, empty, err
		}
		epoch, err := ring.ActiveEpoch()
		if err != nil {
			return e2ee.AAD{}, empty, err
		}
		key, err := epoch.KeyArray()
		if err != nil {
			return e2ee.AAD{}, empty, err
		}
		return e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: context.TenantID, ObjectType: e2ee.ObjectTypeRuntimeTerminalSession, Sender: p.scope.InstanceID, Recipient: context.OwnerUserID, CreatedAt: time.Now().UTC().Format(time.RFC3339), KeyEpochID: epoch.ID, ProtectedContext: &context}, key, nil
	}
	if spec.NetworkID == "" {
		return e2ee.AAD{}, empty, errors.New("terminal requires an authenticated protected content scope")
	}
	state, err := d.contentCryptoReady(spec.NetworkID)
	if err != nil {
		return e2ee.AAD{}, empty, err
	}
	if spec.NetworkTenantID != "" && state.TenantID != spec.NetworkTenantID {
		return e2ee.AAD{}, empty, ErrNativeObservationConflict
	}
	ring, err := hostcrypto.LoadKeyring(d.StateDir, spec.NetworkID)
	if err != nil {
		return e2ee.AAD{}, empty, err
	}
	epoch, ok := ring.EpochByID(state.EpochID)
	if !ok || epoch.State == hostcrypto.EpochRevoked {
		return e2ee.AAD{}, empty, errors.New("terminal current epoch unavailable")
	}
	key, err := epoch.KeyArray()
	if err != nil {
		return e2ee.AAD{}, empty, err
	}
	return e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: state.TenantID, NetworkID: spec.NetworkID, ObjectType: e2ee.ObjectTypeRuntimeTerminalSession, Sender: p.scope.InstanceID, CreatedAt: time.Now().UTC().Format(time.RFC3339), KeyEpochID: epoch.ID}, key, nil
}
func (d *Daemon) newNativeTerminalWindow(conn *websocket.Conn, p *NativeWorkerProxy, sessionID string, snapshot sessionworker.NativeSnapshot, stream *sessionworker.TerminalStream) (*nativeTerminalWindow, error) {
	var origin transport.NativeObservationOrigin
	if json.Unmarshal(snapshot.Origin, &origin) != nil || origin.ID == "" || snapshot.NativeGeneration == "" || snapshot.NativeStartIdentity == "" || snapshot.NativeSessionID == "" {
		return nil, ErrNativeObservationConflict
	}
	window := &nativeTerminalWindow{conn: conn, proxy: p, stream: stream, meta: transport.TerminalSessionKeyPayload{InstanceID: p.scope.InstanceID, SessionID: sessionID, NativeGeneration: snapshot.NativeGeneration, SessionKeyID: uuid.NewString(), SourceOriginID: origin.ID, NativeSessionID: snapshot.NativeSessionID, NativeStartIdentity: snapshot.NativeStartIdentity}}
	if _, err := rand.Read(window.outputKey[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(window.inputKey[:]); err != nil {
		clear(window.outputKey[:])
		return nil, err
	}
	aad, key, err := d.nativeTerminalEpoch(p)
	defer clear(key[:])
	if err != nil {
		window.close()
		return nil, err
	}
	objectID, err := e2ee.TerminalKeyObjectID(window.meta.InstanceID, sessionID, window.meta.NativeGeneration, window.meta.SessionKeyID)
	if err != nil {
		window.close()
		return nil, err
	}
	aad.ObjectID = objectID
	secret := terminalSessionSecret{Format: e2ee.TerminalSessionFormat, InstanceID: window.meta.InstanceID, SessionID: sessionID, NativeGeneration: window.meta.NativeGeneration, SessionKeyID: window.meta.SessionKeyID, SourceOriginID: origin.ID, NativeSessionID: snapshot.NativeSessionID, NativeStartIdentity: snapshot.NativeStartIdentity, RealEpochID: aad.KeyEpochID, OutputKey: base64.StdEncoding.EncodeToString(window.outputKey[:]), InputKey: base64.StdEncoding.EncodeToString(window.inputKey[:])}
	plain, err := json.Marshal(secret)
	if err != nil {
		window.close()
		return nil, err
	}
	defer clear(plain)
	envelope, err := e2ee.Encrypt(plain, key, aad)
	if err != nil {
		window.close()
		return nil, err
	}
	window.aad = aad
	window.meta.Envelope = &envelope
	window.meta.AAD = &aad
	return window, nil
}
func (w *nativeTerminalWindow) close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	w.closed = true
	w.active = false
	clear(w.inputKey[:])
	clear(w.outputKey[:])
	if w.stream != nil {
		_ = w.stream.Close()
	}
}
func (w *nativeTerminalWindow) currentEpoch(d *Daemon) error {
	aad, key, err := d.nativeTerminalEpoch(w.proxy)
	clear(key[:])
	if err != nil {
		return err
	}
	if aad.KeyEpochID != w.aad.KeyEpochID || aad.TenantID != w.aad.TenantID || aad.NetworkID != w.aad.NetworkID {
		return errors.New("terminal source epoch changed; authenticated reattach required")
	}
	if (aad.ProtectedContext == nil) != (w.aad.ProtectedContext == nil) || (aad.ProtectedContext != nil && *aad.ProtectedContext != *w.aad.ProtectedContext) {
		return ErrNativeObservationConflict
	}
	return nil
}
func (w *nativeTerminalWindow) output(d *Daemon, data []byte, sequence uint64, snapshot bool) (transport.TerminalOutputPayload, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.outputLocked(d, data, sequence, snapshot)
}
func (w *nativeTerminalWindow) outputLocked(d *Daemon, data []byte, sequence uint64, snapshot bool) (transport.TerminalOutputPayload, error) {
	if w.closed || (!w.active && !snapshot) {
		return transport.TerminalOutputPayload{}, ErrNativeOriginAdmissionDeferred
	}
	if !snapshot && len(data) > terminalChunk || len(data) > terminalRingCap || uint64(len(data)) > sequence {
		return transport.TerminalOutputPayload{}, ErrNativeObservationConflict
	}
	if err := w.currentEpoch(d); err != nil {
		return transport.TerminalOutputPayload{}, err
	}
	objectID, err := e2ee.TerminalFrameObjectID(w.meta.InstanceID, w.meta.SessionID, w.meta.NativeGeneration, w.meta.SessionKeyID, "output", snapshot, sequence)
	if err != nil {
		return transport.TerminalOutputPayload{}, err
	}
	aad := w.aad
	aad.ObjectType = e2ee.ObjectTypeRuntimeTerminal
	aad.ObjectID = objectID
	aad.KeyEpochID = w.meta.SessionKeyID
	envelope, err := e2ee.Encrypt(data, w.outputKey, aad)
	if err != nil {
		return transport.TerminalOutputPayload{}, err
	}
	frame := transport.TerminalOutputPayload{InstanceID: w.meta.InstanceID, SessionID: w.meta.SessionID, Snapshot: snapshot, NativeGeneration: w.meta.NativeGeneration, SessionKeyID: w.meta.SessionKeyID, Envelope: &envelope, AAD: &aad}
	if snapshot {
		frame.LastSeq = sequence
	} else {
		frame.Seq = sequence
	}
	return frame, nil
}
func (w *nativeTerminalWindow) input(d *Daemon, p transport.TerminalInputPayload) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || !w.active || p.Data != "" || p.Envelope == nil || p.AAD == nil || p.InstanceID != w.meta.InstanceID || p.SessionID != w.meta.SessionID || p.NativeGeneration != w.meta.NativeGeneration || p.SessionKeyID != w.meta.SessionKeyID || p.Seq != w.inputSequence+1 || len(p.Envelope.Ciphertext) > ((4096+16+2)/3)*4 {
		return errors.New("invalid original encrypted terminal input")
	}
	if err := w.currentEpoch(d); err != nil {
		return err
	}
	objectID, err := e2ee.TerminalFrameObjectID(p.InstanceID, p.SessionID, p.NativeGeneration, p.SessionKeyID, "input", false, p.Seq)
	if err != nil {
		return err
	}
	aad := w.aad
	aad.ObjectType = e2ee.ObjectTypeRuntimeTerminalInput
	aad.ObjectID = objectID
	aad.KeyEpochID = w.meta.SessionKeyID
	// Frames use the bootstrap's complete scope/timestamp, not caller-selected AAD.
	if string(aad.CanonicalBytes()) != string(p.AAD.CanonicalBytes()) {
		return ErrNativeObservationConflict
	}
	plain, err := e2ee.Decrypt(*p.Envelope, w.inputKey, aad)
	if err != nil {
		return err
	}
	defer clear(plain)
	if len(plain) == 0 || len(plain) > 4096 {
		return errors.New("invalid encrypted terminal input bound")
	}
	w.inputSequence = p.Seq
	return w.stream.SendInput(plain)
}

// write uses this exact authenticated connection, never d.send's curConn fallback.
func (d *Daemon) nativeSendTerminal(conn *websocket.Conn, p *NativeWorkerProxy, typ string, payload any) error {
	current, err := d.nativeWorkerFor(conn, p.scope.InstanceID)
	if err != nil || current != p {
		return ErrNativeOriginAdmissionDeferred
	}
	envelope, err := transport.NewEnvelope(typ, payload)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	return d.write(conn, raw)
}
