package federation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"reflect"
	"sync"
	"time"
)

const controlVersion = "pagnet.fabric.control-ledger.v1"
const controlConfigurationID = "control-configuration-v1"

type ControlLedger struct{ config ControlConfig }
type controlConfiguration struct {
	Version     string `json:"version"`
	MaxControls uint64 `json:"maxControls,string"`
	Controls    uint64 `json:"controls,string"`
}
type controlRecord struct {
	Version string         `json:"version"`
	Request ControlRequest `json:"request"`
	Digest  [32]byte       `json:"digest"`
	Result  *ControlResult `json:"result,omitempty"`
}

func newControlLedger(c ControlConfig) (*ControlLedger, error) {
	if c.Ledger == nil || c.Authenticator == nil || c.Cursors == nil || c.Results == nil || c.MaxControls == 0 || c.MaxControls > 1000000 {
		return nil, authError()
	}
	return &ControlLedger{c}, nil
}
func BootstrapControlLedger(ctx context.Context, c ControlConfig) (*ControlLedger, error) {
	l, e := newControlLedger(c)
	if e != nil {
		return nil, e
	}
	a := c.Ledger
	e = a.withOwner(ctx, func(ctx context.Context, tx *registry.AuthorityTx) error {
		if _, e := tx.Get(admissionKey(controlConfigurationID)); !missingAuthority(e) {
			if e != nil {
				return e
			}
			return authError()
		}
		row, config, e := a.configuration(tx)
		if e != nil {
			return e
		}
		_, n, e := a.cas(tx, controlConfigurationID, 0, controlConfiguration{Version: controlVersion, MaxControls: c.MaxControls})
		if e != nil {
			return e
		}
		return a.charge(tx, row, config, uint64(n), false)
	})
	if e != nil {
		return nil, e
	}
	return l, nil
}
func OpenControlLedger(ctx context.Context, c ControlConfig) (*ControlLedger, error) {
	l, e := newControlLedger(c)
	if e != nil {
		return nil, e
	}
	e = c.Ledger.withOwner(ctx, func(ctx context.Context, tx *registry.AuthorityTx) error { _, _, e := l.configuration(tx); return e })
	if e != nil {
		return nil, e
	}
	return l, nil
}
func (l *ControlLedger) configuration(tx *registry.AuthorityTx) (registry.AuthorityRecord, controlConfiguration, error) {
	var c controlConfiguration
	row, e := l.config.Ledger.read(tx, controlConfigurationID, &c)
	if e != nil {
		return row, c, e
	}
	if c.Version != controlVersion || c.MaxControls != l.config.MaxControls || c.Controls > c.MaxControls {
		return row, c, authError()
	}
	return row, c, nil
}
func controlKey(p fabric.Principal, id string) string {
	raw, _ := json.Marshal(struct {
		Purpose   string
		Principal fabric.Principal
		ReplayID  string
	}{controlVersion, p, id})
	sum := sha256.Sum256(raw)
	return "control:" + hex.EncodeToString(sum[:])
}
func ownedControl(r ControlRequest) (ControlRequest, [32]byte, error) {
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > 24<<10 {
		return ControlRequest{}, [32]byte{}, protocolError()
	}
	var owned ControlRequest
	if fabric.DecodeJSONWithLimits(raw, &owned, fabric.WireLimits{MaxBytes: 24 << 10, MaxDepth: 16, MaxMembers: 512}) != nil {
		return owned, [32]byte{}, protocolError()
	}
	if _, e = owned.Proof.Frame.SigningBytes(); e != nil || len(owned.Payload) == 0 || len(owned.Payload) > 4096 || len(owned.Proof.Signature) != ed25519.SignatureSize {
		return owned, [32]byte{}, protocolError()
	}
	return owned, sha256.Sum256(raw), nil
}
func cursorValid(c *ConsumerCursor) bool {
	return c != nil && c.Ordinal >= -1 && (c.Ordinal == -1 && c.FrameDigest == ([32]byte{}) || c.Ordinal >= 0 && c.FrameDigest != ([32]byte{}))
}
func controlPayload(r ControlRequest) (ControlPayload, error) {
	var p ControlPayload
	if fabric.DecodeJSONWithLimits(r.Payload, &p, fabric.WireLimits{MaxBytes: 4096, MaxDepth: 4, MaxMembers: 128}) != nil {
		return p, protocolError()
	}
	switch r.Proof.Frame.Action {
	case "status", "cancel":
		if p.Cursor != nil || p.NextCursor != nil || p.Credit != 0 {
			return p, protocolError()
		}
	case "pull":
		if !cursorValid(p.Cursor) || p.NextCursor != nil || p.Credit < 1 || p.Credit > 4 {
			return p, protocolError()
		}
	case "ack":
		if !cursorValid(p.Cursor) || !cursorValid(p.NextCursor) || p.NextCursor.Ordinal < 0 || p.NextCursor.Ordinal != p.Cursor.Ordinal+1 || p.Credit != 0 {
			return p, protocolError()
		}
	default:
		return p, protocolError()
	}
	return p, nil
}
func controlMatches(c Config, r ControlRequest) bool {
	f := r.Proof.Frame
	raw, e := f.SigningBytes()
	return e == nil && !c.SourceRole && f.SourceDomain == c.Remote.Authority.Namespace && f.SourceStoreID == c.Remote.Authority.StoreID && f.SourceKeyRevision == c.Remote.Authority.KeyRevision && f.DestinationDomain == c.Local.Authority.Namespace && f.DestinationStoreID == c.Local.Authority.StoreID && sha256.Sum256(r.Payload) == f.PayloadDigest && ed25519.Verify(c.Remote.Authority.PublicKey, raw, r.Proof.Signature)
}
func controlAction(action string) AdmissionAction {
	switch action {
	case "cancel":
		return ActionCancel
	case "ack":
		return ActionCheckpoint
	default:
		return ActionRead
	}
}
func (l *ControlLedger) current(ctx context.Context, c Config, r ControlRequest, fn func(context.Context, *registry.AuthorityTx, fabric.ExecutionContext) error) error {
	if ctx == nil || l == nil {
		return authError()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c = cloneConfig(c)
	if !controlMatches(c, r) {
		return authError()
	}
	signing, _ := r.Proof.Frame.SigningBytes()
	var mu sync.Mutex
	active, called, invalid := true, false, false
	var result error
	// Recovered authenticator panics must not leave a captured accept live.
	defer func() { mu.Lock(); active = false; mu.Unlock() }()
	authRequest, _, copyErr := ownedControl(r)
	if copyErr != nil {
		return copyErr
	}
	e := l.config.Authenticator.AuthenticateControl(ctx, cloneConfig(c), authRequest, func(current context.Context, caller fabric.ExecutionContext) error {
		mu.Lock()
		defer mu.Unlock()
		if !active || called || current == nil || current.Err() != nil || ctx.Err() != nil || caller.PrincipalView() != r.Proof.Frame.Principal || caller.VerifyAuthenticatedData(signing, c.Local.Authority.Namespace) != nil {
			invalid = true
			return authError()
		}
		called = true
		result = l.config.Ledger.withOwner(current, func(ctx context.Context, tx *registry.AuthorityTx) error {
			return l.config.Ledger.current(ctx, tx, c, func(ctx context.Context) error { return fn(ctx, tx, caller) })
		})
		return result
	})
	mu.Lock()
	active = false
	valid := called && !invalid
	failure := result
	mu.Unlock()
	if e != nil {
		return e
	}
	if !valid {
		return authError()
	}
	return failure
}
func controlFresh(f fabric.ControlFrame) bool {
	issued, e := time.Parse(time.RFC3339Nano, f.IssuedAt)
	if e != nil {
		return false
	}
	expires, e := time.Parse(time.RFC3339Nano, f.ExpiresAt)
	now := time.Now()
	return e == nil && now.Before(expires) && !issued.After(now.Add(time.Second))
}
func (l *ControlLedger) readControl(tx *registry.AuthorityTx, key string) (registry.AuthorityRecord, controlRecord, error) {
	var r controlRecord
	row, e := l.config.Ledger.read(tx, key, &r)
	if e != nil {
		return row, r, e
	}
	owned, digest, e := ownedControl(r.Request)
	if e != nil || r.Version != controlVersion || digest != r.Digest || controlKey(owned.Proof.Frame.Principal, owned.Proof.Frame.ReplayID) != key {
		return row, r, authError()
	}
	if _, e = controlPayload(owned); e != nil {
		return row, r, e
	}
	if r.Result != nil && !validControlResult(owned, *r.Result) {
		return row, r, authError()
	}
	return row, r, nil
}
func statusFrom(m admissionManifest) AdmissionStatus {
	return AdmissionStatus{Attempted: m.AttemptID != "", CancelRequested: m.CancelRequested, Cursor: m.Cursor}
}

// Begin FULL-commits the intent before any source actuation. fresh=false never
// authorizes another actuation, even when Result is absent (uncertain outcome).
func (l *ControlLedger) Begin(ctx context.Context, c Config, request ControlRequest) (ControlPermit, ControlState, bool, error) {
	if l == nil {
		return ControlPermit{}, ControlState{}, false, authError()
	}
	c = cloneConfig(c)
	r, digest, e := ownedControl(request)
	if e != nil {
		return ControlPermit{}, ControlState{}, false, e
	}
	payload, e := controlPayload(r)
	if e != nil {
		return ControlPermit{}, ControlState{}, false, e
	}
	a := l.config.Ledger
	key := controlKey(r.Proof.Frame.Principal, r.Proof.Frame.ReplayID)
	var permit ControlPermit
	var state ControlState
	fresh := false
	e = l.current(ctx, c, r, func(ctx context.Context, tx *registry.AuthorityTx, caller fabric.ExecutionContext) error {
		counterRow, counter, e := l.configuration(tx)
		if e != nil {
			return e
		}
		writeRow, writeCounter, e := a.configuration(tx)
		if e != nil {
			return e
		}
		invocation := invocationKey(r.Proof.Frame.OriginalPrincipal, r.Proof.Frame.InvocationID)
		mrow, m, e := a.manifest(tx, invocation)
		if e != nil {
			return e
		}
		if m.Facts.BundleDigest != r.Proof.Frame.ReceiptDigest || m.AttemptID != r.Proof.Frame.AttemptID || !sameRoot(m.Facts.Source.Authority, c.Remote.Authority) || !sameRoot(m.Facts.Destination.Authority, c.Local.Authority) {
			return authError()
		}
		if e = a.authorize(ctx, tx, controlAction(r.Proof.Frame.Action), caller, m); e != nil {
			return e
		}
		_, record, e := l.readControl(tx, key)
		if e == nil {
			if record.Digest != digest {
				return authError()
			}
			permit = ControlPermit{l, key, digest, r, Admission{a, invocation, m.Facts.BundleDigest}}
			state = ControlState{record.Result, statusFrom(m)}
			return nil
		}
		if !missingAuthority(e) {
			return e
		}
		if r.Proof.Frame.SourcePeerBindingDigest != c.Remote.BindingDigest || r.Proof.Frame.DestinationPeerBindingDigest != c.Local.BindingDigest {
			return authError()
		}
		if !controlFresh(r.Proof.Frame) {
			return fabric.NewError(fabric.CodeDeadlineExceeded, "Fresh control validity expired")
		}
		if counter.Controls >= counter.MaxControls {
			return fabric.NewError(fabric.ErrorCode("federation.capacity"), "Control replay capacity exhausted")
		}
		var nbytes uint64
		before := m
		switch r.Proof.Frame.Action {
		case "pull":
			if m.Association == nil || m.Cursor != *payload.Cursor {
				return fabric.NewError(fabric.CodeStaleContinuation, "Pull does not match retained consumer cursor")
			}
		case "cancel":
			m.CancelRequested = true
		case "ack":
			if m.Association == nil {
				return authError()
			}
			if m.Cursor != *payload.NextCursor {
				if m.Cursor != *payload.Cursor {
					return fabric.NewError(fabric.CodeStaleContinuation, "ACK does not match retained consumer cursor")
				}
				if e = l.config.Cursors.VerifyCursorTx(ctx, tx, cloneAdmissionFacts(m.Facts), Association{m.Association.Protocol, m.Association.BindingDigest, bytes.Clone(m.Association.PrivateReference)}, *payload.NextCursor); e != nil {
					return e
				}
				m.Cursor = *payload.NextCursor
			}
		}
		if !reflect.DeepEqual(before, m) {
			_, n, e := a.cas(tx, invocation, mrow.Revision, m)
			if e != nil {
				return e
			}
			nbytes += uint64(n)
		}
		_, n, e := a.cas(tx, key, 0, controlRecord{Version: controlVersion, Request: r, Digest: digest})
		if e != nil {
			return e
		}
		nbytes += uint64(n)
		counter.Controls++
		_, n, e = a.cas(tx, controlConfigurationID, counterRow.Revision, counter)
		if e != nil {
			return e
		}
		nbytes += uint64(n)
		if e = a.charge(tx, writeRow, writeCounter, nbytes, false); e != nil {
			return e
		}
		permit = ControlPermit{l, key, digest, r, Admission{a, invocation, m.Facts.BundleDigest}}
		state = ControlState{Status: statusFrom(m)}
		fresh = true
		return nil
	})
	if e != nil {
		return ControlPermit{}, ControlState{}, false, e
	}
	return permit, state, fresh, nil
}
func validControlResult(r ControlRequest, result ControlResult) bool {
	if result.State != "confirmed" && result.State != "unknown" || result.ResponseDigest == ([32]byte{}) || result.FrameCount > 4 {
		return false
	}
	p, e := controlPayload(r)
	if e != nil {
		return false
	}
	if result.Cursor != nil && !cursorValid(result.Cursor) {
		return false
	}
	switch r.Proof.Frame.Action {
	case "pull":
		return result.FrameCount <= p.Credit && !result.StopAcknowledged
	case "cancel":
		return result.FrameCount == 0 && result.Cursor == nil && (!result.StopAcknowledged || result.State == "confirmed")
	case "ack":
		return result.FrameCount == 0 && !result.StopAcknowledged && result.Cursor != nil && *result.Cursor == *p.NextCursor
	case "status":
		return result.FrameCount == 0 && !result.StopAcknowledged
	default:
		return false
	}
}

// Complete records exact actual source results after actuation outside SQL.
// The mandatory verifier checks original retained evidence locally in this TX.
func (l *ControlLedger) Complete(ctx context.Context, c Config, p ControlPermit, result ControlResult) error {
	if l == nil || p.ledger != l || !validControlResult(p.request, result) {
		return authError()
	}
	raw, _ := json.Marshal(result)
	var owned ControlResult
	if fabric.DecodeJSON(raw, &owned) != nil {
		return protocolError()
	}
	a := l.config.Ledger
	c = cloneConfig(c)
	return l.current(ctx, c, p.request, func(ctx context.Context, tx *registry.AuthorityTx, caller fabric.ExecutionContext) error {
		row, record, e := l.readControl(tx, p.key)
		if e != nil {
			return e
		}
		if record.Digest != p.digest {
			return authError()
		}
		_, m, e := a.manifest(tx, p.invocation.key)
		if e != nil {
			return e
		}
		if e = a.authorize(ctx, tx, controlAction(p.request.Proof.Frame.Action), caller, m); e != nil {
			return e
		}
		if record.Result != nil {
			if !reflect.DeepEqual(*record.Result, owned) {
				return authError()
			}
			return nil
		}
		verificationRequest, _, e := ownedControl(p.request)
		if e != nil {
			return e
		}
		var verificationResult ControlResult
		if fabric.DecodeJSON(raw, &verificationResult) != nil {
			return protocolError()
		}
		if e = l.config.Results.VerifyControlResultTx(ctx, tx, cloneAdmissionFacts(m.Facts), verificationRequest, verificationResult); e != nil {
			return e
		}
		record.Result = &owned
		counterRow, counter, e := a.configuration(tx)
		if e != nil {
			return e
		}
		_, n, e := a.cas(tx, p.key, row.Revision, record)
		if e != nil {
			return e
		}
		return a.charge(tx, counterRow, counter, uint64(n), false)
	})
}
