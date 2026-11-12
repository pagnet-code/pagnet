package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"time"

	"github.com/pagnet-code/pagnet/accountmessage"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/nativecontent"
	"github.com/pagnet-code/pagnet/transport"
)

const accountReplyReadMaxOperations = 2
const accountReplyReadMaxRetainedWire = 64 << 20
const accountReplyReadMaxSeenFrames = 4096

type accountReplyRead struct {
	id         string
	begin      transport.BrowserAccountReplyReadBeginPayload
	fragments  []transport.NativeContentFragment
	ctx        context.Context
	cancel     context.CancelFunc
	guard      func() bool
	wireBytes  int
	committing bool
	frameIDs   []string
}

func (c *accountMessagingReadinessConnection) readEnabled() bool {
	s, ok := c.session()
	return ok && c.d.AccountReplyReadEnabled && c.usesSubscription() && slices.Contains(s.ProtocolFeatures, transport.BrowserAccountReplyReadProtocol)
}

func (c *accountMessagingReadinessConnection) admitAccountReplyRead(s transport.HostSessionPayload) {
	if c.d.AccountReplyReadEnabled && c.usesSubscription() && slices.Contains(s.ProtocolFeatures, transport.BrowserAccountReplyReadProtocol) {
		c.send(transport.MsgAccountReplyReadHello, transport.BrowserAccountReplyReadHelloPayload{V: 1, Protocol: transport.BrowserAccountReplyReadProtocol})
	}
}

// Intercept the entire reserved family before generic decoding, logging or
// command journaling, including malformed and incorrectly directed frames.
func (c *accountMessagingReadinessConnection) interceptAccountReplyRead(raw []byte) bool {
	reserved := false
	for _, kind := range []string{transport.MsgAccountReplyRead, transport.MsgAccountReplyReadFragment, transport.MsgAccountReplyReadCommit, transport.MsgAccountReplyReadCancel, transport.MsgAccountReplyReadHello, transport.MsgAccountReplyReadChunk, transport.MsgAccountReplyReadDone, transport.MsgAccountReplyReadError} {
		if reservedAccountMessageType(raw, kind) {
			reserved = true
			break
		}
	}
	if !reserved {
		return false
	}
	env, err := transport.DecodeBrowserAccountReplyReadFrame(raw)
	if err != nil {
		c.closeAccountReplyReads()
		return true
	}
	id := env.ID
	if env.CorrelationID != nil {
		id = *env.CorrelationID
	}
	if !c.readEnabled() {
		c.readError(id, "unavailable")
		return true
	}
	c.readMu.Lock()
	if env.Type != transport.MsgAccountReplyRead && c.reads[id] == nil {
		c.readMu.Unlock()
		return true
	}
	if c.readSeen == nil {
		c.readSeen = make(map[string]bool)
	}
	if len(c.readSeen) >= accountReplyReadMaxSeenFrames {
		c.readMu.Unlock()
		// Explicitly reconnect before bounded socket-local replay evidence fills.
		c.readError(id, "unavailable")
		c.close()
		if c.socket != nil {
			_ = c.socket.Close()
		}
		return true
	}
	if c.readSeen[env.ID] {
		op := c.reads[id]
		c.readMu.Unlock()
		if op != nil {
			c.endAccountReplyRead(op)
			c.readError(id, "invalid_request")
		}
		return true
	}
	c.readSeen[env.ID] = true
	if op := c.reads[id]; op != nil {
		op.frameIDs = append(op.frameIDs, env.ID)
	}
	c.readMu.Unlock()
	if env.Type == transport.MsgAccountReplyRead {
		c.beginAccountReplyRead(env, len(raw))
		return true
	}
	c.readMu.Lock()
	op := c.reads[id]
	if op == nil {
		c.readMu.Unlock()
		return true
	}
	invalid := false
	commit := false
	switch env.Type {
	case transport.MsgAccountReplyReadCancel, transport.MsgAccountReplyReadCommit:
		var p transport.BrowserAccountReplyReadVersionPayload
		invalid = transport.DecodeBrowserAccountReplyReadPayload(env.Payload, &p) != nil || p.V != 1 || (env.Type == transport.MsgAccountReplyReadCommit && op.committing)
		if !invalid && env.Type == transport.MsgAccountReplyReadCommit {
			invalid = len(op.fragments) != op.begin.Reference.FragmentCount
			if !invalid {
				op.committing = true
				commit = true
			}
		}
	case transport.MsgAccountReplyReadFragment:
		var p transport.BrowserAccountReplyReadFragmentPayload
		invalid = transport.DecodeBrowserAccountReplyReadPayload(env.Payload, &p) != nil || p.V != 1 || op.committing || p.Fragment.Ordinal != len(op.fragments) || nativecontent.ValidateFragment(op.begin.Reference, p.Fragment) != nil || c.readWireBytes+len(raw) > accountReplyReadMaxRetainedWire
		canonical, canonicalErr := transport.MarshalNativeJSON(p)
		invalid = invalid || canonicalErr != nil || !bytes.Equal(env.Payload, canonical)
		if !invalid {
			op.fragments = append(op.fragments, p.Fragment)
			op.wireBytes += len(raw)
			c.readWireBytes += len(raw)
		}
	default:
		invalid = true
	}
	c.readMu.Unlock()
	if invalid {
		c.endAccountReplyRead(op)
		c.readError(id, "invalid_request")
	} else if env.Type == transport.MsgAccountReplyReadCancel {
		c.endAccountReplyRead(op)
	} else if commit {
		go c.finishAccountReplyRead(op)
	}
	return true
}

func (c *accountMessagingReadinessConnection) beginAccountReplyRead(env transport.Envelope, size int) {
	var p transport.BrowserAccountReplyReadBeginPayload
	if transport.DecodeBrowserAccountReplyReadPayload(env.Payload, &p) != nil || p.V != 1 || transport.ValidateNativeAccountReplyReference(p.Reference) != nil || nativecontent.ValidateReference(p.Reference) != nil {
		c.readError(env.ID, "invalid_request")
		return
	}
	canonical, canonicalErr := transport.MarshalNativeJSON(p)
	if canonicalErr != nil || !bytes.Equal(env.Payload, canonical) {
		c.readError(env.ID, "invalid_request")
		return
	}
	s := p.Proof.AccountMessageSource
	deadline, err := time.Parse(time.RFC3339Nano, p.Deadline)
	now := time.Now()
	if err != nil || deadline.UTC().Format(time.RFC3339Nano) != p.Deadline || !deadline.After(now) || deadline.After(now.Add(time.Minute)) || s == nil || p.Proof.TaskSource != nil || p.Proof.InvocationSource != nil || s.Validate() != nil || p.MessageID != s.MessageID || p.Proof.SourceRunnerID != s.Descriptor.RunnerID || p.Proof.SourceRunnerEpoch.UTC().Format(time.RFC3339Nano) != s.Descriptor.RunnerConnectedAt || s.ValidateReplyAAD(p.Reference.ManifestAAD, p.Proof) != nil || p.Reference.ManifestAAD.KeyEpochID != s.Descriptor.EpochID || p.Reference.InstanceID != s.Descriptor.TargetInstanceID || p.Reference.SubjectID != p.MessageID {
		c.readError(env.ID, "invalid_request")
		return
	}
	guard := c.accountReplyReadGuard(s.Descriptor)
	if guard == nil {
		c.readError(env.ID, "unavailable")
		return
	}
	ctx, cancel := context.WithDeadline(c.ctx, deadline)
	op := &accountReplyRead{id: env.ID, begin: p, ctx: ctx, cancel: cancel, guard: guard, wireBytes: size, frameIDs: []string{env.ID}}
	c.readMu.Lock()
	if c.reads == nil {
		c.reads = make(map[string]*accountReplyRead)
	}
	if len(c.reads) >= accountReplyReadMaxOperations || c.readWireBytes+size > accountReplyReadMaxRetainedWire || c.readCipherBytes+p.Reference.CiphertextBytes > accountReplyReadMaxOperations*transport.NativeContentMaxCiphertextBytes {
		c.readMu.Unlock()
		cancel()
		c.readError(env.ID, "unavailable")
		return
	}
	c.reads[env.ID] = op
	c.readWireBytes += size
	c.readCipherBytes += p.Reference.CiphertextBytes
	c.readMu.Unlock()
	go func() { <-ctx.Done(); c.endAccountReplyRead(op) }()
}

// Historical provenance is frozen; current local evidence fences only the
// stable owner/connection/network/identity route, not an old runner or epoch.
func (c *accountMessagingReadinessConnection) accountReplyReadGuard(d accountmessage.Descriptor, beforeEvidenceLock ...func()) func() bool {
	a := c.subscription
	if a == nil {
		return nil
	}
	a.mu.Lock()
	revision := a.revision
	a.mu.Unlock()
	guard := func() bool {
		// Optional barrier lets concurrency tests stop an actual writer guard
		// before its evidence lock, without substituting its authority checks.
		if len(beforeEvidenceLock) != 0 {
			beforeEvidenceLock[0]()
		}
		// Acquire evidence locks before the final socket/session/mutation checks.
		// A waiter must not carry an earlier successful check across invalidation.
		a.mu.Lock()
		defer a.mu.Unlock()
		c.mu.Lock()
		defer c.mu.Unlock()
		s, ok := c.session()
		if !ok || !c.d.AccountReplyReadEnabled || !c.usesSubscription() || !slices.Contains(s.ProtocolFeatures, transport.BrowserAccountReplyReadProtocol) || s.TenantID != d.TenantID || s.AccountID != d.OwnerUserID || s.HostID != d.HostID {
			return false
		}
		n, ok := c.networks[d.NetworkID]
		if !ok || n.TenantID != d.TenantID || n.Status != "active" {
			return false
		}
		if a.revision != revision || !a.complete {
			return false
		}
		for _, r := range a.accepted {
			if r.ConnectionID.String() == d.ConnectionID && r.ResourceID == d.ResourceID && r.IdentityIncarnationID == d.IdentityIncarnationID && r.LogicalSenderID.String() == d.Sender.ID && r.NetworkID.String() == d.NetworkID && r.TargetPrincipalID.String() == d.TargetPrincipalID && r.HostID.String() == d.HostID && r.Status == "ready" && r.AckedAt != nil && time.Now().Before(r.ExpiresAt) {
				return !c.d.accountMessagingMutationActive()
			}
		}
		return false
	}
	if !guard() {
		return nil
	}
	return guard
}

func (c *accountMessagingReadinessConnection) readPublish(op *accountReplyRead, kind string, payload any) bool {
	if op.ctx.Err() != nil || !op.guard() {
		return false
	}
	return c.readResponse(op.id, kind, payload, func() bool { return op.guard() && op.ctx.Err() == nil })
}

func (c *accountMessagingReadinessConnection) readResponse(id, kind string, payload any, guard func() bool) bool {
	if _, ok := c.session(); !ok {
		return false
	}
	e, err := transport.NewEnvelope(kind, payload)
	if err != nil {
		return false
	}
	defer clear(e.Payload)
	e.CorrelationID = &id
	raw, err := transport.MarshalNativeJSON(e)
	if err != nil || len(raw) > transport.BrowserAccountReplyReadMaxWireBytes {
		return false
	}
	defer clear(raw)
	published := false
	err = c.write(raw, func() bool {
		if _, ok := c.session(); !ok || (guard != nil && !guard()) {
			return false
		}
		published = true
		return true
	})
	return err == nil && published
}

func (c *accountMessagingReadinessConnection) readError(id, code string) {
	c.readResponse(id, transport.MsgAccountReplyReadError, transport.BrowserAccountReplyReadErrorPayload{V: 1, Code: code}, nil)
}

func (c *accountMessagingReadinessConnection) finishAccountReplyRead(op *accountReplyRead) {
	defer c.releaseAccountReplyRead(op)
	d := op.begin.Proof.AccountMessageSource.Descriptor
	err := crypto.WithNetworkKeyring(op.ctx, c.d.StateDir, d.NetworkID, func(kr *crypto.Keyring) error {
		defer func() {
			for i := range kr.Epochs {
				clear(kr.Epochs[i].Key)
			}
		}()
		if op.ctx.Err() != nil || !op.guard() || kr.NetworkID != d.NetworkID {
			return errAccountReplyOutput
		}
		epoch, ok := kr.EpochByID(d.EpochID)
		if !ok || (epoch.State != crypto.EpochActive && epoch.State != crypto.EpochRotated) {
			return errAccountReplyOutput
		}
		key, err := epoch.KeyArray()
		if err != nil {
			return errAccountReplyOutput
		}
		defer clear(key[:])
		plain, mime, err := nativecontent.Open(op.begin.Reference, op.fragments, key)
		if err != nil {
			return errAccountReplyOutput
		}
		defer clear(plain)
		if mime != "application/json" {
			return errAccountReplyOutput
		}
		if _, err = decodeAccountReplyOutput(plain); err != nil {
			return errAccountReplyOutput
		}
		sum := sha256.Sum256(plain)
		count := 0
		for offset := 0; offset < len(plain); offset += transport.BrowserAccountReplyReadChunkBytes {
			part := plain[offset:min(offset+transport.BrowserAccountReplyReadChunkBytes, len(plain))]
			if !c.readPublish(op, transport.MsgAccountReplyReadChunk, transport.BrowserAccountReplyReadChunkPayload{V: 1, Sequence: count, Data: base64.StdEncoding.EncodeToString(part)}) {
				return errAccountReplyOutput
			}
			count++
		}
		if !c.readPublish(op, transport.MsgAccountReplyReadDone, transport.BrowserAccountReplyReadDonePayload{V: 1, MessageID: op.begin.MessageID, ContentID: op.begin.Reference.ContentID, CiphertextDigest: op.begin.Reference.CiphertextDigest, ChunkCount: count, PlaintextBytes: int64(len(plain)), PlaintextDigest: hex.EncodeToString(sum[:])}) {
			return errAccountReplyOutput
		}
		return nil
	})
	if err != nil && op.ctx.Err() == nil {
		c.readError(op.id, "unavailable")
	}
}

func (c *accountMessagingReadinessConnection) endAccountReplyRead(op *accountReplyRead) {
	op.cancel()
	c.readMu.Lock()
	defer c.readMu.Unlock()
	// A canceled decrypt still owns its bounded capacity until its worker exits.
	// Releasing it here would allow cancel/restart to accumulate private buffers.
	if !op.committing {
		c.releaseAccountReplyReadLocked(op)
	}
}

func (c *accountMessagingReadinessConnection) releaseAccountReplyRead(op *accountReplyRead) {
	op.cancel()
	c.readMu.Lock()
	defer c.readMu.Unlock()
	c.releaseAccountReplyReadLocked(op)
}

func (c *accountMessagingReadinessConnection) releaseAccountReplyReadLocked(op *accountReplyRead) {
	if c.reads[op.id] == op {
		// Retain the begin ID as a tombstone. Followup IDs need only remain
		// fresh during this operation; old correlations cannot create a read.
		for _, id := range op.frameIDs {
			if id != op.id {
				delete(c.readSeen, id)
			}
		}
		delete(c.reads, op.id)
		c.readWireBytes -= op.wireBytes
		c.readCipherBytes -= op.begin.Reference.CiphertextBytes
	}
}

func (c *accountMessagingReadinessConnection) closeAccountReplyReads() {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for _, op := range c.reads {
		op.cancel()
		if !op.committing {
			c.releaseAccountReplyReadLocked(op)
		}
	}
}
