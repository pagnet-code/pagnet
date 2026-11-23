package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
	"github.com/pagnet-code/pagnet/sdk"
	"github.com/pagnet-code/pagnet/transport"
)

const ownerTextConsoleEpoch = "2006-01-02T15:04:05.000000000Z"

func (d *Daemon) ownerTextConsoleReady() bool {
	d.ownerTextConsoleMu.Lock()
	handlers := d.ownerTextConsoleHandlers
	d.ownerTextConsoleMu.Unlock()
	if handlers == 0 || d.textServices == nil {
		return false
	}
	s := d.textServices
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.running {
		if r.client == s.client && r.profile.ProjectContract == textbridge.OwnerTextProjectContract && r.profile.ServiceRole() == "sender" && r.enabled.Load() && r.controller != nil && r.consoleBinding != nil && r.client.ctx.Err() == nil {
			done, ok := r.endpoint.Load().(<-chan struct{})
			if !ok || done == nil {
				continue
			}
			select {
			case <-done:
				continue
			default:
			}
			select {
			case <-r.stopped:
				continue
			default:
			}
			return true
		}
	}
	return false
}

// Runtime publication changes are pushed once; no idle polling is needed.
func (d *Daemon) refreshOwnerTextConsoleInventory(expected transport.HostSessionPayload) {
	d.connMu.Lock()
	conn, native := d.curConn, d.nativeConn
	d.connMu.Unlock()
	if conn == nil || native == nil {
		return
	}
	current, err := native.AuthenticatedNativeHostSession()
	if err == nil && sameOwnerMailboxAuthority(current, expected) {
		d.sendInventory(conn)
	}
}

func consoleHostMatches(d e2ee.OwnerTextConsoleDescriptor, p transport.HostSessionPayload) bool {
	return p.OwnershipScope == "personal" && p.HostCredentialID != "" && d.TenantID == p.TenantID && d.OwnerUserID == p.AccountID && d.HostID == p.HostID && d.RunnerID == p.RunnerID && d.RunnerEpoch == p.RunnerEpoch.UTC().Format(ownerTextConsoleEpoch) && d.HostCredentialID == p.HostCredentialID
}
func consoleBindingMatches(d e2ee.OwnerTextConsoleDescriptor, b sdk.OwnerTextProjectBindingSnapshot) bool {
	var project struct {
		ProjectID     string `json:"projectId"`
		NetworkID     string `json:"networkId"`
		OwnerTenantID string `json:"ownerTenantId"`
		OwnerUserID   string `json:"ownerUserId"`
		PolicyHash    string `json:"policyHash"`
	}
	if json.Unmarshal(b.Descriptor, &project) != nil || project.ProjectID != d.ProjectID || project.NetworkID != d.NetworkID || project.OwnerTenantID != d.TenantID || project.OwnerUserID != d.OwnerUserID || project.PolicyHash != d.PolicyHash {
		return false
	}
	if b.ProjectContract != textbridge.OwnerTextProjectContract || b.ProjectID != d.ProjectID || b.NetworkID != d.NetworkID || b.ProjectVersion != d.ProjectVersion || b.PolicyHash != d.PolicyHash || !bytes.Equal(b.DescriptorHash, d.ProjectDescriptorHash) {
		return false
	}
	if b.PrincipalID != d.SenderPrincipalID || b.InstallationID != d.SenderInstallationID || b.ClaimID != d.SenderClaimID || strconv.FormatInt(b.Generation, 10) != d.SenderGeneration || b.EndpointID != d.SenderEndpointID {
		return false
	}
	p := b.EndpointProof
	if p == nil || p.ProofID != d.SenderProofID || p.PrincipalID != d.SenderPrincipalID || p.InstallationID != d.SenderInstallationID || p.ClaimID != d.SenderClaimID || p.Generation != d.SenderGeneration || p.EndpointID != d.SenderEndpointID || p.CredentialID != d.SenderEndpointCredentialID || p.EndpointStartedAt != d.SenderEndpointStartedAt || !bytes.Equal(p.DescriptorHash, d.ProjectDescriptorHash) {
		return false
	}
	return len(b.Roles) == 2 && b.Roles[0].Role == "sender" && b.Roles[0].PrincipalID == d.SenderPrincipalID && b.Roles[0].InstallationID == d.SenderInstallationID && b.Roles[1].Role == "responder" && b.Roles[1].PrincipalID == d.ResponderPrincipalID && b.Roles[1].InstallationID == d.ResponderInstallationID
}

// consoleSender resolves authority from the current managed runtime and its SDK
// installation proof. Descriptor fields never select credentials or local paths.
func (d *Daemon) consoleSender(ctx context.Context, desc e2ee.OwnerTextConsoleDescriptor, p transport.HostSessionPayload) (*TextSender, <-chan struct{}, <-chan struct{}, error) {
	s := d.textServices
	if s == nil || !consoleHostMatches(desc, p) {
		return nil, nil, nil, ErrTextSenderUnavailable
	}
	s.mu.Lock()
	r := s.running[desc.SenderInstallationID]
	if r == nil || r.client != s.client || !sameOwnerMailboxAuthority(r.client.session, p) || r.profile.ProjectContract != textbridge.OwnerTextProjectContract || r.profile.ServiceRole() != "sender" || r.profile.Service != desc.SenderPrincipalID || r.claimID != desc.SenderClaimID || strconv.FormatInt(r.generation, 10) != desc.SenderGeneration || !r.enabled.Load() || r.controller == nil || r.consoleBinding == nil {
		s.mu.Unlock()
		return nil, nil, nil, ErrTextSenderUnavailable
	}
	binding, controller := r.consoleBinding, r.controller
	s.mu.Unlock()
	b, done, err := binding(ctx, desc.ProjectID, desc.SenderInstallationID)
	if err != nil || done == nil || !consoleBindingMatches(desc, b) {
		return nil, nil, nil, ErrTextSenderUnavailable
	}
	select {
	case <-done:
		return nil, nil, nil, ErrTextSenderUnavailable
	default:
	}
	s.mu.Lock()
	current := s.running[desc.SenderInstallationID] == r && s.client == r.client && r.enabled.Load() && r.controller == controller && r.client.ctx.Err() == nil
	s.mu.Unlock()
	if !current {
		return nil, nil, nil, ErrTextSenderUnavailable
	}
	handle, err := d.TextSender(ctx, desc.SenderInstallationID, desc.ProjectID)
	if err != nil || handle.controller != controller {
		return nil, nil, nil, ErrTextSenderUnavailable
	}
	return handle, done, r.stopped, nil
}

type ownerTextConsoleSession struct {
	descriptor      e2ee.OwnerTextConsoleDescriptor
	crypto          *e2ee.OwnerTextConsoleSession
	authority       transport.HostSessionPayload
	sender          *TextSender
	bindingDone     <-chan struct{}
	runtimeDone     <-chan struct{}
	ctx             context.Context
	cancel          context.CancelFunc
	confirmed, busy bool
}

// A connection owns fresh session keys; only public replay tombstones survive it.
type ownerTextConsoleConnection struct {
	daemon   *Daemon
	native   *NativeObservationConnection
	send     func(string, any) error
	mu       sync.Mutex
	closed   bool
	sessions map[string]*ownerTextConsoleSession
}

func newOwnerTextConsoleConnection(d *Daemon, n *NativeObservationConnection, send func(string, any) error) *ownerTextConsoleConnection {
	d.ownerTextConsoleMu.Lock()
	d.ownerTextConsoleHandlers++
	d.ownerTextConsoleMu.Unlock()
	return &ownerTextConsoleConnection{daemon: d, native: n, send: send, sessions: map[string]*ownerTextConsoleSession{}}
}
func (c *ownerTextConsoleConnection) erase(id string, notify bool) {
	s := c.sessions[id]
	if s == nil {
		return
	}
	delete(c.sessions, id)
	s.cancel()
	s.crypto.Close()
	if notify {
		_ = c.send(transport.MsgOwnerTextConsoleClose, transport.OwnerTextConsoleClosePayload{Protocol: transport.OwnerTextConsoleProtocolV1, SessionID: id})
	}
}
func (c *ownerTextConsoleConnection) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	for id := range c.sessions {
		c.erase(id, false)
	}
	c.daemon.ownerTextConsoleMu.Lock()
	c.daemon.ownerTextConsoleHandlers--
	c.daemon.ownerTextConsoleMu.Unlock()
}
func (c *ownerTextConsoleConnection) fail() {
	for id := range c.sessions {
		c.erase(id, true)
	}
}
func (c *ownerTextConsoleConnection) handle(env transport.Envelope, wireBytes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	p, err := c.native.AuthenticatedNativeHostSession()
	if err != nil || wireBytes > transport.OwnerTextConsoleMaxWireBytes {
		c.fail()
		return
	}
	switch env.Type {
	case transport.MsgOwnerTextConsoleOpen:
		var open transport.OwnerTextConsoleOpenPayload
		if transport.DecodeOwnerTextConsolePayload(env.Payload, &open) != nil || open.Protocol != transport.OwnerTextConsoleProtocolV1 {
			c.fail()
			return
		}
		c.open(open.Descriptor, p)
	case transport.MsgOwnerTextConsoleClose:
		var close transport.OwnerTextConsoleClosePayload
		if transport.DecodeOwnerTextConsolePayload(env.Payload, &close) != nil || close.Protocol != transport.OwnerTextConsoleProtocolV1 {
			c.fail()
			return
		}
		c.erase(close.SessionID, false)
	case transport.MsgOwnerTextConsoleFrame:
		var f transport.OwnerTextConsoleFramePayload
		if transport.DecodeOwnerTextConsolePayload(env.Payload, &f) != nil || f.Validate(f.SessionID) != nil {
			c.fail()
			return
		}
		s := c.sessions[f.SessionID]
		if s == nil {
			return
		}
		if !sameOwnerMailboxAuthority(s.authority, p) || s.busy || !consoleHostMatches(s.descriptor, p) {
			c.erase(f.SessionID, true)
			return
		}
		select {
		case <-s.bindingDone:
			c.erase(f.SessionID, true)
			return
		default:
		}
		if !s.confirmed {
			if s.crypto.OpenConfirmation(f.Sequence, f.Ciphertext) != nil {
				c.erase(f.SessionID, true)
				return
			}
			ct, err := s.crypto.SealConfirmation()
			if err != nil {
				c.erase(f.SessionID, true)
				return
			}
			s.confirmed = true
			if c.send(transport.MsgOwnerTextConsoleFrame, transport.OwnerTextConsoleFramePayload{Protocol: transport.OwnerTextConsoleProtocolV1, SessionID: f.SessionID, Sequence: 0, Ciphertext: ct}) != nil {
				c.erase(f.SessionID, false)
			}
			return
		}
		plain, err := s.crypto.Open(f.Sequence, f.Ciphertext)
		if err != nil {
			c.erase(f.SessionID, true)
			return
		}
		s.busy = true
		go c.operation(s, plain)
	}
}
func (c *ownerTextConsoleConnection) open(d e2ee.OwnerTextConsoleDescriptor, p transport.HostSessionPayload) {
	reject := func() {
		_ = c.send(transport.MsgOwnerTextConsoleClose, transport.OwnerTextConsoleClosePayload{Protocol: transport.OwnerTextConsoleProtocolV1, SessionID: d.SessionID})
	}
	if _, err := e2ee.EncodeOwnerTextConsoleDescriptor(d); err != nil {
		return
	}
	now := time.Now()
	if !consoleHostMatches(d, p) || now.Unix() < int64(d.IssuedAtUnixSeconds) || now.Unix() >= int64(d.ExpiresAtUnixSeconds) || len(c.sessions) >= 32 {
		reject()
		return
	}
	identity, err := c.daemon.cryptoManager().hostIdentity()
	if err != nil || !bytes.Equal(identity.X25519Pub, d.HostX25519Pub) || !bytes.Equal(identity.Ed25519Pub, d.HostEd25519Pub) {
		reject()
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(int64(d.ExpiresAtUnixSeconds), 0))
	setup, doneSetup := context.WithTimeout(ctx, 5*time.Second)
	handle, done, runtimeDone, err := c.daemon.consoleSender(setup, d, p)
	doneSetup()
	if err != nil {
		cancel()
		reject()
		return
	}
	c.daemon.ownerTextConsoleMu.Lock()
	if c.daemon.ownerTextConsoleUsed == nil {
		c.daemon.ownerTextConsoleUsed = map[string]time.Time{}
	}
	for id, expiry := range c.daemon.ownerTextConsoleUsed {
		if !now.Before(expiry) {
			delete(c.daemon.ownerTextConsoleUsed, id)
		}
	}
	_, used := c.daemon.ownerTextConsoleUsed[d.SessionID]
	if !used && len(c.daemon.ownerTextConsoleUsed) < 4096 {
		c.daemon.ownerTextConsoleUsed[d.SessionID] = time.Unix(int64(d.ExpiresAtUnixSeconds), 0)
	} else {
		used = true
	}
	c.daemon.ownerTextConsoleMu.Unlock()
	if used {
		cancel()
		c.erase(d.SessionID, false)
		reject()
		return
	}
	bootstrap, keys, err := e2ee.CreateOwnerTextConsoleBootstrap(d, identity.Ed25519Priv)
	if err != nil {
		cancel()
		reject()
		return
	}
	crypto, err := e2ee.NewOwnerTextConsoleSession(d, bootstrap, keys, true, nil)
	clear(keys.ClientToHost[:])
	clear(keys.HostToClient[:])
	if err != nil {
		cancel()
		reject()
		return
	}
	s := &ownerTextConsoleSession{descriptor: d, crypto: crypto, authority: p, sender: handle, bindingDone: done, runtimeDone: runtimeDone, ctx: ctx, cancel: cancel}
	c.sessions[d.SessionID] = s
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		case <-runtimeDone:
		case <-c.native.closed:
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.sessions[d.SessionID] == s {
			c.erase(d.SessionID, true)
		}
	}()
	if c.send(transport.MsgOwnerTextConsoleReady, transport.OwnerTextConsoleReadyPayload{Protocol: transport.OwnerTextConsoleProtocolV1, Descriptor: d, Bootstrap: bootstrap}) != nil {
		c.erase(d.SessionID, false)
	}
}

type ownerTextConsoleRequest struct {
	Version   int    `json:"version"`
	Type      string `json:"type"`
	RequestID string `json:"requestId"`
	AskID     string `json:"askId,omitempty"`
	Text      string `json:"text,omitempty"`
	Cursor    string `json:"cursor,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}
type ownerTextConsoleResult struct {
	Version   int    `json:"version"`
	Type      string `json:"type"`
	RequestID string `json:"requestId"`
	Code      string `json:"code"`
	Data      any    `json:"data,omitempty"`
}
type ownerTextConsoleOperation struct {
	AskID    string                 `json:"askId"`
	Phase    sender.Phase           `json:"phase"`
	Admitted bool                   `json:"admitted"`
	Reply    *ownerTextConsoleReply `json:"reply,omitempty"`
}
type ownerTextConsoleReply struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

func consoleUUID(s string, version uuid.Version) bool {
	id, err := uuid.Parse(s)
	return err == nil && id.String() == s && id.Variant() == uuid.RFC4122 && id.Version() == version
}
func consoleRequest(raw []byte) (ownerTextConsoleRequest, bool) {
	var r ownerTextConsoleRequest
	if len(raw) > e2ee.OwnerTextConsoleMaxPlaintext || !utf8.Valid(raw) || transport.DecodeOwnerTextConsolePayload(raw, &r) != nil || r.Version != 1 || !consoleUUID(r.RequestID, 4) {
		return r, false
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	switch r.Type {
	case "submit":
		return r, len(fields) == 5 && consoleUUID(r.AskID, 7) && strings.TrimSpace(r.Text) != "" && utf8.RuneCountInString(r.Text) <= 16000 && r.Cursor == "" && r.Limit == 0
	case "status":
		return r, len(fields) == 4 && consoleUUID(r.AskID, 7) && r.Text == "" && r.Cursor == "" && r.Limit == 0
	case "list":
		_, hasCursor := fields["cursor"]
		return r, (len(fields) == 4 || len(fields) == 5 && hasCursor) && r.AskID == "" && r.Text == "" && r.Limit >= 1 && r.Limit <= 100 && (!hasCursor || consoleUUID(r.Cursor, 7))
	}
	return r, false
}
func consoleProjection(o TextSenderOperation, reply bool) ownerTextConsoleOperation {
	r := ownerTextConsoleOperation{AskID: o.AskID, Phase: o.Phase, Admitted: o.Admitted}
	if reply && o.Reply != nil {
		r.Reply = &ownerTextConsoleReply{ID: o.Reply.ID, Text: o.Reply.Text}
	}
	return r
}
func consoleCode(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, sender.ErrInvalid):
		return "invalid"
	case errors.Is(err, sender.ErrConflict):
		return "conflict"
	case errors.Is(err, sender.ErrNotFound):
		return "not_found"
	default:
		return "unavailable"
	}
}

// Keep storage and authenticated binding requests off the websocket read loop.
// busy remains set until the encrypted response is written.
func (c *ownerTextConsoleConnection) operation(s *ownerTextConsoleSession, plain []byte) {
	defer clear(plain)
	r, valid := consoleRequest(plain)
	result := ownerTextConsoleResult{Version: 1, Type: "result", RequestID: r.RequestID, Code: "invalid"}
	if !valid && !consoleUUID(r.RequestID, 4) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.sessions[s.descriptor.SessionID] == s {
			c.erase(s.descriptor.SessionID, true)
		}
		return
	}
	if valid {
		ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
		defer cancel()
		p, err := c.native.AuthenticatedNativeHostSession()
		if err != nil || !sameOwnerMailboxAuthority(p, s.authority) {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.erase(s.descriptor.SessionID, true)
			return
		}
		handle, done, runtimeDone, err := c.daemon.consoleSender(ctx, s.descriptor, p)
		if err != nil || done != s.bindingDone || runtimeDone != s.runtimeDone || handle.controller != s.sender.controller {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.erase(s.descriptor.SessionID, true)
			return
		}
		switch r.Type {
		case "submit", "status":
			var o TextSenderOperation
			if r.Type == "submit" {
				o, err = s.sender.Submit(ctx, r.AskID, s.descriptor.ResponderPrincipalID, r.Text)
			} else {
				o, err = s.sender.Read(ctx, r.AskID)
			}
			result.Code = consoleCode(err)
			if err == nil {
				result.Data = consoleProjection(o, true)
			}
		case "list":
			var rows []TextSenderOperation
			rows, err = s.sender.List(ctx, r.Cursor, r.Limit)
			result.Code = consoleCode(err)
			if err == nil {
				items := make([]ownerTextConsoleOperation, 0, len(rows))
				for _, o := range rows {
					items = append(items, consoleProjection(o, false))
				}
				data := struct {
					Operations []ownerTextConsoleOperation `json:"operations"`
					Cursor     string                      `json:"cursor,omitempty"`
				}{Operations: items}
				if len(rows) == r.Limit {
					data.Cursor = rows[len(rows)-1].AskID
				}
				result.Data = data
			}
		}
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > e2ee.OwnerTextConsoleMaxPlaintext {
		result.Code = "response_too_large"
		result.Data = nil
		raw, _ = json.Marshal(result)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.sessions[s.descriptor.SessionID] != s {
		return
	}
	select {
	case <-s.bindingDone:
		c.erase(s.descriptor.SessionID, true)
		return
	default:
	}
	p, err := c.native.AuthenticatedNativeHostSession()
	if err != nil || !sameOwnerMailboxAuthority(p, s.authority) {
		c.erase(s.descriptor.SessionID, true)
		return
	}
	seq, ct, err := s.crypto.Seal(raw)
	clear(raw)
	if err != nil {
		c.erase(s.descriptor.SessionID, true)
		return
	}
	s.busy = false
	if c.send(transport.MsgOwnerTextConsoleFrame, transport.OwnerTextConsoleFramePayload{Protocol: transport.OwnerTextConsoleProtocolV1, SessionID: s.descriptor.SessionID, Sequence: seq, Ciphertext: ct}) != nil {
		c.erase(s.descriptor.SessionID, false)
	}
}
