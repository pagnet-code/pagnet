package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

type cliTerminalScope struct {
	Required         bool                   `json:"required"`
	TenantID         string                 `json:"tenantId"`
	NetworkID        string                 `json:"networkId"`
	ProtectedContext *e2ee.ProtectedContext `json:"protectedContext,omitempty"`
}
type cliTerminalSecret struct {
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
type cliTerminalChannel struct {
	mu                  sync.Mutex
	scope               cliTerminalScope
	instance, session   string
	bootstrap           *ptyFrame
	inputKey, outputKey [32]byte
	inputSequence       uint64
	closed              bool
	load                func() (string, [32]byte, error)
}

func (c *cliCtx) newCLITerminalChannel(scope *cliTerminalScope, network, instance, session string) (*cliTerminalChannel, error) {
	if scope == nil || !scope.Required || scope.NetworkID != network || scope.ProtectedContext != nil || scope.TenantID == "" {
		return nil, errors.New("attach requires the server's authenticated private network terminal descriptor")
	}
	channel := &cliTerminalChannel{scope: *scope, instance: instance, session: session}
	channel.load = func() (string, [32]byte, error) {
		var empty [32]byte
		state, ring, err := c.clientCrypto(network)
		if ring != nil {
			defer func() {
				for i := range ring.Epochs {
					clear(ring.Epochs[i].Key)
				}
			}()
		}
		if err != nil {
			return "", empty, err
		}
		if state.TenantID != scope.TenantID {
			return "", empty, errors.New("terminal tenant changed")
		}
		epoch, ok := ring.EpochByID(state.EpochID)
		if !ok || epoch.State == crypto.EpochRevoked {
			return "", empty, errors.New("terminal epoch unavailable")
		}
		key, err := epoch.KeyArray()
		return state.EpochID, key, err
	}
	return channel, nil
}
func (c *cliTerminalChannel) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	clear(c.inputKey[:])
	clear(c.outputKey[:])
	c.bootstrap = nil
}
func (c *cliTerminalChannel) watch(ws *websocket.Conn) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				c.mu.Lock()
				closed := c.closed
				epoch := ""
				if c.bootstrap != nil {
					epoch = c.bootstrap.AAD.KeyEpochID
				}
				c.mu.Unlock()
				if closed {
					return
				}
				if epoch != "" {
					current, key, err := c.load()
					clear(key[:])
					if err != nil || current != epoch {
						c.close()
						ws.Close()
						return
					}
				}
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done); c.close() }) }
}
func (c *cliTerminalChannel) open(f ptyFrame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || f.Data != "" || f.InstanceID != c.instance || f.SessionID != c.session || f.Envelope == nil || f.AAD == nil || f.SourceOriginID == "" || f.NativeSessionID == "" || f.NativeStartIdentity == "" {
		return errors.New("invalid private terminal bootstrap")
	}
	if c.bootstrap != nil {
		a, _ := json.Marshal(c.bootstrap)
		b, _ := json.Marshal(f)
		if !bytes.Equal(a, b) {
			return errors.New("terminal source changed")
		}
		return nil
	}
	objectID, err := e2ee.TerminalKeyObjectID(c.instance, c.session, f.NativeGeneration, f.SessionKeyID)
	if err != nil {
		return err
	}
	epoch, key, err := c.load()
	defer clear(key[:])
	if err != nil {
		return err
	}
	aad := f.AAD
	if aad.ProtocolVersion != transport.ProtocolVersion || aad.TenantID != c.scope.TenantID || aad.NetworkID != c.scope.NetworkID || aad.ProtectedContext != nil || aad.NativeContent != nil || aad.Sender != c.instance || aad.Recipient != "" || aad.ObjectType != e2ee.ObjectTypeRuntimeTerminalSession || aad.ObjectID != objectID || aad.KeyEpochID != epoch || f.SessionKeyID == epoch || len(f.Envelope.Ciphertext) > 5500 {
		return errors.New("terminal bootstrap authority changed")
	}
	plain, err := e2ee.Decrypt(*f.Envelope, key, *aad)
	if err != nil {
		return err
	}
	defer clear(plain)
	if len(plain) > 4096 {
		return errors.New("terminal bootstrap too large")
	}
	var secret cliTerminalSecret
	if json.Unmarshal(plain, &secret) != nil || secret.Format != e2ee.TerminalSessionFormat || secret.InstanceID != c.instance || secret.SessionID != c.session || secret.NativeGeneration != f.NativeGeneration || secret.SessionKeyID != f.SessionKeyID || secret.SourceOriginID != f.SourceOriginID || secret.NativeSessionID != f.NativeSessionID || secret.NativeStartIdentity != f.NativeStartIdentity || secret.RealEpochID != epoch {
		return errors.New("terminal original source changed")
	}
	output, err := base64.StdEncoding.Strict().DecodeString(secret.OutputKey)
	if err != nil {
		return err
	}
	defer clear(output)
	input, err := base64.StdEncoding.Strict().DecodeString(secret.InputKey)
	if err != nil {
		return err
	}
	defer clear(input)
	if len(output) != 32 || len(input) != 32 || bytes.Equal(output, input) {
		return errors.New("invalid terminal directional keys")
	}
	copy(c.outputKey[:], output)
	copy(c.inputKey[:], input)
	c.bootstrap = &f
	return nil
}
func (c *cliTerminalChannel) aad(direction string, snapshot bool, sequence uint64) (e2ee.AAD, error) {
	if c.closed || c.bootstrap == nil {
		return e2ee.AAD{}, errors.New("terminal bootstrap unavailable")
	}
	b := c.bootstrap
	id, err := e2ee.TerminalFrameObjectID(c.instance, c.session, b.NativeGeneration, b.SessionKeyID, direction, snapshot, sequence)
	aad := *b.AAD
	aad.ObjectID = id
	aad.KeyEpochID = b.SessionKeyID
	aad.ObjectType = e2ee.ObjectTypeRuntimeTerminal
	if direction == "input" {
		aad.ObjectType = e2ee.ObjectTypeRuntimeTerminalInput
	}
	return aad, err
}
func (c *cliTerminalChannel) output(f ptyFrame) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	end := f.Seq
	if f.Snapshot {
		end = f.LastSeq
	}
	aad, err := c.aad("output", f.Snapshot, end)
	if err != nil {
		return nil, err
	}
	b := c.bootstrap
	if f.Data != "" || f.InstanceID != c.instance || f.SessionID != c.session || f.NativeGeneration != b.NativeGeneration || f.SessionKeyID != b.SessionKeyID || f.Envelope == nil || f.AAD == nil || !bytes.Equal(aad.CanonicalBytes(), f.AAD.CanonicalBytes()) {
		return nil, errors.New("invalid private terminal frame")
	}
	bound := 16 * 1024
	if f.Snapshot {
		bound = 256 * 1024
	}
	if len(f.Envelope.Ciphertext) > base64.StdEncoding.EncodedLen(bound+16) {
		return nil, errors.New("terminal frame too large")
	}
	plain, err := e2ee.Decrypt(*f.Envelope, c.outputKey, aad)
	if err != nil {
		return nil, err
	}
	if len(plain) > bound || uint64(len(plain)) > end {
		clear(plain)
		return nil, errors.New("invalid terminal byte cursor")
	}
	return plain, nil
}
func (c *cliTerminalChannel) input(data []byte) (transport.TerminalInputPayload, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(data) == 0 || len(data) > 4096 || c.inputSequence >= e2ee.TerminalMaxSafeSequence {
		return transport.TerminalInputPayload{}, errors.New("terminal input bound exceeded")
	}
	seq := c.inputSequence + 1
	aad, err := c.aad("input", false, seq)
	if err != nil {
		return transport.TerminalInputPayload{}, err
	}
	env, err := e2ee.Encrypt(data, c.inputKey, aad)
	if err != nil {
		return transport.TerminalInputPayload{}, err
	}
	c.inputSequence = seq
	b := c.bootstrap
	return transport.TerminalInputPayload{InstanceID: c.instance, SessionID: c.session, NativeGeneration: b.NativeGeneration, SessionKeyID: b.SessionKeyID, Seq: seq, Envelope: &env, AAD: &aad}, nil
}
func (c *cliTerminalChannel) matches(f ptyFrame) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.closed && c.bootstrap != nil && f.NativeGeneration == c.bootstrap.NativeGeneration && f.SessionKeyID == c.bootstrap.SessionKeyID
}
