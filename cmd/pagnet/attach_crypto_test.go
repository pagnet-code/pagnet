package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

func terminalCLIExample(t *testing.T) (*cliTerminalChannel, ptyFrame, [32]byte, [32]byte) {
	t.Helper()
	var real, output, input [32]byte
	for i := range real {
		real[i] = 1
		output[i] = 2
		input[i] = 3
	}
	instance, session, epoch, keyID, network, tenant := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	c := &cliTerminalChannel{scope: cliTerminalScope{Required: true, TenantID: tenant, NetworkID: network}, instance: instance, session: session, load: func() (string, [32]byte, error) { return epoch, real, nil }}
	id, _ := e2ee.TerminalKeyObjectID(instance, session, "original-generation", keyID)
	aad := e2ee.AAD{ProtocolVersion: 2, TenantID: tenant, NetworkID: network, ObjectType: e2ee.ObjectTypeRuntimeTerminalSession, ObjectID: id, Sender: instance, KeyEpochID: epoch, CreatedAt: "2026-10-02T00:00:00Z"}
	secret := cliTerminalSecret{Format: e2ee.TerminalSessionFormat, InstanceID: instance, SessionID: session, NativeGeneration: "original-generation", SessionKeyID: keyID, SourceOriginID: uuid.NewString(), NativeSessionID: uuid.NewString(), NativeStartIdentity: "original-birth", RealEpochID: epoch, OutputKey: base64.StdEncoding.EncodeToString(output[:]), InputKey: base64.StdEncoding.EncodeToString(input[:])}
	plain, _ := json.Marshal(secret)
	env, err := e2ee.Encrypt(plain, real, aad)
	clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	frame := ptyFrame{Type: "terminal_key", TerminalSessionKeyPayload: transport.TerminalSessionKeyPayload{InstanceID: instance, SessionID: session, NativeGeneration: secret.NativeGeneration, SessionKeyID: keyID, SourceOriginID: secret.SourceOriginID, NativeSessionID: secret.NativeSessionID, NativeStartIdentity: secret.NativeStartIdentity, Envelope: &env, AAD: &aad}}
	return c, frame, output, input
}
func TestCLIPrivateTerminalActualWebsocketBootstrapBytesAndInput(t *testing.T) {
	c, key, outputKey, inputKey := terminalCLIExample(t)
	defer c.close()
	expected := []byte{0, 0xff, 0x1b, '[', '3', '1', 'm', 0xe2, 0x98, 0x83}
	inputDone := make(chan error, 1)
	ws := attachTestSocket(t, func(peer *websocket.Conn) {
		if err := peer.WriteJSON(key); err != nil {
			inputDone <- err
			return
		}
		id, _ := e2ee.TerminalFrameObjectID(c.instance, c.session, key.NativeGeneration, key.SessionKeyID, "output", true, uint64(len(expected)))
		aad := *key.AAD
		aad.ObjectID = id
		aad.ObjectType = e2ee.ObjectTypeRuntimeTerminal
		aad.KeyEpochID = key.SessionKeyID
		env, err := e2ee.Encrypt(expected, outputKey, aad)
		if err != nil {
			inputDone <- err
			return
		}
		f := key
		f.Type = "terminal"
		f.Snapshot = true
		f.LastSeq = uint64(len(expected))
		f.Envelope = &env
		f.AAD = &aad
		if err := peer.WriteJSON(f); err != nil {
			inputDone <- err
			return
		}
		var input struct {
			Type string `json:"type"`
			transport.TerminalInputPayload
		}
		if err := peer.ReadJSON(&input); err != nil {
			inputDone <- err
			return
		}
		if input.Type != "input" || input.Data != "" || input.Seq != 1 || input.Envelope == nil {
			inputDone <- assertionFailure("plaintext or non-sequenced CLI input")
			return
		}
		wantID, _ := e2ee.TerminalFrameObjectID(c.instance, c.session, key.NativeGeneration, key.SessionKeyID, "input", false, 1)
		wantAAD := *key.AAD
		wantAAD.ObjectID = wantID
		wantAAD.ObjectType = e2ee.ObjectTypeRuntimeTerminalInput
		wantAAD.KeyEpochID = key.SessionKeyID
		if !bytes.Equal(wantAAD.CanonicalBytes(), input.AAD.CanonicalBytes()) {
			inputDone <- assertionFailure("wrong input authority")
			return
		}
		plain, err := e2ee.Decrypt(*input.Envelope, inputKey, wantAAD)
		defer clear(plain)
		if err == nil && !bytes.Equal(plain, []byte("private key\n")) {
			err = assertionFailure("input bytes changed")
		}
		inputDone <- err
	})
	var out bytes.Buffer
	done, ready, reason := outputPumpToReady(ws, &out, c)
	if err := waitAttachReady(ws, done, ready, reason); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), expected) {
		t.Fatal("original PTY bytes changed")
	}
	newAttachWriter(ws, c)(map[string]any{"type": "input", "data": base64.StdEncoding.EncodeToString([]byte("private key\n"))})
	select {
	case err := <-inputDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("CLI input waited for ACK")
	}
}

type assertionFailure string

func (e assertionFailure) Error() string { return string(e) }
func TestCLIPrivateTerminalRejectsPlaintextAndChangedOriginal(t *testing.T) {
	c, key, _, _ := terminalCLIExample(t)
	defer c.close()
	if err := c.open(key); err != nil {
		t.Fatal(err)
	}
	if err := c.open(key); err != nil {
		t.Fatal("identical bootstrap reset rejected", err)
	}
	bad := key
	bad.NativeGeneration = "other"
	if c.open(bad) == nil {
		t.Fatal("source replacement accepted")
	}
	if _, err := c.output(ptyFrame{Type: "terminal", Data: base64.StdEncoding.EncodeToString([]byte("plaintext")), Snapshot: true, LastSeq: 9}); err == nil {
		t.Fatal("plaintext private output accepted")
	}
	c.close()
	if c.inputKey != ([32]byte{}) || c.outputKey != ([32]byte{}) {
		t.Fatal("keys retained after detach")
	}
	if _, err := c.input([]byte("x")); err == nil {
		t.Fatal("detached input accepted")
	}
}
