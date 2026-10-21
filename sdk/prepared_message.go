package sdk

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
)

// PreparedMessage identifies an immutable, locally persisted encrypted request.
// Changing this returned value does not change the saved request.
type PreparedMessage struct {
	ID                   string
	NetworkID            string
	ThreadID             string
	CorrelationID        string
	RecipientPrincipalID string
	Kind                 string
}

const preparedMessageMaxSize = 256 << 10
const preparedMessageHistoryLimit = 10000

var preparedMessageMu sync.Mutex

type savedMessage struct {
	PrincipalID string             `json:"principalId"`
	NetworkID   string             `json:"networkId"`
	Digest      string             `json:"digest"`
	Request     restMessageRequest `json:"request"`
	MAC         string             `json:"mac"`
}

func validMessageUUID(id string) bool {
	u, err := uuid.Parse(id)
	return err == nil && u != uuid.Nil && u.String() == id
}

func (p savedMessage) metadata() PreparedMessage {
	r := p.Request
	return PreparedMessage{ID: r.ID, NetworkID: p.NetworkID, ThreadID: r.ThreadID, CorrelationID: r.CorrelationID, RecipientPrincipalID: r.RecipientPrincipalID, Kind: r.Kind}
}

// Authenticate the complete persisted routing metadata as well as ciphertext.
// The domain separator keeps this use separate from identity cryptography.
func (c *Client) messageMAC(p savedMessage) string {
	p.MAC = ""
	b, _ := json.Marshal(p)
	h := hmac.New(sha256.New, c.identityPriv)
	h.Write([]byte("pagnet-sdk-prepared-message-v1\x00"))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func (c *Client) preparedMessagePath(network, id string) (string, error) {
	if !validMessageUUID(network) || !validMessageUUID(id) || !validMessageUUID(c.PrincipalID()) || len(c.identityPriv) != 32 || c.kr == nil {
		return "", errors.New("sdk: prepared message requires canonical nonzero UUIDs and a persistent identity")
	}
	return filepath.Join(c.kr.root, c.PrincipalID(), "prepared-messages", id+".json"), nil
}

func (c *Client) loadPreparedMessage(path, network, id string) (*savedMessage, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > preparedMessageMaxSize {
		return nil, errors.New("sdk: invalid prepared message file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("sdk: prepared message file changed")
	}
	b, err := io.ReadAll(io.LimitReader(f, preparedMessageMaxSize+1))
	if err != nil {
		return nil, err
	}
	var p savedMessage
	if len(b) > preparedMessageMaxSize || json.Unmarshal(b, &p) != nil || !hmac.Equal([]byte(p.MAC), []byte(c.messageMAC(p))) {
		return nil, errors.New("sdk: prepared message authentication failed")
	}
	r := p.Request
	if p.PrincipalID != c.PrincipalID() || p.NetworkID != network || r.ID != id || r.AAD.NetworkID != network || r.AAD.ObjectID != id || r.AAD.ObjectType != e2ee.ObjectTypeMessage || r.AAD.Sender != p.PrincipalID || r.AAD.Recipient != r.RecipientPrincipalID {
		return nil, errors.New("sdk: prepared message identity mismatch")
	}
	return &p, nil
}

// PrepareMessage encrypts and durably saves a direct ASK or REPLY before any
// request is sent. Set OutgoingMessage.ID to reuse an identity: identical input
// loads the saved request, while conflicting input is refused. ASK defaults its
// thread to its own ID; REPLY requires both thread and correlation UUIDs.
// Only ciphertext, authenticated routing metadata and a keyed digest are saved.
// History is bounded to 10000 messages per principal; a full history returns an
// error without discarding any request that might still need replay.
func (c *Client) PrepareMessage(ctx context.Context, m OutgoingMessage) (PreparedMessage, error) {
	var zero PreparedMessage
	if err := c.checkOpen(); err != nil {
		return zero, err
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if m.ID == "" {
		m.ID = newObjectID()
	}
	path, err := c.preparedMessagePath(m.NetworkID, m.ID)
	if err != nil {
		return zero, err
	}
	if m.Kind == "" {
		m.Kind = string(domain.MessageKindAsk)
	}
	if m.Kind != string(domain.MessageKindAsk) && m.Kind != string(domain.MessageKindReply) || !validMessageUUID(m.RecipientPrincipalID) || m.RecipientGroupID != "" {
		return zero, errors.New("sdk: preparation requires a direct ASK or REPLY")
	}
	if m.ThreadID == "" && m.Kind == string(domain.MessageKindAsk) {
		m.ThreadID = m.ID
	}
	if !validMessageUUID(m.ThreadID) || (m.CorrelationID != "" && !validMessageUUID(m.CorrelationID)) || (m.Kind == string(domain.MessageKindReply) && m.CorrelationID == "") {
		return zero, errors.New("sdk: invalid message thread or correlation UUID")
	}
	plain, err := domain.EncodeMessageContent(m.Parts)
	if err != nil {
		return zero, err
	}
	if len(m.Parts) == 0 || len(plain) > 64<<10 {
		return zero, errors.New("sdk: prepared message content must be nonempty and at most 65536 bytes")
	}
	input, err := json.Marshal(m)
	if err != nil {
		return zero, err
	}
	h := hmac.New(sha256.New, c.identityPriv)
	h.Write([]byte("pagnet-sdk-prepared-input-v1\x00"))
	h.Write(input)
	digest := hex.EncodeToString(h.Sum(nil))
	preparedMessageMu.Lock()
	defer preparedMessageMu.Unlock()
	if p, err := c.loadPreparedMessage(path, m.NetworkID, m.ID); err == nil {
		if p.Digest != digest {
			return zero, errors.New("sdk: message UUID already bound to different input")
		}
		return p.metadata(), nil
	} else if !os.IsNotExist(err) {
		return zero, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return zero, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return zero, errors.New("sdk: invalid prepared message directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return zero, err
	}
	if len(entries) >= preparedMessageHistoryLimit {
		return zero, errors.New("sdk: prepared message local history limit reached")
	}
	env, aad, err := c.encryptObject(m.NetworkID, e2ee.ObjectTypeMessage, m.ID, c.PrincipalID(), m.RecipientPrincipalID, plain)
	if err != nil {
		return zero, err
	}
	p := savedMessage{PrincipalID: c.PrincipalID(), NetworkID: m.NetworkID, Digest: digest, Request: restMessageRequest{ID: m.ID, ThreadID: m.ThreadID, CorrelationID: m.CorrelationID, RecipientPrincipalID: m.RecipientPrincipalID, Kind: m.Kind, Envelope: env, AAD: aad}}
	p.MAC = c.messageMAC(p)
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > preparedMessageMaxSize {
		return zero, errors.New("sdk: prepared message exceeds storage limit")
	}
	f, err := os.CreateTemp(dir, ".message-*")
	if err != nil {
		return zero, err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return zero, err
	}
	if closeErr != nil {
		return zero, closeErr
	}
	if err = os.Link(f.Name(), path); err != nil {
		if !os.IsExist(err) {
			return zero, err
		}
		existing, err := c.loadPreparedMessage(path, m.NetworkID, m.ID)
		if err != nil {
			return zero, err
		}
		if existing.Digest != digest {
			return zero, errors.New("sdk: message UUID already bound to different input")
		}
		return existing.metadata(), nil
	}
	for _, name := range []string{dir, filepath.Dir(dir)} {
		d, err := os.Open(name)
		if err != nil {
			return zero, err
		}
		err = d.Sync()
		closeErr := d.Close()
		if err != nil {
			return zero, err
		}
		if closeErr != nil {
			return zero, closeErr
		}
	}
	return p.metadata(), nil
}

// SendPrepared sends the exact saved ciphertext and AAD without re-encryption.
// On an ambiguous send failure it returns messageID and the error. Retry this
// method with the same network and message ID, including after process restart.
func (c *Client) SendPrepared(ctx context.Context, networkID, messageID string) (string, error) {
	if err := c.checkOpen(); err != nil {
		return "", err
	}
	path, err := c.preparedMessagePath(networkID, messageID)
	if err != nil {
		return "", err
	}
	p, err := c.loadPreparedMessage(path, networkID, messageID)
	if err != nil {
		return "", err
	}
	id, err := c.rest.sendMessage(ctx, networkID, p.Request)
	if err != nil {
		return messageID, err
	}
	if id != messageID {
		return messageID, errors.New("sdk: server returned a different prepared message identity")
	}
	return id, nil
}
