package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
)

// BrowserAskResult contains only this connector's direct ASK and replies.
// Content is decrypted on the device, never on the hosted MCP gateway.
type BrowserAskResult struct {
	RequestID         string           `json:"requestId,omitempty"`
	MessageID         string           `json:"messageId"`
	ThreadID          string           `json:"threadId"`
	TargetPrincipalID string           `json:"targetPrincipalId"`
	Messages          []domain.Message `json:"messages"`
}

var browserAskCacheMu sync.Mutex

type preparedBrowserAsk struct {
	Digest  string             `json:"digest"`
	Request restMessageRequest `json:"request"`
}

// SendBrowserAsk persists the encrypted request before sending it, making an
// identical UUID+input retry safe after an ambiguous timeout or device restart.
// A different input with that UUID is refused; no plaintext is saved locally.
func (c *Client) SendBrowserAsk(ctx context.Context, network, target, message, text string) (*BrowserAskResult, error) {
	for _, id := range []string{network, target, message, c.PrincipalID()} {
		if _, err := uuid.Parse(id); err != nil {
			return nil, errors.New("browser ASK identifiers must be UUIDs")
		}
	}
	if len(text) == 0 || len(text) > 64<<10 {
		return nil, errors.New("browser ASK text must be 1..65536 bytes")
	}
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	canonical, _ := json.Marshal([]string{network, target, message, text})
	hash := sha256.Sum256(canonical)
	digest := hex.EncodeToString(hash[:])
	dir := filepath.Join(c.kr.root, c.PrincipalID(), "browser-asks", network)
	path := filepath.Join(dir, message+".json")
	browserAskCacheMu.Lock()
	prepared, err := c.prepareBrowserAsk(ctx, path, digest, network, target, message, text)
	browserAskCacheMu.Unlock()
	if err != nil {
		return nil, err
	}
	id, err := c.rest.sendMessage(ctx, network, prepared.Request)
	if err != nil {
		return &BrowserAskResult{MessageID: message, ThreadID: message, TargetPrincipalID: target, Messages: []domain.Message{}}, err
	}
	if id != message {
		return nil, errors.New("browser ASK returned a different message identity")
	}
	return &BrowserAskResult{MessageID: message, ThreadID: message, TargetPrincipalID: target, Messages: []domain.Message{}}, nil
}
func (c *Client) prepareBrowserAsk(ctx context.Context, path, digest, network, target, message, text string) (*preparedBrowserAsk, error) {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Size() > 256<<10 {
			return nil, errors.New("invalid saved browser ASK")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var p preparedBrowserAsk
		if json.Unmarshal(raw, &p) != nil || p.Digest != digest || p.Request.ID != message || p.Request.ThreadID != message || p.Request.RecipientPrincipalID != target || p.Request.AAD.NetworkID != network {
			return nil, errors.New("browser ASK UUID already bound to different input")
		}
		return &p, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if len(entries) >= 10000 {
		return nil, errors.New("browser ASK local history limit reached")
	}
	plain, err := domain.EncodeMessageContent([]domain.MessagePart{domain.TextPart(text)})
	if err != nil {
		return nil, err
	}
	envelope, aad, err := c.encryptObject(network, e2ee.ObjectTypeMessage, message, c.PrincipalID(), target, plain)
	if err != nil {
		return nil, err
	}
	p := preparedBrowserAsk{Digest: digest, Request: restMessageRequest{ID: message, ThreadID: message, RecipientPrincipalID: target, Kind: string(domain.MessageKindAsk), Envelope: envelope, AAD: aad}}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	// Publish a fully written file without overwriting a concurrent preparer.
	temp, err := os.CreateTemp(filepath.Dir(path), ".ask-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(temp.Name())
	if err = temp.Chmod(0600); err == nil {
		_, err = temp.Write(raw)
	}
	if err == nil {
		err = temp.Sync()
	}
	closeErr := temp.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if err = os.Link(temp.Name(), path); err != nil {
		if os.IsExist(err) {
			return c.prepareBrowserAsk(ctx, path, digest, network, target, message, text)
		}
		return nil, fmt.Errorf("persist browser ASK: %w", err)
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return &p, nil
}

func (c *Client) GetBrowserAsk(ctx context.Context, network, message string) (*BrowserAskResult, error) {
	if _, err := uuid.Parse(network); err != nil {
		return nil, errors.New("network must be UUID")
	}
	if _, err := uuid.Parse(message); err != nil {
		return nil, errors.New("message must be UUID")
	}
	var out BrowserAskResult
	if err := c.rest.do(ctx, "GET", "/networks/"+network+"/browser-asks/"+message, nil, &out); err != nil {
		return nil, err
	}
	if out.MessageID != message || out.ThreadID != message || len(out.Messages) < 1 || len(out.Messages) > 101 {
		return nil, errors.New("invalid browser ASK result identity")
	}
	for i := range out.Messages {
		m := &out.Messages[i]
		if m.NetworkID.String() != network || m.ThreadID.String() != message || m.SenderPrincipalID == nil || m.RecipientPrincipalID == nil || m.RecipientGroupID != nil {
			return nil, errors.New("browser ASK result outside its private thread")
		}
		if i == 0 {
			if m.ID.String() != message || m.Kind != domain.MessageKindAsk || m.SenderPrincipalID.String() != c.PrincipalID() || m.RecipientPrincipalID.String() != out.TargetPrincipalID {
				return nil, errors.New("invalid browser ASK sender")
			}
		} else if m.Kind != domain.MessageKindReply || m.SenderPrincipalID.String() != out.TargetPrincipalID || m.RecipientPrincipalID.String() != c.PrincipalID() || m.CorrelationID == nil || m.CorrelationID.String() != message {
			return nil, errors.New("invalid browser ASK reply participants")
		}
		envRaw, ok := m.Metadata["e2ee_envelope"]
		aadRaw, aok := m.Metadata["e2ee_aad"]
		if !ok || !aok {
			return nil, errors.New("browser ASK result lacks encryption")
		}
		raw, _ := json.Marshal(envRaw)
		var envelope e2ee.EncryptedPayloadV1
		if json.Unmarshal(raw, &envelope) != nil {
			return nil, errors.New("invalid message encryption")
		}
		raw, _ = json.Marshal(aadRaw)
		var aad e2ee.AAD
		if json.Unmarshal(raw, &aad) != nil || aad.ObjectID != m.ID.String() || aad.NetworkID != network || aad.ObjectType != e2ee.ObjectTypeMessage || aad.Sender != m.SenderPrincipalID.String() || aad.Recipient != m.RecipientPrincipalID.String() {
			return nil, errors.New("invalid message authenticated routing")
		}
		plain, err := c.decryptObject(network, envelope, aad)
		if err != nil {
			return nil, errors.New("cannot decrypt browser ASK result")
		}
		m.Parts, err = domain.DecodeMessageContent(plain)
		if err != nil {
			return nil, errors.New("invalid browser ASK content")
		}
		delete(m.Metadata, "e2ee_envelope")
		delete(m.Metadata, "e2ee_aad")
	}
	return &out, nil
}
