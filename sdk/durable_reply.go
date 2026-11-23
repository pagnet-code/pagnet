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

var durableReplyCacheMu sync.Mutex

type preparedDurableReply struct {
	Digest  string             `json:"digest"`
	Request restMessageRequest `json:"request"`
}

// SendDurableReply sends one encrypted direct REPLY to an ASK's sender in its
// original thread. It persists the encrypted request before submission, so an
// identical retry after a timeout or restart reuses the same message ID and
// ciphertext. Different input for the same ASK is refused; no plaintext is saved.
// Once prepared, the reply ID is returned even when submission fails.
func (c *Client) SendDurableReply(ctx context.Context, original *Message, text string) (string, error) {
	if original == nil || original.Kind != string(domain.MessageKindAsk) {
		return "", errors.New("sdk: durable reply requires an original ASK")
	}
	ids := []string{original.ID, original.NetworkID, original.ThreadID, original.SenderPrincipalID, c.PrincipalID()}
	if original.RecipientPrincipalID != "" {
		ids = append(ids, original.RecipientPrincipalID)
	}
	for _, id := range ids {
		if parsed, err := uuid.Parse(id); err != nil || parsed == uuid.Nil {
			return "", errors.New("sdk: durable reply identifiers must be nonzero UUIDs")
		}
	}
	if len(text) > 64<<10 {
		return "", errors.New("sdk: durable reply text must be at most 65536 bytes")
	}
	if err := c.checkOpen(); err != nil {
		return "", err
	}
	canonical, _ := json.Marshal([]string{c.PrincipalID(), original.ID, original.NetworkID, original.ThreadID, original.Kind, original.SenderPrincipalID, original.RecipientPrincipalID, text})
	hash := sha256.Sum256(canonical)
	digest := hex.EncodeToString(hash[:])
	path := filepath.Join(c.kr.root, c.PrincipalID(), "durable-replies", original.NetworkID, original.ID+".json")
	durableReplyCacheMu.Lock()
	prepared, err := c.prepareDurableReply(path, digest, original, text)
	durableReplyCacheMu.Unlock()
	if err != nil {
		return "", err
	}
	id := prepared.Request.ID
	returned, err := c.rest.sendMessage(ctx, original.NetworkID, prepared.Request)
	if err != nil {
		return id, err
	}
	if returned != id {
		return id, errors.New("sdk: durable reply returned a different message identity")
	}
	return id, nil
}

func (c *Client) prepareDurableReply(path, digest string, original *Message, text string) (*preparedDurableReply, error) {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Size() > 256<<10 {
			return nil, errors.New("sdk: invalid saved durable reply")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var p preparedDurableReply
		if json.Unmarshal(raw, &p) != nil || p.Digest != digest {
			return nil, errors.New("sdk: ASK already bound to different reply input")
		}
		r := p.Request
		id, err := uuid.Parse(r.ID)
		if err != nil || id == uuid.Nil || r.Kind != string(domain.MessageKindReply) || r.ThreadID != original.ThreadID || r.CorrelationID != original.ID || r.RecipientPrincipalID != original.SenderPrincipalID || r.RecipientGroup != "" || r.AAD.ObjectID != r.ID || r.AAD.ObjectType != e2ee.ObjectTypeMessage || r.AAD.NetworkID != original.NetworkID || r.AAD.Sender != c.PrincipalID() || r.AAD.Recipient != original.SenderPrincipalID {
			return nil, errors.New("sdk: invalid saved durable reply routing")
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
		return nil, errors.New("sdk: durable reply local history limit reached")
	}
	plain, err := domain.EncodeMessageContent([]domain.MessagePart{domain.TextPart(text)})
	if err != nil {
		return nil, err
	}
	id := newObjectID()
	envelope, aad, err := c.encryptObject(original.NetworkID, e2ee.ObjectTypeMessage, id, c.PrincipalID(), original.SenderPrincipalID, plain)
	if err != nil {
		return nil, err
	}
	p := preparedDurableReply{Digest: digest, Request: restMessageRequest{
		ID: id, Kind: string(domain.MessageKindReply), CorrelationID: original.ID,
		ThreadID: original.ThreadID, RecipientPrincipalID: original.SenderPrincipalID,
		Envelope: envelope, AAD: aad,
	}}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	// Publish a fully written request without replacing a concurrent preparer.
	temp, err := os.CreateTemp(filepath.Dir(path), ".reply-*")
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
			return c.prepareDurableReply(path, digest, original, text)
		}
		return nil, fmt.Errorf("persist durable reply: %w", err)
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return &p, nil
}
