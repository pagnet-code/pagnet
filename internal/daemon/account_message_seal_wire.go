package daemon

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/accountmessage"
	"github.com/pagnet-code/pagnet/transport"
)

const accountSealProtocol = "browser-account-message-seal-v1"
const accountSealRequestType = "account.message.seal"
const accountSealReplyType = "account.message.sealed"
const accountSealErrorType = "account.message.seal.error"
const accountSealHelloType = "account.message.seal.hello"
const accountSealMaxReply = 64 << 10
const accountSealRetryDelay = 10 * time.Second

func (d *Daemon) openAccountSealJournal() (*accountmessage.Journal, error) {
	d.accountSealMu.Lock()
	defer d.accountSealMu.Unlock()
	if !d.AccountMessageSealEnabled || d.accountSealClosed {
		return nil, errors.New("account sealing unavailable")
	}
	if d.accountSealJournal == nil {
		j, e := accountmessage.OpenJournal(filepath.Join(d.StateDir, "account-message-staging"))
		if e != nil {
			return nil, e
		}
		d.accountSealJournal = j
	}
	return d.accountSealJournal, nil
}
func (c *accountMessagingReadinessConnection) admitAccountSeal(s transport.HostSessionPayload) {
	if !c.d.AccountMessageSealEnabled || !c.usesSubscription() || !slices.Contains(s.ProtocolFeatures, accountSealProtocol) {
		return
	}
	j, err := c.d.openAccountSealJournal()
	if err != nil {
		return
	}
	// Complete one bounded pass before advertising capacity. Collection remains
	// serialized with seals and repeats periodically and before each request.
	for i := 0; i <= accountmessage.MaxRecords/accountmessage.CollectionBatch; i++ {
		if _, err = j.Collect(c.ctx, time.Now()); err != nil {
			return
		}
	}
	if _, ok := c.session(); !ok {
		return
	}
	c.sealJournal = j
	c.sealReady = true
	c.send(accountSealHelloType, struct {
		V        int    `json:"v"`
		Protocol string `json:"protocol"`
	}{1, accountSealProtocol})
}

// Reserve the type before generic decoding/logging/persistence. Inspect every
// JSON string, so duplicate type fields and malformed tails cannot smuggle a
// plaintext seal frame into another command's persistence path.
func reservedAccountSeal(raw []byte) bool {
	return reservedAccountMessageType(raw, accountSealRequestType)
}

func reservedAccountMessageType(raw []byte, kind string) bool {
	valid := json.Valid(raw)
	depth := 0
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '{', '[':
			depth++
			continue
		case '}', ']':
			depth--
			continue
		}
		if raw[i] != '"' {
			continue
		}
		start := i
		i++
		for i < len(raw) {
			if raw[i] == '\\' {
				i += 2
				continue
			}
			if raw[i] == '"' {
				var value string
				if ((!valid && i-start <= 128) || (valid && depth == 1 && i-start <= 26)) && json.Unmarshal(raw[start:i+1], &value) == nil {
					if !valid && value == kind {
						return true
					}
					if valid && depth == 1 && strings.EqualFold(value, "type") {
						next := i + 1
						for next < len(raw) && (raw[next] == ' ' || raw[next] == '\t' || raw[next] == '\r' || raw[next] == '\n') {
							next++
						}
						if next >= len(raw) || raw[next] != ':' {
							break
						}
						next++
						for next < len(raw) && (raw[next] == ' ' || raw[next] == '\t' || raw[next] == '\r' || raw[next] == '\n') {
							next++
						}
						if next >= len(raw) || raw[next] != '"' {
							break
						}
						end := next + 1
						for end < len(raw) {
							if raw[end] == '\\' {
								end += 2
								continue
							}
							if raw[end] == '"' {
								var typ string
								if end-next <= 128 && json.Unmarshal(raw[next:end+1], &typ) == nil && typ == kind {
									return true
								}
								break
							}
							end++
						}
					}
				}
				break
			}
			i++
		}
	}
	return false
}

const accountSealQueueCount = 8
const accountSealQueueBytes = 64 << 10

func (c *accountMessagingReadinessConnection) reserveAccountSeal(size int) bool {
	c.sealQueueMu.Lock()
	defer c.sealQueueMu.Unlock()
	if size > accountSealQueueBytes || c.sealQueueCount >= accountSealQueueCount || c.sealQueueBytes+size > accountSealQueueBytes {
		return false
	}
	c.sealQueueCount++
	c.sealQueueBytes += size
	return true
}
func (c *accountMessagingReadinessConnection) releaseAccountSeal(size int) {
	c.sealQueueMu.Lock()
	c.sealQueueCount--
	c.sealQueueBytes -= size
	c.sealQueueMu.Unlock()
}

func (c *accountMessagingReadinessConnection) interceptAccountSeal(raw []byte) bool {
	if !reservedAccountSeal(raw) {
		return false
	}
	// No queue item retains more than the full wire bound. Oversize or invalid
	// frames carry only a sanitized error and a validated correlation ID.
	if len(raw) > accountmessage.MaxFrameBytes {
		c.enqueue(func() { c.accountSealError("", "invalid_request") })
		return true
	}
	if !c.reserveAccountSeal(len(raw)) {
		correlation := accountSealCorrelation(raw)
		if correlation == "" {
			return true
		}
		c.enqueue(func() { c.accountSealError(correlation, "unavailable") })
		return true
	}
	var env transport.Envelope
	valid := len(raw) <= accountmessage.MaxFrameBytes && accountmessage.DecodeFrame(raw, &env) == nil && env.ProtocolVersion == transport.ProtocolVersion && env.Type == accountSealRequestType && !env.Timestamp.IsZero() && validAccountSealID(env.ID)
	correlation := ""
	if validAccountSealID(env.ID) {
		correlation = env.ID
	}
	if env.CorrelationID != nil && !validAccountSealID(*env.CorrelationID) {
		valid = false
	}
	if env.CausationID != nil && !validAccountSealID(*env.CausationID) {
		valid = false
	}
	if valid {
		if _, err := accountmessage.ParseSeal(env.Payload); err != nil {
			valid = false
		}
	}
	if !valid {
		c.releaseAccountSeal(len(raw))
		c.enqueue(func() { c.accountSealError(correlation, "invalid_request") })
		return true
	}
	env.Payload = append(json.RawMessage(nil), env.Payload...)
	size := len(raw)
	if !c.enqueue(func() { defer c.releaseAccountSeal(size); c.processAccountSeal(env) }) {
		c.releaseAccountSeal(size)
	}
	return true
}
func validAccountSealID(id string) bool {
	parsed, e := domain.ParseID(id)
	return e == nil && parsed.String() == id
}
func (c *accountMessagingReadinessConnection) accountSealError(correlation, code string) {
	p := struct {
		V       int    `json:"v"`
		Code    string `json:"code"`
		RetryAt string `json:"retryAt,omitempty"`
	}{V: 1, Code: code}
	if code == "staging_full" {
		p.RetryAt = time.Now().UTC().Add(accountSealRetryDelay).Format(time.RFC3339Nano)
	}
	c.accountSealResponse(accountSealErrorType, correlation, p, nil)
}
func (c *accountMessagingReadinessConnection) accountSealResponse(kind, correlation string, p any, guard func() bool) bool {
	if _, ok := c.session(); !ok {
		return false
	}
	env, err := transport.NewEnvelope(kind, p)
	if err != nil {
		return false
	}
	if correlation != "" {
		env.CorrelationID = &correlation
	}
	raw, err := json.Marshal(env)
	if err != nil || len(raw) > accountSealMaxReply {
		return false
	}
	published := false
	_ = c.write(raw, func() bool {
		if _, ok := c.session(); !ok {
			return false
		}
		published = guard == nil || guard()
		return published
	})
	return published
}
func (c *accountMessagingReadinessConnection) processAccountSeal(env transport.Envelope) {
	if !c.sealReady || c.sealJournal == nil || !c.d.AccountMessageSealEnabled || !c.usesSubscription() {
		c.accountSealError(env.ID, "unavailable")
		return
	}
	if _, err := c.sealJournal.Collect(c.ctx, time.Now()); err != nil {
		c.accountSealError(env.ID, "unavailable")
		return
	}
	r, err := accountmessage.ParseSeal(env.Payload)
	if err != nil {
		c.accountSealError(env.ID, "invalid_request")
		return
	}
	// Capture the revision before any SQLite/keyring I/O, retaining this same
	// guard through the socket writer's final publication boundary.
	guard, err := c.accountSealGuard(r.Descriptor)
	if err != nil {
		c.accountSealError(env.ID, "unavailable")
		return
	}
	s, err := c.sealAccountMessage(c.ctx, c.sealJournal, env.Payload)
	if err != nil {
		code := "unavailable"
		if errors.Is(err, accountmessage.ErrFull) {
			code = "staging_full"
		}
		c.accountSealError(env.ID, code)
		return
	}
	if !c.accountSealResponse(accountSealReplyType, env.ID, s.Reply(), guard) {
		c.accountSealError(env.ID, "unavailable")
	}
}

// Probe only the top-level ID of a valid JSON object. The payload is scanned
// without decoding/copying strings; aliases, escapes and duplicate IDs fail.
func accountSealCorrelation(raw []byte) string {
	if !json.Valid(raw) {
		return ""
	}
	depth := 0
	id := ""
	seen := false
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '{', '[':
			depth++
			continue
		case '}', ']':
			depth--
			continue
		}
		if raw[i] != '"' {
			continue
		}
		start := i
		i++
		for i < len(raw) {
			if raw[i] == '\\' {
				i += 2
				continue
			}
			if raw[i] == '"' {
				break
			}
			i++
		}
		if depth != 1 || i-start > 26 {
			continue
		}
		var name string
		if json.Unmarshal(raw[start:i+1], &name) != nil || !strings.EqualFold(name, "id") {
			continue
		}
		if seen || string(raw[start:i+1]) != `"id"` {
			return ""
		}
		seen = true
		next := i + 1
		for next < len(raw) && (raw[next] == ' ' || raw[next] == '\t' || raw[next] == '\r' || raw[next] == '\n') {
			next++
		}
		if next >= len(raw) || raw[next] != ':' {
			return ""
		}
		next++
		for next < len(raw) && (raw[next] == ' ' || raw[next] == '\t' || raw[next] == '\r' || raw[next] == '\n') {
			next++
		}
		if next+37 >= len(raw) || raw[next] != '"' || raw[next+37] != '"' {
			return ""
		}
		candidate := string(raw[next+1 : next+37])
		if !validAccountSealID(candidate) {
			return ""
		}
		id = candidate
	}
	return id
}
