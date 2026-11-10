package daemon

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/pagnet-code/pagnet/e2ee"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/accountmessage"
	"github.com/pagnet-code/pagnet/transport"
)

func accountSealWireFixture(t *testing.T) (readinessFixture, *accountmessage.Journal, accountmessage.SealRequest, string) {
	t.Helper()
	f, _, r := accountSealFixture(t)
	dir := filepath.Join(t.TempDir(), "staging")
	j, e := accountmessage.OpenJournal(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { j.Close() })
	f.c.d.AccountMessageSealEnabled = true
	done := make(chan struct{})
	f.c.enqueue(func() { f.c.sealReady = true; f.c.sealJournal = j; close(done) })
	readinessSubscriptionWait(t, done, "wire setup")
	return f, j, r, dir
}
func accountSealFrame(t *testing.T, r accountmessage.SealRequest) (transport.Envelope, []byte) {
	t.Helper()
	env, e := transport.NewEnvelope(accountSealRequestType, r)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(env)
	if e != nil {
		t.Fatal(e)
	}
	return env, raw
}
func assertAccountSealError(t *testing.T, f readinessFixture, code string, correlation string) {
	t.Helper()
	env := f.expect(t, accountSealErrorType)
	var p struct {
		V       int    `json:"v"`
		Code    string `json:"code"`
		RetryAt string `json:"retryAt,omitempty"`
	}
	if accountmessage.DecodeFrame(env.Payload, &p) != nil || p.V != 1 || p.Code != code {
		t.Fatal("invalid error payload")
	}
	if correlation != "" && (env.CorrelationID == nil || *env.CorrelationID != correlation) {
		t.Fatal("missing correlation")
	}
}
func TestAccountSealWireReplayAndNoPlaintext(t *testing.T) {
	f, j, r, dir := accountSealWireFixture(t)
	var logs bytes.Buffer
	f.c.d.Log = slog.New(slog.NewTextHandler(&logs, nil))
	env, raw := accountSealFrame(t, r)
	if !f.c.interceptAccountSeal(raw) {
		t.Fatal("not intercepted")
	}
	reply := f.expect(t, accountSealReplyType)
	if reply.CorrelationID == nil || *reply.CorrelationID != env.ID {
		t.Fatal("wrong response correlation")
	}
	var payload struct {
		V             int             `json:"v"`
		MessageID     string          `json:"messageId"`
		BindingDigest string          `json:"bindingDigest"`
		SealedDigest  string          `json:"sealedDigest"`
		Envelope      json.RawMessage `json:"envelope"`
	}
	if accountmessage.DecodeFrame(reply.Payload, &payload) != nil || payload.MessageID != r.Descriptor.MessageID {
		t.Fatal("invalid sealed reply")
	}
	readinessSubscriptionIdle(t, f)
	if e := j.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := accountmessage.OpenJournal(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	done := make(chan struct{})
	f.c.enqueue(func() { f.c.sealJournal = reopened; close(done) })
	readinessSubscriptionWait(t, done, "reopen")
	next, raw := accountSealFrame(t, r)
	f.c.interceptAccountSeal(raw)
	again := f.expect(t, accountSealReplyType)
	if again.CorrelationID == nil || *again.CorrelationID != next.ID || !bytes.Equal(reply.Payload, again.Payload) {
		t.Fatal("restart changed sealed ciphertext")
	}
	for _, name := range []string{"account-messages.sqlite", "account-messages.sqlite-wal"} {
		stored, e := os.ReadFile(filepath.Join(dir, name))
		if e == nil && bytes.Contains(stored, []byte(r.Text)) {
			t.Fatal("plaintext persisted")
		}
	}
	if strings.Contains(logs.String(), r.Text) {
		t.Fatal("plaintext logged")
	}
}
func TestAccountSealWireDisabledAndMalformed(t *testing.T) {
	for _, kind := range []string{"disabled", "legacy", "unknown", "duplicate", "duplicateType", "caseAlias", "invalidUTF8", "invalidUnicode", "oversized", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			f, _, r, _ := accountSealWireFixture(t)
			env, raw := accountSealFrame(t, r)
			code := "invalid_request"
			correlation := ""
			if kind == "disabled" || kind == "legacy" {
				correlation = env.ID
			}
			switch kind {
			case "disabled":
				f.c.d.AccountMessageSealEnabled = false
				code = "unavailable"
			case "legacy":
				raw = bytes.Replace(raw, []byte(`"protocolVersion":2`), []byte(`"protocolVersion":1`), 1)
			case "unknown":
				raw = append([]byte(`{"private-unknown-field":true,`), raw[1:]...)
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"text":`), []byte(`"text":"changed","text":`), 1)
			case "duplicateType":
				raw = append([]byte(`{"type":"host.launch_agent",`), raw[1:]...)
			case "caseAlias":
				raw = bytes.Replace(raw, []byte(`"text":`), []byte(`"Text":`), 1)
			case "invalidUTF8":
				raw = bytes.Replace(raw, []byte(r.Text), []byte{0xff}, 1)
			case "invalidUnicode":
				raw = bytes.Replace(raw, []byte(r.Text), []byte(`\ud800`), 1)
			case "oversized":
				raw = append(raw, bytes.Repeat([]byte(" "), accountmessage.MaxFrameBytes)...)
				correlation = ""
			case "malformed":
				raw = raw[:len(raw)-1]
				correlation = ""
			}
			if !f.c.interceptAccountSeal(raw) {
				t.Fatal("reserved frame escaped")
			}
			assertAccountSealError(t, f, code, correlation)
		})
	}
}
func TestAccountSealReservedGenericAndQueueBounds(t *testing.T) {
	generic, _ := transport.NewEnvelope("host.other", map[string]string{"text": accountSealRequestType})
	raw, _ := json.Marshal(generic)
	if reservedAccountSeal(raw) {
		t.Fatal("intercepted unrelated valid generic frame")
	}
	f, _, r, _ := accountSealWireFixture(t)
	block := make(chan struct{})
	started := make(chan struct{})
	f.c.enqueue(func() { close(started); <-block })
	readinessSubscriptionWait(t, started, "queue blocked")
	_, raw = accountSealFrame(t, r)
	for i := 0; i < accountSealQueueCount; i++ {
		if !f.c.interceptAccountSeal(raw) {
			t.Fatal("not reserved")
		}
	}
	f.c.sealQueueMu.Lock()
	count, size := f.c.sealQueueCount, f.c.sealQueueBytes
	f.c.sealQueueMu.Unlock()
	if count != accountSealQueueCount || size > accountSealQueueBytes {
		t.Fatal("queue budget", count, size)
	}
	f.c.interceptAccountSeal(raw)
	f.c.sealQueueMu.Lock()
	if f.c.sealQueueCount != count || f.c.sealQueueBytes != size {
		t.Fatal("overbudget request retained")
	}
	f.c.sealQueueMu.Unlock()
	close(block)
	readinessSubscriptionIdle(t, f)
	for i := 0; i < accountSealQueueCount; i++ {
		f.expect(t, accountSealReplyType)
	}
	assertAccountSealError(t, f, "unavailable", "")
	if f.c.reserveAccountSeal(accountSealQueueBytes + 1) {
		t.Fatal("reserved oversized queue allocation")
	}
}
func TestAccountSealHelloRequiresOpenAndNegotiatedSocket(t *testing.T) {
	for _, kind := range []string{"enabled", "disabled", "legacy", "openFailure"} {
		t.Run(kind, func(t *testing.T) {
			f := newReadinessSubscriptionFixture(t)
			f.session.ProtocolFeatures = append(f.session.ProtocolFeatures, accountSealProtocol)
			f.c.native.mu.Lock()
			f.c.native.session.ProtocolFeatures = f.session.ProtocolFeatures
			f.c.native.mu.Unlock()
			f.c.d.AccountMessageSealEnabled = kind != "disabled"
			if kind == "legacy" {
				f.c.native.mu.Lock()
				f.c.native.session.ProtocolFeatures = []string{accountSealProtocol}
				f.c.native.mu.Unlock()
			}
			if kind == "openFailure" {
				if e := os.WriteFile(filepath.Join(f.c.d.StateDir, "account-message-staging"), []byte("blocked"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			f.c.admitted()
			if kind != "legacy" {
				f.expect(t, transport.MsgAccountMessagingReadinessHello)
			}
			if kind == "enabled" {
				env := f.expect(t, accountSealHelloType)
				if string(env.Payload) != `{"v":1,"protocol":"browser-account-message-seal-v1"}` {
					t.Fatal("wrong hello")
				}
				t.Cleanup(func() { f.c.d.accountSealJournal.Close() })
			} else {
				f.quiet(t)
			}
		})
	}
}
func TestAccountSealWriterInvalidationSuppressesSealed(t *testing.T) {
	f, _, r, _ := accountSealWireFixture(t)
	write := f.c.write
	f.c.write = func(raw []byte, guard func() bool) error {
		var env transport.Envelope
		if json.Unmarshal(raw, &env) == nil && env.Type == accountSealReplyType {
			finish := f.c.d.beginAccountMessagingMutation()
			defer finish()
		}
		return write(raw, guard)
	}
	_, raw := accountSealFrame(t, r)
	f.c.interceptAccountSeal(raw)
	readinessSubscriptionIdle(t, f)
	for {
		select {
		case env := <-f.frames:
			if env.Type == accountSealReplyType {
				t.Fatal("published stale sealed reply")
			}
		default:
			return
		}
	}
}
func TestAccountSealInvalidationWhileSQLiteBusy(t *testing.T) {
	f, _, r, dir := accountSealWireFixture(t)
	db, e := sql.Open("sqlite", filepath.Join(dir, "account-messages.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, e = db.Exec(`BEGIN IMMEDIATE`); e != nil {
		t.Fatal(e)
	}
	defer db.Exec(`ROLLBACK`)
	reached := make(chan struct{})
	lookup := f.c.lookup
	f.c.lookup = func(id string) (*InstanceRow, bool, error) { close(reached); return lookup(id) }
	_, raw := accountSealFrame(t, r)
	f.c.interceptAccountSeal(raw)
	readinessSubscriptionWait(t, reached, "did not reach seal SQLite boundary")
	finish := f.c.d.beginAccountMessagingMutation()
	defer finish()
	db.Exec(`ROLLBACK`)
	readinessSubscriptionIdle(t, f)
	for {
		select {
		case env := <-f.frames:
			if env.Type == accountSealReplyType {
				t.Fatal("published reply after invalidation during SQLite")
			}
		default:
			return
		}
	}
}

func TestAccountSealSaturationIDProbeAndLargeFrame(t *testing.T) {
	f, _, r, _ := accountSealWireFixture(t)
	r.Text = strings.Repeat("\u0001", accountmessage.MaxTextBytes)
	env, raw := accountSealFrame(t, r)
	if len(raw) <= accountSealQueueBytes || len(raw) > accountmessage.MaxFrameBytes {
		t.Fatal("large valid fixture outside wire/queue bounds")
	}
	if accountSealCorrelation(raw) != env.ID {
		t.Fatal("ID probe lost canonical ID")
	}
	if !f.c.interceptAccountSeal(raw) {
		t.Fatal("large reserved frame escaped")
	}
	assertAccountSealError(t, f, "unavailable", env.ID)
	for _, bad := range [][]byte{
		append([]byte(`{"id":"`+env.ID+`",`), raw[1:]...),
		bytes.Replace(raw, []byte(`"id":`), []byte(`"ID":`), 1),
		bytes.Replace(raw, []byte(`"id":`), []byte(`"\u0069d":`), 1),
		bytes.Replace(raw, []byte(env.ID), []byte(`\u0030`+env.ID[1:]), 1),
		bytes.Replace(raw, []byte(`"id":"`+env.ID+`"`), []byte(`"id":null`), 1),
	} {
		if accountSealCorrelation(bad) != "" {
			t.Fatal("saturation probe accepted ambiguous ID")
		}
		if !f.c.interceptAccountSeal(bad) {
			t.Fatal("malformed reserved frame escaped")
		}
		f.quiet(t)
	}
}

func TestAccountSealWireFullHasFixedRetry(t *testing.T) {
	f, _, r, dir := accountSealWireFixture(t)
	kr, e := f.c.loadKeyring(r.Descriptor.NetworkID)
	if e != nil {
		t.Fatal(e)
	}
	epoch, ok := kr.EpochByID(r.Descriptor.EpochID)
	if !ok {
		t.Fatal("epoch missing")
	}
	key, e := epoch.KeyArray()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key[:])
	db, e := sql.Open("sqlite", filepath.Join(dir, "account-messages.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	tx, e := db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < accountmessage.MaxRecords; i++ {
		d := r.Descriptor
		d.MessageID = fmt.Sprintf("capacity-%04d", i)
		binding := d.BindingDigest()
		envelope, e := e2ee.Encrypt([]byte(r.Text), key, d.AAD(binding))
		if e != nil {
			t.Fatal(e)
		}
		s := accountmessage.Sealed{V: 1, MessageID: d.MessageID, BindingDigest: binding, Descriptor: d, Envelope: envelope}
		s.SealedDigest = s.Digest()
		raw, _ := json.Marshal(s)
		if _, e = tx.Exec(`INSERT INTO account_message_seals VALUES(?,?)`, d.MessageID, raw); e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	env, raw := accountSealFrame(t, r)
	before := time.Now().UTC()
	f.c.interceptAccountSeal(raw)
	reply := f.expect(t, accountSealErrorType)
	var p struct {
		V       int    `json:"v"`
		Code    string `json:"code"`
		RetryAt string `json:"retryAt"`
	}
	if accountmessage.DecodeFrame(reply.Payload, &p) != nil || p.Code != "staging_full" || reply.CorrelationID == nil || *reply.CorrelationID != env.ID {
		t.Fatal("invalid full error")
	}
	retry, e := time.Parse(time.RFC3339Nano, p.RetryAt)
	if e != nil || retry.UTC().Format(time.RFC3339Nano) != p.RetryAt || retry.Before(before.Add(accountSealRetryDelay)) || retry.After(time.Now().UTC().Add(accountSealRetryDelay)) {
		t.Fatal("invalid fixed retry time")
	}
}

func TestAccountSealDiscriminatorProbeAllocationBound(t *testing.T) {
	raw := []byte(`{"type":"` + strings.Repeat("private-input", 65536) + `","type":"account.message.seal"}`)
	result := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if !reservedAccountSeal(raw) {
				b.Fatal("missed duplicate reserved type")
			}
		}
	})
	if result.AllocedBytesPerOp() > 16<<10 {
		t.Fatal("discriminator probe copied attacker string before capacity reservation", result.AllocedBytesPerOp())
	}
}
