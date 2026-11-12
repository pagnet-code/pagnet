package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/nativecontent"
	"github.com/pagnet-code/pagnet/transport"
)

func accountDeliveryFrame(t *testing.T, c *NativeObservationConnection, env transport.Envelope) error {
	t.Helper()
	handled, err := c.HandleEnvelope(env)
	if !handled {
		t.Fatal("account reply frame was not routed")
	}
	return err
}

func accountDeliveryFixture(t *testing.T) (sessionworker.NativeObservation, nativecontent.Transfer) {
	t.Helper()
	raw, err := os.ReadFile("../../transport/testdata/account_message_source_reply_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct{ SourceCanonical, ReplyAADCanonical string }
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	var aad e2ee.AAD
	var source transport.NativeAccountMessageSource
	if err = json.Unmarshal([]byte(vector.ReplyAADCanonical), &aad); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal([]byte(vector.SourceCanonical), &source); err != nil {
		t.Fatal(err)
	}
	transfer, err := nativecontent.Build(bytes.Repeat([]byte("encrypted private answer "), 6000), [32]byte{}, aad, *aad.NativeContent, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	n := aad.NativeContent
	origin, _ := transport.MarshalNativeJSON(transport.NativeObservationOrigin{ID: n.OriginID, InstanceID: n.InstanceID, HostID: "test-host", Runtime: "qwen-code", NativeGeneration: n.NativeGeneration})
	observed, _ := time.Parse(time.RFC3339Nano, aad.CreatedAt)
	o := sessionworker.NativeObservation{ID: n.ObservationID, SourceDigest: string(bytes.Repeat([]byte("a"), 64)), Origin: origin, NativeGeneration: n.NativeGeneration, NativeSessionID: n.NativeSessionID, ObservedAt: observed, SourceSequence: 3, OutputContent: &transfer.Reference,
		TurnSource: &sessionworker.NativeTurnSource{Sequence: 7, LogicalTurnID: n.LogicalTurnID, NativeGeneration: n.NativeGeneration, NativeSessionID: n.NativeSessionID, SourceCommandID: n.SourceCommandID, SourceAdmissionID: n.SourceAdmissionID, InputKind: "account_message", SourceAccountMessage: &source},
		Event:      session.SessionEvent{Type: session.EventTurnCompleted, SessionID: n.NativeSessionID, TurnID: n.LogicalTurnID}}
	return o, transfer
}

func TestAccountReplyDeliveryPartialDisconnectReplay(t *testing.T) {
	o, transfer := accountDeliveryFixture(t)
	var originalCommit []byte
	fragments := map[int][]byte{}
	acked := 0
	for attempt := 0; attempt < 3; attempt++ {
		var c *NativeObservationConnection
		c, _ = deliveryFixture(t, func(ctx context.Context, typ string, value any) error {
			switch typ {
			case transport.MsgAccountReplyBegin:
				ref := value.(transport.NativeContentReference)
				expected, _ := transport.MarshalNativeJSON(transfer.Reference)
				actual, _ := transport.MarshalNativeJSON(ref)
				if !bytes.Equal(expected, actual) {
					t.Fatal("begin reference changed on reconnect")
				}
				missing := []int{}
				for i := 0; i < ref.FragmentCount; i++ {
					if fragments[i] == nil {
						missing = append(missing, i)
					}
				}
				env, _ := transport.NewEnvelope(transport.MsgAccountReplyStaged, transport.NativeAccountReplyStagedPayload{ContentID: ref.ContentID, CiphertextDigest: ref.CiphertextDigest, MissingOrdinals: missing})
				return accountDeliveryFrame(t, c, env)
			case transport.MsgAccountReplyFragment:
				f := value.(*transport.NativeContentFragment)
				raw, _ := transport.MarshalNativeJSON(f)
				expected, _ := transport.MarshalNativeJSON(transfer.Fragments[f.Ordinal])
				if !bytes.Equal(raw, expected) {
					t.Fatal("ciphertext fragment changed")
				}
				fragments[f.Ordinal] = raw
				if attempt == 0 {
					c.Close()
				}
			case transport.MsgAccountReplyCommit:
				p := value.(transport.NativeObservationPayload)
				raw, _ := transport.MarshalNativeJSON(p)
				if originalCommit == nil {
					originalCommit = raw
				} else if !bytes.Equal(originalCommit, raw) {
					t.Fatal("commit changed after lost receipt")
				}
				if _, err := transport.DecodeNativeAccountReplyCommit(raw, transfer.Reference); err != nil {
					t.Fatal(err)
				}
				if attempt == 1 {
					c.Close()
					return nil
				}
				b := transfer.Reference.ManifestAAD.BrowserAccountReply
				env, _ := transport.NewEnvelope(transport.MsgAccountReplyReceipt, transport.NativeAccountReplyReceiptPayload{OriginID: p.OriginID, ObservationID: p.ObservationID, ObservationDigest: p.Digest, MessageID: b.MessageID, ReplyID: b.ReplyID, ContentID: transfer.Reference.ContentID, CiphertextDigest: transfer.Reference.CiphertextDigest, Disposition: "committed"})
				return accountDeliveryFrame(t, c, env)
			default:
				t.Fatalf("account reply used generic wire %s", typ)
			}
			return nil
		})
		c.accountReplyEnabled = true
		c.session.ProtocolFeatures = append(c.session.ProtocolFeatures, transport.NativeAccountReplyProtocol)
		call := func(_ context.Context, r sessionworker.Request) (sessionworker.Response, error) {
			switch r.Type {
			case "delivery_observations":
				if r.Cursor != 0 {
					t.Fatal("old capture cursor reached ordered delivery")
				}
				return sessionworker.Response{Observations: []sessionworker.NativeObservation{o}, ObservationPage: &sessionworker.NativeObservationPage{}}, nil
			case "content_fragment":
				f := transfer.Fragments[r.ContentOrdinal]
				return sessionworker.Response{ContentFragment: &f}, nil
			case "account_reply_ack":
				if r.AccountReplyReceipt == nil || r.SourceDigest != o.SourceDigest {
					t.Fatal("lost specialized receipt")
				}
				acked++
				return sessionworker.Response{}, nil
			default:
				t.Fatalf("generic ACK %s", r.Type)
				return sessionworker.Response{}, nil
			}
		}
		budget := 16
		var ready bool
		var err error
		if attempt == 2 {
			var origin transport.NativeObservationOrigin
			if err = json.Unmarshal(o.Origin, &origin); err != nil {
				t.Fatal(err)
			}
			origin.HostID = c.hostID
			o.Origin, _ = transport.MarshalNativeJSON(origin)
			var cursor int64
			cursor, err = c.DrainNativeWorkerSourcesPage(t.Context(), call, 99)
			ready = err == nil
			if cursor != 0 {
				t.Fatal("ordered drain retained legacy cursor", cursor)
			}
		} else {
			ready, err = c.deliverAccountReply(t.Context(), o, call, &budget)
		}
		if attempt < 2 && (err == nil || ready || acked != 0) {
			t.Fatal("retired without receipt", ready, err, acked)
		}
		if attempt == 2 && (err != nil || !ready || acked != 1) {
			t.Fatal("replay failed", ready, err, acked)
		}
	}
}

func TestAccountReplyRequiresNegotiationAndSpecializedReceipt(t *testing.T) {
	o, transfer := accountDeliveryFixture(t)
	for _, mode := range []string{"default_off", "not_negotiated", "generic_receipt", "wrong_digest", "staged_commit", "rejected"} {
		t.Run(mode, func(t *testing.T) {
			var c *NativeObservationConnection
			writes := 0
			c, _ = deliveryFixture(t, func(ctx context.Context, typ string, value any) error {
				writes++
				if typ == transport.MsgAccountReplyBegin {
					env, _ := transport.NewEnvelope(transport.MsgAccountReplyStaged, transport.NativeAccountReplyStagedPayload{ContentID: transfer.Reference.ContentID, CiphertextDigest: transfer.Reference.CiphertextDigest, MissingOrdinals: []int{}})
					return accountDeliveryFrame(t, c, env)
				}
				p := value.(transport.NativeObservationPayload)
				if mode == "generic_receipt" {
					c.NativeWorkerObservationDisposition(transport.MsgNativeObservationReceipt, transport.NativeObservationReceiptPayload{OriginID: p.OriginID, ObservationID: p.ObservationID, Digest: p.Digest, Disposition: "committed"})
					return nil
				}
				b := transfer.Reference.ManifestAAD.BrowserAccountReply
				kind := transport.MsgAccountReplyReceipt
				var reply any = transport.NativeAccountReplyReceiptPayload{OriginID: p.OriginID, ObservationID: p.ObservationID, ObservationDigest: "wrong", MessageID: b.MessageID, ReplyID: b.ReplyID, ContentID: transfer.Reference.ContentID, CiphertextDigest: transfer.Reference.CiphertextDigest, Disposition: "committed"}
				if mode == "staged_commit" {
					kind = transport.MsgAccountReplyStaged
					reply = transport.NativeAccountReplyStagedPayload{ContentID: transfer.Reference.ContentID, CiphertextDigest: transfer.Reference.CiphertextDigest, MissingOrdinals: []int{}}
				}
				if mode == "rejected" {
					kind = transport.MsgAccountReplyRejected
					reply = transport.NativeAccountReplyRejectedPayload{OriginID: p.OriginID, ObservationID: p.ObservationID, ContentID: transfer.Reference.ContentID, CiphertextDigest: transfer.Reference.CiphertextDigest, ErrorCode: "unauthorized"}
				}
				env, _ := transport.NewEnvelope(kind, reply)
				return accountDeliveryFrame(t, c, env)
			})
			c.accountReplyEnabled = mode != "default_off"
			if mode != "not_negotiated" {
				c.session.ProtocolFeatures = append(c.session.ProtocolFeatures, transport.NativeAccountReplyProtocol)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
			defer cancel()
			budget := 16
			ready, err := c.deliverAccountReply(ctx, o, func(context.Context, sessionworker.Request) (sessionworker.Response, error) {
				t.Fatal("ACK without specialized receipt")
				return sessionworker.Response{}, nil
			}, &budget)
			if err == nil || ready {
				t.Fatal("accepted invalid receipt/gate")
			}
			if (mode == "default_off" || mode == "not_negotiated") && (!errors.Is(err, ErrNativeOriginAdmissionDeferred) || writes != 0) {
				t.Fatal("unnegotiated write", writes, err)
			}
		})
	}
}

func TestAccountReplyFeatureOfferDefaultOff(t *testing.T) {
	d := newTestDaemon(t)
	registry, _, _ := nativeRegistryFixture(t)
	d.nativeRegistry = registry
	for _, enabled := range []bool{false, true} {
		d.AccountReplyDeliveryEnabled = enabled
		u, err := url.Parse(d.wsURL(t.Context()))
		if err != nil {
			t.Fatal(err)
		}
		want := ""
		if enabled {
			want = transport.NativeAccountReplyProtocol
		}
		if got := u.Query().Get("native_account_reply"); got != want {
			t.Fatal(got, want)
		}
	}
	d.nativeRegistry = nil
	u, err := url.Parse(d.wsURL(t.Context()))
	if err != nil || u.Query().Get("native_account_reply") != "" {
		t.Fatal("offered without workers", err)
	}
}

func TestAccountReplyDeliveryPaginatesMissingFragments(t *testing.T) {
	o, original := accountDeliveryFixture(t)
	transfer, err := nativecontent.Build(bytes.Repeat([]byte("x"), (transport.NativeContentMaxFragmentPage+1)*transport.NativeContentFragmentPlaintextBytes), [32]byte{}, original.Reference.ManifestAAD, *original.Reference.ManifestAAD.NativeContent, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	o.OutputContent = &transfer.Reference
	stored := map[int]bool{}
	commits, acknowledgements := 0, 0
	var c *NativeObservationConnection
	c, _ = deliveryFixture(t, func(_ context.Context, typ string, value any) error {
		switch typ {
		case transport.MsgAccountReplyBegin:
			missing := []int{}
			for i := range transfer.Fragments {
				if !stored[i] {
					missing = append(missing, i)
				}
			}
			more := len(missing) > transport.NativeContentMaxFragmentPage
			if more {
				missing = missing[:transport.NativeContentMaxFragmentPage]
			}
			env, _ := transport.NewEnvelope(transport.MsgAccountReplyStaged, transport.NativeAccountReplyStagedPayload{ContentID: transfer.Reference.ContentID, CiphertextDigest: transfer.Reference.CiphertextDigest, MissingOrdinals: missing, MoreMissing: more})
			return accountDeliveryFrame(t, c, env)
		case transport.MsgAccountReplyFragment:
			f := value.(*transport.NativeContentFragment)
			if stored[f.Ordinal] {
				t.Fatal("resent an already staged fragment")
			}
			stored[f.Ordinal] = true
		case transport.MsgAccountReplyCommit:
			commits++
			p := value.(transport.NativeObservationPayload)
			b := transfer.Reference.ManifestAAD.BrowserAccountReply
			env, _ := transport.NewEnvelope(transport.MsgAccountReplyReceipt, transport.NativeAccountReplyReceiptPayload{OriginID: p.OriginID, ObservationID: p.ObservationID, ObservationDigest: p.Digest, MessageID: b.MessageID, ReplyID: b.ReplyID, ContentID: transfer.Reference.ContentID, CiphertextDigest: transfer.Reference.CiphertextDigest, Disposition: "committed"})
			return accountDeliveryFrame(t, c, env)
		default:
			t.Fatal(typ)
		}
		return nil
	})
	c.accountReplyEnabled = true
	c.session.ProtocolFeatures = append(c.session.ProtocolFeatures, transport.NativeAccountReplyProtocol)
	call := func(_ context.Context, r sessionworker.Request) (sessionworker.Response, error) {
		switch r.Type {
		case "content_fragment":
			f := transfer.Fragments[r.ContentOrdinal]
			return sessionworker.Response{ContentFragment: &f}, nil
		case "account_reply_ack":
			acknowledgements++
			return sessionworker.Response{}, nil
		default:
			t.Fatal(r.Type)
			return sessionworker.Response{}, nil
		}
	}
	budget := transport.NativeContentMaxFragmentPage
	ready, err := c.deliverAccountReply(t.Context(), o, call, &budget)
	if err != nil || ready || len(stored) != transport.NativeContentMaxFragmentPage || commits != 0 || acknowledgements != 0 {
		t.Fatal("partial page was committed", ready, err, len(stored), commits, acknowledgements)
	}
	budget = transport.NativeContentMaxFragmentPage
	ready, err = c.deliverAccountReply(t.Context(), o, call, &budget)
	if err != nil || !ready || len(stored) != len(transfer.Fragments) || commits != 1 || acknowledgements != 1 {
		t.Fatal("remaining page failed", ready, err, len(stored), commits, acknowledgements)
	}
}

func TestAccountReplyPrivateNonterminalDoesNotBlockGenericDrain(t *testing.T) {
	o, _ := accountDeliveryFixture(t)
	o.Event.Type = session.EventTurnStarted
	o.OutputContent = nil
	o.SourceSequence = 0
	var c *NativeObservationConnection
	c, generic := deliveryFixture(t, func(_ context.Context, typ string, payload any) error {
		if typ != transport.MsgNativeObservation {
			t.Fatal(typ)
		}
		p := payload.(transport.NativeObservationPayload)
		c.NativeWorkerObservationDisposition(transport.MsgNativeObservationReceipt, transport.NativeObservationReceiptPayload{ObservationID: p.ObservationID, OriginID: p.OriginID, Digest: p.Digest, Disposition: "committed"})
		return nil
	})
	o.Origin = generic.Origin
	ack := 0
	err := c.DrainNativeWorkerSources(t.Context(), func(_ context.Context, r sessionworker.Request) (sessionworker.Response, error) {
		switch r.Type {
		case "observations":
			return sessionworker.Response{Observations: []sessionworker.NativeObservation{o, generic}}, nil
		case "observation_ack":
			ack++
			return sessionworker.Response{}, nil
		default:
			t.Fatal(r.Type)
			return sessionworker.Response{}, nil
		}
	})
	if err != nil || ack != 1 {
		t.Fatal("private account start blocked source", ack, err)
	}
}
