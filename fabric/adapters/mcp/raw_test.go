package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

func bindTapFixture(t *testing.T, tap *ResultTap, token string, number int) jsonrpc.ID {
	t.Helper()
	id, err := jsonrpc.MakeID(float64(number))
	if err != nil {
		t.Fatal(err)
	}
	if err := tap.reserve(token, "tools/call"); err != nil {
		t.Fatal(err)
	}
	params, _ := json.Marshal(map[string]any{"_meta": map[string]string{resultTokenKey: token}})
	if err := tap.sent(&jsonrpc.Request{ID: id, Method: "tools/call", Params: params}); err != nil {
		t.Fatal(err)
	}
	return id
}
func TestExactResultAssociationBoundsAndDiscard(t *testing.T) {
	limits := DefaultLimits
	limits.MaxPending = 1
	limits.MaxResultBytes = 64
	tap := newResultTap(limits)
	id := bindTapFixture(t, tap, "original", 1)
	if tap.reserve("overflow", "tools/call") == nil {
		t.Fatal("pending capacity exceeded")
	}
	foreign, _ := jsonrpc.MakeID(float64(2))
	if err := tap.received(&jsonrpc.Response{ID: foreign, Result: json.RawMessage(`{"n":1}`)}); err != nil {
		t.Fatal(err)
	}
	if tap.bytes != 0 {
		t.Fatal("foreign response retained")
	}
	if tap.received(&jsonrpc.Response{ID: id, Result: json.RawMessage(`{"x":1,"\u0078":2}`)}) == nil {
		t.Fatal("duplicate original result accepted")
	}
	if tap.received(&jsonrpc.Response{ID: id, Result: json.RawMessage(`"` + string(bytes.Repeat([]byte("x"), 64)) + `"`)}) == nil {
		t.Fatal("oversized original result accepted")
	}
	raw := json.RawMessage(`{"n":9007199254740993123456789}`)
	if err := tap.received(&jsonrpc.Response{ID: id, Result: raw}); err != nil {
		t.Fatal(err)
	}
	if tap.received(&jsonrpc.Response{ID: id, Result: raw}) == nil {
		t.Fatal("duplicate exact response accepted")
	}
	got, err := tap.take("original")
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("original result changed")
	}
	if tap.bytes != 0 || len(tap.pending) != 0 || len(tap.ids) != 0 {
		t.Fatal("consumed result retained")
	}
	bindTapFixture(t, tap, "closed", 3)
	tap.close()
	if len(tap.pending) != 0 || len(tap.ids) != 0 || tap.bytes != 0 || tap.reserve("later", "tools/call") == nil {
		t.Fatal("closed tap retained results or admitted another call")
	}
}
func TestHTTPResultTapRejectsDuplicateOuterKeysAndPreservesSSEData(t *testing.T) {
	for _, sse := range []bool{false, true} {
		tap := newResultTap(DefaultLimits)
		bindTapFixture(t, tap, "original", 1)
		raw := []byte(`{"jsonrpc":"2.0","id":1,"result":{"n":9007199254740993123456789}}`)
		if sse {
			raw = append(append([]byte("event: message\ndata: "), raw...), []byte("\n\n")...)
		}
		body := &tapBody{ReadCloser: io.NopCloser(bytes.NewReader(raw)), tap: tap, sse: sse}
		// Small reads exercise split SSE lines and split UTF-8/JSON tokens.
		var scratch [3]byte
		for {
			_, err := body.Read(scratch[:])
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		got, err := tap.take("original")
		if err != nil || !bytes.Contains(got, []byte("9007199254740993123456789")) {
			t.Fatal("SSE/JSON original precision lost")
		}
	}
	tap := newResultTap(DefaultLimits)
	bindTapFixture(t, tap, "original", 1)
	body := &tapBody{ReadCloser: io.NopCloser(bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":2,"id":1,"result":{}}`))), tap: tap}
	if _, err := io.ReadAll(body); err == nil {
		t.Fatal("duplicate outer response identity accepted")
	}
	if tap.bytes != 0 {
		t.Fatal("malformed response became accepted original result")
	}
}
