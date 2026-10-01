package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestACPTransportCorrelatesConcurrentRequests(t *testing.T) {
	inputReader, input := io.Pipe()
	outputReader, output := io.Pipe()
	c := newACPConnection(input, outputReader)
	defer c.close(io.EOF)
	go func() {
		decoder := json.NewDecoder(inputReader)
		encoder := json.NewEncoder(output)
		for {
			var m acpMessage
			if decoder.Decode(&m) != nil {
				return
			}
			_ = encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]string{"method": m.Method}})
		}
	}()
	defer inputReader.Close()
	defer output.Close()
	var wg sync.WaitGroup
	for n := 0; n < 40; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			call, err := c.begin(ctx, "fixture", map[string]string{})
			if err != nil {
				t.Error(err)
				return
			}
			defer c.finish(call)
			select {
			case m := <-call.response:
				var result map[string]string
				if json.Unmarshal(m.Result, &result) != nil || result["method"] != "fixture" {
					t.Error("response correlation failed")
				}
			case <-ctx.Done():
				t.Error(ctx.Err())
			}
		}()
	}
	wg.Wait()
}
func TestACPTransportBlockedWriteIsAmbiguousAndCloseUnblocks(t *testing.T) {
	inputReader, input := io.Pipe()
	outputReader, output := io.Pipe()
	defer inputReader.Close()
	defer output.Close()
	c := newACPConnection(input, outputReader)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := c.begin(ctx, "session/prompt", map[string]string{"text": "work"})
	if !errors.Is(err, errACPDeliveryUncertain) {
		t.Fatalf("queued write incorrectly retryable: %v", err)
	}
	c.close(io.EOF)
	select {
	case <-c.done:
	case <-time.After(time.Second):
		t.Fatal("blocked writer prevented bounded close")
	}
}
func TestACPTransportMalformedFramesFailClosed(t *testing.T) {
	for _, frame := range []string{"not-json\n", `{"jsonrpc":"1.0","method":"fake"}` + "\n", `{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1}}` + "\n"} {
		inputReader, input := io.Pipe()
		outputReader, output := io.Pipe()
		c := newACPConnection(input, outputReader)
		go func() { _, _ = io.WriteString(output, frame) }()
		select {
		case <-c.done:
		case <-time.After(time.Second):
			t.Fatal("malformed protocol remained live")
		}
		c.close(io.EOF)
		inputReader.Close()
		output.Close()
	}
}
