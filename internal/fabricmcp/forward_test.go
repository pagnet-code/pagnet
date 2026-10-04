package fabricmcp

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestForwardPreservesBufferedOriginalFramesAndJoinsStreams(t *testing.T) {
	connection, remote := net.Pipe()
	defer remote.Close()
	stdin, writeInput := io.Pipe()
	readOutput, stdout := io.Pipe()
	defer writeInput.Close()
	defer readOutput.Close()
	buffered := "{\"jsonrpc\":\"2.0\", \"id\":1,\"result\":{\"n\":9007199254740993123456789}}\n"
	request := "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n"
	done := make(chan error, 1)
	go func() {
		done <- Forward(t.Context(), connection, io.MultiReader(strings.NewReader(buffered), connection), stdin, stdout, 1<<20)
	}()
	reader := bufio.NewReader(readOutput)
	line, err := reader.ReadString('\n')
	if err != nil || line != buffered {
		t.Fatal("prefetched result bytes altered or lost", err)
	}
	sent := make(chan error, 1)
	go func() { _, err := io.WriteString(writeInput, request); sent <- err }()
	actual, err := bufio.NewReader(remote).ReadString('\n')
	if err != nil || actual != request {
		t.Fatal("original request altered", err)
	}
	if err = <-sent; err != nil {
		t.Fatal(err)
	}
	remote.Close()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("EOF did not join both transport directions")
	}
}
func TestForwardCancellationClosesBlockedPipes(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	connection, remote := net.Pipe()
	defer remote.Close()
	stdin, writer := io.Pipe()
	reader, stdout := io.Pipe()
	defer writer.Close()
	defer reader.Close()
	done := make(chan error, 1)
	go func() { done <- Forward(ctx, connection, connection, stdin, stdout, 1024) }()
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatal("cancellation lost", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation left forwarding goroutines")
	}
}
func TestCopyFramesRejectsMalformedBeforeWriting(t *testing.T) {
	for _, raw := range []string{"{\"a\":1,\"a\":2}\n", "{} {}\n", "{}", "{\"a\":\"" + strings.Repeat("x", 1024) + "\"}\n"} {
		var out strings.Builder
		if err := copyFrames(&out, strings.NewReader(raw), 1024); err == nil || out.Len() != 0 {
			t.Fatal("malformed frame was forwarded", err)
		}
	}
}
