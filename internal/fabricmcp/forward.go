package fabricmcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
)

// Forward relays original bounded MCP JSON frames on a connection whose private
// peer handshake was already completed. It never supplies an identity or signs
// an envelope. reader must include any buffered bytes after that handshake.
// It owns connection, stdin and stdout and closes them on either direction's
// end/cancellation, then joins both copies. No request is replayed.
func Forward(ctx context.Context, connection net.Conn, reader io.Reader, stdin io.ReadCloser, stdout io.WriteCloser, maxLineBytes int) error {
	if ctx == nil || connection == nil || reader == nil || stdin == nil || stdout == nil || maxLineBytes < 1024 || maxLineBytes > 2<<20 {
		return fabric.NewError(fabric.CodeInvalidInput, "Invalid local MCP forwarding configuration")
	}
	var once sync.Once
	closeAll := func() { once.Do(func() { connection.Close(); stdin.Close(); stdout.Close() }) }
	defer closeAll()
	stop := context.AfterFunc(ctx, closeAll)
	defer stop()
	done := make(chan error, 2)
	go func() { done <- copyFrames(connection, stdin, maxLineBytes) }()
	go func() { done <- copyFrames(stdout, reader, maxLineBytes) }()
	first := <-done
	closeAll()
	<-done
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if first == nil {
		return nil
	}
	return first
}
func copyFrames(output io.Writer, input io.Reader, max int) error {
	reader := bufio.NewReader(input)
	for {
		frame := make([]byte, 0, 4096)
		for {
			part, err := reader.ReadSlice('\n')
			if len(frame)+len(part) > max {
				return fabric.NewError(fabric.CodeProtocolError, "Local MCP forwarding frame exceeds bound")
			}
			frame = append(frame, part...)
			if err == bufio.ErrBufferFull {
				continue
			}
			if err == io.EOF && len(frame) == 0 {
				return nil
			}
			if err != nil {
				return fabric.NewError(fabric.CodeProtocolError, "Local MCP forwarding stream interrupted")
			}
			break
		}
		var raw json.RawMessage
		if err := fabric.DecodeJSONWithLimits(bytes.TrimSpace(frame), &raw, fabric.WireLimits{MaxBytes: max, MaxDepth: 64, MaxMembers: 4096}); err != nil {
			return err
		}
		for len(frame) > 0 {
			n, err := output.Write(frame)
			if n < 0 || n > len(frame) {
				return io.ErrShortWrite
			}
			frame = frame[n:]
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
		}
	}
}
