package sdk

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/internal/netpolicy"
	"github.com/pagnet-code/pagnet/transport"
)

var (
	ErrManagedBrowserStandbyUnsupported  = errors.New("sdk: managed browser standby unsupported")
	ErrManagedBrowserStandbyUnauthorized = errors.New("sdk: managed browser standby unauthorized")
	// ErrManagedBrowserStandbyTransport identifies an interrupted single attempt.
	// It contains no remote address, credential, or protocol material.
	ErrManagedBrowserStandbyTransport = errors.New("sdk: managed browser standby transport interrupted")
	errManagedBrowserStandby          = errors.New("sdk: managed browser standby failed")
)

// ManagedBrowserStandbyConfig contains one immutable, locally authorized assignment.
// AuthorityDeadline must be the conservative minimum of local assignment, lease,
// credential, and controller deadlines, retaining its monotonic clock component.
// Server observations can shorten this deadline, but cannot renew local authority.
type ManagedBrowserStandbyConfig struct {
	Server            string
	BindingCredential string
	ExpectedTuple     transport.ManagedBrowserStandbyTuple
	AuthorityDeadline time.Time
}

// ServeManagedBrowserStandby serves one control-only connection until cancellation
// or failure. It never registers handlers, authorizes execution, or reconnects.
func ServeManagedBrowserStandby(ctx context.Context, config ManagedBrowserStandbyConfig) error {
	started := time.Now()
	authority := config.AuthorityDeadline
	fail := func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errManagedBrowserStandby
	}
	transportFailure := func(err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if authority.After(time.Now()) && managedStandbyTransportError(err) {
			return ErrManagedBrowserStandbyTransport
		}
		return errManagedBrowserStandby
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if config.ExpectedTuple.Validate() != nil || config.AuthorityDeadline.IsZero() || !config.AuthorityDeadline.After(started) || !strings.HasPrefix(config.BindingCredential, "pgn_epd_") || len(config.BindingCredential) <= len("pgn_epd_") || strings.ContainsAny(config.BindingCredential, " \t\r\n") {
		return errManagedBrowserStandby
	}
	u, err := url.Parse(config.Server)
	if err != nil || u.RawQuery != "" || u.ForceQuery || netpolicy.Check(config.Server, false) != nil {
		return errManagedBrowserStandby
	}
	switch u.Scheme {
	case "https", "wss":
		u.Scheme = "wss"
	case "http", "ws":
		u.Scheme = "ws"
	default:
		return errManagedBrowserStandby
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/wss/managed-browser-bindings/" + config.ExpectedTuple.BindingID + "/standby"
	u.RawPath = ""
	handshakeDeadline := standbyEarlier(started.Add(5*time.Second), config.AuthorityDeadline)
	handshakeCtx, cancel := context.WithDeadline(ctx, handshakeDeadline)
	defer cancel()
	headers := http.Header{"Authorization": []string{"Bearer " + config.BindingCredential}}
	// Gorilla applies deadlines during the HTTP upgrade, but does not close
	// the socket when a context is canceled before its deadline. Track the raw
	// connection so cancellation also interrupts TLS and upgrade response reads.
	finishDialCancellation := func() {}
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	dialer.NetDialContext = func(dialCtx context.Context, network, address string) (net.Conn, error) {
		socket, err := (&net.Dialer{}).DialContext(dialCtx, network, address)
		if err != nil {
			return nil, err
		}
		closed := make(chan struct{})
		stop := context.AfterFunc(handshakeCtx, func() { defer close(closed); socket.Close() })
		finishDialCancellation = func() {
			if !stop() {
				<-closed
			}
		}
		return socket, nil
	}
	conn, response, err := dialer.DialContext(handshakeCtx, u.String(), headers)
	finishDialCancellation()
	if response != nil && response.Body != nil {
		response.Body.Close()
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if response != nil {
			switch response.StatusCode {
			case http.StatusNotFound:
				return ErrManagedBrowserStandbyUnsupported
			case http.StatusUnauthorized:
				return ErrManagedBrowserStandbyUnauthorized
			}
			return errManagedBrowserStandby
		}
		return transportFailure(err)
	}
	conn.SetReadLimit(transport.MaxManagedBrowserStandbyFrameBytes)
	stopped := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stopped:
		}
	}()
	defer func() { close(stopped); conn.Close(); <-watcherDone }()
	read := func() (transport.ManagedBrowserStandbyFrame, error) {
		kind, raw, err := conn.ReadMessage()
		if err != nil {
			return nil, err
		}
		return transport.DecodeManagedBrowserStandbyFrame(kind, raw)
	}
	write := func(frame transport.ManagedBrowserStandbyFrame, deadline time.Time) error {
		raw, err := transport.EncodeManagedBrowserStandbyFrame(frame)
		if err != nil {
			return errManagedBrowserStandby
		}
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return transportFailure(err)
		}
		if err := conn.WriteMessage(websocket.TextMessage, raw); err != nil {
			return transportFailure(err)
		}
		return nil
	}
	conn.SetReadDeadline(handshakeDeadline)
	frame, err := read()
	if err != nil {
		return transportFailure(err)
	}
	challenge, ok := frame.(*transport.ManagedBrowserStandbyChallenge)
	if !ok || challenge.Tuple != config.ExpectedTuple {
		return fail()
	}
	handshakeDeadline = standbyEarlier(handshakeDeadline, started.Add(time.Duration(challenge.ValidForMs)*time.Millisecond))
	if !handshakeDeadline.After(time.Now()) {
		return fail()
	}
	session := challenge.ManagedBrowserStandbySession
	session.Type = "ack"
	operationStarted := time.Now()
	if err := write(transport.ManagedBrowserStandbyAck{ManagedBrowserStandbySession: session, Nonce: challenge.Nonce}, handshakeDeadline); err != nil {
		return err
	}
	conn.SetReadDeadline(handshakeDeadline)
	frame, err = read()
	if err != nil {
		return transportFailure(err)
	}
	standby, ok := frame.(*transport.ManagedBrowserStandby)
	if !ok || standby.SessionID != session.SessionID || standby.SessionGeneration != session.SessionGeneration || !handshakeDeadline.After(time.Now()) {
		return fail()
	}
	freshness := func(lease, credential string, validFor int64, start time.Time) time.Time {
		now := time.Now()
		for _, raw := range []string{lease, credential} {
			expiry, _ := time.Parse(time.RFC3339Nano, raw)
			authority = standbyEarlier(authority, now.Add(expiry.Sub(now)))
		}
		return standbyEarlier(authority, start.Add(time.Duration(validFor)*time.Millisecond))
	}
	deadline := freshness(standby.LeaseExpiresAt, standby.CredentialExpiresAt, standby.ValidForMs, operationStarted)
	if !deadline.After(time.Now()) {
		return fail()
	}
	// The loop owns writes and ordering; its single reader is closed and joined
	// before return, including cancellation and authority expiry.
	conn.SetReadDeadline(time.Time{})
	type observation struct {
		frame      transport.ManagedBrowserStandbyFrame
		err        error
		receivedAt time.Time
	}
	frames := make(chan observation)
	readerDone := make(chan struct{})
	readerStop := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			f, e := read()
			select {
			case frames <- observation{frame: f, err: e, receivedAt: time.Now()}:
			case <-readerStop:
				return
			}
			if e != nil {
				return
			}
		}
	}()
	defer func() { close(readerStop); conn.Close(); <-readerDone }()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	expiry := time.NewTimer(time.Until(deadline))
	defer expiry.Stop()
	var sequence int64
	var pending bool
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-expiry.C:
			if pending && authority.After(time.Now()) {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return ErrManagedBrowserStandbyTransport
			}
			return fail()
		case <-ticker.C:
			if !deadline.After(time.Now()) {
				if pending && authority.After(time.Now()) {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					return ErrManagedBrowserStandbyTransport
				}
				return fail()
			}
			if pending {
				continue
			}
			sequence++
			session.Type = "heartbeat"
			operationStarted = time.Now()
			if err := write(transport.ManagedBrowserStandbyHeartbeat{ManagedBrowserStandbySession: session, Sequence: sequence}, deadline); err != nil {
				return err
			}
			pending = true
		case f := <-frames:
			if f.err != nil {
				return transportFailure(f.err)
			}
			ack, ok := f.frame.(*transport.ManagedBrowserStandbyHeartbeatAck)
			if !ok || !pending || f.receivedAt.Before(operationStarted) || ack.SessionID != session.SessionID || ack.SessionGeneration != session.SessionGeneration || ack.Sequence != sequence || !deadline.After(time.Now()) {
				return fail()
			}
			deadline = freshness(ack.LeaseExpiresAt, ack.CredentialExpiresAt, ack.ValidForMs, operationStarted)
			if !deadline.After(time.Now()) {
				return fail()
			}
			pending = false
			if !expiry.Stop() {
				select {
				case <-expiry.C:
				default:
				}
			}
			expiry.Reset(time.Until(deadline))
		}
	}
}

func standbyEarlier(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// Only recognized transport failures qualify; TLS, HTTP, frame decoding, and
// protocol errors remain terminal. Callers sanitize the result at each IO site.
func managedStandbyTransportError(err error) bool {
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) {
		return closeErr.Code == websocket.CloseAbnormalClosure
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) && networkErr.Timeout() {
		return true
	}
	for _, interruption := range []error{syscall.ECONNRESET, syscall.ECONNABORTED, syscall.ECONNREFUSED, syscall.EPIPE, syscall.ENETDOWN, syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ETIMEDOUT} {
		if errors.Is(err, interruption) {
			return true
		}
	}
	return false
}
