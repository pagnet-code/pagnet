package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestHostWSDialerDisabledPreservesDefaults(t *testing.T) {
	original := websocket.DefaultDialer
	defaults := *original
	defaults.NetDial = func(string, string) (net.Conn, error) { return nil, errors.New("custom dial") }
	defaults.NetDialContext = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("custom context dial") }
	defaults.NetDialTLSContext = defaults.NetDialContext
	websocket.DefaultDialer = &defaults
	t.Cleanup(func() { websocket.DefaultDialer = original })

	dialer, err := hostWSDialer(false)
	if err != nil {
		t.Fatal(err)
	}
	if dialer == &defaults {
		t.Fatal("returned the shared default dialer")
	}
	got, want := reflect.ValueOf(*dialer), reflect.ValueOf(defaults)
	for i := 0; i < got.NumField(); i++ {
		if got.Field(i).Kind() == reflect.Func {
			if got.Field(i).Pointer() != want.Field(i).Pointer() {
				t.Errorf("changed callback %s", got.Type().Field(i).Name)
			}
		} else if !reflect.DeepEqual(got.Field(i).Interface(), want.Field(i).Interface()) {
			t.Errorf("changed field %s", got.Type().Field(i).Name)
		}
	}
	dialer.HandshakeTimeout++
	if defaults.HandshakeTimeout != original.HandshakeTimeout {
		t.Fatal("mutating clone changed default dialer")
	}
}

func TestHostWSDialerRejectsCustomHooks(t *testing.T) {
	for _, hook := range []string{"NetDial", "NetDialContext", "NetDialTLSContext"} {
		t.Run(hook, func(t *testing.T) {
			original := websocket.DefaultDialer
			defaults := *original
			switch hook {
			case "NetDial":
				defaults.NetDial = func(string, string) (net.Conn, error) { return nil, nil }
			case "NetDialContext":
				defaults.NetDialContext = func(context.Context, string, string) (net.Conn, error) { return nil, nil }
			case "NetDialTLSContext":
				defaults.NetDialTLSContext = func(context.Context, string, string) (net.Conn, error) { return nil, nil }
			}
			websocket.DefaultDialer = &defaults
			t.Cleanup(func() { websocket.DefaultDialer = original })
			if _, err := hostWSDialer(true); err == nil {
				t.Fatal("accepted custom " + hook)
			}
		})
	}
}

func TestHostWSDialerIPv4HostnameAndProxy(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seenHost := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost <- r.Host
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err == nil {
			conn.Close()
		}
	}))
	server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	address := "localhost:" + strings.Split(listener.Addr().String(), ":")[1]
	original := websocket.DefaultDialer
	defaults := *original
	proxyCalled := false
	defaults.Proxy = func(r *http.Request) (*url.URL, error) {
		proxyCalled = true
		if r.URL.Host != address {
			t.Errorf("proxy received host %q, want %q", r.URL.Host, address)
		}
		return nil, nil
	}
	websocket.DefaultDialer = &defaults
	t.Cleanup(func() { websocket.DefaultDialer = original })
	dialer, err := hostWSDialer(true)
	if err != nil {
		t.Fatal(err)
	}
	conn, _, err := dialer.DialContext(t.Context(), "ws://"+address, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if !proxyCalled {
		t.Error("default proxy callback was not called")
	}
	if got := <-seenHost; got != address {
		t.Errorf("Host = %q, want %q", got, address)
	}
	if defaults.NetDialContext != nil {
		t.Error("changed default dial hook")
	}
}

func TestHostWSDialerTLSHostnameVerification(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	type requestInfo struct{ host, sni string }
	seen := make(chan requestInfo, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- requestInfo{r.Host, r.TLS.ServerName}
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err == nil {
			conn.Close()
		}
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	dialer, err := hostWSDialer(true)
	if err != nil {
		t.Fatal(err)
	}
	dialer.Proxy = nil
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	dialer.TLSClientConfig = &tls.Config{RootCAs: roots}
	address := "localhost:" + strings.Split(server.Listener.Addr().String(), ":")[1]
	conn, _, err := dialer.DialContext(t.Context(), "wss://"+address, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if got := <-seen; got.host != address || got.sni != "localhost" {
		t.Errorf("request = %+v, want Host %q and SNI localhost", got, address)
	}
	if conn, _, err := dialer.DialContext(t.Context(), "wss://"+server.Listener.Addr().String(), nil); err == nil {
		conn.Close()
		t.Fatal("accepted certificate for a different hostname")
	}
}

func TestHostWSDialerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if conn, err := dialHostWSIPv4(ctx, "tcp", "localhost:80"); !errors.Is(err, context.Canceled) {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("dial error = %v, want context canceled", err)
	}
}

func TestHostWSDialerHandshakeTimeout(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer server.Close()
	defer close(release)
	dialer, err := hostWSDialer(true)
	if err != nil {
		t.Fatal(err)
	}
	dialer.Proxy = nil
	dialer.HandshakeTimeout = 25 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	conn, _, err := dialer.DialContext(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if conn != nil {
		conn.Close()
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("handshake error = %v, want timeout", err)
	}
	if ctx.Err() != nil {
		t.Fatal("handshake waited for outer context instead of its timeout")
	}
}

func TestHostWSConnectAndRunRejectsCustomHook(t *testing.T) {
	d := newTestDaemon(t)
	d.HostWSIPv4Only = true
	d.ServerURL = "http://127.0.0.1:1"
	original := websocket.DefaultDialer
	defaults := *original
	called := false
	defaults.NetDial = func(string, string) (net.Conn, error) {
		called = true
		return nil, errors.New("custom hook invoked")
	}
	websocket.DefaultDialer = &defaults
	t.Cleanup(func() { websocket.DefaultDialer = original })
	_, err := d.connectAndRun(t.Context())
	if err == nil || !strings.Contains(err.Error(), "cannot override custom WebSocket dial hooks") {
		t.Fatalf("connect error = %v, want custom hook rejection", err)
	}
	if called {
		t.Fatal("called custom dial hook")
	}
}

func TestHostWSDialerNoProxy(t *testing.T) {
	if os.Getenv("PAGNET_TEST_HOST_WS_PROXY") == "1" {
		dialer, err := hostWSDialer(true)
		if err != nil {
			t.Fatal(err)
		}
		for _, host := range []string{"bypass.example", "proxy.example"} {
			proxy, err := dialer.Proxy(&http.Request{URL: &url.URL{Scheme: "http", Host: host}})
			if err != nil {
				t.Fatal(err)
			}
			if host == "bypass.example" && proxy != nil {
				t.Errorf("NO_PROXY host selected proxy %v", proxy)
			}
			if host == "proxy.example" && (proxy == nil || proxy.String() != "http://127.0.0.1:12345") {
				t.Errorf("proxy = %v, want configured HTTP proxy", proxy)
			}
		}
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHostWSDialerNoProxy$")
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(key) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "REQUEST_METHOD", "PAGNET_TEST_HOST_WS_PROXY":
			continue
		}
		cmd.Env = append(cmd.Env, entry)
	}
	cmd.Env = append(cmd.Env, "PAGNET_TEST_HOST_WS_PROXY=1", "HTTP_PROXY=http://127.0.0.1:12345", "NO_PROXY=bypass.example")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("proxy subprocess: %v\n%s", err, output)
	}
}

func TestHostWSDialerForcesIPv4Network(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := dialHostWSIPv4(t.Context(), "tcp6", "localhost:"+strings.Split(listener.Addr().String(), ":")[1])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.RemoteAddr().(*net.TCPAddr).IP.To4() == nil {
		t.Fatalf("connected to non-IPv4 address %v", conn.RemoteAddr())
	}
}
