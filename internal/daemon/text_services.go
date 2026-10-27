package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/netpolicy"
	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/sdk"
	"github.com/pagnet-code/pagnet/transport"
)

const textServiceBridgeProtocol = "text_service_bridge_v1"
const textServicesChanged = "host.text_services_changed"

var errTextServiceSession = errors.New("text service session unavailable")
var errTextServiceOutstanding = errors.New("text service reconciliation outstanding")

type textServiceInstallation struct {
	ID             string     `json:"id"`
	ServiceID      string     `json:"serviceId"`
	HostID         string     `json:"hostId"`
	Role           string     `json:"role"`
	ProfileVersion int        `json:"profileVersion"`
	DesiredState   string     `json:"desiredState"`
	Generation     int64      `json:"generation"`
	ActiveClaimID  *string    `json:"activeClaimId,omitempty"`
	ClaimExpiresAt *time.Time `json:"claimExpiresAt,omitempty"`
	Ready          bool       `json:"ready"`
}

// Each client owns an immutable admission and cancellation context. It never
// consults mutable daemon credentials or adopts a replacement connection.
type textServiceClient struct {
	session            transport.HostSessionPayload
	server, credential string
	http               *http.Client
	ctx                context.Context
	cancel             context.CancelFunc
}

func newTextServiceClient(d *Daemon, p transport.HostSessionPayload) (*textServiceClient, error) {
	for _, id := range []string{p.TenantID, p.AccountID, p.HostID, p.NativeAdmissionID, p.RunnerID, p.HostCredentialID, p.BootID} {
		if !textServiceUUID(id) {
			return nil, errTextServiceSession
		}
	}
	if p.HostID != d.HostID || p.OwnershipScope != "personal" || p.RunnerEpoch.IsZero() {
		return nil, errTextServiceSession
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := netpolicy.NewHTTPClient(15*time.Second, d.InsecureRemoteHTTP)
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	p.ProtocolFeatures = append([]string(nil), p.ProtocolFeatures...)
	return &textServiceClient{p, strings.TrimRight(d.ServerURL, "/"), d.Credential, h, ctx, cancel}, nil
}
func textServiceUUID(s string) bool {
	v, e := uuid.Parse(s)
	return e == nil && v != uuid.Nil && v.String() == s
}
func textServiceServer(s string) string {
	u, e := url.Parse(strings.TrimSpace(s))
	if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String()
}
func (c *textServiceClient) request(ctx context.Context, method, path string, body []byte, out any) error {
	if c.ctx.Err() != nil {
		return errTextServiceSession
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	req, e := http.NewRequestWithContext(ctx, method, c.server+"/api/v1/hosts/self/text-services/installations"+path, bytes.NewReader(body))
	if e != nil {
		return errTextServiceSession
	}
	req.Header.Set("Authorization", "Bearer "+c.credential)
	req.Header.Set("X-Pagnet-Native-Admission-Id", c.session.NativeAdmissionID)
	req.Header.Set("Content-Type", "application/json")
	resp, e := c.http.Do(req)
	if e != nil {
		return errTextServiceOutstanding
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if c.ctx.Err() != nil || ctx.Err() != nil {
		return errTextServiceSession
	}
	if e != nil || len(raw) > 1<<20 || resp.StatusCode != http.StatusOK || json.Unmarshal(raw, out) != nil {
		return errTextServiceOutstanding
	}
	if c.ctx.Err() != nil || ctx.Err() != nil {
		return errTextServiceSession
	}
	return nil
}

type textServiceClaimBody struct {
	ClaimID            string    `json:"claimId"`
	Nonce              string    `json:"nonce"`
	RunnerID           string    `json:"runnerId"`
	ConnectionEpoch    time.Time `json:"connectionEpoch"`
	ExpectedGeneration int64     `json:"expectedGeneration"`
}

// This private durable record precedes POST and retains the exact encoded body.
// Never log it: Body contains the claim nonce.
type textServiceAttempt struct {
	InstallationID, Server, AdmissionID string
	Body                                json.RawMessage
	Result                              *sdk.TextServiceReadiness `json:",omitempty"`
}

type textServiceSupervisor struct {
	daemon *Daemon
	mu     sync.Mutex
	client *textServiceClient
	wake   chan struct{}
	retry  time.Duration
}

func newTextServiceSupervisor(d *Daemon) *textServiceSupervisor {
	return &textServiceSupervisor{daemon: d, wake: make(chan struct{}, 1), retry: time.Second}
}
func (s *textServiceSupervisor) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *textServiceSupervisor) admit(p transport.HostSessionPayload) {
	c, e := newTextServiceClient(s.daemon, p)
	s.mu.Lock()
	if s.client != nil {
		s.client.cancel()
	}
	s.client = nil
	if e == nil {
		s.client = c
	}
	s.mu.Unlock()
	s.signal()
}
func (s *textServiceSupervisor) disconnect() {
	s.mu.Lock()
	if s.client != nil {
		s.client.cancel()
	}
	s.client = nil
	s.mu.Unlock()
	s.signal()
}
func (s *textServiceSupervisor) run(ctx context.Context) {
	defer s.disconnect()
	var retry <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-retry:
		}
		retry = nil
		s.mu.Lock()
		c := s.client
		s.mu.Unlock()
		if c == nil {
			continue
		}
		if e := s.reconcile(ctx, c); e != nil && ctx.Err() == nil && c.ctx.Err() == nil {
			retry = time.After(s.retry)
		}
	}
}
func (s *textServiceSupervisor) reconcile(ctx context.Context, c *textServiceClient) error {
	var all []textServiceInstallation
	if e := c.request(ctx, http.MethodGet, "", nil, &all); e != nil {
		return e
	}
	seen := map[string]bool{}
	for _, v := range all {
		if !textServiceUUID(v.ID) || !textServiceUUID(v.ServiceID) || v.HostID != c.session.HostID || v.Role != "responder" || v.ProfileVersion != 1 || v.Generation < 1 || seen[v.ID] || (v.DesiredState != "enabled" && v.DesiredState != "disabled") {
			return errTextServiceOutstanding
		}
		seen[v.ID] = true
	}
	var outstanding bool
	for _, v := range all {
		if e := s.installation(ctx, c, v); e != nil {
			outstanding = true
		}
	}
	if outstanding {
		return errTextServiceOutstanding
	}
	return nil
}
func (s *textServiceSupervisor) installation(ctx context.Context, c *textServiceClient, v textServiceInstallation) error {
	base, e := textbridge.ProfileBase(s.daemon.StateDir)
	if e != nil {
		return e
	}
	dir := filepath.Join(base, v.ServiceID)
	if _, err := os.Lstat(filepath.Join(dir, "profile.json")); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	// Lock contention may be the owner's registration PUT: keep a bounded retry
	// outstanding until its final local Pending=false write becomes visible.
	unlock, e := textbridge.LockProfile(dir)
	if e != nil {
		return e
	}
	defer unlock()
	p, e := textbridge.LoadProfile(dir, v.ServiceID)
	if e != nil {
		return nil
	}
	r := p.Registration
	if r == nil || p.Disabled || r.DesiredState == "disabled" {
		return nil
	}
	if r.Pending {
		return errTextServiceOutstanding
	}
	if textServiceServer(p.Server) == "" || textServiceServer(p.Server) != textServiceServer(c.server) || r.InstallationID != v.ID || r.HostID != c.session.HostID || r.TenantID != c.session.TenantID || r.OwnerUserID != c.session.AccountID || r.Role != v.Role || r.ProfileVersion != v.ProfileVersion || r.Generation > v.Generation {
		return nil
	}
	store, e := textbridge.OpenProfileLedger(dir, p)
	if e != nil {
		return nil
	}
	defer store.Close()
	budget, e := store.BudgetSnapshot(ctx)
	if e != nil {
		return e
	}
	if !budget.Enabled || v.DesiredState != "enabled" {
		return nil
	}
	// Serialize the final session check and all local claim mutations with
	// disconnect. HTTP remains cancelable without holding the supervisor lock.
	var a textServiceAttempt
	raw, e := textbridge.ReadPrivate(filepath.Join(dir, "claim-attempt.json"), 8192)
	if e == nil {
		if json.Unmarshal(raw, &a) != nil || a.InstallationID != v.ID || a.Server != c.server || a.AdmissionID != c.session.NativeAdmissionID {
			return nil
		}
	} else {
		if _, statErr := os.Lstat(filepath.Join(dir, "claim-attempt.json")); !errors.Is(statErr, os.ErrNotExist) {
			return errTextServiceOutstanding
		}
		nonce := make([]byte, 32)
		if _, e = rand.Read(nonce); e != nil {
			return e
		}
		body, _ := json.Marshal(textServiceClaimBody{uuid.NewString(), base64.StdEncoding.EncodeToString(nonce), c.session.RunnerID, c.session.RunnerEpoch, v.Generation})
		a = textServiceAttempt{InstallationID: v.ID, Server: c.server, AdmissionID: c.session.NativeAdmissionID, Body: body}
		s.mu.Lock()
		if s.client != c || c.ctx.Err() != nil {
			s.mu.Unlock()
			return errTextServiceSession
		}
		e = textbridge.SavePrivateJSON(dir, "claim-attempt.json", a)
		s.mu.Unlock()
		if e != nil {
			return e
		}
	}
	if a.Result != nil {
		return nil
	}
	var body textServiceClaimBody
	if json.Unmarshal(a.Body, &body) != nil || !textServiceUUID(body.ClaimID) || body.RunnerID != c.session.RunnerID || !body.ConnectionEpoch.Equal(c.session.RunnerEpoch) || body.ExpectedGeneration < 1 {
		return nil
	}
	var result sdk.TextServiceReadiness
	if e = c.request(ctx, http.MethodPost, "/"+v.ID+"/claim", a.Body, &result); e != nil {
		return e
	}
	if result.InstallationID != v.ID || result.ClaimID == nil || *result.ClaimID != body.ClaimID || result.Generation != body.ExpectedGeneration+1 {
		return errTextServiceOutstanding
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != c || c.ctx.Err() != nil {
		return errTextServiceSession
	}
	a.Result = &result
	return textbridge.SavePrivateJSON(dir, "claim-attempt.json", a)
}
