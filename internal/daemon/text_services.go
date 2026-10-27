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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/netpolicy"
	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
	"github.com/pagnet-code/pagnet/internal/textbridge/senderipc"
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
	if !slices.Contains(p.ProtocolFeatures, textServiceBridgeProtocol) || p.HostID != d.HostID || p.OwnershipScope != "personal" || p.RunnerEpoch.IsZero() {
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
	Started                             bool                      `json:",omitempty"`
	Result                              *sdk.TextServiceReadiness `json:",omitempty"`
}

type textServiceSupervisor struct {
	daemon        *Daemon
	senderIPC     *senderipc.Server
	mu            sync.Mutex
	controlMu     sync.Mutex
	client        *textServiceClient
	wake          chan struct{}
	retry         time.Duration
	savePrivate   func(string, string, any) error
	running       map[string]*textServiceRuntime
	runSender     func(context.Context, string, textbridge.Profile, *sender.Store, textbridge.RuntimeConfig) error
	runProfile    func(context.Context, string, textbridge.Profile, textbridge.Ledger, textbridge.RuntimeConfig) error
	connect       func(context.Context, sdk.Config) (textbridge.RuntimeConnection, error)
	newProvider   func(provider.Config) (textbridge.Provider, error)
	proofRetry    time.Duration
	disableLedger func(*ledger.Store) error
	disableSender func(*sender.Store) error
}

func newTextServiceSupervisor(d *Daemon) *textServiceSupervisor {
	return &textServiceSupervisor{daemon: d, wake: make(chan struct{}, 1), retry: time.Second, savePrivate: textbridge.SavePrivateJSON, running: map[string]*textServiceRuntime{}, runProfile: textbridge.RunProfile, runSender: textbridge.RunSenderProfile, proofRetry: time.Second, disableSender: func(store *sender.Store) error { return store.Disable(context.Background()) }, disableLedger: func(store *ledger.Store) error { return store.SetEnabled(context.Background(), false) }}
}
func (s *textServiceSupervisor) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *textServiceSupervisor) admit(p transport.HostSessionPayload) {
	s.disconnect()
	c, e := newTextServiceClient(s.daemon, p)
	s.mu.Lock()
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
	all := make(map[string]*textServiceRuntime, len(s.running))
	for id, r := range s.running {
		r.enabled.Store(false)
		r.cancel()
		all[id] = r
	}
	s.mu.Unlock()
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	for id, r := range all {
		if s.stopRuntime(r, false) == nil {
			s.mu.Lock()
			if s.running[id] == r {
				delete(s.running, id)
			}
			s.mu.Unlock()
		}
	}
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
	requestErr := c.request(ctx, http.MethodGet, "", nil, &all)
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	if requestErr != nil {
		s.fenceRuntimes(c)
		return requestErr
	}
	if c.ctx.Err() != nil {
		return errTextServiceSession
	}
	seen := map[string]bool{}
	for _, v := range all {
		if !textServiceUUID(v.ID) || !textServiceUUID(v.ServiceID) || v.HostID != c.session.HostID || (v.Role != "responder" && v.Role != "sender") || v.ProfileVersion != 1 || v.Generation < 1 || (v.ActiveClaimID != nil && !textServiceUUID(*v.ActiveClaimID)) || seen[v.ID] || (v.DesiredState != "enabled" && v.DesiredState != "disabled") {
			s.fenceRuntimes(c)
			return errTextServiceOutstanding
		}
		seen[v.ID] = true
	}
	var outstanding bool
	desired := make(map[string]textServiceInstallation, len(all))
	for _, v := range all {
		desired[v.ID] = v
	}
	s.mu.Lock()
	running := make(map[string]*textServiceRuntime, len(s.running))
	for id, r := range s.running {
		running[id] = r
	}
	s.mu.Unlock()
	for id, r := range running {
		v, exists := desired[id]
		stopped := false
		select {
		case <-r.stopped:
			stopped = true
		default:
		}
		matches := exists && v.ServiceID == r.profile.Service && v.HostID == c.session.HostID && v.Role == r.profile.ServiceRole() && v.ProfileVersion == 1 && v.Generation == r.generation && v.ActiveClaimID != nil && *v.ActiveClaimID == r.claimID && v.DesiredState == "enabled" && r.client == c
		if !matches || stopped {
			if e := s.stopRuntime(r, exists && v.DesiredState == "disabled"); e != nil {
				outstanding = true
				continue
			}
			s.mu.Lock()
			if s.running[id] == r {
				delete(s.running, id)
			}
			s.mu.Unlock()
		}
	}
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
	s.mu.Lock()
	existing := s.running[v.ID]
	s.mu.Unlock()
	if existing != nil {
		return nil
	}
	base, e := textbridge.ProfileBase(s.daemon.StateDir)
	if e != nil {
		return e
	}
	dir := filepath.Join(base, v.ServiceID)
	if v.Role == "sender" {
		dir = filepath.Join(base, "senders", v.ServiceID)
	}
	if _, err := os.Lstat(filepath.Join(dir, "profile.json")); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	// Lock contention may be the owner's registration PUT: keep a bounded retry
	// outstanding until its final local Pending=false write becomes visible.
	unlock, e := textbridge.LockProfile(dir)
	if e != nil {
		return e
	}
	retained := false
	defer func() {
		if !retained {
			unlock()
		}
	}()
	p, e := textbridge.LoadProfile(dir, v.ServiceID)
	if e != nil {
		return nil
	}
	r := p.Registration
	if r == nil {
		return nil
	}
	if v.DesiredState != "disabled" && (p.Disabled || r.DesiredState == "disabled") {
		return nil
	}
	if r.Pending {
		return errTextServiceOutstanding
	}
	if textServiceServer(p.Server) == "" || textServiceServer(p.Server) != textServiceServer(c.server) || r.InstallationID != v.ID || r.HostID != c.session.HostID || r.TenantID != c.session.TenantID || r.OwnerUserID != c.session.AccountID || r.Role != v.Role || r.ProfileVersion != v.ProfileVersion || r.Generation > v.Generation {
		return nil
	}
	if p.ServiceRole() != v.Role {
		return nil
	}
	var store *ledger.Store
	var senderStore *sender.Store
	if v.Role == "sender" {
		senderStore, e = textbridge.OpenSenderStore(dir, p)
	} else {
		store, e = textbridge.OpenProfileLedger(dir, p)
	}
	if e != nil {
		if v.DesiredState == "disabled" {
			p.Disabled = true
			r.DesiredState = "disabled"
			r.Generation = v.Generation
			return errors.Join(e, s.savePrivate(dir, "profile.json", p))
		}
		return nil
	}
	defer func() {
		if !retained {
			if store != nil {
				store.Close()
			}
			if senderStore != nil {
				senderStore.Close()
			}
		}
	}()
	launch := func(a textServiceAttempt) error {
		var err error
		retained, err = s.startRuntime(ctx, c, dir, p, store, senderStore, unlock, a)
		return err
	}
	// Repair both durable gates after a partially persisted remote disable.
	if v.DesiredState == "disabled" {
		r.Generation = v.Generation
		return s.disableProfile(dir, p, store, senderStore)
	}
	if senderStore != nil {
		enabled, err := senderStore.Enabled(ctx)
		if err != nil {
			return err
		}
		if !enabled {
			return nil
		}
	} else {
		budget, err := store.BudgetSnapshot(ctx)
		if err != nil {
			return err
		}
		if !budget.Enabled {
			return nil
		}
	}
	var a textServiceAttempt
	raw, e := textbridge.ReadPrivate(filepath.Join(dir, "claim-attempt.json"), 8192)
	exists := e == nil
	if exists {
		if json.Unmarshal(raw, &a) != nil || a.InstallationID != v.ID || a.Server != c.server {
			return nil
		}
	} else if _, statErr := os.Lstat(filepath.Join(dir, "claim-attempt.json")); !errors.Is(statErr, os.ErrNotExist) {
		return errTextServiceOutstanding
	}
	var body textServiceClaimBody
	replace := !exists
	if exists {
		if json.Unmarshal(a.Body, &body) != nil || !textServiceUUID(body.ClaimID) || body.ExpectedGeneration < 1 {
			return nil
		}
		nonce, err := base64.StdEncoding.Strict().DecodeString(body.Nonce)
		if err != nil || len(nonce) != 32 {
			return nil
		}
		// A reconnect does not excuse inconsistent installation evidence.
		if v.Generation < body.ExpectedGeneration {
			return nil
		}
		if v.ActiveClaimID != nil && *v.ActiveClaimID == body.ClaimID && v.Generation != body.ExpectedGeneration+1 {
			return nil
		}
		if v.Generation > body.ExpectedGeneration && (v.ActiveClaimID == nil || !textServiceUUID(*v.ActiveClaimID)) {
			return nil
		}
		if a.AdmissionID != c.session.NativeAdmissionID {
			// v came from the new session's authoritative GET. Retain the old
			// attempt as retired before replacing it; never transport its nonce.
			replace = true
		} else {
			if body.RunnerID != c.session.RunnerID || !body.ConnectionEpoch.Equal(c.session.RunnerEpoch) {
				return nil
			}
			if v.Generation > body.ExpectedGeneration && *v.ActiveClaimID != body.ClaimID {
				// Another active claim conclusively superseded this attempt.
				// Retrying its old expected generation could only conflict.
				replace = true
			} else if a.Started || (a.Result != nil && a.Result.ClaimExpiresAt != nil && !a.Result.ClaimExpiresAt.After(time.Now())) {
				replace = true
			} else if a.Result != nil {
				if v.Generation != body.ExpectedGeneration+1 {
					return nil
				}
				return launch(a)
			}
		}
	}
	// Serialize all local mutations with disconnect. Each POST requires a
	// successful full persistence pass, even for an existing attempt: a prior
	// rename may have succeeded while its directory fsync returned an error.
	s.mu.Lock()
	if s.client != c || c.ctx.Err() != nil {
		s.mu.Unlock()
		return errTextServiceSession
	}
	if replace {
		if exists {
			if e = s.savePrivate(dir, "claim-attempt-retired.json", a); e != nil {
				s.mu.Unlock()
				return e
			}
		}
		nonce := make([]byte, 32)
		if _, e = rand.Read(nonce); e != nil {
			s.mu.Unlock()
			return e
		}
		body = textServiceClaimBody{uuid.NewString(), base64.StdEncoding.EncodeToString(nonce), c.session.RunnerID, c.session.RunnerEpoch, v.Generation}
		encoded, _ := json.Marshal(body)
		a = textServiceAttempt{InstallationID: v.ID, Server: c.server, AdmissionID: c.session.NativeAdmissionID, Body: encoded}
	}
	e = s.savePrivate(dir, "claim-attempt.json", a)
	s.mu.Unlock()
	if e != nil {
		return e
	}

	var result sdk.TextServiceReadiness
	if e = c.request(ctx, http.MethodPost, "/"+v.ID+"/claim", a.Body, &result); e != nil {
		return e
	}
	if result.InstallationID != v.ID || result.ClaimID == nil || *result.ClaimID != body.ClaimID || result.Generation != body.ExpectedGeneration+1 {
		return errTextServiceOutstanding
	}
	s.mu.Lock()
	if s.client != c || c.ctx.Err() != nil {
		s.mu.Unlock()
		return errTextServiceSession
	}
	a.Result = &result
	e = s.savePrivate(dir, "claim-attempt.json", a)
	s.mu.Unlock()
	if e != nil {
		return e
	}
	return launch(a)
}

// Unknown authority fences dispatch until an authoritative snapshot recovers.
// Caller holds controlMu, serializing disable persistence with disconnect.
func (s *textServiceSupervisor) fenceRuntimes(c *textServiceClient) {
	s.mu.Lock()
	all := make(map[string]*textServiceRuntime)
	for id, r := range s.running {
		if r.client == c {
			all[id] = r
		}
	}
	s.mu.Unlock()
	for id, r := range all {
		if s.stopRuntime(r, false) == nil {
			s.mu.Lock()
			if s.running[id] == r {
				delete(s.running, id)
			}
			s.mu.Unlock()
		}
	}
}
