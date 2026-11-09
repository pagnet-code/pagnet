package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/netpolicy"
	"github.com/pagnet-code/pagnet/sdk"
	"github.com/pagnet-code/pagnet/transport"
)

// These slots own control-only standby children. They never admit execution
// and never leave this controller's memory.
type browserBindingSlot struct {
	binding      browserBindingMetadata
	secret       []byte
	credentialID string
	generation   int64
	expiresAt    time.Time
	attempted    bool
	cancel       context.CancelFunc
	done         chan struct{}
	result       chan error
}

func (browserBindingSlot) String() string   { return "[redacted browser binding slot]" }
func (browserBindingSlot) GoString() string { return "[redacted browser binding slot]" }
func (s *browserBindingSlot) wipe() {
	if s.cancel != nil {
		s.cancel()
		<-s.done
		s.cancel = nil
	}
	clear(s.secret)
	s.secret = nil
}

type browserBindingLease struct {
	Generation int64     `json:"generation"`
	Active     bool      `json:"active"`
	ExpiresAt  time.Time `json:"expiresAt"`
	LeaseID    string    `json:"leaseId"`
	InstanceID string    `json:"instanceId"`
}
type browserBindingLeaseHolder struct {
	InstanceID string `json:"instanceId"`
	LeaseID    string `json:"leaseId"`
	Generation int64  `json:"generation"`
}

type browserBindingTuple struct {
	ExpectedDesiredRevision int64  `json:"expectedDesiredRevision"`
	LeaseID                 string `json:"leaseId"`
	InstanceID              string `json:"instanceId"`
	Generation              int64  `json:"generation"`
}
type browserBindingMetadata struct {
	ID                   string `json:"id"`
	PolicyFingerprint    string `json:"policyFingerprint"`
	CredentialGeneration int64  `json:"credentialGeneration"`
	NetworkID            string `json:"networkId"`
	PrincipalID          string `json:"principalId"`
	DesiredRevision      int64  `json:"desiredRevision"`
	AppliedRevision      int64  `json:"appliedRevision"`
	ApplicationState     string `json:"applicationState"`
}
type browserBindingStatus struct {
	BindingID                 string    `json:"bindingId"`
	DesiredRevision           int64     `json:"desiredRevision"`
	AppliedRevision           int64     `json:"appliedRevision"`
	PolicyFingerprint         string    `json:"policyFingerprint"`
	Acknowledged              bool      `json:"acknowledged"`
	ExecutionReady            bool      `json:"executionReady"`
	CredentialExpiresAt       time.Time `json:"credentialExpiresAt"`
	CredentialRefreshRequired bool      `json:"credentialRefreshRequired"`
}
type browserBindingHTTPError int

func (browserBindingHTTPError) Error() string { return "browser binding request rejected" }

var errBrowserBinding = errors.New("invalid browser binding response")

type browserBindingController struct {
	client                            *http.Client
	serverURL, credential, instanceID string
	now                               func() time.Time
	wait                              func(context.Context, time.Duration) bool
	retryDelay, renewInterval         time.Duration
	lease                             browserBindingLease
	authorityUntil                    time.Time
	reacquire                         bool
	consumed                          map[string]bool
	assignmentContext                 context.Context
	serve                             func(context.Context, sdk.ManagedBrowserStandbyConfig) error
	wake                              chan struct{}
	standbyUntil                      time.Time
	recoveries                        map[string]int
	recoveryUntil                     map[string]time.Time
	recoveryNetwork                   string
	slots                             map[string]*browserBindingSlot
}

func newBrowserBindingRunner(d *Daemon, instanceID string) func(context.Context, browserAssignment) {
	client := netpolicy.NewHTTPClient(10*time.Second, d.InsecureRemoteHTTP)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return func(ctx context.Context, a browserAssignment) {
		c := &browserBindingController{client: client, serverURL: d.ServerURL, credential: d.Credential, instanceID: instanceID, now: time.Now, wait: browserBindingWait, retryDelay: time.Second, renewInterval: 10 * time.Second, slots: map[string]*browserBindingSlot{}}
		c.serve = sdk.ServeManagedBrowserStandby
		c.runBrowserBinding(ctx, a)
		// Keep terminal assignments attached until the supervisor changes authority.
		<-ctx.Done()
	}
}
func browserBindingWait(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
func browserBindingTransient(err error) bool {
	if e, ok := err.(browserBindingHTTPError); ok {
		return e >= 500 || e == 429
	}
	return err != nil && err != errBrowserBinding
}

// request never returns transport details or response bodies. Every response is
// bounded and must contain precisely one JSON value.
func (c *browserBindingController) request(ctx context.Context, method, path string, in, out any) error {
	deadline := c.localDeadline()
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return errBrowserBinding
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.serverURL+path, body)
	if err != nil {
		return errBrowserBinding
	}
	req.Header.Set("Authorization", "Bearer "+c.credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		c.reacquire = true
		return errors.New("browser binding request failed")
	}
	defer resp.Body.Close()
	if !deadline.IsZero() && !c.now().Before(deadline) {
		c.reacquire = true
		return errBrowserBinding
	}
	c.reacquire = false
	if resp.StatusCode != http.StatusOK {
		c.reacquire = resp.StatusCode >= 500 || resp.StatusCode == 429
		return browserBindingHTTPError(resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		clear(raw)
		c.reacquire = true
		return errors.New("browser binding response unavailable")
	}
	if len(raw) > 1<<20 {
		clear(raw)
		return errBrowserBinding
	}
	defer clear(raw)
	dec := json.NewDecoder(bytes.NewReader(raw))
	if dec.Decode(out) != nil {
		return errBrowserBinding
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return errBrowserBinding
	}
	if !deadline.IsZero() && !c.now().Before(deadline) {
		c.reacquire = true
		return errBrowserBinding
	}
	return nil
}
func (c *browserBindingController) retry(ctx context.Context) bool {
	deadline := c.localDeadline()
	if ctx.Err() != nil || (!deadline.IsZero() && !c.now().Before(deadline)) {
		return false
	}
	d := c.retryDelay
	if !deadline.IsZero() && deadline.Sub(c.now()) < d {
		d = deadline.Sub(c.now())
	}
	return c.wait(ctx, d) && ctx.Err() == nil && (deadline.IsZero() || c.now().Before(deadline))
}
func (c *browserBindingController) leaseHolder() browserBindingLeaseHolder {
	return browserBindingLeaseHolder{c.instanceID, c.lease.LeaseID, c.lease.Generation}
}
func (c *browserBindingController) tuple(a browserAssignment) browserBindingTuple {
	return browserBindingTuple{a.DesiredRevision, c.lease.LeaseID, c.instanceID, c.lease.Generation}
}
func (c *browserBindingController) validLease(l browserBindingLease, g int64) bool {
	_, err := uuid.Parse(l.LeaseID)
	return err == nil && l.InstanceID == c.instanceID && l.Generation == g && l.Active && l.ExpiresAt.After(c.now())
}
func (c *browserBindingController) claim(ctx context.Context, base string) bool {
	for ctx.Err() == nil {
		var current browserBindingLease
		err := c.request(ctx, http.MethodGet, base+"/runtime-lease", nil, &current)
		if err != nil {
			if browserBindingTransient(err) && c.retry(ctx) {
				continue
			}
			return false
		}
		if current.Generation < 0 {
			return false
		}
		if current.Active {
			if !current.ExpiresAt.After(c.now()) {
				c.reacquire = true
				return false
			}
			if !c.wait(ctx, min(current.ExpiresAt.Sub(c.now()), 30*time.Second)) {
				return false
			}
			continue
		}
		req := struct {
			InstanceID         string `json:"instanceId"`
			ExpectedGeneration int64  `json:"expectedGeneration"`
		}{c.instanceID, current.Generation}
		for ctx.Err() == nil {
			var l browserBindingLease
			started := c.now()
			err = c.request(ctx, http.MethodPost, base+"/runtime-lease", req, &l)
			if err == nil {
				if !c.validLease(l, current.Generation+1) {
					return false
				}
				c.lease = l
				c.confirmDeadline(started)
				return true
			}
			if err == browserBindingHTTPError(http.StatusConflict) {
				break
			}
			if !browserBindingTransient(err) || !c.retry(ctx) {
				return false
			}
		}
	}
	return false
}
func (c *browserBindingController) reconcile(ctx context.Context, a browserAssignment, base string) ([]browserBindingMetadata, error) {
	for {
		var out struct {
			Items []browserBindingMetadata `json:"items"`
		}
		err := c.request(ctx, http.MethodPost, base+"/bindings/reconcile", c.tuple(a), &out)
		if err != nil {
			if browserBindingTransient(err) && c.retry(ctx) {
				continue
			}
			return nil, err
		}
		expected := map[string]bool{}
		fingerprints := map[string]string{}
		for _, n := range a.Networks {
			if expected[n.NetworkID] {
				return nil, errBrowserBinding
			}
			expected[n.NetworkID] = true
			raw, _ := json.Marshal(n)
			sum := sha256.Sum256(raw)
			fingerprints[n.NetworkID] = hex.EncodeToString(sum[:])
		}
		ids := map[string]bool{}
		principals := map[string]bool{}
		if len(out.Items) != len(expected) {
			return nil, errBrowserBinding
		}
		for _, b := range out.Items {
			fp, e := hex.DecodeString(b.PolicyFingerprint)
			_, idErr := domain.ParseID(b.ID)
			_, principalErr := domain.ParseID(b.PrincipalID)
			if idErr != nil || principalErr != nil || principals[b.PrincipalID] || e != nil || len(fp) != 32 || len(b.PolicyFingerprint) != 64 || ids[b.ID] || !expected[b.NetworkID] || b.DesiredRevision != a.DesiredRevision || b.CredentialGeneration < 0 || b.PolicyFingerprint != fingerprints[b.NetworkID] {
				return nil, errBrowserBinding
			}
			ids[b.ID] = true
			principals[b.PrincipalID] = true
			delete(expected, b.NetworkID)
		}
		return out.Items, nil
	}
}
func (c *browserBindingController) validStatus(s browserBindingStatus, b browserBindingMetadata, a browserAssignment) bool {
	return s.BindingID == b.ID && s.DesiredRevision == a.DesiredRevision && s.AppliedRevision == a.DesiredRevision && s.PolicyFingerprint == b.PolicyFingerprint && !s.ExecutionReady
}
func (c *browserBindingController) rotate(ctx context.Context, a browserAssignment, base string, b browserBindingMetadata) error {
	for {
		if network := c.recoveryNetwork; network != "" {
			attempt := c.recoveries[network]
			if attempt >= 3 {
				return errBrowserBinding
			}
			until := c.recoveryUntil[network]
			delay := time.Second << attempt
			delay += time.Duration(rand.Float64() * float64(delay/4))
			if delay >= until.Sub(c.now()) || !c.wait(ctx, delay) || !c.now().Before(until) {
				return errBrowserBinding
			}
			// Even an ambiguous issuance consumes one replacement attempt.
			c.recoveries[network]++
		}

		req := struct {
			browserBindingTuple
			ExpectedCredentialGeneration int64 `json:"expectedCredentialGeneration"`
		}{c.tuple(a), b.CredentialGeneration}
		var out struct {
			CredentialID         string    `json:"credentialId"`
			CredentialGeneration int64     `json:"credentialGeneration"`
			Credential           string    `json:"credential"`
			ExpiresAt            time.Time `json:"expiresAt"`
		}
		err := c.request(ctx, http.MethodPost, base+"/bindings/"+b.ID+"/endpoint-credential", req, &out)
		if err != nil {
			out.Credential = ""
			if !browserBindingTransient(err) || !c.retry(ctx) {
				return err
			}
			items, e := c.reconcile(ctx, a, base)
			if e != nil {
				return e
			}
			found := false
			for _, next := range items {
				if next.ID == b.ID && next.NetworkID == b.NetworkID && next.PrincipalID == b.PrincipalID && next.PolicyFingerprint == b.PolicyFingerprint {
					b = next
					found = true
				}
			}
			if !found {
				return errBrowserBinding
			}
			continue
		}
		_, idErr := domain.ParseID(out.CredentialID)
		if idErr != nil || c.consumed[out.CredentialID] || out.CredentialGeneration != b.CredentialGeneration+1 || out.Credential == "" || !out.ExpiresAt.After(c.now()) || out.ExpiresAt.After(c.lease.ExpiresAt) {
			out.Credential = ""
			return errBrowserBinding
		}
		slot := &browserBindingSlot{secret: []byte(out.Credential), credentialID: out.CredentialID, generation: out.CredentialGeneration, expiresAt: out.ExpiresAt}
		out.Credential = ""
		if old := c.slots[b.NetworkID]; old != nil {
			old.wipe()
		}
		c.slots[b.NetworkID] = slot
		ack := struct {
			browserBindingTuple
			CredentialID         string `json:"credentialId"`
			CredentialGeneration int64  `json:"credentialGeneration"`
			PolicyFingerprint    string `json:"policyFingerprint"`
		}{c.tuple(a), slot.credentialID, slot.generation, b.PolicyFingerprint}
		for {
			var status browserBindingStatus
			err = c.request(ctx, http.MethodPost, base+"/bindings/"+b.ID+"/apply-ack", ack, &status)
			if err != nil {

				if browserBindingTransient(err) && c.retry(ctx) {
					continue
				}
				return err
			}
			if !c.validStatus(status, b, a) || !status.Acknowledged || status.CredentialRefreshRequired || !status.CredentialExpiresAt.After(c.now()) || status.CredentialExpiresAt.After(c.lease.ExpiresAt) {
				return errBrowserBinding
			}
			slot.expiresAt = minBrowserBindingTime(slot.expiresAt, status.CredentialExpiresAt)
			c.startStandby(ctx, a, b, slot)
			return nil
		}
	}
}
func (c *browserBindingController) refreshStatus(ctx context.Context, a browserAssignment, base string, items []browserBindingMetadata) error {
	for {
		var out struct {
			ConnectionID    string                 `json:"connectionId"`
			DesiredRevision int64                  `json:"desiredRevision"`
			Bindings        []browserBindingStatus `json:"bindings"`
			Acknowledged    bool                   `json:"acknowledged"`
			ExecutionReady  bool                   `json:"executionReady"`
		}
		err := c.request(ctx, http.MethodGet, base+"/runtime-status", nil, &out)
		if err != nil {
			if browserBindingTransient(err) && c.retry(ctx) {
				continue
			}
			return err
		}
		if out.ConnectionID != a.ID || out.DesiredRevision != a.DesiredRevision || out.ExecutionReady || len(out.Bindings) != len(items) {
			return errBrowserBinding
		}
		byID := map[string]browserBindingMetadata{}
		for _, b := range items {
			byID[b.ID] = b
		}
		refresh := map[string]bool{}
		for _, status := range out.Bindings {
			b, ok := byID[status.BindingID]
			if !ok || status.ExecutionReady || status.DesiredRevision != a.DesiredRevision || status.PolicyFingerprint != b.PolicyFingerprint {
				return errBrowserBinding
			}
			delete(byID, status.BindingID)
			if status.CredentialRefreshRequired {
				if slot := c.slots[b.NetworkID]; slot != nil {
					if slot.cancel != nil {
						slot.cancel()
						<-slot.done
						slot.cancel = nil
						result := <-slot.result
						if ctx.Err() != nil {
							return ctx.Err()
						}
						if !errors.Is(result, context.Canceled) {
							// A failure racing status fetch must retain its own
							// recovery policy. Discard this now-stale status.
							slot.result <- result
							return c.finishStandbys(ctx, a, base)
						}
					}
					slot.wipe()
					delete(c.slots, b.NetworkID)
				}
				refresh[b.NetworkID] = true
				continue
			}
			if !c.validStatus(status, b, a) || !status.Acknowledged || !status.CredentialExpiresAt.After(c.now()) || status.CredentialExpiresAt.After(c.lease.ExpiresAt) {
				return errBrowserBinding
			}
			slot := c.slots[b.NetworkID]
			if slot == nil || len(slot.secret) == 0 {
				return errBrowserBinding
			}
			slot.expiresAt = minBrowserBindingTime(slot.expiresAt, status.CredentialExpiresAt)
		}
		if len(refresh) == 0 {
			if !out.Acknowledged {
				return errBrowserBinding
			}
			return nil
		}
		next, err := c.reconcile(ctx, a, base)
		if err != nil {
			return err
		}
		for _, b := range next {
			if refresh[b.NetworkID] {
				if err = c.rotate(ctx, a, base, b); err != nil {
					return err
				}
			}
		}
		return nil
	}
}
func (c *browserBindingController) runAttempt(ctx context.Context, a browserAssignment) {
	if _, err := domain.ParseID(a.ID); err != nil {
		return
	}
	if _, err := uuid.Parse(c.instanceID); err != nil {
		return
	}
	base := "/api/v1/hosts/self/browser-connections/" + a.ID
	if c.slots == nil {
		c.slots = map[string]*browserBindingSlot{}
	}
	defer func() {
		for network, s := range c.slots {
			s.wipe()
			delete(c.slots, network)
		}
	}()
	if !c.claim(ctx, base) {
		return
	}
	defer func() {
		for _, slot := range c.slots {
			slot.wipe()
			// A deliberate stop reports context cancellation or expiry. A
			// queued terminal failure must veto reacquisition even when the
			// lease request or local cutoff independently requested a retry.
			select {
			case result := <-slot.result:
				if c.reacquire && !errors.Is(result, context.Canceled) && !errors.Is(result, context.DeadlineExceeded) && !errors.Is(result, sdk.ErrManagedBrowserStandbyTransport) {
					c.reacquire = false
				}
			default:
			}
		}
		// Cleanup cannot inherit a canceled assignment or an expired lease deadline.
		releaseCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		retry := c.reacquire
		defer func() { c.reacquire = retry }()
		holder := c.leaseHolder()
		c.lease.ExpiresAt = time.Time{}
		c.authorityUntil = time.Time{}
		c.standbyUntil = time.Time{}
		_ = c.request(releaseCtx, http.MethodDelete, base+"/runtime-lease", holder, nil)
	}()
	c.assignmentContext = ctx
	c.standbyUntil = c.localDeadline()
	if deadline, ok := ctx.Deadline(); ok {
		c.standbyUntil = minBrowserBindingTime(c.standbyUntil, deadline)
	}
	c.wake = make(chan struct{}, 1)
	c.recoveries = map[string]int{}
	c.recoveryUntil = map[string]time.Time{}
	items, err := c.reconcile(ctx, a, base)
	if err != nil {
		return
	}
	for _, b := range items {
		if c.rotate(ctx, a, base, b) != nil {
			return
		}
	}
	for ctx.Err() == nil {
		cutoff := minBrowserBindingTime(c.authorityUntil, c.standbyUntil)
		for _, slot := range c.slots {
			if slot.expiresAt.Before(cutoff) {
				cutoff = slot.expiresAt
			}
		}
		delay := c.renewInterval
		if cutoff.Sub(c.now()) < delay {
			delay = cutoff.Sub(c.now())
		}
		if delay <= 0 || !c.waitStandby(ctx, delay) || !c.now().Before(cutoff) {
			c.reacquire = ctx.Err() == nil
			return
		}
		if err = c.finishStandbys(ctx, a, base); err != nil {
			return
		}
		for {
			var renewed browserBindingLease
			started := c.now()
			err = c.request(ctx, http.MethodPost, base+"/runtime-lease/renew", c.leaseHolder(), &renewed)
			if err != nil {
				if err == browserBindingHTTPError(http.StatusConflict) {
					c.reacquire = true
				}
				if browserBindingTransient(err) && c.retry(ctx) {
					continue
				}
				return
			}
			if !c.validLease(renewed, c.lease.Generation) || renewed.LeaseID != c.lease.LeaseID {
				return
			}
			c.lease = renewed
			c.confirmDeadline(started)
			break
		}
		if c.refreshStatus(ctx, a, base, items) != nil {
			return
		}
	}
}

func (c *browserBindingController) confirmDeadline(started time.Time) {
	c.authorityUntil = c.lease.ExpiresAt
	if bound := started.Add(30 * time.Second); bound.Before(c.authorityUntil) {
		c.authorityUntil = bound
	}
	c.authorityUntil = c.authorityUntil.Add(-5 * time.Millisecond)
}

func (c *browserBindingController) localDeadline() time.Time {
	deadline := minBrowserBindingTime(c.authorityUntil, c.standbyUntil)
	for _, slot := range c.slots {
		if len(slot.secret) > 0 && (deadline.IsZero() || slot.expiresAt.Before(deadline)) {
			deadline = slot.expiresAt
		}
	}
	return deadline
}

func (c *browserBindingController) runBrowserBinding(ctx context.Context, a browserAssignment) {
	for ctx.Err() == nil {
		c.reacquire = false
		c.runAttempt(ctx, a)
		if !c.reacquire || ctx.Err() != nil {
			return
		}
		c.lease = browserBindingLease{}
		c.authorityUntil = time.Time{}
		c.standbyUntil = time.Time{}
		if !c.wait(ctx, c.retryDelay+time.Duration(rand.Float64()*float64(c.retryDelay))) {
			return
		}
	}
}

func (browserBindingController) String() string   { return "[redacted browser binding controller]" }
func (browserBindingController) GoString() string { return "[redacted browser binding controller]" }

func minBrowserBindingTime(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

// The controller marks a credential consumed before handing an immutable copy to
// the SDK. Only this goroutine owns slots, credentials, and recovery decisions.
func (c *browserBindingController) startStandby(ctx context.Context, a browserAssignment, b browserBindingMetadata, slot *browserBindingSlot) {
	if c.serve == nil || slot.attempted || ctx.Err() != nil {
		return
	}
	if c.consumed == nil {
		c.consumed = map[string]bool{}
	}
	if c.consumed[slot.credentialID] {
		return
	}
	c.consumed[slot.credentialID] = true
	slot.attempted = true
	slot.binding = b
	config := sdk.ManagedBrowserStandbyConfig{
		Server: c.serverURL, BindingCredential: string(slot.secret),
		AuthorityDeadline: minBrowserBindingTime(c.standbyUntil, slot.expiresAt),
		ExpectedTuple: transport.ManagedBrowserStandbyTuple{
			ConnectionID: a.ID, HostID: a.HostID, Provider: a.Provider, DesiredRevision: a.DesiredRevision,
			BindingID: b.ID, NetworkID: b.NetworkID, PrincipalID: b.PrincipalID, PolicyFingerprint: b.PolicyFingerprint,
			LeaseID: c.lease.LeaseID, InstanceID: c.instanceID, LeaseGeneration: c.lease.Generation,
			CredentialID: slot.credentialID, CredentialGeneration: slot.generation,
		},
	}
	if c.assignmentContext != nil {
		ctx = c.assignmentContext
	}
	if deadline, ok := ctx.Deadline(); ok {
		config.AuthorityDeadline = minBrowserBindingTime(config.AuthorityDeadline, deadline)
	}
	child, cancel := context.WithDeadline(ctx, config.AuthorityDeadline)
	slot.cancel, slot.done, slot.result = cancel, make(chan struct{}), make(chan error, 1)
	done, result, wake, serve := slot.done, slot.result, c.wake, c.serve
	go func() {
		defer close(done)
		result <- serve(child, config)
		select {
		case wake <- struct{}{}:
		default:
		}
	}()
}

func (c *browserBindingController) waitStandby(ctx context.Context, delay time.Duration) bool {
	if c.serve == nil {
		return c.wait(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-c.wake:
		return ctx.Err() == nil
	case <-timer.C:
		return ctx.Err() == nil
	}
}

func (c *browserBindingController) finishStandbys(ctx context.Context, a browserAssignment, base string) error {
	for network, slot := range c.slots {
		var result error
		select {
		case result = <-slot.result:
		default:
			continue
		}
		// Join before revalidation, issuance, replacement, or release.
		if slot.cancel != nil {
			slot.cancel()
		}
		<-slot.done
		// The completed credential no longer constrains fresh authority.
		clear(slot.secret)
		slot.secret = nil
		slot.cancel = nil
		if !errors.Is(result, sdk.ErrManagedBrowserStandbyTransport) {
			c.reacquire = false
			return errBrowserBinding
		}
		if c.recoveries[network] >= 3 {
			c.reacquire = false
			return errBrowserBinding
		}
		until := c.recoveryUntil[network]
		if until.IsZero() {
			until = minBrowserBindingTime(c.now().Add(15*time.Second), c.localDeadline())
			c.recoveryUntil[network] = until
		}
		recoveryCtx, cancel := context.WithDeadline(ctx, until)
		var lease browserBindingLease
		err := c.request(recoveryCtx, http.MethodGet, base+"/runtime-lease", nil, &lease)
		if err == nil && (!c.validLease(lease, c.lease.Generation) || lease.LeaseID != c.lease.LeaseID || lease.ExpiresAt.Before(c.standbyUntil) || !c.now().Before(c.localDeadline())) {
			err = errBrowserBinding
		}
		var items []browserBindingMetadata
		if err == nil {
			items, err = c.reconcile(recoveryCtx, a, base)
		}
		if err == nil {
			found := false
			for _, b := range items {
				if b.NetworkID == network {
					found = true
					if b.CredentialGeneration != slot.generation || b.ID != slot.binding.ID || b.PrincipalID != slot.binding.PrincipalID || b.PolicyFingerprint != slot.binding.PolicyFingerprint {
						err = errBrowserBinding
						break
					}
					c.recoveryNetwork = network
					err = c.rotate(recoveryCtx, a, base, b)
					c.recoveryNetwork = ""
					break
				}
			}
			if !found {
				err = errBrowserBinding
			}
		}
		cancel()
		if err != nil {
			c.reacquire = false
			return err
		}
	}
	return nil
}
