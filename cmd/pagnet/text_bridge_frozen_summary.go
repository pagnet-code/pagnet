package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
	"github.com/pagnet-code/pagnet/sdk"
	"github.com/spf13/cobra"
)

type frozenSummaryReservation struct {
	Version                                int
	RequestID, Service, Server, Credential string
	Disabled, Approving                    bool
}

type frozenSummaryCreationJournal struct {
	Version                  int
	RequestID, Name, Service string
}

func readFrozenSummaryJSON(path string, value any) error {
	raw, err := textbridge.ReadPrivate(path, 32768)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid frozen summary local setup")
	}
	return nil
}

func loadFrozenSummaryReservation(dir, service string) (frozenSummaryReservation, error) {
	var r frozenSummaryReservation
	if err := readFrozenSummaryJSON(filepath.Join(dir, "frozen-summary-reservation.json"), &r); err != nil {
		return r, err
	}
	if r.Version != 1 || r.Service != service || !textBridgeUUID(r.RequestID) || (sdk.Config{Server: r.Server, Credential: r.Credential, ExpectedPrincipalID: r.Service}).Validate() != nil {
		return r, errors.New("invalid frozen summary reservation")
	}
	var journal frozenSummaryCreationJournal
	if err := readFrozenSummaryJSON(filepath.Join(filepath.Dir(dir), "frozen-summary-reservations", r.RequestID+".json"), &journal); err != nil {
		return r, errors.New("reservation has no completed local creation journal")
	}
	if journal.Version != 1 || journal.RequestID != r.RequestID || journal.Service != r.Service || strings.TrimSpace(journal.Name) == "" {
		return r, errors.New("reservation does not match its local creation journal")
	}
	return r, nil
}

func printFrozenSummaryReservation(cmd *cobra.Command, service string) {
	fmt.Fprintf(cmd.OutOrStdout(), "%s\nCreate a V2 sharing project with this service in its roster, then run pagnet text-bridge frozen-summary approve --service %s --project PROJECT_UUID with the owner policy flags.\n", service, service)
}

func textBridgeFrozenSummaryCmd(stateDir *string, deps textBridgeDependencies) *cobra.Command {
	cmd := &cobra.Command{Use: "frozen-summary", Args: cobra.NoArgs, Short: "Reserve, approve, inspect or retire a frozen summary responder"}
	var name, requestID string
	reserve := &cobra.Command{Use: "reserve", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) (retErr error) {
		if strings.TrimSpace(name) == "" {
			return errors.New("--name is required")
		}
		if requestID == "" {
			requestID = uuid.NewString()
		}
		if !textBridgeUUID(requestID) {
			return errors.New("--request-id must be a UUID")
		}
		base, err := textbridge.ProfileBase(*stateDir)
		if err != nil {
			return err
		}
		journals := filepath.Join(base, "frozen-summary-reservations")
		if err := textbridge.PrivateDir(journals); err != nil {
			return err
		}
		unlock, err := textbridge.LockProfile(journals)
		if err != nil {
			return err
		}
		defer unlock()
		journalPath := filepath.Join(journals, requestID+".json")
		var journal frozenSummaryCreationJournal
		if _, err := os.Lstat(journalPath); err == nil {
			if err := readFrozenSummaryJSON(journalPath, &journal); err != nil {
				return err
			}
			if journal.Version != 1 || journal.RequestID != requestID || journal.Name != name {
				return errors.New("reservation request does not match saved creation journal")
			}
			if !textBridgeUUID(journal.Service) {
				return errors.New("reservation creation outcome uncertain; inspect Services; this request will not be retried")
			}
			dir, err := textbridge.ProfileDirectory(*stateDir, journal.Service)
			if err != nil {
				return err
			}
			r, err := loadFrozenSummaryReservation(dir, journal.Service)
			if err != nil {
				return err
			}
			if r.RequestID != requestID || r.Disabled || r.Approving {
				return errors.New("reservation is retired or approval has started")
			}
			if err := frozenSummaryNoProfile(dir); err != nil {
				return err
			}
			printFrozenSummaryReservation(cmd, r.Service)
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		owner, err := deps.owner()
		if err != nil {
			return err
		}
		journal = frozenSummaryCreationJournal{Version: 1, RequestID: requestID, Name: name}
		if err := textbridge.SavePrivateJSON(journals, requestID+".json", journal); err != nil {
			return err
		}
		defer func() {
			if retErr != nil {
				retErr = fmt.Errorf("reservation request %s: %w", requestID, retErr)
			}
		}()
		created, err := textBridgeCreateService(cmd.Context(), owner, name)
		if err != nil {
			return err
		}
		defer func() {
			if retErr != nil {
				retErr = fmt.Errorf("service %s was created but local reservation failed; inspect Services; do not retry creation: %w", created.ID, retErr)
			}
		}()
		dir := filepath.Join(base, created.ID)
		if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
			return errors.New("service already has local state")
		}
		if err := textbridge.PrivateDir(dir); err != nil {
			return err
		}
		r := frozenSummaryReservation{Version: 1, RequestID: requestID, Service: created.ID, Server: owner.base, Credential: created.Credential}
		if (sdk.Config{Server: r.Server, Credential: r.Credential, ExpectedPrincipalID: r.Service}).Validate() != nil {
			return errors.New("invalid created service connection configuration")
		}
		if err := textbridge.SavePrivateJSON(dir, "frozen-summary-reservation.json", r); err != nil {
			return err
		}
		journal.Service = created.ID
		if err := textbridge.SavePrivateJSON(journals, requestID+".json", journal); err != nil {
			return err
		}
		printFrozenSummaryReservation(cmd, created.ID)
		return nil
	}}
	reserve.Flags().StringVar(&name, "name", "", "new service name")
	reserve.Flags().StringVar(&requestID, "request-id", "", "local creation request UUID; uncertain requests are never retried")
	cmd.AddCommand(reserve)
	var service, source, origin, model, keyFile, expires, label string
	var projects []string
	var calls int64
	approve := &cobra.Command{Use: "approve", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) (retErr error) {
		if !textBridgeUUID(service) || source == "" || len(projects) == 0 || calls <= 0 || keyFile == "" || expires == "" {
			return errors.New("approve requires --service UUID --project UUID --frozen-summary-file PATH --provider-origin URL --model MODEL --key-file PATH --calls-per-day N --expires-at RFC3339")
		}
		expiry, err := time.Parse(time.RFC3339, expires)
		if err != nil {
			return errors.New("--expires-at must be RFC3339")
		}
		dir, err := textbridge.ProfileDirectory(*stateDir, service)
		if err != nil {
			return err
		}
		r, err := loadFrozenSummaryReservation(dir, service)
		if err != nil {
			return errors.New("approval requires a private local frozen summary reservation")
		}
		keyPath, err := filepath.Abs(keyFile)
		if err != nil {
			return errors.New("invalid local key file path")
		}
		key, err := textbridge.ReadProviderKey(keyPath)
		if err != nil {
			return err
		}
		config := provider.Config{BaseURL: origin, Model: model, APIKey: key}
		if _, err := deps.provider(config); err != nil {
			return err
		}
		p := textbridge.Profile{Service: service, Server: r.Server, Credential: r.Credential, Role: "responder", ProjectContract: textbridge.SharingProjectContract, ProviderOrigin: origin, Model: model, KeyFile: keyPath, Fingerprint: textbridge.ProviderFingerprint(config), Limits: ledger.Limits{CallsPerDay: calls, MaxConcurrent: 1}}
		in := textbridge.FrozenSummaryInput{Profile: p, ProjectIDs: projects, InstructionFile: source, CallsPerDay: calls, ExpiresAt: expiry, HistoricalSourceLabel: label}
		if err := textbridge.ValidateFrozenSummaryInput(in, time.Now()); err != nil {
			return err
		}
		unlock, err := textbridge.LockProfile(dir)
		if err != nil {
			return err
		}
		defer unlock()
		unlockPolicy, err := textbridge.LockProfilePolicy(cmd.Context(), dir)
		if err != nil {
			return err
		}
		defer unlockPolicy()
		r, err = loadFrozenSummaryReservation(dir, service)
		if err != nil {
			return err
		}
		if r.Disabled || r.Approving {
			return errors.New("reservation is retired or approval has already started; create a new reservation")
		}
		if err := frozenSummaryNoProfile(dir); err != nil {
			return err
		}
		r.Approving = true
		if err := textbridge.SavePrivateJSON(dir, "frozen-summary-reservation.json", r); err != nil {
			return err
		}
		defer func() {
			if retErr != nil {
				retErr = fmt.Errorf("frozen summary activation incomplete for service %s; create a new reservation: %w", service, retErr)
			}
		}()
		a, err := textbridge.CreateFrozenSummaryApproval(dir, in, time.Now())
		if err != nil {
			return err
		}
		unlockPolicy()
		// The durable immutable approval is the authorization boundary. Verify
		// pristine remote enrollment after that boundary and before activation.
		owner, err := deps.owner()
		if err != nil {
			return errors.New("could not verify frozen summary owner")
		}
		if owner.base != r.Server {
			return errors.New("reservation belongs to a different server")
		}
		validationCtx, cancelValidation := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancelValidation()
		if err := verifyFrozenSummaryEnrollment(validationCtx, owner, service, projects); err != nil {
			return err
		}
		unlockPublish, err := textbridge.LockProfilePolicy(cmd.Context(), dir)
		if err != nil {
			return err
		}
		defer unlockPublish()
		currentReservation, err := loadFrozenSummaryReservation(dir, service)
		if err != nil {
			return err
		}
		if currentReservation.Disabled || currentReservation != r {
			return errors.New("reservation was cancelled or changed during approval")
		}
		currentApproval, err := textbridge.LoadFrozenSummaryApproval(dir, a.ID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(currentApproval, a) || a.Disabled || !a.ExpiresAt.After(time.Now()) {
			return errors.New("approval changed or expired before activation")
		}
		if _, err := os.Lstat(filepath.Join(dir, "profile.json")); !errors.Is(err, os.ErrNotExist) {
			return errors.New("service profile already exists or cannot be inspected")
		}
		p.FrozenSummaryApprovalID = a.ID
		store, err := ledger.Open(filepath.Join(dir, "ledger"), p.LedgerBinding(), p.Limits)
		if err != nil {
			return err
		}
		if err := store.Close(); err != nil {
			return err
		}
		// First publication only, with policy.lock held and the selected approval complete.
		if err := textbridge.SavePrivateJSON(dir, "profile.json", p); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), p.Service)
		return nil
	}}
	approve.Flags().StringVar(&service, "service", "", "reserved service UUID")
	approve.Flags().StringArrayVar(&projects, "project", nil, "allowed V2 project UUID (repeatable)")
	approve.Flags().StringVar(&source, "frozen-summary-file", "", "private frozen summary source")
	approve.Flags().StringVar(&origin, "provider-origin", "", "owner-selected provider origin")
	approve.Flags().StringVar(&model, "model", "", "fixed provider model")
	approve.Flags().StringVar(&keyFile, "key-file", "", "private provider key file")
	approve.Flags().Int64Var(&calls, "calls-per-day", 0, "maximum calls per UTC day")
	approve.Flags().StringVar(&expires, "expires-at", "", "approval expiry in RFC3339")
	approve.Flags().StringVar(&label, "historical-source-label", "", "historical source attribution")
	cmd.AddCommand(approve)
	for _, operation := range []string{"status", "disable"} {
		op := operation
		var service string
		sub := &cobra.Command{Use: op, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			if !textBridgeUUID(service) {
				return errors.New("--service must be a service UUID")
			}
			dir, err := textbridge.ProfileDirectory(*stateDir, service)
			if err != nil {
				return err
			}
			r, err := loadFrozenSummaryReservation(dir, service)
			if err != nil {
				return errors.New("service has no private frozen summary reservation")
			}
			if op == "disable" {
				unlock, err := textbridge.LockProfilePolicy(cmd.Context(), dir)
				if err != nil {
					return err
				}
				r, err = loadFrozenSummaryReservation(dir, service)
				if err != nil {
					unlock()
					return err
				}
				_, profileErr := os.Lstat(filepath.Join(dir, "profile.json"))
				if errors.Is(profileErr, os.ErrNotExist) {
					r.Disabled = true
					err := textbridge.SavePrivateJSON(dir, "frozen-summary-reservation.json", r)
					unlock()
					return err
				}
				if profileErr != nil {
					unlock()
					return profileErr
				}
				p, err := textbridge.LoadProfile(dir, service)
				unlock()
				if err != nil {
					return err
				}
				if p.FrozenSummaryApprovalID == "" {
					return errors.New("reservation has an unexpected generic profile")
				}
				// Retire runnable policy before reporting reservation retirement.
				// Every intermediate durable state therefore fails closed.
				if err := textbridge.DisableFrozenSummaryApprovalContext(cmd.Context(), dir, p.FrozenSummaryApprovalID); err != nil {
					return err
				}
				if err := textbridge.DisableProfile(cmd.Context(), dir, service); err != nil {
					return err
				}
				unlock, err = textbridge.LockProfilePolicy(cmd.Context(), dir)
				if err != nil {
					return err
				}
				defer unlock()
				r, err = loadFrozenSummaryReservation(dir, service)
				if err != nil {
					return err
				}
				r.Disabled = true
				return textbridge.SavePrivateJSON(dir, "frozen-summary-reservation.json", r)
			}
			_, profileErr := os.Lstat(filepath.Join(dir, "profile.json"))
			if errors.Is(profileErr, os.ErrNotExist) {
				state := "reserved"
				if r.Approving {
					state = "approval-incomplete"
				}
				if r.Disabled {
					state = "disabled"
				}
				return json.NewEncoder(cmd.OutOrStdout()).Encode(struct{ Service, State string }{service, state})
			}
			if profileErr != nil {
				return profileErr
			}
			p, err := textbridge.LoadProfile(dir, service)
			if err != nil {
				return err
			}
			if p.FrozenSummaryApprovalID == "" {
				return errors.New("reservation has an unexpected generic profile")
			}
			a, err := textbridge.LoadFrozenSummaryApproval(dir, p.FrozenSummaryApprovalID)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
				Service, State, ApprovalID string
				ProjectIDs                 []string
				CallsPerDay                int64
				CreatedAt, ExpiresAt       time.Time
				HistoricalSourceLabel      string `json:",omitempty"`
				Disabled, Expired          bool
			}{service, "approved", a.ID, a.ProjectIDs, a.CallsPerDay, a.CreatedAt, a.ExpiresAt, a.HistoricalSourceLabel, r.Disabled || p.Disabled || a.Disabled, !time.Now().Before(a.ExpiresAt)})
		}}
		sub.Flags().StringVar(&service, "service", "", "reserved service UUID")
		cmd.AddCommand(sub)
	}
	return cmd
}

func frozenSummaryNoProfile(dir string) error {
	for _, name := range []string{"profile.json", "ledger", "sdk", "frozen-summaries"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("reservation already has profile, approval or runtime state")
		}
	}
	return nil
}

// Owner checks use bounded, nonredirecting GETs and never disclose response bodies.
func frozenSummaryOwnerGet(ctx context.Context, owner *cliCtx, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(owner.base, "/")+"/api/v1"+path, nil)
	if err != nil {
		return errors.New("invalid frozen summary verification request")
	}
	req.Header.Set("Authorization", "Bearer "+owner.token)
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("frozen summary owner verification failed")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || resp.StatusCode != http.StatusOK || len(raw) > 1<<20 || json.Unmarshal(raw, out) != nil {
		return errors.New("frozen summary owner verification failed")
	}
	return nil
}

func verifyFrozenSummaryEnrollment(ctx context.Context, owner *cliCtx, service string, projects []string) error {
	var me struct {
		UserID   string `json:"userId"`
		TenantID string `json:"tenantId"`
	}
	if err := frozenSummaryOwnerGet(ctx, owner, "/auth/me", &me); err != nil {
		return err
	}
	if !textBridgeUUID(me.UserID) || !textBridgeUUID(me.TenantID) {
		return errors.New("frozen summary requires the personal service owner account")
	}
	var detail struct {
		Principal     struct{ ID, OwningTenantID, OwnershipScope, OwnerUserID, Kind string }
		CanManage     bool              `json:"canManage"`
		DiscoveryOnly bool              `json:"discoveryOnly"`
		Endpoints     []json.RawMessage `json:"endpoints"`
	}
	if err := frozenSummaryOwnerGet(ctx, owner, "/principals/"+service, &detail); err != nil {
		return err
	}
	p := detail.Principal
	if !detail.CanManage || detail.DiscoveryOnly || detail.Endpoints == nil || len(detail.Endpoints) != 0 || p.ID != service || p.Kind != "service" || p.OwnershipScope != "personal" || p.OwnerUserID != me.UserID || p.OwningTenantID != me.TenantID {
		return errors.New("frozen summary requires a personally owned service with no endpoint history")
	}
	for _, id := range projects {
		var project struct {
			ID                    string   `json:"id"`
			ContractVersion       string   `json:"contractVersion"`
			State                 string   `json:"state"`
			Role                  string   `json:"role"`
			IssuerTenantID        string   `json:"issuerTenantId"`
			RecipientTenantID     string   `json:"recipientTenantId"`
			IssuerPrincipalIDs    []string `json:"issuerPrincipalIds"`
			RecipientPrincipalIDs []string `json:"recipientPrincipalIds"`
		}
		if err := frozenSummaryOwnerGet(ctx, owner, "/sharing-projects/"+id, &project); err != nil {
			return err
		}
		if project.ID != id || project.ContractVersion != textbridge.SharingProjectContract || (project.State != "pending" && project.State != "enrolling") {
			return errors.New("frozen summary requires a pending or enrolling V2 project")
		}
		roster, other := project.IssuerPrincipalIDs, project.RecipientPrincipalIDs
		if project.Role == "recipient" && project.RecipientTenantID == me.TenantID {
			roster, other = other, roster
		} else if project.Role != "issuer" || project.IssuerTenantID != me.TenantID {
			return errors.New("frozen summary project owner does not match reservation")
		}
		found := 0
		seen := map[string]bool{}
		for _, member := range append(append([]string(nil), roster...), other...) {
			if !textBridgeUUID(member) || seen[member] {
				return errors.New("invalid frozen summary project roster")
			}
			seen[member] = true
		}
		for _, member := range roster {
			if member == service {
				found++
			}
		}
		if found != 1 {
			return errors.New("reserved service is not on the owner's project roster")
		}
	}
	return nil
}
