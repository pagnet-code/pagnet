package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/netpolicy"
	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type textBridgeInstallation struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenantId"`
	OwnerUserID    string    `json:"ownerUserId"`
	ServiceID      string    `json:"serviceId"`
	HostID         string    `json:"hostId"`
	Role           string    `json:"role"`
	ProfileVersion int       `json:"profileVersion"`
	DesiredState   string    `json:"desiredState"`
	Generation     int64     `json:"generation"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

func textBridgeRegisterCmd(stateDir *string, deps textBridgeDependencies) *cobra.Command {
	if deps.registrationContext == nil {
		deps.registrationContext = func() (*cliCtx, error) { return newCLIContext("") }
	}
	if deps.registrationAuthenticate == nil {
		deps.registrationAuthenticate = authenticateCLI
	}
	var service string
	cmd := &cobra.Command{Use: "register", Short: "Register an enabled local responder on the enrolled host", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		dir, err := textbridge.ProfileDirectory(*stateDir, service)
		if err != nil {
			return err
		}
		unlock, err := textbridge.LockProfile(dir)
		if err != nil {
			return err
		}
		defer unlock()
		p, err := textbridge.LoadProfile(dir, service)
		if err != nil {
			return err
		}
		if p.Disabled {
			return errors.New("text bridge is disabled; registration requires an enabled responder")
		}
		store, err := textbridge.OpenProfileLedger(dir, p)
		if err != nil {
			return err
		}
		defer store.Close()
		budget, err := store.BudgetSnapshot(cmd.Context())
		if err != nil {
			return err
		}
		if !budget.Enabled {
			return errors.New("text bridge is disabled; registration requires an enabled responder")
		}
		// Resolve config without loading or validating an owner token. In
		// particular, an overridden URL must be rejected before bearerMe.
		owner, err := deps.registrationContext()
		if err != nil {
			return errors.New("registration requires an enrolled active account and owner sign-in")
		}
		server, err := textBridgeRegistrationAccount(owner, p.Server)
		if err != nil {
			return err
		}
		if p.Registration != nil && p.Registration.HostID != owner.cfg.HostID {
			return errors.New("saved registration belongs to a different enrolled host; select its account before retrying")
		}
		owner.base = server
		if err := deps.registrationAuthenticate(owner); err != nil {
			return errors.New("registration requires owner sign-in for the matching enrolled account")
		}
		if owner.principal || strings.TrimSpace(owner.token) == "" || owner.token == owner.cfg.Credential || strings.HasPrefix(owner.token, "pgn_act_") || strings.HasPrefix(owner.token, "pgn_epd_") || strings.HasPrefix(owner.token, "pgn_host_") {
			return errors.New("registration requires an owner user token for the matching enrolled account")
		}
		if p.Registration == nil {
			p.Registration = &textbridge.ProfileRegistration{InstallationID: uuid.NewString(), HostID: owner.cfg.HostID, Role: "responder", ProfileVersion: 1, Pending: true}
		}
		// Persist the immutable retry tuple before any owner-authenticated PUT. An
		// interrupted or uncertain request must never cause a replacement ID.
		p.Registration.Pending = true
		if err := textbridge.SaveProfile(dir, p); err != nil {
			return errors.New("registration pending state could not be saved; no registration request was sent")
		}
		installation, err := textBridgePutInstallation(cmd.Context(), server, owner.token, p)
		retry := fmt.Sprintf("installation %s registration unconfirmed; retry pagnet text-bridge register --service %s to reconcile; pending daemon verification", p.Registration.InstallationID, p.Service)
		if err != nil {
			return errors.New(retry)
		}
		if !textBridgeRegistrationResponse(p, installation) {
			return fmt.Errorf("%s; server response did not match the saved registration", retry)
		}
		r := p.Registration
		r.TenantID, r.OwnerUserID = installation.TenantID, installation.OwnerUserID
		r.Generation, r.DesiredState, r.Pending = installation.Generation, installation.DesiredState, false
		var disableErr error
		if installation.DesiredState == "disabled" {
			p.Disabled = true
			disableErr = store.SetEnabled(cmd.Context(), false)
		}
		// Always persist the disabled profile even if disabling the ledger
		// failed; either local gate prevents dispatch after remote disable.
		saveErr := textbridge.SaveProfile(dir, p)
		if disableErr != nil || saveErr != nil {
			return errors.New(retry + "; confirmed response could not be fully applied locally; inspect text-bridge status")
		}
		fmt.Fprintf(cmd.OutOrStdout(), "service %s installation %s host %s: %s; pending daemon verification\n", p.Service, r.InstallationID, r.HostID, r.DesiredState)
		return nil
	}}
	cmd.Flags().StringVar(&service, "service", "", "existing local responder service UUID")
	return cmd
}

// The host enrollment must be persisted in the active context, including for
// legacy flat configurations. Environment and flag overrides cannot retarget it.
func textBridgeRegistrationAccount(owner *cliCtx, profileServer string) (string, error) {
	if owner == nil || owner.principal || isWorkerDir(owner.stateDir) || !textBridgeUUID(owner.cfg.HostID) || owner.cfg.Credential == "" {
		return "", errors.New("registration requires an enrolled active account and owner sign-in")
	}
	raw, err := os.ReadFile(filepath.Join(accountConfigDir(owner.stateDir, owner.account), "config.yaml"))
	var persisted struct {
		ServerURL  string `yaml:"serverUrl"`
		HostID     string `yaml:"hostId"`
		Credential string `yaml:"credential"`
	}
	if err != nil || yaml.Unmarshal(raw, &persisted) != nil || persisted.HostID != owner.cfg.HostID || persisted.Credential == "" || persisted.Credential != owner.cfg.Credential {
		return "", errors.New("registration requires a verified persisted host enrollment for the active account")
	}
	server, err := textBridgeRegistrationServer(profileServer)
	if err != nil {
		return "", errors.New("invalid saved registration server")
	}
	for _, candidate := range []string{owner.base, owner.cfg.ServerURL, persisted.ServerURL} {
		normalized, err := textBridgeRegistrationServer(candidate)
		if err != nil || normalized != server {
			return "", errors.New("saved profile and active account host enrollment use different servers; select the matching account")
		}
	}
	return server, nil
}

func textBridgeRegistrationServer(server string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(server))
	if err != nil {
		return "", errors.New("invalid server URL")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("invalid server URL")
	}
	escapedPath := strings.ToLower(u.EscapedPath())
	if strings.Contains(escapedPath, "%2f") || strings.Contains(escapedPath, "%5c") || strings.Contains(u.Path, "\\") {
		return "", errors.New("invalid server URL")
	}
	hostname, port := strings.ToLower(u.Hostname()), u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		u.Host = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		u.Host = "[" + hostname + "]"
	} else {
		u.Host = hostname
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = strings.TrimRight(u.RawPath, "/")
	return u.String(), nil
}

func textBridgeRegistrationResponse(p textbridge.Profile, v textBridgeInstallation) bool {
	r := p.Registration
	return v.ID == r.InstallationID && v.ServiceID == p.Service && v.HostID == r.HostID && v.Role == r.Role && v.ProfileVersion == r.ProfileVersion && textBridgeUUID(v.TenantID) && textBridgeUUID(v.OwnerUserID) && v.Generation >= 1 && v.Generation >= r.Generation && (v.DesiredState == "enabled" || v.DesiredState == "disabled") && (r.TenantID == "" || v.TenantID == r.TenantID) && (r.OwnerUserID == "" || v.OwnerUserID == r.OwnerUserID) && (r.DesiredState != "disabled" || v.DesiredState == "disabled")
}

func textBridgePutInstallation(ctx context.Context, server, token string, p textbridge.Profile) (textBridgeInstallation, error) {
	var out textBridgeInstallation
	body, _ := json.Marshal(struct {
		ServiceID      string `json:"serviceId"`
		HostID         string `json:"hostId"`
		Role           string `json:"role"`
		ProfileVersion int    `json:"profileVersion"`
	}{p.Service, p.Registration.HostID, p.Registration.Role, p.Registration.ProfileVersion})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, server+"/api/v1/sharing/text-services/installations/"+p.Registration.InstallationID, bytes.NewReader(body))
	if err != nil {
		return out, errors.New("invalid registration request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := netpolicy.NewHTTPClient(15*time.Second, insecureRemoteHTTP)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return out, errors.New("registration outcome unconfirmed")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32769))
	if err != nil || len(raw) > 32768 || resp.StatusCode < 200 || resp.StatusCode >= 300 || json.Unmarshal(raw, &out) != nil {
		return textBridgeInstallation{}, errors.New("registration response unconfirmed")
	}
	return out, nil
}
