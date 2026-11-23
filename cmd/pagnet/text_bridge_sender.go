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
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
	"github.com/pagnet-code/pagnet/sdk"
	"github.com/spf13/cobra"
)

type textBridgeCreatedService struct {
	ID         string `json:"id"`
	Credential string `json:"activationCredential"`
}

// Creation is deliberately one request, without redirects or reauthentication
// retries. Error responses and credentials are never included in diagnostics.
func textBridgeCreateService(ctx context.Context, owner *cliCtx, name string) (created textBridgeCreatedService, retErr error) {
	body, _ := json.Marshal(map[string]string{"name": name})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(owner.base, "/")+"/api/v1/service-recipes", bytes.NewReader(body))
	if err != nil {
		return created, errors.New("invalid service creation request")
	}
	req.Header.Set("Authorization", "Bearer "+owner.token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return created, errors.New("service creation outcome uncertain; inspect Services before creating another service")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32769))
	decodeErr := json.Unmarshal(raw, &created)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && textBridgeUUID(created.ID) {
		defer func() {
			if retErr != nil {
				retErr = fmt.Errorf("service %s was created but local setup failed; inspect this service in Services before retrying: %w", created.ID, retErr)
			}
		}()
	}
	if err != nil || len(raw) > 32768 || resp.StatusCode < 200 || resp.StatusCode >= 300 || decodeErr != nil || !textBridgeUUID(created.ID) || created.Credential == "" {
		return created, errors.New("service creation did not return a usable setup; inspect Services before creating another service")
	}
	return created, nil
}

type textBridgeSenderProfile = textbridge.Profile

type textBridgeSenderConnection interface {
	sender.Connection
	Close() error
}

type textBridgeSenderDependencies struct {
	owner   func() (*cliCtx, error)
	connect func(context.Context, sdk.Config) (textBridgeSenderConnection, error)
}

func textBridgeSenderCmd(stateDir *string, deps textBridgeSenderDependencies) *cobra.Command {
	if deps.connect == nil {
		deps.connect = func(ctx context.Context, c sdk.Config) (textBridgeSenderConnection, error) {
			return sdk.Connect(ctx, c)
		}
	}
	cmd := &cobra.Command{Use: "sender", Short: "Send text from a separate personal service", Args: cobra.NoArgs}
	var name, projectContract string
	create := &cobra.Command{Use: "create", Short: "Create a sender service and private local profile", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) (retErr error) {
		if err := textBridgeValidateProjectContract(projectContract); err != nil {
			return err
		}
		if strings.TrimSpace(name) == "" {
			return errors.New("--name is required")
		}
		base, err := textbridge.ProfileBase(*stateDir)
		if err != nil {
			return err
		}
		base = filepath.Join(base, "senders")
		if err = textbridge.PrivateDir(base); err != nil {
			return err
		}
		// Establish durable local storage before creating a remote service.
		probe, err := os.CreateTemp(base, ".preflight-*")
		if err != nil {
			return errors.New("sender state directory is not writable")
		}
		writeErr, closeErr := probe.Sync(), probe.Close()
		removeErr := os.Remove(probe.Name())
		if writeErr != nil || closeErr != nil || removeErr != nil {
			return errors.New("sender state directory cannot persist local setup")
		}
		owner, err := deps.owner()
		if err != nil {
			return err
		}
		created, err := textBridgeCreateService(cmd.Context(), owner, name)
		if err != nil {
			return err
		}
		defer func() {
			if retErr != nil {
				retErr = fmt.Errorf("service %s was created but local sender setup failed; inspect Services before retrying: %w", created.ID, retErr)
			}
		}()
		p := textBridgeSenderProfile{Role: "sender", Service: created.ID, Server: owner.base, Credential: created.Credential}
		if cmd.Flags().Changed("project-contract") {
			p.ProjectContract = projectContract
		}
		if err := (sdk.Config{Server: p.Server, Credential: p.Credential, ExpectedPrincipalID: p.Service}).Validate(); err != nil {
			return errors.New("created sender has invalid connection configuration")
		}
		dir := filepath.Join(base, p.Service)
		if err := textbridge.PrivateDir(dir); err != nil {
			return err
		}
		unlock, err := textbridge.LockProfile(dir)
		if err != nil {
			return err
		}
		defer unlock()
		if _, err := os.Lstat(filepath.Join(dir, "profile.json")); !errors.Is(err, os.ErrNotExist) {
			return errors.New("sender profile already exists or cannot be inspected")
		}
		store, err := sender.Open(filepath.Join(dir, "operations"), p.SenderBinding())
		if err != nil {
			return err
		}
		if err := store.Close(); err != nil {
			return err
		}
		if err := textbridge.SavePrivateJSON(dir, "profile.json", p); err != nil {
			return errors.New("sender profile could not be saved")
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), p.Service)
		return err
	}}
	create.Flags().StringVar(&projectContract, "project-contract", textbridge.SharingProjectContract, "project contract: sdk_project_v2 or owner_text_project_v1")
	create.Flags().StringVar(&name, "name", "", "personal sender service name")
	cmd.AddCommand(create)
	for _, action := range []string{"ask", "resume", "result"} {
		action := action
		var service, project, recipient, ask, file string
		var wait time.Duration
		sub := &cobra.Command{Use: action, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			if !textBridgeUUID(service) || !textBridgeUUID(project) {
				return errors.New("--service and --project must be UUIDs")
			}
			if action == "ask" && !textBridgeUUID(recipient) {
				return errors.New("--to must be a recipient UUID")
			}
			if (action != "ask" || ask != "") && !textBridgeSenderAskUUID(ask) {
				return errors.New("--ask must be an ASK UUID")
			}
			if action != "result" && wait <= 0 {
				return errors.New("--wait must be a positive duration")
			}
			base, err := textbridge.ProfileBase(*stateDir)
			if err != nil {
				return err
			}
			dir := filepath.Join(base, "senders", service)
			if err := textbridge.PrivateDir(dir); err != nil {
				return err
			}
			p, err := textBridgeSenderLoadProfile(dir, service)
			if err != nil {
				return err
			}
			managed := func() error {
				operation, err := textBridgeSenderManaged(cmd, filepath.Dir(base), p, action, project, recipient, ask, file, wait)
				if err != nil {
					return err
				}
				if action == "result" {
					return json.NewEncoder(cmd.OutOrStdout()).Encode(operation)
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), operation.Reply.Text)
				return err
			}
			if p.Registration != nil {
				return managed()
			}
			if p.ProjectContract == textbridge.OwnerTextProjectContract && action != "result" {
				return errors.New("owner project sender requires confirmed managed installation registration")
			}
			unlock, err := textbridge.LockProfile(dir)
			if err != nil {
				return err
			}
			// Registration may have completed after the first unlocked read. Never
			// connect a foreground SDK after acquiring a newly registered profile.
			p, err = textBridgeSenderLoadProfile(dir, service)
			if err != nil {
				unlock()
				return err
			}
			if p.Registration != nil {
				unlock()
				return managed()
			}
			if p.ProjectContract == textbridge.OwnerTextProjectContract && action != "result" {
				unlock()
				return errors.New("owner project sender requires confirmed managed installation registration")
			}
			defer unlock()
			if action != "result" && p.Disabled {
				return errors.New("sender is disabled")
			}
			// A saved profile must never recreate missing deduplication state.
			if _, err := textbridge.ReadPrivate(filepath.Join(dir, "operations", "state"), 64<<20); err != nil {
				return errors.New("saved sender operation state is missing or inaccessible")
			}
			store, err := sender.Open(filepath.Join(dir, "operations"), p.SenderBinding())
			if err != nil {
				return err
			}
			defer store.Close()
			var operation sender.Operation
			if action == "ask" {
				prompt, inputErr := textBridgeSenderInput(cmd.InOrStdin(), file)
				if inputErr != nil {
					return inputErr
				}
				if ask == "" {
					operation, err = store.Reserve(cmd.Context(), project, recipient, prompt)
				} else {
					operation, err = store.ReserveWithID(cmd.Context(), project, recipient, ask, prompt)
				}
				if err != nil {
					return err
				}
				// The stable ID is available even when connect/prepare/send fails.
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), operation.AskID); err != nil {
					return err
				}
			} else {
				operation, err = store.Get(cmd.Context(), project, ask)
				if err != nil {
					return err
				}
			}
			if action == "result" {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(operation)
			}
			if operation.Phase == sender.Admitted && operation.Reply != nil {
				_, err := fmt.Fprintln(cmd.OutOrStdout(), operation.Reply.Text)
				return err
			}
			if err := textbridge.PrivateDir(filepath.Join(dir, "sdk")); err != nil {
				return err
			}
			operation, err = textBridgeSenderRun(cmd.Context(), dir, p, store, operation, wait, deps)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), operation.Reply.Text)
			return err
		}}
		sub.Flags().StringVar(&service, "service", "", "saved sender service UUID")
		sub.Flags().StringVar(&project, "project", "", "sharing project UUID")
		if action == "ask" {
			sub.Flags().StringVar(&ask, "ask", "", "retry an existing durable ASK UUID")
			sub.Flags().StringVar(&recipient, "to", "", "recipient service UUID")
			sub.Flags().StringVar(&file, "file", "-", "UTF-8 prompt file, or - for stdin")
		} else {
			sub.Flags().StringVar(&ask, "ask", "", "durable ASK UUID")
		}
		if action != "result" {
			sub.Flags().DurationVar(&wait, "wait", 60*time.Second, "maximum foreground duration including connection and reply wait")
		}
		cmd.AddCommand(sub)
	}
	return cmd
}

func textBridgeSenderLoadProfile(dir, service string) (textBridgeSenderProfile, error) {
	p, err := textbridge.LoadProfile(dir, service)
	if err != nil {
		return p, err
	}
	if p.ServiceRole() != "sender" {
		return p, errors.New("invalid local sender profile")
	}
	return p, nil
}

func textBridgeSenderInput(stdin io.Reader, file string) (string, error) {
	input := stdin
	if file != "" && file != "-" {
		f, err := os.Open(file)
		if err != nil {
			return "", errors.New("prompt file unavailable")
		}
		defer f.Close()
		input = f
	}
	raw, err := io.ReadAll(io.LimitReader(input, sender.MaxPromptChars*utf8.UTFMax+1))
	if err != nil || len(raw) > sender.MaxPromptChars*utf8.UTFMax || !utf8.Valid(raw) || utf8.RuneCount(raw) > sender.MaxPromptChars || strings.TrimSpace(string(raw)) == "" {
		return "", errors.New("prompt must contain 1 to 16000 UTF-8 characters")
	}
	return string(raw), nil
}

func textBridgeSenderReply(ctx context.Context, store *sender.Store, principal string, message sdk.SharingProjectMessage) (sender.Operation, error) {
	return sender.RecordReply(ctx, store, principal, message)
}

func textBridgeSenderRun(parent context.Context, dir string, p textBridgeSenderProfile, store *sender.Store, operation sender.Operation, wait time.Duration, deps textBridgeSenderDependencies) (sender.Operation, error) {
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	conn, err := deps.connect(ctx, sdk.Config{Server: p.Server, Credential: p.Credential, StateDir: filepath.Join(dir, "sdk"), ExpectedPrincipalID: p.Service})
	if err != nil {
		return operation, errors.New("sender service connection failed; resume the saved ASK")
	}
	defer conn.Close()
	return sender.Run(ctx, conn, store, p.Service, operation)
}
