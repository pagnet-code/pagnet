package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

type textBridgeSenderProfile struct{ Service, Server, Credential string }

type textBridgeSenderConnection interface {
	WhoAmI(context.Context) (*sdk.Identity, error)
	SharingProjectStatus(context.Context, string) (sdk.SharingProjectStatus, error)
	PrepareSharingProjectMessageWithID(string, string, string, string, []byte, []byte) (sdk.PreparedSharingProjectMessage, error)
	LoadPreparedSharingProjectMessage(string, string) (sdk.PreparedSharingProjectMessage, error)
	SharingProjectMessageReceipt(context.Context, string, string) (sdk.SharingProjectMessageReceipt, error)
	SendPreparedSharingProjectMessage(context.Context, string, string) (sdk.SharingProjectMessageReceipt, error)
	OnSharingProjectMessage(func(context.Context, sdk.SharingProjectMessage) error)
	OnSharingProjectReady(func(string))
	EnableSharingProjects()
	Done() <-chan struct{}
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
	var name string
	create := &cobra.Command{Use: "create", Short: "Create a sender service and private local profile", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) (retErr error) {
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
		p := textBridgeSenderProfile{Service: created.ID, Server: owner.base, Credential: created.Credential}
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
		store, err := sender.Open(filepath.Join(dir, "operations"), sender.Binding{ServiceOrigin: p.Server, PrincipalID: p.Service})
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
			if action != "ask" && !textBridgeUUID(ask) {
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
			unlock, err := textbridge.LockProfile(dir)
			if err != nil {
				return err
			}
			defer unlock()
			p, err := textBridgeSenderLoadProfile(dir, service)
			if err != nil {
				return err
			}
			// A saved profile must never recreate missing deduplication state.
			if _, err := textbridge.ReadPrivate(filepath.Join(dir, "operations", "state"), 64<<20); err != nil {
				return errors.New("saved sender operation state is missing or inaccessible")
			}
			store, err := sender.Open(filepath.Join(dir, "operations"), sender.Binding{ServiceOrigin: p.Server, PrincipalID: p.Service})
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
				operation, err = store.Reserve(cmd.Context(), project, recipient, prompt)
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
	var p textBridgeSenderProfile
	raw, err := textbridge.ReadPrivate(filepath.Join(dir, "profile.json"), 32768)
	if err != nil {
		return p, errors.New("sender profile unavailable")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Service != service {
		return p, errors.New("invalid local sender profile")
	}
	if err := (sdk.Config{Server: p.Server, Credential: p.Credential, ExpectedPrincipalID: service}).Validate(); err != nil {
		return p, errors.New("invalid local sender connection profile")
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
	h := message.Header
	if h.Kind != "REPLY" || h.CorrelationID == nil || h.ThreadID != *h.CorrelationID || h.RecipientPrincipalID != principal || len(message.Wire) == 0 {
		return sender.Operation{}, errors.New("sender requires an authenticated correlated REPLY")
	}
	sum := sha256.Sum256(message.Wire)
	return store.RecordReply(ctx, sender.Reply{ProjectID: h.ProjectID, AskID: *h.CorrelationID, ReplyID: h.ID, WireDigest: hex.EncodeToString(sum[:]), SenderID: h.SenderPrincipalID, RecipientID: h.RecipientPrincipalID, Text: string(message.Plaintext)})
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
	identity, err := conn.WhoAmI(ctx)
	if err != nil || identity == nil || identity.Kind != "service" || identity.PrincipalID != p.Service {
		return operation, errors.New("sender authenticated identity does not match saved service")
	}
	// SDK admission retires ciphertext before this store can record the receipt.
	// Reconcile historical evidence before waiting for active project authority.
	if operation.Phase == sender.Prepared {
		if receipt, receiptErr := conn.SharingProjectMessageReceipt(ctx, operation.ProjectID, operation.AskID); receiptErr == nil {
			operation, err = store.MarkAdmitted(ctx, operation.ProjectID, operation.AskID, receipt)
			if err != nil {
				return operation, err
			}
		}
	}
	if operation.Phase == sender.Admitted && operation.Reply != nil {
		return operation, nil
	}
	ready, received := make(chan struct{}, 1), make(chan struct{}, 1)
	callbackErrors := make(chan error, 1)
	projectID, askID := operation.ProjectID, operation.AskID
	conn.OnSharingProjectMessage(func(callbackCtx context.Context, message sdk.SharingProjectMessage) error {
		if message.Header.Kind != "REPLY" {
			return nil // A sender service never dispatches incoming ASK work.
		}
		o, err := textBridgeSenderReply(callbackCtx, store, p.Service, message)
		if err != nil {
			if message.Header.ProjectID == projectID && message.Header.CorrelationID != nil && *message.Header.CorrelationID == askID {
				select {
				case callbackErrors <- errors.New("sender could not persist an authenticated reply; inbox delivery remains pending"):
				default:
				}
			}
			return err
		}
		if o.ProjectID == projectID && o.AskID == askID {
			select {
			case received <- struct{}{}:
			default:
			}
		}
		return nil // Durable reply commit precedes the SDK's ACK.
	})
	conn.OnSharingProjectReady(func(project string) {
		if project == projectID {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
	})
	conn.EnableSharingProjects()
	for {
		select {
		case <-ready:
			operation, err = textBridgeSenderReconcile(ctx, conn, store, operation)
			if err != nil {
				return operation, err
			}
		case <-received:
			operation, err = store.Get(ctx, operation.ProjectID, operation.AskID)
			if err != nil {
				return operation, err
			}
		case err := <-callbackErrors:
			return operation, err
		case <-conn.Done():
			return operation, errors.New("sender connection ended; resume the saved ASK")
		case <-ctx.Done():
			return operation, fmt.Errorf("sender wait ended; resume or inspect the saved ASK: %w", ctx.Err())
		}
		if operation.Phase == sender.Admitted && operation.Reply != nil {
			return operation, nil
		}
	}
}

func textBridgeSenderReconcile(ctx context.Context, conn textBridgeSenderConnection, store *sender.Store, operation sender.Operation) (sender.Operation, error) {
	operation, err := store.Get(ctx, operation.ProjectID, operation.AskID)
	if err != nil {
		return operation, err
	}
	if operation.Phase == sender.Admitted {
		return operation, nil
	}
	if operation.Phase == sender.Prepared {
		if receipt, receiptErr := conn.SharingProjectMessageReceipt(ctx, operation.ProjectID, operation.AskID); receiptErr == nil {
			return store.MarkAdmitted(ctx, operation.ProjectID, operation.AskID, receipt)
		}
	}
	status, err := conn.SharingProjectStatus(ctx, operation.ProjectID)
	if err != nil || status.ProjectID != operation.ProjectID || status.State != "active" || !status.EndpointProved {
		return operation, errors.New("sender project is not ready; resume the saved ASK after enrollment")
	}
	var prepared sdk.PreparedSharingProjectMessage
	if operation.Phase == sender.Reserved {
		prompt, promptErr := store.RecoverPrompt(ctx, operation.ProjectID, operation.AskID)
		if promptErr != nil {
			return operation, promptErr
		}
		operation, err = store.MarkPreparing(ctx, operation.ProjectID, operation.AskID)
		if err != nil {
			return operation, err
		}
		prepared, err = conn.PrepareSharingProjectMessageWithID(operation.ProjectID, operation.RecipientID, "ASK", operation.AskID, []byte(prompt), nil)
		if err != nil {
			prepared, err = conn.LoadPreparedSharingProjectMessage(operation.ProjectID, operation.AskID)
		}
	} else {
		prepared, err = conn.LoadPreparedSharingProjectMessage(operation.ProjectID, operation.AskID)
	}
	if err != nil {
		return operation, errors.New("saved ASK has no recoverable prepared ciphertext; preparation outcome remains unresolved and must not be prepared again")
	}
	operation, err = store.MarkPrepared(ctx, operation.ProjectID, operation.AskID, prepared)
	if err != nil {
		return operation, err
	}
	receipt, err := conn.SharingProjectMessageReceipt(ctx, operation.ProjectID, operation.AskID)
	if err != nil {
		receipt, err = conn.SendPreparedSharingProjectMessage(ctx, operation.ProjectID, operation.AskID)
		if err != nil {
			return operation, errors.New("sender admission outcome unresolved; resume the same saved ASK")
		}
	}
	return store.MarkAdmitted(ctx, operation.ProjectID, operation.AskID, receipt)
}
