package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
	"github.com/pagnet-code/pagnet/internal/textbridge/senderipc"
	"github.com/spf13/cobra"
)

func textBridgeSenderAskUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value && id.Version() == 7 && id.Variant() == uuid.RFC4122
}
func textBridgeSenderBinding(p textbridge.Profile) senderipc.Binding {
	r := p.Registration
	return senderipc.Binding{Server: p.Server, TenantID: r.TenantID, OwnerUserID: r.OwnerUserID, HostID: r.HostID, InstallationID: r.InstallationID, ServiceID: p.Service}
}

type textBridgeSenderIntent struct {
	Binding                                     senderipc.Binding
	ProjectID, RecipientID, AskID, PromptDigest string
}

// Persist a complete immutable intent before contacting the daemon. Atomic link
// publication makes concurrent same-ID retries observe complete identical data;
// a conflicting tuple, unsafe path or incomplete file always fails closed.
func textBridgeSenderSaveIntent(state string, req senderipc.Request) error {
	if !textBridgeSenderAskUUID(req.AskID) {
		return sender.ErrInvalid
	}
	base, err := textbridge.ProfileBase(state)
	if err != nil {
		return err
	}
	root := filepath.Join(base, "sender-requests")
	dir := filepath.Join(root, req.AskID)
	if err := textbridge.PrivateDir(dir); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(req.Prompt))
	want := textBridgeSenderIntent{Binding: req.Binding, ProjectID: req.ProjectID, RecipientID: req.RecipientID, AskID: req.AskID, PromptDigest: hex.EncodeToString(sum[:])}
	temp, err := os.CreateTemp(dir, ".intent-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err = json.NewEncoder(temp).Encode(want); err == nil {
		err = temp.Sync()
	}
	closeErr := temp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	path := filepath.Join(dir, "intent.json")
	if err := os.Link(temp.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	raw, err := textbridge.ReadPrivate(path, 16384)
	if err != nil {
		return err
	}
	var got textBridgeSenderIntent
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&got) != nil || d.Decode(new(any)) != io.EOF || got != want {
		return sender.ErrConflict
	}
	for _, path := range []string{dir, root, base} {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		syncErr := f.Sync()
		closeErr := f.Close()
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func textBridgeSenderManaged(cmd *cobra.Command, state string, p textbridge.Profile, action, project, recipient, ask, file string, wait time.Duration) (sender.Operation, error) {
	r := p.Registration
	if action != "result" && (p.Disabled || r.Pending || r.DesiredState != "enabled") {
		return sender.Operation{}, errors.New("sender is disabled or registration is unconfirmed")
	}
	if action != "result" && wait > senderipc.MaxWait {
		return sender.Operation{}, errors.New("managed sender --wait must not exceed 5m")
	}
	req := senderipc.Request{Version: senderipc.Version, Binding: textBridgeSenderBinding(p), Action: action, ProjectID: project, AskID: ask}
	if action != "result" {
		req.WaitMillis = max(1, wait.Milliseconds())
	}
	if action == "ask" {
		prompt, err := textBridgeSenderInput(cmd.InOrStdin(), file)
		if err != nil {
			return sender.Operation{}, err
		}
		req.Prompt, req.RecipientID = prompt, recipient
		if req.AskID == "" {
			id, err := uuid.NewV7()
			if err != nil {
				return sender.Operation{}, err
			}
			req.AskID = id.String()
		}
		if err := textBridgeSenderSaveIntent(state, req); err != nil {
			return sender.Operation{}, err
		}
		if _, err := cmd.OutOrStdout().Write([]byte(req.AskID + "\n")); err != nil {
			return sender.Operation{}, err
		}
	}
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	operation, err := senderipc.Call(ctx, state, req)
	if err == nil || action != "result" {
		return operation, err
	}
	// Historical results may be read offline only after obtaining exclusive,
	// nonblocking ownership. Never open operation state under a live daemon lock.
	dir, dirErr := textbridge.ProfileDirectoryForRole(state, p.Service, "sender")
	if dirErr != nil {
		return sender.Operation{}, dirErr
	}
	unlock, lockErr := textbridge.LockProfile(dir)
	if lockErr != nil {
		return sender.Operation{}, senderipc.ErrUnavailable
	}
	defer unlock()
	current, loadErr := textBridgeSenderLoadProfile(dir, p.Service)
	if loadErr != nil {
		return sender.Operation{}, loadErr
	}
	if current.Registration == nil || textBridgeSenderBinding(current) != req.Binding {
		return sender.Operation{}, senderipc.ErrUnavailable
	}
	store, openErr := textbridge.OpenSenderStore(dir, current)
	if openErr != nil {
		return sender.Operation{}, openErr
	}
	defer store.Close()
	return store.Get(cmd.Context(), project, ask)
}
