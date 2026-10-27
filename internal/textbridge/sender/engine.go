package sender

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/pagnet-code/pagnet/sdk"
)

// Connection is the authenticated SDK connection used by the sender engine.
// Message callbacks must receive only SDK-authenticated and validated messages.
type Connection interface {
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
}

// RecordReply durably records an authenticated correlated reply before its SDK
// callback may return nil and acknowledge delivery.
func RecordReply(ctx context.Context, store *Store, principal string, message sdk.SharingProjectMessage) (Operation, error) {
	h := message.Header
	if h.Kind != "REPLY" || h.CorrelationID == nil || h.ThreadID != *h.CorrelationID || h.RecipientPrincipalID != principal || len(message.Wire) == 0 {
		return Operation{}, errors.New("sender requires an authenticated correlated REPLY")
	}
	sum := sha256.Sum256(message.Wire)
	return store.RecordReply(ctx, Reply{ProjectID: h.ProjectID, AskID: *h.CorrelationID, ReplyID: h.ID, WireDigest: hex.EncodeToString(sum[:]), SenderID: h.SenderPrincipalID, RecipientID: h.RecipientPrincipalID, Text: string(message.Plaintext)})
}

// Run reconciles one saved ASK and waits for its durable reply. The caller owns
// the connection, context deadline and Store lock. Run installs the connection's
// project callbacks, so the connection must be dedicated to this run.
func Run(ctx context.Context, conn Connection, store *Store, principal string, operation Operation) (Operation, error) {
	identity, err := conn.WhoAmI(ctx)
	if err != nil || identity == nil || identity.Kind != "service" || identity.PrincipalID != principal {
		return operation, errors.New("sender authenticated identity does not match saved service")
	}
	// SDK admission retires ciphertext before this store can record the receipt.
	// Reconcile historical evidence before waiting for active project authority.
	if operation.Phase == Prepared {
		if receipt, receiptErr := conn.SharingProjectMessageReceipt(ctx, operation.ProjectID, operation.AskID); receiptErr == nil {
			operation, err = store.MarkAdmitted(ctx, operation.ProjectID, operation.AskID, receipt)
			if err != nil {
				return operation, err
			}
		}
	}
	if operation.Phase == Admitted && operation.Reply != nil {
		return operation, nil
	}
	ready, received := make(chan struct{}, 1), make(chan struct{}, 1)
	callbackErrors := make(chan error, 1)
	projectID, askID := operation.ProjectID, operation.AskID
	conn.OnSharingProjectMessage(func(callbackCtx context.Context, message sdk.SharingProjectMessage) error {
		if message.Header.Kind != "REPLY" {
			return nil // A sender service never dispatches incoming ASK work.
		}
		o, err := RecordReply(callbackCtx, store, principal, message)
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
			operation, err = Reconcile(ctx, conn, store, operation)
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
		if operation.Phase == Admitted && operation.Reply != nil {
			return operation, nil
		}
	}
}

// Reconcile advances a saved ASK using durable SDK ciphertext and receipts.
// The caller must authenticate the connection for the Store binding and wait
// for SDK project readiness. A preparing ASK
// without ciphertext remains unresolved and is never prepared again.
func Reconcile(ctx context.Context, conn Connection, store *Store, operation Operation) (Operation, error) {
	operation, err := store.Get(ctx, operation.ProjectID, operation.AskID)
	if err != nil {
		return operation, err
	}
	if operation.Phase == Admitted {
		return operation, nil
	}
	if operation.Phase == Prepared {
		if receipt, receiptErr := conn.SharingProjectMessageReceipt(ctx, operation.ProjectID, operation.AskID); receiptErr == nil {
			return store.MarkAdmitted(ctx, operation.ProjectID, operation.AskID, receipt)
		}
	}
	status, err := conn.SharingProjectStatus(ctx, operation.ProjectID)
	if err != nil || status.ProjectID != operation.ProjectID || status.State != "active" || !status.EndpointProved {
		return operation, errors.New("sender project is not ready; resume the saved ASK after enrollment")
	}
	var prepared sdk.PreparedSharingProjectMessage
	if operation.Phase == Reserved {
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
