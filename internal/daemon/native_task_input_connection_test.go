package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

func TestOriginalTaskInputReadCannotMoveSourceOrEpoch(t *testing.T) {
	for _, scenario := range []string{"original", "command", "admission", "instance", "epoch", "aad", "disconnect", "unsupported"} {
		t.Run(scenario, func(t *testing.T) {
			task := domain.NewID().String()
			instance := domain.NewID().String()
			command := domain.NewID().String()
			admission := domain.NewID().String()
			aad := e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: domain.NewID().String(), NetworkID: domain.NewID().String(), ObjectID: task, ObjectType: e2ee.ObjectTypeTask, KeyEpochID: domain.NewID().String()}
			envelope, err := e2ee.Encrypt([]byte("private original task"), [32]byte{1}, aad)
			if err != nil {
				t.Fatal(err)
			}
			original := &transport.NativeTaskSource{TaskID: task, InputAAD: aad}
			var c *NativeObservationConnection
			c, _ = deliveryFixture(t, func(ctx context.Context, typ string, value any) error {
				if typ != transport.MsgNativeTaskInput {
					t.Fatal("foreign message", typ)
				}
				req := value.(transport.NativeTaskInputPayload)
				source := *original
				env := envelope
				reply := transport.NativeTaskInputReadPayload{RequestID: req.RequestID, InstanceID: req.InstanceID, SourceCommandID: req.SourceCommandID, SourceAdmissionID: req.SourceAdmissionID, TaskSource: &source, Envelope: &env}
				switch scenario {
				case "command":
					reply.SourceCommandID = domain.NewID().String()
				case "admission":
					reply.SourceAdmissionID = domain.NewID().String()
				case "instance":
					reply.InstanceID = domain.NewID().String()
				case "epoch":
					env.KeyEpochID = domain.NewID().String()
				case "aad":
					source.InputAAD.Sender = "foreign"
				case "disconnect":
					c.Close()
				}
				c.NativeTaskInputDisposition(reply)
				return nil
			})
			if scenario != "unsupported" {
				c.session.ProtocolFeatures = append(c.session.ProtocolFeatures, transport.NativeTaskContentProtocol)
			}
			reply, err := c.ReadOriginalTaskInput(t.Context(), instance, command, admission, original)
			if scenario == "original" {
				if err != nil || reply.Envelope == nil {
					t.Fatal("original input rejected", err)
				}
			} else if err == nil {
				t.Fatal("source/epoch substitution accepted", scenario)
			}
			if scenario == "unsupported" && !errors.Is(err, ErrNativeSourceUnsupported) {
				t.Fatal("unsupported protocol relabeled", err)
			}
			c.mu.Lock()
			count := c.pendingCountLocked()
			c.mu.Unlock()
			if count != 0 {
				t.Fatal("RPC slot leaked", count)
			}
		})
	}
}
