package daemon

import (
	"context"

	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
)

// TextSender is an in-process handle to one proved installation and project.
// It remains pinned to that runtime: callers must resolve a fresh handle after
// fencing or reconnect. No caller-supplied filesystem or connection data is used.
type TextSender struct {
	controller *sender.Controller
	project    string
}

// TextSenderOperation contains only text-service data safe for local UI callers.
type TextSenderOperation struct {
	ProjectID    string           `json:"projectId"`
	AskID        string           `json:"askId"`
	RecipientID  string           `json:"recipientId"`
	PromptDigest string           `json:"promptDigest"`
	Phase        sender.Phase     `json:"phase"`
	Admitted     bool             `json:"admitted"`
	Reply        *TextSenderReply `json:"reply,omitempty"`
}

type TextSenderReply struct {
	ID          string `json:"id"`
	SenderID    string `json:"senderId"`
	RecipientID string `json:"recipientId"`
	Text        string `json:"text"`
}

// TextSender resolves the current local profile through its installation. A
// handle is published only after the native claim and exact SDK endpoint proof.
func (d *Daemon) TextSender(ctx context.Context, installation, project string) (*TextSender, error) {
	if !textServiceUUID(installation) || !textServiceUUID(project) {
		return nil, sender.ErrInvalid
	}
	s := d.textServices
	if s == nil {
		return nil, sender.ErrDisabled
	}
	s.mu.Lock()
	r := s.running[installation]
	var controller *sender.Controller
	if r != nil && r.client == s.client && r.enabled.Load() {
		controller = r.controller
	}
	s.mu.Unlock()
	if controller == nil {
		return nil, sender.ErrDisabled
	}
	if _, err := controller.Revision(ctx, project); err != nil {
		return nil, err
	}
	return &TextSender{controller: controller, project: project}, nil
}

func textSenderProjection(o sender.Operation) TextSenderOperation {
	result := TextSenderOperation{ProjectID: o.ProjectID, AskID: o.AskID, RecipientID: o.RecipientID, PromptDigest: o.PromptDigest, Phase: o.Phase, Admitted: o.Receipt != nil}
	if o.Reply != nil {
		result.Reply = &TextSenderReply{ID: o.Reply.ReplyID, SenderID: o.Reply.SenderID, RecipientID: o.Reply.RecipientID, Text: o.Reply.Text}
	}
	return result
}

// Submit requires the caller's stable ASK UUID; retries with changed content
// return the durable store's conflict error instead of creating another ASK.
func (s *TextSender) Submit(ctx context.Context, ask, recipient, prompt string) (TextSenderOperation, error) {
	o, err := s.controller.ReserveWithID(ctx, s.project, recipient, ask, prompt)
	return textSenderProjection(o), err
}

func (s *TextSender) Read(ctx context.Context, ask string) (TextSenderOperation, error) {
	o, err := s.controller.Get(ctx, s.project, ask)
	return textSenderProjection(o), err
}

func (s *TextSender) Resume(ctx context.Context, ask string) (TextSenderOperation, error) {
	o, err := s.controller.Resume(ctx, s.project, ask)
	return textSenderProjection(o), err
}

// List returns at most limit operations (1..100), ordered by ASK UUID, after
// the optional exclusive ASK cursor. Reply text is available only through Read.
func (s *TextSender) List(ctx context.Context, after string, limit int) ([]TextSenderOperation, error) {
	operations, err := s.controller.List(ctx, s.project, after, limit)
	if err != nil {
		return nil, err
	}
	result := make([]TextSenderOperation, 0, len(operations))
	for _, o := range operations {
		item := textSenderProjection(o)
		item.Reply = nil
		result = append(result, item)
	}
	return result, nil
}

// Status returns the runtime's current revision. Subscribe waits for a revision
// change without an idle timer and ends with ErrDisabled when the runtime fences.
func (s *TextSender) Status(ctx context.Context) (uint64, error) {
	return s.controller.Revision(ctx, s.project)
}

func (s *TextSender) Subscribe(ctx context.Context, after uint64) (uint64, error) {
	return s.controller.WaitRevision(ctx, s.project, after)
}
