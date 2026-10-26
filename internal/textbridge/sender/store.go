// Package sender stores private sender operations independently of the responder.
// The SDK spool remains authoritative for ciphertext. Callers must hold an
// exclusive external lock for the lifetime of a Store, including across processes.
package sender

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/sdk"
)

const (
	MaxPromptChars = 16_000
	MaxReplyChars  = 16_000
	maxStateBytes  = 64 << 20
)

type Phase string

const (
	Reserved Phase = "reserved"
	Prepared Phase = "prepared"
	Admitted Phase = "admitted"
)

var (
	ErrInvalid  = errors.New("invalid sender operation state")
	ErrConflict = errors.New("sender operation conflicts with durable state")
	ErrNotFound = errors.New("sender operation not found")
)

type Binding struct {
	ServiceOrigin string
	PrincipalID   string
}

// Operation deliberately excludes the recoverable prompt. Reserved operations
// are unresolved: recovery may load existing SDK ciphertext, but must never
// invoke preparation again merely because that ciphertext cannot be found.
type Operation struct {
	ProjectID    string
	AskID        string
	RecipientID  string
	PromptDigest string
	Phase        Phase
	WireDigest   string
	Receipt      *sdk.SharingProjectMessageReceipt
	Reply        *Reply
}

// Reply is supplied only after SDK authentication and predecessor validation.
type Reply struct {
	ProjectID   string
	AskID       string
	ReplyID     string
	WireDigest  string
	SenderID    string
	RecipientID string
	Text        string
}

type storedOperation struct {
	Operation Operation
	Prompt    string
}

type state struct {
	Version    int
	Binding    Binding
	Operations map[string]storedOperation
}

type Store struct {
	mu        sync.Mutex
	dir       string
	aead      cipher.AEAD
	keyDigest string
	state     state
	failed    bool
}

func validID(id string, v7 bool) bool {
	u, err := uuid.Parse(id)
	return err == nil && u != uuid.Nil && u.Variant() == uuid.RFC4122 && u.String() == id && (!v7 || u.Version() == 7)
}

func normalizeBinding(b Binding) (Binding, error) {
	u, err := url.Parse(b.ServiceOrigin)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || !validID(b.PrincipalID, false) {
		return b, ErrInvalid
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if host == "" {
		return b, ErrInvalid
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return b, ErrInvalid
		}
	}
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	b.ServiceOrigin = u.Scheme + "://" + host
	return b, nil
}

func digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func validText(s string, limit int) bool {
	return len(s) <= limit*utf8.UTFMax && utf8.ValidString(s) && strings.TrimSpace(s) != "" && utf8.RuneCountInString(s) <= limit
}
func operationKey(project, ask string) string { return project + "/" + ask }

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// Refuse symlinks throughout the directory path, not only at the leaf.
func privateDir(dir string) error {
	parent := filepath.Dir(dir)
	if parent != dir {
		if err := privateDir(parent); err != nil {
			return err
		}
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err = os.Mkdir(dir, 0700); err != nil {
			return err
		}
		return syncDir(parent)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalid
	}
	return nil
}

func readPrivate(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > max {
		return nil, ErrInvalid
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if int64(len(b)) > max {
		return nil, ErrInvalid
	}
	return b, err
}

func atomicWrite(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, ".sender-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	target := filepath.Join(dir, name)
	if info, err := os.Lstat(target); err == nil && !info.Mode().IsRegular() {
		return ErrInvalid
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err = os.Rename(f.Name(), target); err != nil {
		return err
	}
	return syncDir(dir)
}

// Open creates an empty store only in an empty directory. Initialization evidence
// without either key or state fails closed; an incomplete first initialization
// therefore also requires operator investigation. No network action occurs here.
func Open(dir string, binding Binding) (*Store, error) {
	b, err := normalizeBinding(binding)
	if err != nil {
		return nil, err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err = privateDir(dir); err != nil {
		return nil, err
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	initialize := len(entries) == 0
	var key []byte
	if initialize {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		if err = atomicWrite(dir, "key", key); err != nil {
			return nil, err
		}
	} else {
		key, err = readPrivate(filepath.Join(dir, "key"), 32)
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("sender key unavailable: %w", ErrInvalid)
		}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, aead: aead, keyDigest: digest(key), state: state{Version: 1, Binding: b, Operations: make(map[string]storedOperation)}}
	if initialize {
		if err = s.persist(s.state); err != nil {
			return nil, err
		}
	} else {
		if s.state, err = s.read(); err != nil {
			return nil, err
		}
		if s.state.Binding != b {
			return nil, fmt.Errorf("sender binding mismatch: %w", ErrInvalid)
		}
	}
	return s, nil
}

func (s *Store) read() (state, error) {
	var st state
	sealed, err := readPrivate(filepath.Join(s.dir, "state"), maxStateBytes)
	if err != nil {
		return st, err
	}
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return st, ErrInvalid
	}
	plain, err := s.aead.Open(nil, sealed[:n], sealed[n:], []byte("text-bridge-sender-v1"))
	if err != nil {
		return st, fmt.Errorf("sender authentication failed: %w", ErrInvalid)
	}
	if err = json.Unmarshal(plain, &st); err != nil {
		return st, ErrInvalid
	}
	if st.Version != 1 || st.Operations == nil {
		return st, ErrInvalid
	}
	if b, err := normalizeBinding(st.Binding); err != nil || b != st.Binding {
		return st, ErrInvalid
	}
	for key, stored := range st.Operations {
		o := stored.Operation
		if key != operationKey(o.ProjectID, o.AskID) || !validID(o.ProjectID, false) || !validID(o.AskID, true) || !validID(o.RecipientID, false) || !validText(stored.Prompt, MaxPromptChars) || o.PromptDigest != digest([]byte(stored.Prompt)) {
			return st, ErrInvalid
		}
		switch o.Phase {
		case Reserved:
			if o.WireDigest != "" || o.Receipt != nil {
				return st, ErrInvalid
			}
		case Prepared:
			if !validDigest(o.WireDigest) || o.Receipt != nil {
				return st, ErrInvalid
			}
		case Admitted:
			if !validDigest(o.WireDigest) || o.Receipt == nil || !validReceipt(o, *o.Receipt) {
				return st, ErrInvalid
			}
		default:
			return st, ErrInvalid
		}
		if o.Reply != nil && !validReply(st.Binding, o, *o.Reply) {
			return st, ErrInvalid
		}
	}
	return st, nil
}

func (s *Store) persist(st state) error {
	plain, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if len(plain)+s.aead.NonceSize()+s.aead.Overhead() > maxStateBytes {
		return ErrInvalid
	}
	n := make([]byte, s.aead.NonceSize())
	if _, err = rand.Read(n); err != nil {
		return err
	}
	return atomicWrite(s.dir, "state", s.aead.Seal(n, n, plain, []byte("text-bridge-sender-v1")))
}

// load authenticates disk state on every operation, detecting missing/corrupt
// files even while this Store remains open. After an ambiguous write failure the
// handle is unusable; reopen and reconcile durable state before proceeding.
func (s *Store) load(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.failed {
		return ErrInvalid
	}
	key, err := readPrivate(filepath.Join(s.dir, "key"), 32)
	if err != nil || len(key) != 32 || digest(key) != s.keyDigest {
		return ErrInvalid
	}
	st, err := s.read()
	if err != nil {
		return err
	}
	if st.Binding != s.state.Binding {
		return ErrInvalid
	}
	s.state = st
	return nil
}

func clone(o Operation) Operation {
	if o.Receipt != nil {
		r := *o.Receipt
		r.RequestDigest = append([]byte(nil), r.RequestDigest...)
		if r.AcknowledgedAt != nil {
			t := *r.AcknowledgedAt
			r.AcknowledgedAt = &t
		}
		o.Receipt = &r
	}
	if o.Reply != nil {
		r := *o.Reply
		o.Reply = &r
	}
	return o
}

func (s *Store) save(stored storedOperation) (Operation, error) {
	s.state.Operations[operationKey(stored.Operation.ProjectID, stored.Operation.AskID)] = stored
	if err := s.persist(s.state); err != nil {
		s.failed = true
		return Operation{}, err
	}
	return clone(stored.Operation), nil
}

// Reserve is the sole ID generation point. It durably binds input and identity
// before SDK preparation. Each invocation is a new operation; resume via Get.
func (s *Store) Reserve(ctx context.Context, project, recipient, prompt string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(ctx); err != nil {
		return Operation{}, err
	}
	if !validID(project, false) || !validID(recipient, false) || !validText(prompt, MaxPromptChars) {
		return Operation{}, ErrInvalid
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Operation{}, err
	}
	o := Operation{ProjectID: project, AskID: id.String(), RecipientID: recipient, PromptDigest: digest([]byte(prompt)), Phase: Reserved}
	return s.save(storedOperation{Operation: o, Prompt: prompt})
}

func (s *Store) get(project, ask string) (storedOperation, error) {
	if !validID(project, false) || !validID(ask, true) {
		return storedOperation{}, ErrInvalid
	}
	o, ok := s.state.Operations[operationKey(project, ask)]
	if !ok {
		return o, ErrNotFound
	}
	return o, nil
}

func (s *Store) Get(ctx context.Context, project, ask string) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(ctx); err != nil {
		return Operation{}, err
	}
	o, err := s.get(project, ask)
	return clone(o.Operation), err
}

func (s *Store) List(ctx context.Context, phases ...Phase) ([]Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	for _, p := range phases {
		if p != Reserved && p != Prepared && p != Admitted {
			return nil, ErrInvalid
		}
	}
	result := []Operation{}
	for _, stored := range s.state.Operations {
		include := len(phases) == 0
		for _, p := range phases {
			include = include || p == stored.Operation.Phase
		}
		if include {
			result = append(result, clone(stored.Operation))
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return operationKey(result[i].ProjectID, result[i].AskID) < operationKey(result[j].ProjectID, result[j].AskID)
	})
	return result, nil
}

// RecoverPrompt explicitly requests sensitive input for the initial preparation.
// Its availability does not authorize preparing a recovered reserved operation.
func (s *Store) RecoverPrompt(ctx context.Context, project, ask string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(ctx); err != nil {
		return "", err
	}
	o, err := s.get(project, ask)
	return o.Prompt, err
}

// MarkPrepared accepts evidence loaded from the authoritative SDK spool. It
// never stores ciphertext or calls preparation. Reconciliation can advance a
// reserved operation after a crash between SDK preparation and this transition.
func (s *Store) MarkPrepared(ctx context.Context, project, ask string, prepared sdk.PreparedSharingProjectMessage) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(ctx); err != nil {
		return Operation{}, err
	}
	stored, err := s.get(project, ask)
	if err != nil {
		return Operation{}, err
	}
	if prepared.ID != ask || len(prepared.Wire) == 0 {
		return Operation{}, ErrInvalid
	}
	d := digest(prepared.Wire)
	if stored.Operation.Phase != Reserved {
		if stored.Operation.WireDigest != d {
			return Operation{}, ErrConflict
		}
		return clone(stored.Operation), nil
	}
	stored.Operation.Phase, stored.Operation.WireDigest = Prepared, d
	return s.save(stored)
}

func validReceipt(o Operation, r sdk.SharingProjectMessageReceipt) bool {
	return r.MessageID == o.AskID && hex.EncodeToString(r.RequestDigest) == o.WireDigest && r.AdmissionSeq > 0 && !r.CreatedAt.IsZero() && (r.Status == "pending" || r.Status == "acknowledged")
}

func (s *Store) MarkAdmitted(ctx context.Context, project, ask string, receipt sdk.SharingProjectMessageReceipt) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(ctx); err != nil {
		return Operation{}, err
	}
	stored, err := s.get(project, ask)
	if err != nil {
		return Operation{}, err
	}
	if stored.Operation.Phase == Reserved || !validReceipt(stored.Operation, receipt) {
		return Operation{}, ErrInvalid
	}
	if stored.Operation.Receipt != nil {
		old := stored.Operation.Receipt
		if old.AdmissionSeq != receipt.AdmissionSeq || !old.CreatedAt.Equal(receipt.CreatedAt) {
			return Operation{}, ErrConflict
		}
		return clone(stored.Operation), nil
	}
	stored.Operation.Phase, stored.Operation.Receipt = Admitted, &receipt
	stored.Operation = clone(stored.Operation)
	return s.save(stored)
}

func validReply(b Binding, o Operation, r Reply) bool {
	return r.ProjectID == o.ProjectID && r.AskID == o.AskID && validID(r.ReplyID, true) && validDigest(r.WireDigest) && r.SenderID == o.RecipientID && r.RecipientID == b.PrincipalID && validText(r.Text, MaxReplyChars)
}

// RecordReply commits before the caller acknowledges SDK inbox delivery. Same
// authenticated reply is idempotent; any changed field for this ASK conflicts.
func (s *Store) RecordReply(ctx context.Context, reply Reply) (Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(ctx); err != nil {
		return Operation{}, err
	}
	stored, err := s.get(reply.ProjectID, reply.AskID)
	if err != nil {
		return Operation{}, err
	}
	if !validReply(s.state.Binding, stored.Operation, reply) {
		return Operation{}, ErrInvalid
	}
	if old := stored.Operation.Reply; old != nil {
		if *old != reply {
			return Operation{}, ErrConflict
		}
		return clone(stored.Operation), nil
	}
	stored.Operation.Reply = &reply
	return s.save(stored)
}

// Close releases no OS resources; the caller owns the external exclusive lock.
func (s *Store) Close() error { s.mu.Lock(); defer s.mu.Unlock(); s.failed = true; return nil }
