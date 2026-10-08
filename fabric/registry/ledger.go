package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/search"
)

type tombstone struct {
	Ref      fabric.EndpointRef `json:"ref"`
	Revision fabric.Revision    `json:"revision"`
	Kind     string             `json:"kind"`
}
type storedObject struct {
	ref, domain, parent, kind string
	revision                  fabric.Revision
	retired                   bool
	payload                   []byte
	owner                     string
	mutation                  []byte
}

func text(s string, max int, optional bool) bool {
	return (optional || s != "") && len(s) <= max && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\n\r")
}
func validateEndpoint(d fabric.EndpointDescriptor, bound int) error {
	if _, e := fabric.ParseEndpointRef(d.Ref.String()); e != nil {
		return e
	}
	if d.Ref.IsOffer() || !fabric.ValidNamespacedName(d.Kind) || !text(d.Name, 256, false) || !description(d.Description, 4096) || len(d.Bindings) > 32 || len(d.Metadata) > 32 {
		return invalid("invalid endpoint descriptor header")
	}
	ids := map[string]bool{}
	for _, b := range d.Bindings {
		if !text(b.ID, 256, false) || !fabric.ValidNamespacedName(b.Protocol) || !text(b.Version, 128, false) || ids[b.ID] {
			return invalid("invalid binding summary")
		}
		ids[b.ID] = true
	}
	for k, v := range d.Metadata {
		if !fabric.ValidNamespacedName(k) || !strings.HasPrefix(k, "extensions.") {
			return invalid("descriptor metadata requires extension namespace")
		}
		var x any
		if e := decodePayload(v, &x, bound); e != nil {
			return e
		}
	}
	return nil
}
func validateOffer(d fabric.OfferDescriptor, bound int) error {
	if _, e := fabric.ParseEndpointRef(d.Ref.String()); e != nil {
		return e
	}
	if !d.Ref.IsOffer() || !text(d.Name, 256, false) || !description(d.Description, 4096) || !text(d.BindingID, 256, false) || len(d.Tags) > 32 || len(d.Examples) > 16 {
		return invalid("invalid separately addressable offer")
	}
	for _, tag := range d.Tags {
		if !text(tag, 256, false) {
			return invalid("invalid offer tag")
		}
	}
	for _, v := range append(append([]json.RawMessage{}, d.Examples...), d.InputSchema, d.OutputSchema) {
		if len(v) > 0 {
			var x any
			if e := decodePayload(v, &x, bound); e != nil {
				return e
			}
		}
	}
	return nil
}
func mutationDigest(action string, ref fabric.EndpointRef, expected fabric.Revision, raw []byte) [32]byte {
	h := sha256.New()
	for _, p := range [][]byte{[]byte("pagnet.fabric.registry.mutation.v1"), []byte(action), []byte(ref.String()), []byte(expected), raw} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		h.Write(n[:])
		h.Write(p)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}
func newRevision(sequence uint64, previous [32]byte, mutation [32]byte) fabric.Revision {
	h := sha256.New()
	h.Write([]byte("pagnet.fabric.registry.revision.v1\x00"))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], sequence)
	h.Write(n[:])
	h.Write(previous[:])
	h.Write(mutation[:])
	return fabric.Revision(hex.EncodeToString(h.Sum(nil)))
}
func recordHash(r Record) ([32]byte, error) {
	frame, e := r.Frame.SigningBytes()
	if e != nil {
		return [32]byte{}, e
	}
	h := sha256.New()
	h.Write(frame)
	h.Write(r.Signature)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
func objectFromRecord(r Record, publicKey []byte, limits Limits) (storedObject, error) {
	var out storedObject
	if len(r.Payload) > limits.MaxPayloadBytes || len(r.Signature) != ed25519.SignatureSize {
		return out, invalid("record payload or signature exceeds bound")
	}
	frame, e := r.Frame.SigningBytes()
	if e != nil {
		return out, e
	}
	ns, e := fabric.DomainNamespace(publicKey)
	if e != nil || r.Frame.IssuerNamespace != ns || r.Frame.AudienceDomain != ns || r.Frame.ExactTargetRef.Domain() != ns || r.Frame.IssuerKeyRevision != 1 || r.Frame.Sequence > math.MaxInt64 || sha256.Sum256(r.Payload) != r.Frame.PayloadDigest || !ed25519.Verify(publicKey, frame, r.Signature) {
		return out, invalid("signed record authority or exact payload commitment mismatch")
	}
	out = storedObject{ref: r.Frame.ExactTargetRef.String(), domain: ns, revision: r.Frame.NewRevision, payload: bytes.Clone(r.Payload)}
	var unsigned []byte
	switch r.Frame.ActionKind {
	case "endpoint.publish":
		var d fabric.EndpointDescriptor
		if e = decodePayload(r.Payload, &d, limits.MaxPayloadBytes); e != nil {
			return out, e
		}
		if e = validateEndpoint(d, limits.MaxPayloadBytes); e != nil {
			return out, e
		}
		if d.Ref != r.Frame.ExactTargetRef || d.Revision != r.Frame.NewRevision {
			return out, invalid("endpoint signed binding mismatch")
		}
		out.kind = "endpoint"
		d.Revision = ""
		unsigned, e = json.Marshal(d)
	case "offer.publish":
		var d fabric.OfferDescriptor
		if e = decodePayload(r.Payload, &d, limits.MaxPayloadBytes); e != nil {
			return out, e
		}
		if e = validateOffer(d, limits.MaxPayloadBytes); e != nil {
			return out, e
		}
		if d.Ref != r.Frame.ExactTargetRef || d.Revision != r.Frame.NewRevision {
			return out, invalid("offer signed binding mismatch")
		}
		out.kind = "offer"
		out.parent = d.Ref.Endpoint().String()
		d.Revision = ""
		unsigned, e = json.Marshal(d)
	case "endpoint.retire", "offer.retire":
		var d tombstone
		if e = decodePayload(r.Payload, &d, limits.MaxPayloadBytes); e != nil {
			return out, e
		}
		out.kind = strings.TrimSuffix(r.Frame.ActionKind, ".retire")
		if d.Ref != r.Frame.ExactTargetRef || d.Revision != r.Frame.NewRevision || d.Kind != out.kind || d.Ref.IsOffer() != (out.kind == "offer") {
			return out, invalid("tombstone signed binding mismatch")
		}
		out.retired = true
		if d.Ref.IsOffer() {
			out.parent = d.Ref.Endpoint().String()
		}
		d.Revision = ""
		unsigned, e = json.Marshal(d)
	default:
		return out, invalid("unsupported signed registry action")
	}
	if e != nil {
		return out, e
	}
	m := mutationDigest(r.Frame.ActionKind, r.Frame.ExactTargetRef, r.Frame.ExpectedPriorRevision, unsigned)
	out.mutation = bytes.Clone(m[:])
	if newRevision(r.Frame.Sequence, r.Frame.PreviousHeadDigest, m) != r.Frame.NewRevision {
		return out, invalid("record revision commitment mismatch")
	}
	return out, nil
}
func head(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, domain string) (uint64, [32]byte, error) {
	var seq uint64
	var raw []byte
	e := q.QueryRowContext(ctx, "SELECT sequence,head FROM ledger WHERE domain=? ORDER BY sequence DESC LIMIT 1", domain).Scan(&seq, &raw)
	if errors.Is(e, sql.ErrNoRows) {
		return 0, [32]byte{}, nil
	}
	if e != nil {
		return 0, [32]byte{}, e
	}
	var h [32]byte
	if len(raw) != 32 {
		return 0, h, invalid("malformed ledger head")
	}
	copy(h[:], raw)
	return seq, h, nil
}
func loadObject(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, ref string) (storedObject, error) {
	var o storedObject
	e := q.QueryRowContext(ctx, "SELECT ref,domain,parent,kind,revision,retired,payload,owner,mutation FROM objects WHERE ref=?", ref).Scan(&o.ref, &o.domain, &o.parent, &o.kind, &o.revision, &o.retired, &o.payload, &o.owner, &o.mutation)
	return o, e
}

func (s *Store) Register(ctx context.Context, c fabric.ExecutionContext, u fabric.RegistryUpdate) (fabric.Revision, error) {
	if u.ExpectedRevision != "" {
		return "", invalid("registration has no prior revision")
	}
	return s.writeEndpoint(ctx, c, u)
}
func (s *Store) Update(ctx context.Context, c fabric.ExecutionContext, u fabric.RegistryUpdate) (fabric.Revision, error) {
	if u.ExpectedRevision == "" {
		return "", invalid("update requires exact prior revision")
	}
	return s.writeEndpoint(ctx, c, u)
}
func (s *Store) writeEndpoint(ctx context.Context, c fabric.ExecutionContext, u fabric.RegistryUpdate) (fabric.Revision, error) {
	d := u.Descriptor
	if d.Revision != "" {
		return "", invalid("new descriptor revision is allocated by registry")
	}
	if e := validateEndpoint(d, s.options.Limits.MaxPayloadBytes); e != nil {
		return "", e
	}
	raw, e := json.Marshal(d)
	if e != nil {
		return "", e
	}
	return s.mutate(ctx, c, d.Ref, u.ExpectedRevision, "endpoint.publish", raw, func(rev fabric.Revision) ([]byte, error) { d.Revision = rev; return json.Marshal(d) })
}
func (s *Store) PutOffer(ctx context.Context, c fabric.ExecutionContext, d fabric.OfferDescriptor, expected fabric.Revision) (fabric.Revision, error) {
	if d.Revision != "" {
		return "", invalid("new offer revision is allocated by registry")
	}
	if e := validateOffer(d, s.options.Limits.MaxPayloadBytes); e != nil {
		return "", e
	}
	raw, e := json.Marshal(d)
	if e != nil {
		return "", e
	}
	return s.mutate(ctx, c, d.Ref, expected, "offer.publish", raw, func(rev fabric.Revision) ([]byte, error) { d.Revision = rev; return json.Marshal(d) })
}
func (s *Store) Retire(ctx context.Context, c fabric.ExecutionContext, ref fabric.EndpointRef, expected fabric.Revision) (fabric.Revision, error) {
	if ref.IsOffer() {
		return "", invalid("use explicit offer retirement")
	}
	return s.retire(ctx, c, ref, expected, "endpoint")
}
func (s *Store) RetireOffer(ctx context.Context, c fabric.ExecutionContext, ref fabric.EndpointRef, expected fabric.Revision) (fabric.Revision, error) {
	if !ref.IsOffer() {
		return "", invalid("offer retirement requires exact offer")
	}
	return s.retire(ctx, c, ref, expected, "offer")
}
func (s *Store) retire(ctx context.Context, c fabric.ExecutionContext, ref fabric.EndpointRef, expected fabric.Revision, kind string) (fabric.Revision, error) {
	if expected == "" {
		return "", invalid("retirement requires exact prior revision")
	}
	d := tombstone{Ref: ref, Kind: kind}
	raw, e := json.Marshal(d)
	if e != nil {
		return "", e
	}
	return s.mutate(ctx, c, ref, expected, kind+".retire", raw, func(rev fabric.Revision) ([]byte, error) { d.Revision = rev; return json.Marshal(d) })
}
func (s *Store) mutate(ctx context.Context, c fabric.ExecutionContext, ref fabric.EndpointRef, expected fabric.Revision, action string, unsigned []byte, encode func(fabric.Revision) ([]byte, error)) (fabric.Revision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.authorize(c); e != nil {
		return "", e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	rev, e := s.mutateTx(ctx, tx, ref, expected, action, unsigned, encode)
	if e != nil {
		return "", e
	}
	if e = tx.Commit(); e != nil {
		return "", e
	}
	return rev, nil
}

// mutateTx is used only while the original registry writer lock, authenticated
// owner authorization and caller-owned transaction are held.
func (s *Store) mutateTx(ctx context.Context, tx *sql.Tx, ref fabric.EndpointRef, expected fabric.Revision, action string, unsigned []byte, encode func(fabric.Revision) ([]byte, error)) (fabric.Revision, error) {
	if ref.Domain() != s.identity.Namespace {
		return "", fabric.NewError(fabric.CodeUnauthenticated, "cannot modify foreign domain")
	}
	if len(unsigned) > s.options.Limits.MaxPayloadBytes {
		return "", invalid("descriptor exceeds bound")
	}
	m := mutationDigest(action, ref, expected, unsigned)
	old, e := loadObject(ctx, tx, ref.String())
	exists := e == nil
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return "", e
	}
	if exists && bytes.Equal(old.mutation, m[:]) {
		return old.revision, nil
	}
	if exists && (old.retired || old.revision != expected) || !exists && expected != "" {
		return "", conflict("reference or exact prior revision is retired or stale")
	}
	if exists && expected == "" {
		return "", conflict("reference identity already exists")
	}
	if ref.IsOffer() {
		parent, e := loadObject(ctx, tx, ref.Endpoint().String())
		if e != nil || parent.retired || parent.domain != s.identity.Namespace {
			return "", conflict("offer endpoint is missing or retired")
		}
		if action == "offer.publish" {
			var offer fabric.OfferDescriptor
			s.decode(unsigned, &offer)
			var endpoint fabric.EndpointDescriptor
			if e = s.decode(parent.payload, &endpoint); e != nil {
				return "", e
			}
			found := false
			for _, b := range endpoint.Bindings {
				found = found || b.ID == offer.BindingID
			}
			if !found {
				return "", invalid("offer binding is not published by endpoint")
			}
		}
	}
	// Existing active offers cannot silently lose their published binding.
	if action == "endpoint.publish" && exists {
		var next fabric.EndpointDescriptor
		if e = s.decode(unsigned, &next); e != nil {
			return "", e
		}
		ids := map[string]bool{}
		for _, b := range next.Bindings {
			ids[b.ID] = true
		}
		rows, e := tx.QueryContext(ctx, "SELECT payload FROM objects WHERE parent=? AND retired=0", ref.String())
		if e != nil {
			return "", e
		}
		for rows.Next() {
			var p []byte
			if e = rows.Scan(&p); e != nil {
				break
			}
			var offer fabric.OfferDescriptor
			if e = s.decode(p, &offer); e != nil {
				break
			}
			if !ids[offer.BindingID] {
				e = conflict("retire dependent offers before removing their binding")
				break
			}
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return "", e
		}
	}
	seq, previous, e := head(ctx, tx, s.identity.Namespace)
	if e != nil {
		return "", e
	}
	if seq >= s.options.Limits.MaxRecords {
		return "", invalid("registry identity ledger capacity reached")
	}
	rev := newRevision(seq+1, previous, m)
	payload, e := encode(rev)
	if e != nil {
		return "", e
	}
	if len(payload) > s.options.Limits.MaxPayloadBytes {
		return "", invalid("descriptor exceeds bound")
	}
	frame := fabric.RegistryFrame{IssuerNamespace: s.identity.Namespace, IssuerKeyRevision: 1, AudienceDomain: s.identity.Namespace, ActionKind: action, ExactTargetRef: ref, ExpectedPriorRevision: expected, NewRevision: rev, Sequence: seq + 1, PreviousHeadDigest: previous, PayloadDigest: sha256.Sum256(payload)}
	signing, e := frame.SigningBytes()
	if e != nil {
		return "", e
	}
	r := Record{Frame: frame, Payload: payload, Signature: ed25519.Sign(s.key, signing)}
	o, e := objectFromRecord(r, s.identity.PublicKey, s.options.Limits)
	if e != nil {
		return "", e
	}
	o.owner = s.identity.Owner.Ref
	if e = s.insertRecord(ctx, tx, r, o, true); e != nil {
		return "", e
	}
	if e = s.syncReferenceHandle(ctx, tx, ref, action, rev, exists); e != nil {
		return "", e
	}
	return rev, nil
}

func (s *Store) insertRecord(ctx context.Context, tx *sql.Tx, r Record, o storedObject, outbox bool) error {
	encoded, e := json.Marshal(r)
	if e != nil {
		return e
	}
	var count, total int64
	if e = tx.QueryRowContext(ctx, "SELECT records,bytes FROM ledger_budget WHERE singleton=1").Scan(&count, &total); e != nil {
		return e
	}
	if uint64(count) >= s.options.Limits.MaxRecords || int64(len(encoded)) > s.options.Limits.MaxLedgerBytes-total {
		return invalid("registry signed history capacity reached")
	}
	if _, e = tx.ExecContext(ctx, "UPDATE ledger_budget SET records=records+1,bytes=bytes+? WHERE singleton=1", len(encoded)); e != nil {
		return e
	}
	h, e := recordHash(r)
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO ledger(domain,sequence,record,head) VALUES(?,?,?,?)", o.domain, r.Frame.Sequence, encoded, h[:]); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO objects VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(ref) DO UPDATE SET revision=excluded.revision,retired=excluded.retired,payload=excluded.payload,mutation=excluded.mutation`, o.ref, o.domain, o.parent, o.kind, o.revision, o.retired, o.payload, o.owner, o.mutation); e != nil {
		return e
	}
	if outbox {
		data, encodeErr := searchDocument(o)
		if encodeErr != nil {
			return encodeErr
		}
		_, e = tx.ExecContext(ctx, "INSERT INTO search_outbox(ref,revision,retired,document) VALUES(?,?,?,?)", o.ref, o.revision, o.retired, data)
	}
	if e == nil && outbox && o.kind == "endpoint" && o.retired {
		rows, x := tx.QueryContext(ctx, "SELECT ref,revision FROM objects WHERE parent=? AND retired=0 ORDER BY ref", o.ref)
		if x != nil {
			return x
		}
		var offers []struct{ ref, rev string }
		for rows.Next() {
			var child struct{ ref, rev string }
			if x = rows.Scan(&child.ref, &child.rev); x != nil {
				break
			}
			offers = append(offers, child)
		}
		if x == nil {
			x = rows.Err()
		}
		rows.Close()
		if x != nil {
			return x
		}
		for _, child := range offers {
			if _, e = tx.ExecContext(ctx, "INSERT INTO search_outbox(ref,revision,retired,document) VALUES(?,?,1,NULL)", child.ref, child.rev); e != nil {
				return e
			}
		}
	}

	return e
}
func (s *Store) verifyLedger(ctx context.Context) error { return s.verifyLedgerStream(ctx) }

var _ fabric.EndpointRegistry = (*Store)(nil)

func compactDescription(s string) string {
	if len(s) <= 1024 {
		return s
	}
	s = s[:1024]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

var _ fabric.OfferRegistry = (*Store)(nil)

func searchDocument(o storedObject) ([]byte, error) {
	ref, e := fabric.ParseEndpointRef(o.ref)
	if e != nil {
		return nil, e
	}
	doc := fabric.SearchDocument{Ref: ref, Revision: o.revision}
	if !o.retired {
		if o.kind == "endpoint" {
			var d fabric.EndpointDescriptor
			if e = decodePayload(o.payload, &d, len(o.payload)); e != nil {
				return nil, e
			}
			doc.Name = d.Name
			doc.ShortDescription = compactDescription(d.Description)
			doc.Kind = d.Kind
		} else {
			var d fabric.OfferDescriptor
			if e = decodePayload(o.payload, &d, len(o.payload)); e != nil {
				return nil, e
			}
			doc.Name = d.Name
			doc.ShortDescription = compactDescription(d.Description)
			doc.Tags = d.Tags
			doc.Kind = "fabric.offer"
			if len(d.InputSchema) > 0 {
				digest := sha256.Sum256(d.InputSchema)
				doc.SchemaFingerprint = hex.EncodeToString(digest[:])
			}
		}
	}
	raw, e := json.Marshal(doc)
	if e != nil {
		return nil, e
	}
	if len(raw) > search.MaxDocumentBytes {
		return nil, invalid("descriptor header exceeds compact discovery budget")
	}
	return raw, nil
}

func decodePayload(raw []byte, out any, bound int) error {
	return fabric.DecodeJSONWithLimits(raw, out, fabric.WireLimits{MaxBytes: bound, MaxDepth: 64, MaxMembers: 4096})
}

func description(s string, bound int) bool {
	return len(s) <= bound && utf8.ValidString(s) && !strings.Contains(s, "\x00")
}
