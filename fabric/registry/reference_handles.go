package registry

import (
	"context"
	"database/sql"
	"errors"

	"github.com/pagnet-code/pagnet/fabric"
)

// Friendly persistent reference handles.
//
// A reference handle is a compact private-root alias for one exact canonical
// endpoint reference, for example "#7.r3": slot 7, handle revision 3. It lets
// an agent answer with a short friendly reference instead of copying a 118
// byte canonical reference while staying exactly routable: a handle resolves
// to one canonical reference plus its bound revision, or fails explicitly.
// Handles grant no authority and never change canonical references, revisions
// or signatures.
//
// State is durable in this private root, scoped to the installation identity
// (root store, network namespace, owner principal). Slots are allocated from a
// monotonic counter, bounded by a finite per-scope quota, permanently bound to
// the endpoint they were allocated for and never reused. When the endpoint
// descriptor updates, the slot's handle revision advances in the same
// transaction: the old handle text resolves as CodeStaleReference with the
// current handle, never as a silently different target.

const referenceHandleSchema = `CREATE TABLE reference_handle_counter(singleton INTEGER PRIMARY KEY CHECK(singleton=1),scope TEXT NOT NULL,next_slot INTEGER NOT NULL);
CREATE TABLE reference_handles(scope TEXT NOT NULL,slot INTEGER NOT NULL,ref TEXT NOT NULL,handle_revision INTEGER NOT NULL,bound_revision TEXT NOT NULL,label TEXT NOT NULL,retired INTEGER NOT NULL,PRIMARY KEY(scope,slot),UNIQUE(scope,ref));
PRAGMA user_version=3;`

const referenceHandleBySlotQuery = "SELECT scope,slot,ref,handle_revision,bound_revision,label,retired FROM reference_handles WHERE scope=? AND slot=?"
const referenceHandleByRefQuery = "SELECT scope,slot,ref,handle_revision,bound_revision,label,retired FROM reference_handles WHERE scope=? AND ref=?"

// referenceHandleScope is the installation identity: root store, network
// namespace and owner principal. Rows in any other scope are foreign state and
// can never resolve in this root.
func (s *Store) referenceHandleScope() string {
	return s.identity.StoreID + "\x00" + s.identity.Namespace + "\x00" + s.identity.Owner.Ref
}

type referenceHandleRow struct {
	scope          string
	slot           int64
	ref            string
	handleRevision int64
	boundRevision  fabric.Revision
	label          string
	retired        bool
}

func scanReferenceHandleRow(row interface {
	Scan(dest ...any) error
}) (referenceHandleRow, error) {
	var r referenceHandleRow
	if e := row.Scan(&r.scope, &r.slot, &r.ref, &r.handleRevision, &r.boundRevision, &r.label, &r.retired); e != nil {
		return r, e
	}
	return r, nil
}

func (s *Store) referenceHandleView(r referenceHandleRow) (fabric.ReferenceHandleView, error) {
	ref, e := fabric.ParseEndpointRef(r.ref)
	if e != nil {
		return fabric.ReferenceHandleView{}, invalid("malformed reference handle target")
	}
	return fabric.ReferenceHandleView{
		Handle:   fabric.FormatReferenceHandle(uint64(r.slot), uint64(r.handleRevision)),
		Label:    r.label,
		Ref:      ref,
		Revision: r.boundRevision,
	}, nil
}

// ensureReferenceHandleSchema lazily adopts the handle state inside the
// private root, the same way native authority and descriptor projections are
// adopted. The version history stays strictly ordered: an original v1 root
// first adopts the native authority schema (1 -> 2) before the handle state
// (2 -> 3), so no adoption ever skips a version. It never mutates Store flags;
// the caller records adoption only after the surrounding transaction commits.
// Partial or foreign state fails closed.
func (s *Store) ensureReferenceHandleSchema(ctx context.Context, tx *sql.Tx) error {
	var version int
	if e := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); e != nil {
		return e
	}
	if version == 1 {
		if _, e := tx.ExecContext(ctx, nativeAuthoritySchema); e != nil {
			return e
		}
		version = 2
	}
	if version == 2 {
		var tables int
		if e := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('reference_handle_counter','reference_handles')").Scan(&tables); e != nil {
			return e
		}
		if tables != 0 {
			return invalid("Incomplete reference handle state")
		}
		if _, e := tx.ExecContext(ctx, referenceHandleSchema); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO reference_handle_counter VALUES(1,?,1)", s.referenceHandleScope()); e != nil {
			return e
		}
		return nil
	}
	if version == 3 {
		return nil
	}
	return invalid("Unsupported registry format for reference handles")
}

// AllocateReferenceHandle returns the endpoint's existing handle or allocates
// the next slot in this installation scope. Allocation is owner-authenticated,
// bounded by the finite per-scope quota, and idempotent per exact endpoint
// reference: an endpoint holds at most one slot, permanently. The returned
// handle is bound to the endpoint's exact current canonical revision.
func (s *Store) AllocateReferenceHandle(ctx context.Context, c fabric.ExecutionContext, ref fabric.EndpointRef, label string) (fabric.ReferenceHandleView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.authorize(c); e != nil {
		return fabric.ReferenceHandleView{}, e
	}
	if ref.IsOffer() || ref.Domain() != s.identity.Namespace {
		return fabric.ReferenceHandleView{}, invalid("reference handle requires a local endpoint reference")
	}
	if !text(label, 256, false) {
		return fabric.ReferenceHandleView{}, invalid("reference handle label exceeds bound")
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return fabric.ReferenceHandleView{}, e
	}
	defer tx.Rollback()
	if e = s.ensureReferenceHandleSchema(ctx, tx); e != nil {
		return fabric.ReferenceHandleView{}, e
	}
	scope := s.referenceHandleScope()
	row, e := scanReferenceHandleRow(tx.QueryRowContext(ctx, referenceHandleByRefQuery, scope, ref.String()))
	if e == nil {
		if row.retired {
			return fabric.ReferenceHandleView{}, conflict("reference handle target is retired")
		}
		return s.referenceHandleView(row)
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return fabric.ReferenceHandleView{}, e
	}
	o, e := loadObject(ctx, tx, ref.String())
	if errors.Is(e, sql.ErrNoRows) {
		return fabric.ReferenceHandleView{}, fabric.NewError(fabric.CodeNotFound, "reference handle target is not registered")
	}
	if e != nil {
		return fabric.ReferenceHandleView{}, e
	}
	if o.retired || o.domain != s.identity.Namespace || o.kind != "endpoint" {
		return fabric.ReferenceHandleView{}, conflict("reference handle target is retired or foreign")
	}
	var storedScope string
	var nextSlot int64
	if e = tx.QueryRowContext(ctx, "SELECT scope,next_slot FROM reference_handle_counter WHERE singleton=1").Scan(&storedScope, &nextSlot); e != nil {
		return fabric.ReferenceHandleView{}, invalid("reference handle counter absent")
	}
	if storedScope != scope || nextSlot < 1 {
		return fabric.ReferenceHandleView{}, invalid("reference handle scope does not match pinned identity")
	}
	if nextSlot > int64(s.options.Limits.MaxReferenceHandles) {
		return fabric.ReferenceHandleView{}, invalid("reference handle quota reached for scope")
	}
	res, e := tx.ExecContext(ctx, "UPDATE reference_handle_counter SET next_slot=next_slot+1 WHERE singleton=1 AND scope=? AND next_slot=?", scope, nextSlot)
	if e != nil {
		return fabric.ReferenceHandleView{}, e
	}
	if n, e := res.RowsAffected(); e != nil || n != 1 {
		return fabric.ReferenceHandleView{}, conflict("reference handle counter conflict")
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO reference_handles VALUES(?,?,?,?,?,?,0)", scope, nextSlot, ref.String(), 1, o.revision, label); e != nil {
		return fabric.ReferenceHandleView{}, e
	}
	if e = tx.Commit(); e != nil {
		return fabric.ReferenceHandleView{}, e
	}
	s.hasReferenceHandles = true
	return fabric.ReferenceHandleView{
		Handle:   fabric.FormatReferenceHandle(uint64(nextSlot), 1),
		Label:    label,
		Ref:      ref,
		Revision: o.revision,
	}, nil
}

// SetReferenceHandleLabel durably replaces the truthful persisted label for an
// allocated handle. It never allocates a slot, changes a revision or touches
// any canonical reference or signature.
func (s *Store) SetReferenceHandleLabel(ctx context.Context, c fabric.ExecutionContext, ref fabric.EndpointRef, label string) (fabric.ReferenceHandleView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.authorize(c); e != nil {
		return fabric.ReferenceHandleView{}, e
	}
	if ref.IsOffer() || ref.Domain() != s.identity.Namespace {
		return fabric.ReferenceHandleView{}, invalid("reference handle requires a local endpoint reference")
	}
	if !text(label, 256, false) {
		return fabric.ReferenceHandleView{}, invalid("reference handle label exceeds bound")
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return fabric.ReferenceHandleView{}, e
	}
	defer tx.Rollback()
	if e = s.ensureReferenceHandleSchema(ctx, tx); e != nil {
		return fabric.ReferenceHandleView{}, e
	}
	scope := s.referenceHandleScope()
	row, e := scanReferenceHandleRow(tx.QueryRowContext(ctx, referenceHandleByRefQuery, scope, ref.String()))
	if errors.Is(e, sql.ErrNoRows) {
		return fabric.ReferenceHandleView{}, fabric.NewError(fabric.CodeNotFound, "no reference handle allocated for reference")
	}
	if e != nil {
		return fabric.ReferenceHandleView{}, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE reference_handles SET label=? WHERE scope=? AND slot=? AND ref=?", label, scope, row.slot, ref.String()); e != nil {
		return fabric.ReferenceHandleView{}, e
	}
	if e = tx.Commit(); e != nil {
		return fabric.ReferenceHandleView{}, e
	}
	s.hasReferenceHandles = true
	row.label = label
	return s.referenceHandleView(row)
}

// ResolveReferenceHandle resolves a compact handle to exactly one canonical
// endpoint reference plus its bound revision inside this private root.
// Unknown slots, retired slots and foreign-scope state fail explicitly and
// never return a wrong target. A live slot whose requested handle revision is
// not current fails with CodeStaleReference while returning the CURRENT
// handle alongside the error, so the caller recovers the friendly reference
// it needs instead of a silent wrong target.
func (s *Store) ResolveReferenceHandle(ctx context.Context, text string) (fabric.ReferenceHandleView, error) {
	slot, revision, e := fabric.ParseReferenceHandle(text)
	if e != nil {
		return fabric.ReferenceHandleView{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fabric.ReferenceHandleView{}, errors.New("registry closed")
	}
	if !s.hasReferenceHandles {
		return fabric.ReferenceHandleView{}, fabric.NewError(fabric.CodeNotFound, "reference handle unknown")
	}
	row, e := scanReferenceHandleRow(s.db.QueryRowContext(ctx, referenceHandleBySlotQuery, s.referenceHandleScope(), int64(slot)))
	if errors.Is(e, sql.ErrNoRows) {
		return fabric.ReferenceHandleView{}, fabric.NewError(fabric.CodeNotFound, "reference handle unknown")
	}
	if e != nil {
		return fabric.ReferenceHandleView{}, e
	}
	if row.retired {
		return fabric.ReferenceHandleView{}, fabric.NewError(fabric.CodeNotFound, "reference handle slot is retired")
	}
	o, e := loadObject(ctx, s.db, row.ref)
	if e != nil {
		return fabric.ReferenceHandleView{}, fabric.NewError(fabric.CodeProtocolError, "reference handle target is missing from the signed ledger")
	}
	if o.retired || o.revision != row.boundRevision {
		return fabric.ReferenceHandleView{}, fabric.NewError(fabric.CodeProtocolError, "reference handle state disagrees with the signed ledger")
	}
	current, e := s.referenceHandleView(row)
	if e != nil {
		return fabric.ReferenceHandleView{}, e
	}
	if revision != uint64(row.handleRevision) {
		stale := fabric.NewError(fabric.CodeStaleReference, "reference handle "+fabric.FormatReferenceHandle(slot, revision)+" is stale; current handle is "+current.Handle)
		return current, stale
	}
	return current, nil
}

// ReferenceHandleForRef returns the allocated handle for an exact canonical
// endpoint reference when one exists. A missing allocation is CodeNotFound:
// the endpoint is described normally and no friendly reference is fabricated.
func (s *Store) ReferenceHandleForRef(ctx context.Context, ref fabric.EndpointRef) (fabric.ReferenceHandleView, error) {
	if _, e := fabric.ParseEndpointRef(ref.String()); e != nil {
		return fabric.ReferenceHandleView{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fabric.ReferenceHandleView{}, errors.New("registry closed")
	}
	if !s.hasReferenceHandles {
		return fabric.ReferenceHandleView{}, fabric.NewError(fabric.CodeNotFound, "no reference handle allocated for reference")
	}
	row, e := scanReferenceHandleRow(s.db.QueryRowContext(ctx, referenceHandleByRefQuery, s.referenceHandleScope(), ref.String()))
	if errors.Is(e, sql.ErrNoRows) {
		return fabric.ReferenceHandleView{}, fabric.NewError(fabric.CodeNotFound, "no reference handle allocated for reference")
	}
	if e != nil {
		return fabric.ReferenceHandleView{}, e
	}
	if row.retired {
		return fabric.ReferenceHandleView{}, fabric.NewError(fabric.CodeNotFound, "reference handle slot is retired")
	}
	o, e := loadObject(ctx, s.db, row.ref)
	if e != nil || o.retired || o.revision != row.boundRevision {
		return fabric.ReferenceHandleView{}, fabric.NewError(fabric.CodeProtocolError, "reference handle state disagrees with the signed ledger")
	}
	return s.referenceHandleView(row)
}

// syncReferenceHandle keeps the friendly handle bound to the exact current
// canonical revision. It runs inside the same transaction as the endpoint
// mutation, so handle state and the signed ledger can never diverge: an update
// advances the slot's handle revision (the old text becomes CodeStaleReference
// without changing endpoint identity), and a retirement retires the slot
// permanently. It is a no-op for offers and before handle state is adopted.
func (s *Store) syncReferenceHandle(ctx context.Context, tx *sql.Tx, ref fabric.EndpointRef, action string, rev fabric.Revision, exists bool) error {
	if !s.hasReferenceHandles || ref.IsOffer() {
		return nil
	}
	scope := s.referenceHandleScope()
	switch action {
	case "endpoint.publish":
		if !exists {
			return nil
		}
		_, e := tx.ExecContext(ctx, "UPDATE reference_handles SET bound_revision=?,handle_revision=handle_revision+1 WHERE scope=? AND ref=?", rev, scope, ref.String())
		return e
	case "endpoint.retire":
		_, e := tx.ExecContext(ctx, "UPDATE reference_handles SET retired=1,bound_revision=? WHERE scope=? AND ref=? AND retired=0", rev, scope, ref.String())
		return e
	}
	return nil
}

// verifyReferenceHandles is the restart gate for adopted handle state: the
// counter must match the pinned installation identity, slots must be
// contiguous from 1 with no foreign-scope rows, and every row must be
// permanently bound to one local endpoint consistent with the signed ledger
// head. Any disagreement fails Open; state is never repaired or purged.
func (s *Store) verifyReferenceHandles(ctx context.Context) error {
	var tables int
	if e := s.db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('reference_handle_counter','reference_handles')").Scan(&tables); e != nil {
		return e
	}
	if tables != 2 {
		return invalid("Incomplete reference handle state")
	}
	scope := s.referenceHandleScope()
	var storedScope string
	var nextSlot int64
	if e := s.db.QueryRowContext(ctx, "SELECT scope,next_slot FROM reference_handle_counter WHERE singleton=1").Scan(&storedScope, &nextSlot); e != nil {
		return invalid("reference handle counter absent")
	}
	if storedScope != scope || nextSlot < 1 {
		return invalid("reference handle scope does not match pinned identity")
	}
	if nextSlot-1 > int64(s.options.Limits.MaxReferenceHandles) {
		return invalid("reference handle quota below retained slots")
	}
	var total, scoped int64
	if e := s.db.QueryRowContext(ctx, "SELECT count(*) FROM reference_handles").Scan(&total); e != nil {
		return e
	}
	if e := s.db.QueryRowContext(ctx, "SELECT count(*) FROM reference_handles WHERE scope=?", scope).Scan(&scoped); e != nil {
		return e
	}
	if total != nextSlot-1 || scoped != nextSlot-1 {
		return invalid("reference handle slot sequence has gaps or foreign rows")
	}
	// One bounded join stream over the single-writer database: the writer pool
	// holds a single connection, so verification must never issue a second
	// query while a result set is open.
	rows, e := s.db.QueryContext(ctx, `SELECT h.scope,h.slot,h.ref,h.handle_revision,h.bound_revision,h.label,h.retired,o.revision,o.retired,o.domain,o.kind
FROM reference_handles h JOIN objects o ON o.ref=h.ref WHERE h.scope=? ORDER BY h.slot`, scope)
	if e != nil {
		return e
	}
	defer rows.Close()
	expected := int64(1)
	for rows.Next() {
		var r referenceHandleRow
		var oRevision fabric.Revision
		var oRetired bool
		var oDomain, oKind string
		if e = rows.Scan(&r.scope, &r.slot, &r.ref, &r.handleRevision, &r.boundRevision, &r.label, &r.retired, &oRevision, &oRetired, &oDomain, &oKind); e != nil {
			return e
		}
		if r.slot != expected || r.handleRevision < 1 || !text(r.label, 256, false) {
			return invalid("malformed reference handle row")
		}
		expected++
		ref, e := fabric.ParseEndpointRef(r.ref)
		if e != nil || ref.IsOffer() || ref.Domain() != s.identity.Namespace {
			return invalid("reference handle target is not a local endpoint")
		}
		if oDomain != s.identity.Namespace || oKind != "endpoint" || oRetired != r.retired || oRevision != r.boundRevision {
			return invalid("reference handle state disagrees with the signed ledger")
		}
	}
	if e = rows.Err(); e != nil {
		return e
	}
	if expected-1 != scoped {
		return invalid("reference handle target is missing from the signed ledger")
	}
	return nil
}

var _ fabric.ReferenceHandleResolver = (*Store)(nil)
