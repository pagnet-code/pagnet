package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/pagnet-code/pagnet/fabric"
)

type AuthorityRecordPage struct {
	Records    []AuthorityRecord
	NextCursor string
}
type authorityPageCursor struct {
	Kind       NativeAuthorityKind `json:"kind"`
	Prefix     string              `json:"prefix"`
	After      string              `json:"after"`
	Generation uint64              `json:"generation,string"`
}

// ListGlobalAuthorityRecords is owner-only retained infrastructure enumeration.
// It does not grant execution authority or establish liveness. Indexed keyset
// pages keep startup recovery bounded independently of registry/tool count.
func (s *Store) ListGlobalAuthorityRecords(ctx context.Context, owner fabric.ExecutionContext, kind NativeAuthorityKind, idPrefix, cursor string, limit int) (AuthorityRecordPage, error) {
	if ctx == nil || !globalAuthorityKind(kind) || !validAuthorityKind(kind) || idPrefix == "" || len(idPrefix) > 128 || strings.ContainsRune(idPrefix, 0) || limit < 1 || limit > 32 || len(cursor) > 4096 {
		return AuthorityRecordPage{}, invalid("Invalid authority page bounds")
	}
	// Prefixes are private ASCII purpose namespaces, not arbitrary SQL patterns.
	for _, r := range idPrefix {
		if r < 33 || r > 126 {
			return AuthorityRecordPage{}, invalid("Invalid authority page namespace")
		}
	}
	root := s.AuthorityIdentity()
	var page AuthorityRecordPage
	err := s.WithNativeAuthority(ctx, owner, AuthorityScope{}, func(a *AuthorityTx) error {
		a.mu.Lock()
		defer a.mu.Unlock()
		if err := a.guard(); err != nil {
			return err
		}
		var generation uint64
		if err := a.tx.QueryRowContext(a.ctx, "SELECT sequence FROM native_authority_head WHERE singleton=1").Scan(&generation); err != nil {
			return err
		}
		c := authorityPageCursor{Kind: kind, Prefix: idPrefix, Generation: generation}
		lower := string(kind) + "\x00\x00" + idPrefix
		upperBytes := []byte(lower)
		upperBytes[len(upperBytes)-1]++
		upper := string(upperBytes)
		after := ""
		if cursor != "" {
			raw, err := base64.RawURLEncoding.DecodeString(cursor)
			if err != nil {
				return invalid("Invalid authority cursor")
			}
			if err = fabric.DecodeJSON(raw, &c); err != nil {
				return err
			}
			if c.Kind != kind || c.Prefix != idPrefix || c.Generation != generation {
				return conflict("Authority page snapshot changed")
			}
			if !strings.HasPrefix(c.After, lower) || c.After >= upper {
				return invalid("Authority cursor scope differs")
			}
			after = c.After
		}
		rows, err := a.tx.QueryContext(a.ctx, "SELECT key,CASE WHEN length(record)<=65536 THEN record END FROM native_authority_state WHERE key>=? AND key<? AND key>? ORDER BY key LIMIT ?", lower, upper, after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		bytes := 0
		for rows.Next() {
			var key string
			var raw []byte
			if err = rows.Scan(&key, &raw); err != nil {
				return err
			}
			if len(page.Records) == limit || len(page.Records) > 0 && bytes+len(raw) > 1<<20 {
				last := page.Records[len(page.Records)-1]
				c.After = last.Key.string()
				b, _ := json.Marshal(c)
				page.NextCursor = base64.RawURLEncoding.EncodeToString(b)
				break
			}
			if len(raw) == 0 {
				return invalid("Retained authority record exceeds page bound")
			}
			var record AuthorityRecord
			if s.decodeAuthority(raw, &record) != nil || record.Key.string() != key || record.Key.Kind != kind || record.Key.Endpoint.String() != "" || !strings.HasPrefix(record.Key.ID, idPrefix) || VerifyAuthorityRecord(root, record) != nil {
				return invalid("Retained authority page record differs")
			}
			page.Records = append(page.Records, record)
			bytes += len(raw)
		}
		return rows.Err()
	})
	if err != nil {
		return AuthorityRecordPage{}, err
	}
	return page, nil
}
