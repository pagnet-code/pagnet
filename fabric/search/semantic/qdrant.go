package semantic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

type QdrantConfig struct {
	BaseURL, Collection, Token string
	Dimensions                 int
	Client                     *http.Client
	AllowHTTP                  bool
	QueryTimeout               time.Duration
}
type Qdrant struct {
	http         *transport
	collection   string
	dimensions   int
	queryTimeout time.Duration
}

func NewQdrant(c QdrantConfig) (*Qdrant, error) {
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`).MatchString(c.Collection) || c.Dimensions < 1 || c.Dimensions > 4096 {
		return nil, errors.New("explicit safe collection name/dimensions required")
	}
	if c.QueryTimeout == 0 {
		c.QueryTimeout = 15 * time.Second
	}
	if c.QueryTimeout < time.Second || c.QueryTimeout > time.Minute {
		return nil, errors.New("ANN query deadline must be1..60 seconds")
	}
	t, e := newTransport(c.BaseURL, c.Token, c.Client, c.AllowHTTP)
	if e != nil {
		return nil, e
	}
	return &Qdrant{http: t, collection: c.Collection, dimensions: c.Dimensions, queryTimeout: c.QueryTimeout}, nil
}
func (q *Qdrant) Identity() string {
	raw := []byte(q.http.base + "/" + q.collection + fmt.Sprint(q.dimensions))
	h := sha256.Sum256(raw)
	return "qdrant-rest-v1:" + hex.EncodeToString(h[:])
}
func (q *Qdrant) path(s string) string { return "/collections/" + url.PathEscape(q.collection) + s }

// Setup is explicit operator initialization, never called by New/Search.
// Payload indexes are built before vector ingestion. No inference/model download.
func (q *Qdrant) Setup(ctx context.Context) error {
	config := map[string]any{"vectors": map[string]any{"size": q.dimensions, "distance": "Cosine"}, "hnsw_config": map[string]any{"m": 16, "ef_construct": 128, "full_scan_threshold": 10}, "optimizers_config": map[string]any{"indexing_threshold": 1, "default_segment_number": 1}, "strict_mode_config": map[string]any{"enabled": true, "max_query_limit": 100, "search_max_hnsw_ef": 4096, "search_allow_exact": true, "unindexed_filtering_retrieve": false, "unindexed_filtering_update": false}}
	if e := q.http.request(ctx, http.MethodPut, q.path(""), config, nil, "api-key"); e != nil {
		return e
	}
	for _, name := range []string{"ref", "revision", "domain", "kind", "provider", "tags", "model"} {
		if e := q.http.request(ctx, http.MethodPut, q.path("/index?wait=true"), map[string]any{"field_name": name, "field_schema": "keyword"}, nil, "api-key"); e != nil {
			return e
		}
	}
	for _, name := range []string{"from", "until"} {
		if e := q.http.request(ctx, http.MethodPut, q.path("/index?wait=true"), map[string]any{"field_name": name, "field_schema": "integer"}, nil, "api-key"); e != nil {
			return e
		}
	}
	return nil
}
func condition(key string, value any) map[string]any {
	return map[string]any{"key": key, "match": map[string]any{"value": value}}
}
func generationCondition(key string, op string, g uint64) map[string]any {
	return map[string]any{"key": key, "range": map[string]any{op: g}}
}
func (q *Qdrant) ResetStage(ctx context.Context, g uint64) error {
	if g == 0 || g > math.MaxInt64-1 {
		return errors.New("invalid unpublished generation")
	}
	if e := q.http.request(ctx, http.MethodPost, q.path("/points/delete?wait=true"), map[string]any{"filter": map[string]any{"must": []any{condition("from", g)}}}, nil, "api-key"); e != nil {
		return e
	}
	return q.http.request(ctx, http.MethodPost, q.path("/points/payload?wait=true"), map[string]any{"payload": map[string]any{"until": int64(math.MaxInt64)}, "filter": map[string]any{"must": []any{condition("until", g)}}}, nil, "api-key")
}
func (q *Qdrant) Stage(ctx context.Context, g uint64, points []VectorPoint, retire []string) error {
	if g == 0 || g > math.MaxInt64-1 || len(points)+len(retire) > 256 {
		return errors.New("invalid staged vector bounds")
	}
	if len(retire) > 0 {
		if e := q.http.request(ctx, http.MethodPost, q.path("/points/payload?wait=true"), map[string]any{"payload": map[string]any{"until": g}, "points": retire}, nil, "api-key"); e != nil {
			return e
		}
	}
	if len(points) == 0 {
		return nil
	}
	raw := make([]map[string]any, len(points))
	for i, p := range points {
		if e := validateVectors([][]float32{p.Vector}, 1, q.dimensions); e != nil {
			return e
		}
		if p.From != g {
			return errors.New("point generation mismatch")
		}
		raw[i] = map[string]any{"id": p.Key, "vector": p.Vector, "payload": map[string]any{"ref": p.Ref.String(), "revision": p.Revision, "domain": p.Domain, "kind": p.Kind, "provider": p.Provider, "tags": p.Tags, "from": g, "until": int64(math.MaxInt64), "model": p.Model}}
	}
	return q.http.request(ctx, http.MethodPut, q.path("/points?wait=true"), map[string]any{"points": raw}, nil, "api-key")
}
func (q *Qdrant) Ready(ctx context.Context) error {
	var reply struct {
		Result struct {
			Status  string `json:"status"`
			Points  uint64 `json:"points_count"`
			Indexed uint64 `json:"indexed_vectors_count"`
			Config  struct {
				Params struct {
					Vectors struct {
						Size     int
						Distance string
					}
				}
				HNSW struct {
					FullScan int `json:"full_scan_threshold"`
				} `json:"hnsw_config"`
			}
			Payload map[string]any `json:"payload_schema"`
		}
	}
	if e := q.http.request(ctx, http.MethodGet, q.path(""), nil, &reply, "api-key"); e != nil {
		return e
	}
	r := reply.Result
	if r.Config.Params.Vectors.Size != q.dimensions || r.Config.Params.Vectors.Distance != "Cosine" || r.Config.HNSW.FullScan != 10 {
		return errors.New("selected ANN collection vector/index configuration mismatch")
	}
	for _, key := range []string{"ref", "revision", "domain", "kind", "provider", "tags", "model", "from", "until"} {
		if _, ok := r.Payload[key]; !ok {
			return errors.New("selected ANN collection is missing required payload index")
		}
	}
	if r.Status != "green" || r.Indexed < r.Points {
		return ErrIndexNotReady
	}
	return nil
}
func (q *Qdrant) Query(ctx context.Context, v VectorQuery) (VectorResult, error) {
	if v.Limit < 1 || v.Limit > 100 || v.Ef < v.Limit || v.Ef > 4096 || v.Generation > math.MaxInt64-1 {
		return VectorResult{}, errors.New("invalid finite ANN query budget")
	}
	if e := validateVectors([][]float32{v.Vector}, 1, q.dimensions); e != nil {
		return VectorResult{}, e
	}
	must := []any{condition("model", v.Model), generationCondition("from", "lte", v.Generation), generationCondition("until", "gt", v.Generation)}
	for _, group := range []struct {
		key    string
		values []string
	}{{"domain", v.Domains}, {"kind", v.Kinds}, {"provider", v.Providers}, {"tags", v.Tags}} {
		if len(group.values) > 64 {
			return VectorResult{}, errors.New("ANN filter budget exceeded")
		}
		if len(group.values) > 0 {
			must = append(must, map[string]any{"key": group.key, "match": map[string]any{"any": group.values}})
		}
	}
	body := map[string]any{"query": v.Vector, "filter": map[string]any{"must": must}, "limit": v.Limit, "with_payload": []string{"ref", "revision"}, "with_vector": false, "params": map[string]any{"hnsw_ef": v.Ef, "exact": false, "indexed_only": true}}
	var reply struct {
		Result struct {
			Points []struct {
				Score   float64
				Payload struct {
					Ref      string
					Revision fabric.Revision
				}
			}
		}
		Usage struct {
			Hardware *struct {
				CPU           uint64 `json:"cpu"`
				VectorReads   uint64 `json:"vector_io_read"`
				VectorWrites  uint64 `json:"vector_io_write"`
				PayloadReads  uint64 `json:"payload_io_read"`
				PayloadWrites uint64 `json:"payload_io_write"`
			}
		}
	}
	if e := q.http.request(ctx, http.MethodPost, q.path("/points/query?timeout="+fmt.Sprint(q.querySeconds(ctx))), body, &reply, "api-key"); e != nil {
		return VectorResult{}, e
	}
	if len(reply.Result.Points) > v.Limit {
		return VectorResult{}, errors.New("ANN service exceeded requested candidate bound")
	}
	r := VectorResult{Hits: []VectorHit{}}
	if h := reply.Usage.Hardware; h != nil {
		r.Usage = Usage{Reported: true, CPU: h.CPU, VectorReads: h.VectorReads, VectorWrites: h.VectorWrites, PayloadReads: h.PayloadReads, PayloadWrites: h.PayloadWrites}
	}

	for _, p := range reply.Result.Points {
		ref, e := fabric.ParseEndpointRef(p.Payload.Ref)
		if e != nil || p.Payload.Revision == "" || math.IsNaN(p.Score) || math.IsInf(p.Score, 0) {
			return r, errors.New("ANN service returned invalid candidate")
		}
		r.Hits = append(r.Hits, VectorHit{Ref: ref, Revision: p.Payload.Revision, Score: p.Score})
	}
	return r, nil
}
func (q *Qdrant) Snapshot(ctx context.Context) (ANNSnapshot, error) {
	var r struct {
		Result struct{ Name, Checksum string }
	}
	if e := q.http.request(ctx, http.MethodPost, q.path("/snapshots?wait=true"), map[string]any{}, &r, "api-key"); e != nil {
		return ANNSnapshot{}, e
	}
	if r.Result.Name == "" || r.Result.Checksum == "" {
		return ANNSnapshot{}, errors.New("ANN snapshot commitment missing")
	}
	return ANNSnapshot{Name: r.Result.Name, SHA256: r.Result.Checksum, IndexIdentity: q.Identity()}, nil
}
func (q *Qdrant) VerifySnapshot(ctx context.Context, s ANNSnapshot) error {
	if s.IndexIdentity != q.Identity() || !regexp.MustCompile(`^[a-zA-Z0-9._-]{1,256}$`).MatchString(s.Name) || strings.Contains(s.Name, "..") || len(s.SHA256) != 64 {
		return errors.New("ANN checkpoint identity mismatch")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, q.http.base+q.path("/snapshots/"+url.PathEscape(s.Name)), nil)
	if err != nil {
		return err
	}
	if q.http.token != "" {
		req.Header.Set("api-key", q.http.token)
	}
	response, err := q.http.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("ANN snapshot verification request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("selected ANN checkpoint is unavailable")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(response.Body, (4<<30)+1))
	if err != nil {
		return errors.New("ANN snapshot verification stream failed")
	}
	if n > 4<<30 || hex.EncodeToString(hash.Sum(nil)) != s.SHA256 {
		return errors.New("ANN snapshot exceeds budget or commitment differs")
	}
	return ctx.Err()
}

// Count is startup/checkpoint maintenance, never called from hot Query.
func (q *Qdrant) Count(ctx context.Context, g uint64, model string) (uint64, error) {
	var reply struct{ Result struct{ Count uint64 } }
	body := map[string]any{"exact": true, "filter": map[string]any{"must": []any{condition("model", model), generationCondition("from", "lte", g), generationCondition("until", "gt", g)}}}
	if e := q.http.request(ctx, http.MethodPost, q.path("/points/count"), body, &reply, "api-key"); e != nil {
		return 0, e
	}
	return reply.Result.Count, nil
}

func (q *Qdrant) querySeconds(ctx context.Context) int64 {
	budget := q.queryTimeout
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < budget {
		budget = time.Until(deadline)
	}
	seconds := int64(math.Ceil(budget.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	return seconds
}
