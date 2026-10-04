package semantic

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/fabric/search/hybrid"
)

func document(i uint64, text string) fabric.SearchDocument {
	pub := make([]byte, 32)
	pub[0] = 1
	domain, _ := fabric.DomainNamespace(pub)
	id := make([]byte, 32)
	binary.BigEndian.PutUint64(id, i)
	enc := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	ref, e := fabric.ParseEndpointRef("pagnet://" + domain + "/e/" + enc.EncodeToString(id))
	if e != nil {
		panic(e)
	}
	return fabric.SearchDocument{Ref: ref, Revision: "r1", Name: fmt.Sprintf("actor%d", i), ShortDescription: text, Kind: "actor.agent", Provider: "local", Tags: []string{"test"}}
}
func gates(c *Config) {
	c.DisclosureGate = func(context.Context, Disclosure) error { return nil }
	c.IndexGate = func(context.Context, []fabric.SearchDocument) error { return nil }
	c.CandidateGate = func(_ context.Context, _ fabric.DiscoverRequest, cs []fabric.Candidate) (hybrid.GateResult, error) {
		return hybrid.GateResult{ScopeKey: "verification", PolicyRevision: "policy1", Candidates: cs}, nil
	}
}
func qdrant(t *testing.T, dims int) *Qdrant {
	t.Helper()
	base := os.Getenv("QDRANT_TEST_URL")
	if base == "" {
		t.Skip("set explicit QDRANT_TEST_URL for real isolated ANN integration")
	}
	q, e := NewQdrant(QdrantConfig{BaseURL: base, Collection: fmt.Sprintf("pagnet_test_%d", time.Now().UnixNano()), Dimensions: dims})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if e = q.Setup(ctx); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = q.http.request(ctx, "DELETE", q.path(""), nil, nil, "api-key")
	})
	return q
}
func ready(t *testing.T, q ANNIndex) {
	t.Helper()
	readyWithin(t, q, 45*time.Second)
}
func readyWithin(t *testing.T, q ANNIndex, budget time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	for {
		e := q.Ready(ctx)
		if e == nil {
			return
		}
		if !errors.Is(e, ErrIndexNotReady) {
			t.Fatal(e)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

type featureEmbedding struct{ dims int }

func (f featureEmbedding) Identity() EmbeddingIdentity {
	return EmbeddingIdentity{Provider: "verification-only", Model: "byte-features", Version: "v1", Dimensions: f.dims}
}
func (f featureEmbedding) Embed(_ context.Context, texts []string) ([][]float32, error) {
	vectors := make([][]float32, len(texts))
	for i, text := range texts {
		v := make([]float32, f.dims)
		for _, ch := range []byte(text) {
			v[int(ch)%f.dims]++
		}
		if len(text) == 0 {
			v[0] = 1
		}
		vectors[i] = v
	}
	return vectors, nil
}
func applyReady(t *testing.T, b *Backend, batch search.Batch) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	e := b.Apply(ctx, batch)
	if errors.Is(e, ErrIndexNotReady) {
		ready(t, b.config.ANN)
		e = b.Apply(ctx, batch)
	}
	if e != nil {
		t.Fatal(e)
	}
}
func TestRealQdrantLifecycleCheckpointAndFailedPublication(t *testing.T) {
	q := qdrant(t, 384)
	config := Config{ANN: q, Embeddings: featureEmbedding{384}}
	gates(&config)
	records := []search.CommitRecord{}
	fail := false
	config.Commit = func(_ context.Context, r search.CommitRecord) error {
		if fail {
			return errors.New("durable commit refused")
		}
		records = append(records, r)
		return nil
	}
	b, e := New(config)
	if e != nil {
		t.Fatal(e)
	}
	docs := make([]fabric.SearchDocument, 32)
	for i := range docs {
		docs[i] = document(uint64(i+1), fmt.Sprintf("warehouse inventory number%d", i))
	}
	applyReady(t, b, search.Batch{Upserts: docs, UpstreamCursor: "1"})
	request := fabric.DiscoverRequest{Query: "warehouse inventory", Limit: 5}
	before, e := b.Search(context.Background(), request)
	if e != nil || len(before.Candidates) != 5 || before.NextCursor == "" {
		t.Fatal(before, e)
	}
	cp, e := b.Checkpoint(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	changed := docs[0]
	changed.Revision = "r2"
	changed.ShortDescription = "different accounting invoice"
	applyReady(t, b, search.Batch{Upserts: []fabric.SearchDocument{changed}, Deletes: []search.Deletion{{Ref: docs[1].Ref, ExpectedRevision: docs[1].Revision}}, UpstreamCursor: "2"})
	fail = true
	discarded := document(99, "private abandoned stage")
	e = b.Apply(context.Background(), search.Batch{Upserts: []fabric.SearchDocument{discarded}, UpstreamCursor: "3"})
	if e == nil {
		t.Fatal("durable failure published")
	}
	fail = false
	replacement := document(100, "warehouse inventory replacement")
	applyReady(t, b, search.Batch{Upserts: []fabric.SearchDocument{replacement}, UpstreamCursor: "3"})
	all, e := b.Search(context.Background(), fabric.DiscoverRequest{Query: "warehouse inventory", Limit: 100})
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range all.Candidates {
		if c.Document.Ref == discarded.Ref || c.Document.Ref == docs[1].Ref {
			t.Fatal("abandoned/retired vector leaked")
		}
	}
	request.Cursor = before.NextCursor
	if _, e = b.Search(context.Background(), request); !errors.Is(e, snapshotStale()) {
		t.Fatal("stale semantic page accepted", e)
	}
	i := 1
	loaded, e := Load(context.Background(), config, cp.Header(), func(ctx context.Context, section, after string, _ int) (search.CheckpointPage, error) {
		return cp.Page(ctx, section, after, 7)
	}, func(context.Context) (search.CommitRecord, bool, error) {
		if i == len(records) {
			return search.CommitRecord{}, false, nil
		}
		r := records[i]
		i++
		return r, true, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	restored, e := loaded.Search(context.Background(), fabric.DiscoverRequest{Query: "warehouse inventory", Limit: 100})
	if e != nil || fmt.Sprint(all.Candidates) != fmt.Sprint(restored.Candidates) {
		t.Fatal("restored committed ANN/catalog changed", e)
	}
	bad := cp.Header()
	bad.Embedding.Version = "wrong"
	if _, e = Load(context.Background(), config, bad, nil, nil); e == nil {
		t.Fatal("wrong embedding checkpoint restored")
	}
	t.Logf("real qdrant indexed lifecycle documents=%d usage=%+v snapshot=%s", len(restored.Candidates), loaded.LastUsage(), cp.Header().ANN.Name)
}
func snapshotStale() error { return hybrid.ErrStaleSnapshot }
func TestSelectedInstalledOllamaProviderIntegration(t *testing.T) {
	base, model, digest := os.Getenv("OLLAMA_TEST_URL"), os.Getenv("OLLAMA_TEST_MODEL"), os.Getenv("OLLAMA_TEST_DIGEST")
	if base == "" || model == "" || digest == "" {
		t.Skip("explicit installed Ollama endpoint/model/digest required; never pull a model")
	}
	cpu := 0
	o, e := NewOllama(OllamaConfig{NumGPU: &cpu, BaseURL: base, Model: model, Digest: digest, Version: digest, Dimensions: 384})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	vectors, e := o.Embed(ctx, []string{"Summarize incoming email and manage the inbox.", "Check warehouse inventory and shipments.", "A short summary of new messages in my mailbox."})
	if e != nil {
		t.Fatal(e)
	}
	if e = validateVectors(vectors, 3, 384); e != nil {
		t.Fatal(e)
	}
	cos := func(a, b []float32) float64 {
		dot, na, nb := 0.0, 0.0, 0.0
		for i, n := range a {
			dot += float64(n) * float64(b[i])
			na += float64(n) * float64(n)
			nb += float64(b[i]) * float64(b[i])
		}
		return dot / (math.Sqrt(na) * math.Sqrt(nb))
	}
	mail, warehouse := cos(vectors[2], vectors[0]), cos(vectors[2], vectors[1])
	if mail <= warehouse {
		t.Fatal("selected model role relevance regression", mail, warehouse)
	}
	t.Logf("real installed selected model=%s dimensions384 emailcos=%.4f warehousecos=%.4f", model, mail, warehouse)
}

// Real selected installed model + real ANN + independently authored grades.
// This small English role corpus is a regression baseline, not broad model eval.
func TestRealSelectedSemanticLanguageRelevance(t *testing.T) {
	base, model, digest := os.Getenv("OLLAMA_TEST_URL"), os.Getenv("OLLAMA_TEST_MODEL"), os.Getenv("OLLAMA_TEST_DIGEST")
	if base == "" || model == "" || digest == "" {
		t.Skip("explicit installed embedding provider required")
	}
	cpu := 0
	o, e := NewOllama(OllamaConfig{BaseURL: base, Model: model, Digest: digest, Version: digest, Dimensions: 384, NumGPU: &cpu})
	if e != nil {
		t.Fatal(e)
	}
	q := qdrant(t, 384)
	config := Config{Embeddings: o, ANN: q}
	gates(&config)
	b, e := New(config)
	if e != nil {
		t.Fatal(e)
	}
	descriptions := []string{
		"Summarizes incoming email and manages the inbox.", "Sends email notifications and tracks delivery.",
		"Checks invoices, accounting expenses and outstanding payments.", "Finds vendor invoices and prepares payment reports.",
		"Controls building heating and reduces energy consumption.", "Reads room temperature sensors and building climate data.",
		"Captures microscopy images and analyzes laboratory samples.", "Schedules laboratory instruments and sample processing.",
		"Checks warehouse inventory, stock levels and missing goods.", "Tracks warehouse shipments, freight and delivery routes.",
		"Translates customer support tickets between languages.", "Translates documents and checks language quality.",
		"Reviews software repositories and implements code changes.", "Manages calendar appointments and schedules meetings.",
		"Plays music through speakers and controls audio volume.", "Measures website traffic and marketing campaign performance.",
	}
	docs := make([]fabric.SearchDocument, len(descriptions))
	for i, text := range descriptions {
		docs[i] = document(uint64(i+1), text)
	}
	applyReady(t, b, search.Batch{Upserts: docs, UpstreamCursor: "language1"})
	lex, e := search.New(search.Config{})
	if e != nil {
		t.Fatal(e)
	}
	for _, d := range docs {
		if e = lex.Upsert(context.Background(), d); e != nil {
			t.Fatal(e)
		}
	}
	queries := []string{"Give me a digest of new messages in my mailbox.", "Which bills still need to be paid?", "Make the office warmer without wasting power.", "I need to inspect tiny biological specimens visually.", "What merchandise remains available in the depot?", "Help multilingual customers understand their support requests."}
	type metrics struct{ Recall, MRR, NDCG float64 }
	totals := []metrics{{}, {}}
	for qi, text := range queries {
		r := fabric.DiscoverRequest{Query: text, Limit: 2}
		l, e := lex.Search(context.Background(), r)
		if e != nil {
			t.Fatal(e)
		}
		s, e := b.Search(context.Background(), r)
		if e != nil {
			t.Fatal(e)
		}
		for channel, cs := range [][]fabric.Candidate{l.Candidates, s.Candidates} {
			found, dcg, rr := 0, 0.0, 0.0
			for rank, c := range cs {
				grade := 0
				if c.Document.Ref == docs[qi*2].Ref {
					grade = 2
				} else if c.Document.Ref == docs[qi*2+1].Ref {
					grade = 1
				}
				if grade > 0 {
					found++
					if rr == 0 {
						rr = 1 / float64(rank+1)
					}
				}
				dcg += (math.Pow(2, float64(grade)) - 1) / math.Log2(float64(rank+2))
			}
			m := metrics{float64(found) / 2, rr, dcg / (3 + 1/math.Log2(3))}
			totals[channel].Recall += m.Recall
			totals[channel].MRR += m.MRR
			totals[channel].NDCG += m.NDCG
			t.Logf("real language query%d channel%d Recall@2/MRR/NDCG@2=%+v", qi, channel, m)
		}
	}
	for i := range totals {
		totals[i].Recall /= 6
		totals[i].MRR /= 6
		totals[i].NDCG /= 6
	}
	t.Logf("real selected model=%s rolecorpus16 queries6 lexical=%+v semantic=%+v", model, totals[0], totals[1])
	if totals[1].Recall < .5 || totals[1].MRR < .6 || totals[1].NDCG < .5 {
		t.Fatal("real selected-model relevance baseline regression", totals)
	}
}
