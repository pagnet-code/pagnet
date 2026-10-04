package semantic

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

type OllamaConfig struct {
	BaseURL, Model, Version, Digest, Token string
	Dimensions                             int
	Client                                 *http.Client
	AllowHTTP                              bool
	NumGPU                                 *int
}
type Ollama struct {
	http     *transport
	identity EmbeddingIdentity
	digest   string
	numGPU   *int
}

func NewOllama(c OllamaConfig) (*Ollama, error) {
	if c.Model == "" || c.Version == "" || c.Dimensions < 1 || c.Dimensions > 4096 {
		return nil, errors.New("explicit model/version/dimensions required")
	}
	if c.Digest != "" && len(c.Digest) != 64 {
		return nil, errors.New("invalid selected model digest")
	}
	var gpu *int
	if c.NumGPU != nil {
		n := *c.NumGPU
		if n < 0 || n > 128 {
			return nil, errors.New("invalid explicit embedding GPU count")
		}
		gpu = &n
	}
	t, e := newTransport(c.BaseURL, c.Token, c.Client, c.AllowHTTP)
	if e != nil {
		return nil, e
	}
	return &Ollama{http: t, identity: EmbeddingIdentity{Provider: "ollama", Model: c.Model, Version: c.Version, Dimensions: c.Dimensions}, digest: c.Digest, numGPU: gpu}, nil
}
func (o *Ollama) Identity() EmbeddingIdentity { return o.identity }
func (o *Ollama) verify(ctx context.Context) error {
	if o.digest == "" {
		return nil
	}
	var reply struct {
		Models []struct{ Name, Model, Digest string }
	}
	if e := o.http.request(ctx, http.MethodGet, "/api/tags", nil, &reply, "Authorization"); e != nil {
		return e
	}
	for _, m := range reply.Models {
		if (m.Name == o.identity.Model || m.Model == o.identity.Model) && m.Digest == o.digest {
			return nil
		}
	}
	return errors.New("selected installed embedding model digest changed or is missing")
}
func (o *Ollama) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	if len(texts) < 1 || len(texts) > 128 {
		return nil, errors.New("embedding batch must contain1..128 inputs")
	}
	for _, s := range texts {
		if len(s) > 16384 {
			return nil, errors.New("embedding text exceeds compact byte budget")
		}
	}
	if e := o.verify(ctx); e != nil {
		return nil, e
	}
	var reply struct {
		Model      string
		Embeddings [][]float32
	}
	body := map[string]any{"model": o.identity.Model, "input": texts, "truncate": false, "keep_alive": "0"}
	if o.numGPU != nil {
		body["options"] = map[string]any{"num_gpu": *o.numGPU}
	}
	if e := o.http.request(ctx, http.MethodPost, "/api/embed", body, &reply, "Authorization"); e != nil {
		return nil, e
	}
	if reply.Model != o.identity.Model && !strings.HasPrefix(reply.Model, o.identity.Model+":") {
		return nil, errors.New("embedding response selected a different model")
	}
	if e := validateVectors(reply.Embeddings, len(texts), o.identity.Dimensions); e != nil {
		return nil, e
	}
	if e := o.verify(ctx); e != nil {
		return nil, e
	}
	return reply.Embeddings, nil
}
