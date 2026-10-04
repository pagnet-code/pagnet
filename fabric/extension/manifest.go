package extension

import (
	"container/heap"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

type Placement string

const (
	PlacementSource      Placement = "source"
	PlacementDestination Placement = "destination"
	PlacementRelay       Placement = "relay"
)

type FailureMode string

const (
	FailClosed FailureMode = "fail-closed"
	FailOpen   FailureMode = "fail-open"
)

type Phase string

const (
	PhaseRequest    Phase = "request"
	PhaseResponse   Phase = "response"
	PhaseError      Phase = "error"
	PhaseChunk      Phase = "chunk"
	PhaseCompletion Phase = "completion"
)

// ExtensionManifest is configuration, never an authentication assertion. An
// authenticated operator installs it inside an explicitly trusted node boundary.
// Event observers and work-producing triggers are separate registrations.
type ExtensionManifest struct {
	ManifestVersion     fabric.ProtocolVersion `json:"manifestVersion"`
	ID                  string                 `json:"id"`
	Version             string                 `json:"version"`
	MinProtocol         fabric.ProtocolVersion `json:"minProtocol"`
	MaxProtocol         fabric.ProtocolVersion `json:"maxProtocol"`
	Interceptors        []Registration         `json:"interceptors,omitempty"`
	EventSubscriptions  []EventSubscription    `json:"eventSubscriptions,omitempty"`
	Triggers            []TriggerRegistration  `json:"triggers,omitempty"`
	ConfigurationSchema json.RawMessage        `json:"configurationSchema,omitempty"`
}
type EventSubscription struct {
	ID      string   `json:"id"`
	Types   []string `json:"types"`
	Binding string   `json:"binding"`
}
type TriggerRegistration struct {
	ID      string `json:"id"`
	Binding string `json:"binding"`
}
type Registration struct {
	ID                 string      `json:"id"`
	Priority           int32       `json:"priority"`
	Before             []string    `json:"before,omitempty"`
	After              []string    `json:"after,omitempty"`
	Match              Match       `json:"match"`
	Placement          Placement   `json:"placement"`
	NeedsPlaintext     bool        `json:"needsPlaintext"`
	Phases             []Phase     `json:"phases"`
	TimeoutMillis      uint32      `json:"timeoutMillis"`
	FailureMode        FailureMode `json:"failureMode,omitempty"`
	AllowSelfRecursion bool        `json:"allowSelfRecursion,omitempty"`
	Binding            string      `json:"binding"`
}
type Match struct {
	Operation       fabric.Operation `json:"operation"`
	Stage           string           `json:"stage"`
	SourceKinds     []string         `json:"sourceKinds,omitempty"`
	TargetKinds     []string         `json:"targetKinds,omitempty"`
	TargetProtocols []string         `json:"targetProtocols,omitempty"`
	Domains         []string         `json:"domains,omitempty"`
	Tags            []string         `json:"tags,omitempty"`
}

// MatchContext is derived by the node from verified identity and the selected
// descriptor/binding. Caller-provided tags do not become routing authority.
type MatchContext struct {
	Operation             fabric.Operation
	Stage                 string
	Placement             Placement
	SourceKind            string
	TargetKind            string
	TargetProtocol        string
	Domain                string
	Tags                  []string
	ExecutingInterceptors []string
}
type CompiledRegistration struct {
	ExtensionID  string
	Registration Registration
}
type chainKey struct {
	operation fabric.Operation
	stage     string
	placement Placement
}
type Plan struct {
	chains   map[chainKey][]CompiledRegistration
	revision string
	byID     map[string]CompiledRegistration
}

func Compile(manifests []ExtensionManifest, maxInterceptors int) (*Plan, error) {
	if maxInterceptors < 1 || maxInterceptors > 100000 {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid extension capacity")
	}
	nodes := make(map[string]CompiledRegistration)
	extensions := make(map[string]bool)
	for _, supplied := range manifests {
		// Take immutable ownership: external callers must not mutate an installed
		// plan's slices after validation. No JSON config/credential enters requests.
		raw, err := json.Marshal(supplied)
		if err != nil {
			return nil, invalidRegistration()
		}
		var manifest ExtensionManifest
		if fabric.DecodeJSONWithLimits(raw, &manifest, fabric.WireLimits{MaxBytes: maxInterceptors*4096 + 65536, MaxDepth: 64, MaxMembers: maxInterceptors*128 + 4096}) != nil {
			return nil, invalidRegistration()
		}
		if manifest.ManifestVersion.Validate() != nil || manifest.MinProtocol.Validate() != nil || manifest.MaxProtocol.Validate() != nil || !fabric.ValidNamespacedName(manifest.ID) || extensions[manifest.ID] || manifest.Version == "" || len(manifest.Version) > 128 {
			return nil, invalidRegistration()
		}
		// Initial protocol 1.0 must be inside the declared numeric minor range.
		if !protocolWithin(fabric.CurrentProtocolVersion, manifest.MinProtocol, manifest.MaxProtocol) {
			return nil, fabric.NewError(fabric.CodeUnsupported, "Extension protocol range is incompatible")
		}
		for installed := range extensions {
			if strings.HasPrefix(installed, manifest.ID+".") || strings.HasPrefix(manifest.ID, installed+".") {
				return nil, fabric.NewError(fabric.CodeInvalidInput, "Overlapping extension metadata namespaces")
			}
		}
		if strings.HasPrefix(manifest.ID, "pagnet.") {
			return nil, invalidRegistration()
		}
		extensions[manifest.ID] = true
		for _, r := range manifest.Interceptors {
			if err := validateRegistration(manifest.ID, &r); err != nil {
				return nil, err
			}
			if _, exists := nodes[r.ID]; exists {
				return nil, invalidRegistration()
			}
			if len(nodes) >= maxInterceptors {
				return nil, fabric.NewError(fabric.CodeInvalidInput, "Extension capacity exceeded")
			}
			nodes[r.ID] = CompiledRegistration{ExtensionID: manifest.ID, Registration: r}
		}
		// Registrations have distinct semantics, even when one extension supplies all.
		seen := map[string]bool{}
		for _, s := range manifest.EventSubscriptions {
			if !ownedID(manifest.ID, s.ID) || seen[s.ID] || s.Binding == "" || len(s.Binding) > 256 || len(s.Types) == 0 || len(s.Types) > 64 {
				return nil, invalidRegistration()
			}
			seen[s.ID] = true
			for _, kind := range s.Types {
				if !fabric.ValidNamespacedName(kind) {
					return nil, invalidRegistration()
				}
			}
		}
		for _, s := range manifest.Triggers {
			if !ownedID(manifest.ID, s.ID) || seen[s.ID] || s.Binding == "" || len(s.Binding) > 256 {
				return nil, invalidRegistration()
			}
			seen[s.ID] = true
		}
	}
	adjacency := make(map[string]map[string]bool, len(nodes))
	degree := make(map[string]int, len(nodes))
	add := func(from, to string) error {
		if from == to {
			return fabric.NewError(fabric.CodeExtensionCycle, "Interceptor dependency cycle")
		}
		if _, ok := nodes[from]; !ok {
			return invalidRegistration()
		}
		if _, ok := nodes[to]; !ok {
			return invalidRegistration()
		}
		if adjacency[from] == nil {
			adjacency[from] = map[string]bool{}
		}
		if !adjacency[from][to] {
			adjacency[from][to] = true
			degree[to]++
		}
		return nil
	}
	for id, n := range nodes {
		for _, other := range n.Registration.Before {
			if err := add(id, other); err != nil {
				return nil, err
			}
		}
		for _, other := range n.Registration.After {
			if err := add(other, id); err != nil {
				return nil, err
			}
		}
	}
	ready := &registrationHeap{}
	for id, n := range nodes {
		if degree[id] == 0 {
			heap.Push(ready, n)
		}
	}
	plan := &Plan{chains: make(map[chainKey][]CompiledRegistration), byID: nodes}
	visited := 0
	for ready.Len() > 0 {
		n := heap.Pop(ready).(CompiledRegistration)
		visited++
		r := n.Registration
		key := chainKey{r.Match.Operation, r.Match.Stage, r.Placement}
		plan.chains[key] = append(plan.chains[key], n)
		for to := range adjacency[r.ID] {
			degree[to]--
			if degree[to] == 0 {
				heap.Push(ready, nodes[to])
			}
		}
	}
	if visited != len(nodes) {
		return nil, fabric.NewError(fabric.CodeExtensionCycle, "Interceptor dependency cycle")
	}
	canonical := append([]ExtensionManifest(nil), manifests...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].ID < canonical[j].ID })
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, invalidRegistration()
	}
	digest := sha256.Sum256(encoded)
	plan.revision = hex.EncodeToString(digest[:])
	return plan, nil
}
func (p *Plan) Revision() string {
	if p == nil {
		return ""
	}
	return p.revision
}

func (p *Plan) Select(ctx MatchContext) []CompiledRegistration {
	if p == nil {
		return nil
	}
	candidates := p.chains[chainKey{ctx.Operation, ctx.Stage, ctx.Placement}]
	result := make([]CompiledRegistration, 0, len(candidates))
	for _, candidate := range candidates {
		r := candidate.Registration
		m := r.Match
		if !r.AllowSelfRecursion && contains(ctx.ExecutingInterceptors, r.ID) {
			continue
		}
		if !accept(m.SourceKinds, ctx.SourceKind) || !accept(m.TargetKinds, ctx.TargetKind) || !accept(m.TargetProtocols, ctx.TargetProtocol) || !accept(m.Domains, ctx.Domain) {
			continue
		}
		matches := true
		for _, tag := range m.Tags {
			if !contains(ctx.Tags, tag) {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		// Returned configuration is isolated from the compiled execution plan.
		result = append(result, cloneRegistration(candidate))
	}
	return result
}
func cloneRegistration(n CompiledRegistration) CompiledRegistration {
	r := n.Registration
	r.Before = append([]string(nil), r.Before...)
	r.After = append([]string(nil), r.After...)
	r.Phases = append([]Phase(nil), r.Phases...)
	m := r.Match
	m.SourceKinds = append([]string(nil), m.SourceKinds...)
	m.TargetKinds = append([]string(nil), m.TargetKinds...)
	m.TargetProtocols = append([]string(nil), m.TargetProtocols...)
	m.Domains = append([]string(nil), m.Domains...)
	m.Tags = append([]string(nil), m.Tags...)
	r.Match = m
	n.Registration = r
	return n
}
func validateRegistration(owner string, r *Registration) error {
	if !ownedID(owner, r.ID) || r.Binding == "" || len(r.Binding) > 256 || r.TimeoutMillis == 0 || time.Duration(r.TimeoutMillis)*time.Millisecond > time.Minute || len(r.Before) > 64 || len(r.After) > 64 {
		return invalidRegistration()
	}
	if r.FailureMode == "" {
		r.FailureMode = FailClosed
	}
	if r.FailureMode != FailClosed && r.FailureMode != FailOpen {
		return invalidRegistration()
	}
	switch r.Placement {
	case PlacementSource, PlacementDestination:
	case PlacementRelay:
		if r.NeedsPlaintext {
			return fabric.NewError(fabric.CodeInvalidInput, "Relay interceptor cannot request plaintext")
		}
	default:
		return invalidRegistration()
	}
	switch r.Match.Operation {
	case fabric.OperationDiscover, fabric.OperationDescribe, fabric.OperationInvoke:
	default:
		return invalidRegistration()
	}
	if !fabric.ValidNamespacedName(r.Match.Stage) || len(r.Phases) == 0 || len(r.Phases) > 5 {
		return invalidRegistration()
	}
	seen := map[Phase]bool{}
	for _, phase := range r.Phases {
		switch phase {
		case PhaseRequest, PhaseResponse, PhaseError, PhaseChunk, PhaseCompletion:
		default:
			return invalidRegistration()
		}
		if seen[phase] {
			return invalidRegistration()
		}
		seen[phase] = true
	}
	for _, values := range [][]string{r.Match.SourceKinds, r.Match.TargetKinds, r.Match.TargetProtocols, r.Match.Domains, r.Match.Tags} {
		if len(values) > 64 {
			return invalidRegistration()
		}
		for _, value := range values {
			if value == "" || len(value) > 256 {
				return invalidRegistration()
			}
		}
	}
	for _, values := range [][]string{r.Match.SourceKinds, r.Match.TargetKinds} {
		for _, value := range values {
			if !fabric.ValidNamespacedName(value) {
				return invalidRegistration()
			}
		}
	}
	return nil
}
func ownedID(owner, id string) bool {
	return strings.HasPrefix(id, owner+".") && fabric.ValidNamespacedName(id)
}
func invalidRegistration() error {
	return fabric.NewError(fabric.CodeInvalidInput, "Invalid extension registration")
}
func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
func accept(values []string, value string) bool { return len(values) == 0 || contains(values, value) }
func protocolWithin(current, min, max fabric.ProtocolVersion) bool {
	for _, version := range []fabric.ProtocolVersion{current, min, max} {
		if version.Validate() != nil {
			return false
		}
	}
	c, _ := strconv.ParseUint(strings.Split(string(current), ".")[1], 10, 32)
	a, _ := strconv.ParseUint(strings.Split(string(min), ".")[1], 10, 32)
	b, _ := strconv.ParseUint(strings.Split(string(max), ".")[1], 10, 32)
	return a <= c && c <= b
}

type registrationHeap []CompiledRegistration

func (h registrationHeap) Len() int { return len(h) }
func (h registrationHeap) Less(i, j int) bool {
	a, b := h[i].Registration, h[j].Registration
	if a.Priority != b.Priority {
		return a.Priority < b.Priority
	}
	return a.ID < b.ID
}
func (h registrationHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *registrationHeap) Push(v any)   { *h = append(*h, v.(CompiledRegistration)) }
func (h *registrationHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}
