package fabric

import "context"

// Read-only operation ports have no invocation method or adapter handle.
type Discovery interface {
	Discover(context.Context, ExecutionContext, DiscoverRequest) (DiscoverResult, error)
}

type Describer interface {
	Describe(context.Context, ExecutionContext, DescribeRequest) (DescribeResult, error)
}

// InvocationDispatcher must invoke only Target. It cannot discover a fallback
// or automatically replay a possibly destructive operation on transport error.
type InvocationDispatcher interface {
	Invoke(context.Context, ExecutionContext, InvokeRequest) (InvocationStream, error)
}

type DescriptorStore interface {
	GetEndpoint(context.Context, EndpointRef, Revision) (EndpointDescriptor, error)
	GetOffer(context.Context, EndpointRef, Revision) (OfferDescriptor, error)
	ListOffers(context.Context, EndpointRef, Revision, string, int) ([]OfferSummary, string, error)
}

type RegistryUpdate struct {
	Descriptor       EndpointDescriptor
	ExpectedRevision Revision
	// Authenticated ownership evidence is supplied by the registry's identity
	// boundary, never inferred from descriptive text.
}

type EndpointRegistry interface {
	Register(context.Context, ExecutionContext, RegistryUpdate) (Revision, error)
	Update(context.Context, ExecutionContext, RegistryUpdate) (Revision, error)
	Retire(context.Context, ExecutionContext, EndpointRef, Revision) (Revision, error)
	Resolve(context.Context, EndpointRef, Revision) (EndpointDescriptor, error)
}

// OfferRegistry uses the same owner/revision/tombstone rules as the parent.
// Independent records let description load one schema without sibling scans.
type OfferRegistry interface {
	PutOffer(context.Context, ExecutionContext, OfferDescriptor, Revision) (Revision, error)
	RetireOffer(context.Context, ExecutionContext, EndpointRef, Revision) (Revision, error)
}

type SearchStats struct {
	Documents         uint64
	IndexBytes        uint64
	PostingsVisited   uint64
	CandidatesVisited uint64
	SchemaLoads       uint64
}

type SearchBackend interface {
	Upsert(context.Context, SearchDocument) error
	Delete(context.Context, EndpointRef, Revision) error
	Search(context.Context, DiscoverRequest) (DiscoverResult, error)
	Stats(context.Context) (SearchStats, error)
}

// Rerank receives only bounded candidates AFTER the discovery candidate gate.
// It may reorder/remove candidates, never introduce an arbitrary new target.
type DiscoveryReranker interface {
	Rerank(context.Context, DiscoverRequest, []Candidate) ([]Candidate, error)
}

// EndpointAdapter is registered by protocol, not a closed endpoint-kind switch.
// Binding/private credentials are injected when registering the implementation.
type EndpointAdapter interface {
	Invoke(context.Context, ExecutionContext, EndpointDescriptor, InvokeRequest) (InvocationStream, error)
}
