# Authenticated candidate composition

`New` builds a `hybrid.CandidateGate` using the actual extension engine's `discover.candidates` read projection. It requires the verified original request capability installed by node ingress; a standalone query, serialized caller assertion, or descriptive label cannot manufacture that context.

Composition explicitly supplies `ScopeProvider` (authenticated current scope key/policy revision) and `DocumentValidator` (fresh authoritative descriptor/revision validation). These are policy/registry responsibilities; this adapter grants no rights. The original DISCOVER query, scope, filters and cursor must match. A trusted provider may use a bounded internal limit up to100 to retrieve its horizon rather than the wire page size; that never expands scope.

The projection has exactly `{request,candidates}`. Extensions may filter or reorder the bounded candidate set, but cannot change its request, documents, references, revisions or scores. Both downstream projection and final response are checked; shortcuts and response transformations cannot bypass it. Empty candidate sets still enter the authenticated stage. Current policy is rechecked after execution and every selected descriptor is freshly validated before returning to the external disclosure/reranker boundary. Node final authority/registry barriers remain required for subsequent describe/invoke.

The gate supports no stream, deferral or endpoint invocation. Tests run actual node authentication, extension engine and hybrid retrieval with an external reranker spy, proving restricted/invalid candidates never reach the provider and read operations never invoke endpoints.
