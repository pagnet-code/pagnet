# Fabric tracing

Tracing uses the official OpenTelemetry API and W3C Trace Context. Trusted
composition supplies an explicit tracer; this package installs no exporter,
remote endpoint or global provider. Joining a caller-selected remote trace is
opt-in. Incoming baggage and transport-preloaded remote parents are removed by
default; trusted local operation/interceptor nesting is retained.

An optional explicit OpenTelemetry meter records operation duration and completed
operation counts at actual termination. Metric dimensions are operation and
disposition only, excluding invocation and target identifiers. Instrument creation
fails explicitly; no exporter or collection service is installed automatically.

The node records authenticated discover, describe and invoke operations. An
invocation span follows the actual pull stream until completion, error or close,
not merely until the dispatch method returns. The extension engine records each
inline interceptor phase. Attributes contain bounded infrastructure identifiers
and dispositions only; prompts, payloads, schemas, credentials, arbitrary error
messages and descriptive endpoint names are outside the tracing interface.

`Outgoing` supplies standard traceparent/tracestate for adapters inside the
explicit trust boundary. It never adds baggage. Relay transport composition must
not copy private application tracing into its visible envelope automatically.
Trusted node composition now wraps its actual search reader and selected adapter
with explicit tracing. Search queries and results are not attributes. Adapter
spans follow the original demand-driven stream; observation never prefetches,
buffers, retries, changes a frame or turns premature EOF into completion. These
wrappers install no exporter. Exporter configuration and specialized operational
metrics remain product composition work; this package alone does not claim
complete product observability.
