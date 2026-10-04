# Events are observations

Events use the official CloudEvents Go SDK and the CloudEvents 1.0 envelope.
`Lifecycle` creates only bounded engine metadata. It does not serialize request
or response data, signing material, private runtime paths or resume capabilities.
Events remain within the trusted node unless the operator explicitly configures
an observer binding that receives them. Extensions may deliberately publish richer
application events; that is a separate, explicit disclosure.

`EventBus.TryPublish` admits without waiting for consumer code. It is not an inline
interceptor and cannot veto or change an operation. A publisher must account for
admission errors separately, never turn observer loss into an invocation failure.
Admission durability is implementation-specific and must be stated explicitly.

`Local` is a **volatile** implementation. It compiles event-type subscription
indexes at construction, gives each subscription one worker, and bounds message
size, retained bytes, queue slots, attempts and retention. Retained in-flight and
retry deliveries count against capacity. Fan-out admission is atomic across the
matching subscriptions. Each attempt receives a fresh SDK event parsed from owned
bytes. A consumer must be idempotent on `(source, id)` because a successful effect
with a lost acknowledgement can cause another attempt. Handler errors and panics
never leak provider error strings to publishers.

Statistics expose accepted, rejected, delivered, retry and expired counts plus
pending bytes. Queue saturation is an explicit error; there is no hidden unbounded
overflow buffer. Close cancels workers and observes the caller's deadline. A Go
handler that ignores cancellation can retain its one bounded worker; the bus does
not pretend it can kill arbitrary in-process code. Out-of-process bindings are
required when that isolation matters. Volatile acceptance is not a durable receipt
and shutdown/restart can lose queued observations.

The package tests actual official-SDK data precision, strict duplicate-key grammar,
metadata privacy, nonblocking publication under an occupied handler, bounded retry,
mutation isolation, panic isolation and cancellation during shutdown. Durable
delivery and node lifecycle composition are separate implementation packets; this
package by itself does not claim the Fabric events acceptance criteria are complete.
