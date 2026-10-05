# CloudEvents observation over HTTP

This binding uses the official CloudEvents SDK's structured HTTP representation.
An explicitly selected observer receives the original event identity and owned
bounded data. Credentials are obtained privately per delivery and enter only the
Authorization header. Plain HTTP requires explicit opt-in. URLs with user info,
query strings or fragments are rejected; environment proxies and redirects are
disabled. There is no automatic HTTP retry or destination selection.

Deliver makes one finite, cancellable attempt. A 2xx response means observation
acceptance, never target completion. Durable queues own retry with the same event
identity; consumers must be idempotent. Failed/slow observation does not affect the
original invocation. The product composes this observer behind a bounded event
bus rather than invoking it inline.

CloseContext cancels and joins actual outstanding deliveries before releasing the
private pool. A credential callback ignoring cancellation can occupy only its
bounded existing slot; a close deadline does not falsely report it terminated.
Raw provider errors and HTTP response bodies are never exposed as diagnostics.

Protocol reference: [CloudEvents HTTP binding](https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/bindings/http-protocol-binding.md).
