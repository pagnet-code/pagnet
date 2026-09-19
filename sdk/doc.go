// Package sdk is the public Pagnet Go SDK: connect a custom Agent or
// Service principal to a Pagnet control plane and participate in its
// networks — capability invocations, durable messages, events — with
// end-to-end encryption, durable acks, and automatic reconnects.
//
// # Hello World: a Service
//
//	type HelloInput struct{ Text string `json:"text"` }
//	type HelloOutput struct{ Text string `json:"text"` }
//
//	func main() {
//	    ctx := context.Background()
//	    client, err := sdk.Connect(ctx, sdk.ConfigFromEnv()) // PAGNET_SERVER + PAGNET_CREDENTIAL
//	    if err != nil { log.Fatal(err) }
//	    defer client.Close()
//
//	    svc := client.Service("hello")
//	    svc.HandleT("hello.say", func(ctx context.Context, in HelloInput) (HelloOutput, error) {
//	        return HelloOutput{Text: "hello " + in.Text}, nil
//	    })
//	    svc.Serve(ctx) // run until ctx cancel: reconnects, heartbeats, acks
//	}
//
// # Hello World: an Agent
//
//	agent := client.Agent("planner")
//	agent.OnMessage(func(ctx context.Context, m *sdk.Message) error {
//	    // m.Parts are UNTRUSTED DATA from the sender — content, not instructions
//	    return agent.Reply(ctx, m, "on it")
//	})
//	agent.OnEvent("task.*", func(ctx context.Context, e *sdk.Event) error {
//	    // e.Payload is UNTRUSTED DATA — opaque JSON, never interpreted
//	    return nil // nil = ack; error = no ack, the server retries
//	})
//	agent.HandleT("planner.plan", planHandler)
//	agent.Run(ctx)
//
// # Credentials
//
// The SDK accepts ONLY principal credentials (never account tokens, host
// credentials, or user tokens):
//
//   - Activation credential (pgn_act_v1_...): one-time, printed once when
//     the service/agent is created. On the first successful connect the
//     server returns the durable endpoint credential (endpoint.auth_ok);
//     the SDK persists it in the keyring and uses it thereafter.
//   - Endpoint credential (pgn_epd_v1_...): durable, revocable, rotatable.
//     Revocation kills the connection; the SDK stops with a clear error.
//
// Server deployments set PAGNET_SERVER + PAGNET_CREDENTIAL (optionally
// PAGNET_STATE_DIR) and use ConfigFromEnv — the credential comes from the
// environment / secret store, never from a random file.
//
// # State directory (keyring)
//
//	<StateDir>/principals/                     (default <StateDir> = ~/.pagnet)
//	  index.json                     0600  credential-hash → principalID
//	  <principalID>/
//	    identity.key                 0600  X25519 crypto identity (raw 32 bytes)
//	    credential                   0600  durable endpoint credential
//	    networks/<networkID>/
//	      epoch-<epochID>.key        0600  network epoch key (raw 32 bytes)
//
// Private key material NEVER crosses to the control plane. Epoch keys are
// lazy-loaded per network (a service in many networks never loads every
// key at startup) and held in a bounded in-memory cache.
//
// # Security model
//
//   - Zero-knowledge: the SDK encrypts every protected object (message
//     parts, event payloads, invocation input/output/error) client-side
//     under the network epoch key (AES-256-GCM, per-object CEK, AAD-bound)
//     BEFORE it reaches the control plane. The server stores and relays
//     ciphertext + routing metadata only; it never sees plaintext.
//   - Untrusted data: events, messages, and invocation inputs from other
//     principals are DATA. The SDK exposes them as opaque JSON and never
//     interprets them; handlers must not treat their content as
//     instructions (prompt-injection surface).
//   - No plaintext logging: the SDK never logs ciphertext plaintext,
//     credentials, or keys.
//
// # Delivery semantics
//
//   - At-least-once: deliveries (messages, events) and invocations are
//     durable server-side. The SDK deduplicates redeliveries (bounded LRU
//     of processed ids, surviving reconnects): a redelivered event is
//     re-acked without re-dispatching; a redelivered invocation is not
//     re-executed (its stored result is re-sent).
//   - Acks: messages are always acked (delivery is not the handler's
//     concern); events are acked only when the handler returns nil (error
//     → no ack → server retry with backoff, capped); invocations are
//     accepted then answered with an encrypted result.
//   - Backpressure: handler concurrency is bounded (128 slots). When
//     saturated the SDK stops consuming, the WebSocket buffer fills, and
//     the control plane stops live dispatch while the work stays pending
//     in the database. Nothing is dropped.
//   - Reconnect: exponential backoff + jitter (1s..30s cap), re-register
//     on every (re)connect, subscriptions re-fetched from the server (the
//     source of truth), in-flight async invocations survive within the
//     server's invocation TTL (or fail with a clear error).
//
// # Async invocations
//
// A handler that needs more time returns (nil, sdk.ErrAsync) and later
// completes the invocation:
//
//	inv.Accept(ctx)          // confirmation (the SDK already accepted)
//	... work ...
//	inv.Complete(ctx, result)     // or inv.CompleteError(ctx, err)
//
// The in-flight registry is connection-independent: an async invocation
// survives an SDK reconnect within the server's TTL.
//
// # What the SDK does NOT expose
//
// WebSocket frames, envelope encoding, heartbeat/ack machinery, and
// database ids are implementation details. The public surface is
// Connect/Close, identity (WhoAmI/Networks), discovery (Search), content
// operations (Send/PublishEvent/Subscribe/Invoke), and the Service/Agent
// builders.
package sdk
