# Future worker original source delivery

This adapter is inactive. It does not enable daemon worker routing or relax update admission. It requires the future server's authenticated native content handlers and original-origin lifecycle receipt protocol. Its default tests prove the private journal and simulated backend transport boundary. The opt-in paired proof additionally exercises actual controlplane WebSockets, isolated PostgreSQL transactions and authenticated private worker IPC. It is not a deployed full daemon/native process continuity proof.

`NativeObservationConnection.DrainNativeWorkerSourcesPage(ctx, proxy.SourceCall, after)` scans up to four lease-fenced private worker pages (128 records) and returns the next SQLite sequence cursor. Keep `after` with the exact pinned worker proxy, reset it when replacing/discovering another worker, and keep the returned cursor even when a later page returns an error. A zero cursor starts a fresh bounded pass. The cursor is authenticated IPC page metadata, separate from the immutable observation, capture and digest. Unsupported records are retained and skipped; unfinished or failed supported sources never advance beyond their page. The legacy `DrainNativeWorkerSources` wrapper still reads one page and should not be used for continuous routing. The supplied callback must remain pinned to one authenticated private worker controller and its exact scope. It never redirects a request to a newly discovered worker. Each invocation writes at most 16 original ciphertext fragments; backend missing pages may contain up to 32 ascending ordinals. The next invocation resumes from backend staging status. Original fragment bytes, manifest commitments, capture time, observation identity and source admission remain unchanged across controller replacement.

The exact authenticated server connection must call `Admit` with its negotiated host session before draining. Route content staged/rejected frames to `NativeContentDisposition`, and observation receipt/rejected frames to `NativeWorkerObservationDisposition(frameType, payload)`. Closing that connection wakes pending waits. Call `ConfirmNativeWorkerSession` with fresh authenticated worker snapshots before lifecycle projection; saved observations cannot supply live process proof.

Supported sources are encrypted `interaction.started` and `interaction.resolved`, `host.runtime_session` from actual native session started/resumed events, and `host.agent_status` from native busy/idle events (busy maps to the domain status `working`). No detail is decrypted or newly encrypted by the drainer. An absent encrypted inspection/answer remains unsupported. The adapter also emits actual native `host.runtime_turn_started`, `host.runtime_turn_completed`, and `host.runtime_turn_failed` events when the original accepted operation pinned its command, native admission, input kind, logical worker turn ordinal, generation and session before capture. Legacy captures without that original binding remain unsupported. The server derives its stable turn UUID from original origin and logical turn identity, and resolves task/channel from the original command. No caller task ID, native error, output, summary or result body is emitted. Fixed failure categories, original reliable UTC retry timestamps and nonnegative token counts may be emitted. The adapter emits no stopped/hibernated, lost-session, task-progress, encrypted task-result or plan observations. Those original records remain private.

Lifecycle and supported turn source sequences are allocated transactionally per immutable original origin in worker SQLite, independently of capture digest. The stream watermark survives acknowledgement. Reopen validates sequence mappings against source identities and watermarks; missing or transplanted mappings fail closed. Worker-memory producer retry pins span the sole production native observer append loop. ACK records retired ID/digest only while that exact original producer remains pinned, preventing an ambiguous COMMIT retry from resurrecting evidence with a new sequence. Releasing the callback releases its marker. Worker crash destroys the callback and its retry capability; controller IPC has no append-observation operation. At most 4,096 concurrent producer pins are retained, with no lifetime event tombstone limit. Retained origin stream count is bounded to 4,096. Registered settled native generations are reclaimed after producer quiescence and reference retirement; this is a backlog bound rather than a lifetime generation limit.

Only a receipt with matching observation ID, original origin ID and exact wire payload digest, and disposition `committed`, permits the atomic worker ACK that deletes ciphertext fragments, encrypted capture and observation together. Successful writes, staging progress, expired/stale diagnostics and rejections retain all original evidence. Retained terminal diagnostics may block delivery behind the oldest supported source. Continuous routing must use the cursor API; the legacy one-page wrapper can still be blocked by retained unsupported rows. Full routing needs an explicit recovery/diagnostic policy and complete task-progress/result/plan adapters before enabling this architecture.

Focused race tests cover receipt mismatch and rejection, disconnect and failed writes, deterministic protected ciphertext, bounded multi-invocation staging, invalid progress pages and oversized fragments, original sequence retry/ACK/restart, retired replay suppression, and corrupt sequence denial. A no-allocation overlay fails the sequence test with `sequence[0]=0 want 1`, demonstrating the missing persistent-allocation regression. Real worker process ownership and content encryption are exercised separately by the existing worker suite. No paid provider or owner key reset is used.


## Actual paired backend proof

`TestNativeSourceDrainerActualBackendReconnectAndCiphertextProof` launches the matching server controlplane test helper using private stdin/stdout pipes. The helper exposes only a loopback test HTTP/WebSocket server and seeds a synthetic isolated source/crypto fixture. Test credentials travel through those pipes and are not logged. The worker uses its actual private SQLite journal, whole-owner private IPC service and authenticated A/B controllers; no provider/native process is started in this delivery fixture, and the session proof verifier is explicitly synthetic.

The proof registers original origin A over a genuine authenticated WebSocket, stages more than 16 encrypted fragments in bounded passes, drops the actual committed receipt to simulate transport loss, and confirms original evidence remains private. A fresh B runner retrieves the same durable backend receipt before ACK. It checks immutable origin runner A, ciphertext reference and every fragment, then confirms the fixture session through B and commits a genuine lifecycle source sequence. A deferred PostgreSQL receipt trigger proves attachment/projection/receipt rollback leaves the worker ciphertext intact and produces no success receipt; removing that failure permits exact ciphertext retry. A foreign host receives no staging progress. Database projections/content and worker SQLite/WAL are scanned for a private plaintext sentinel.

The receipt table stores the immutable payload digest rather than a second copy of the source payload. The proof compares that digest against the original exact wire bytes and compares committed content reference/fragments byte for byte. A deliberate early-ACK overlay fails with `disconnect before receipt retired original evidence`; this is an injected negative mutation, not a claim that a prior wired production drainer existed.

Build the server helper with `go test -race -c -o /absolute/path/native-source-backend.test ./internal/controlplane` from the matching future server branch (paired validation used server commit `6467739`). With `TEST_DATABASE_URL` already set to a dedicated test database, run `python3 scripts/test-native-source-backend.py --server-helper /absolute/path/native-source-backend.test`. The script creates a unique schema, passes its DSN only in environment, runs the race proof and drops that schema in cleanup. Without the helper environment the opt-in test skips; default test success alone does not claim this paired proof ran.

The paired backend proof now also queues 160 unsupported original private records before a valid lifecycle record. The first 128-row scan returns a cursor without sending that lifecycle record; the second scan receives its real durable PostgreSQL receipt and ACKs it, while unsupported records retain their exact digest and zero lifecycle sequence.

Registered source retirement now removes settled generation watermarks without resetting an appendable stream. Legacy unpublished fixture streams without registration/quiescence evidence remain conservative; they are not silently reclaimed. Unsupported retained evidence and incomplete native turns still require recovery/adapters before routing enablement. No full routing completion is claimed.


## Actual native turn paired proof

`TestNativeTurnDrainerActualOwnerBackendOriginalSourceAndRollback` uses the turn-capable server helper with `--turns`. Unlike the content fixture above, it starts the actual persistent fake native runtime through the worker owner, obtains genuine process birth identity and native session, and confirms them over actual authenticated A and B WebSocket connections. It tests completed and failed native turns with their original task command and admission A, including a dropped real started receipt, original encrypted source recovery through B, deferred terminal receipt transaction rollback, exact retry, and atomic source ACK only after the durable receipt. Caller-selected task and foreign command payloads cannot create a turn, receipt or sequence advance. Native output remains encrypted source evidence, and private native failure text is excluded from both the server payload and worker SQLite operation outcome. The provider is an isolated local fake executable; no paid provider is called.

The task metadata adapter does not deliver task progress or task result bodies. The paired proof validates this inactive delivery path, not full production `pagnet serve` routing.


## Registered producer retirement

Fake, Qwen and Codex endpoints now receive a paired `NativeEventObserverRegistration` with `Observe` and `Retire`. Retirement closes the original append capability and waits for every in-flight callback, including concurrent Codex interaction resolution. A late callback cannot append or recreate the original registration after its watermark is reclaimed. The owner permits exactly one registration per authenticated original native birth; only a fresh owned activation resets that permit. No lifetime origin or event tombstone set is kept.

The journal persistently enables registration-bound production appends after the first original producer. Direct fixture imports cannot bypass it, including after reopen. Exclusive worker lifetime ownership on reopen proves prior worker-memory producer capabilities no longer exist; pending original source records and references retain their immutable bytes and ordinal. Reclamation selects at most 32 eligible quiesced generations, and requires no original observations, captures, content, interaction or turn references, no producer retry pins, completed turns with original intent ACK floor, and no unACKed activation outcome. Reclamation removes the stream and registration atomically, retaining a single protocol marker.

Automated race tests exercise the actual local fake native subprocess, authenticated private controllers, isolated backend WebSockets/PostgreSQL, reader EOF, original outcome ACK and zero settled reference cardinality. A 4,112-generation SQLite capacity test checks lifetime cardinality with NORMAL fsync for runtime; reopen and ambiguous-COMMIT tests separately use production FULL fsync. Deterministic concurrent reader/resolver and SQLite blocking tests prove retirement waits; pending evidence, unresolved interactions and incomplete turns prevent reclamation. Deliberate old-callback-capability and ambiguous-COMMIT mutations fail the expected assertions. These are isolated automated proofs. No original-host process or live API verification is performed.

### Genuine process EOF and bounded graceful shutdown

`runtime.session.stopped` is emitted by the Fake/Qwen/Codex endpoint reader
only after its single-owner supervised process Wait returns. It uses the
actual activated native session ID and enters the original source journal
before paired observer retirement. It carries no invented terminal turn or
private error. Its wire adapter is `host.agent_stopped` in the same contiguous
original-origin sequence stream.

Each active registered original producer reserves one row and 64 KiB for its
final stopped observation **within** the existing 4096-row/48-MiB aggregate
observation and private-capture budget. Ordinary append and new registration
account for outstanding reservations. A committed stopped source consumes its
own reservation; paired retirement releases any unused one. There is no extra
queue or lifetime tombstone. Reopen does not revive old producer capabilities.

Shutdown cancels ordinary execution/backpressure, requests supervised process
termination, and waits for registered observer retirement before clearing the
private capture key. Genuine EOF admission has a separate three-second bounded
context so execution cancellation cannot erase it. Observer quiescence has a
five-second bound; failure is recorded and the capture key is retained rather
than cleared while a callback might still use it. Permanent SQLite failure or
an unkillable native process remains an honest shutdown failure; this protocol
cannot fabricate an EOF or receipt for those cases.

Automated proofs use an actual isolated fake native process with a full ordinary
outbox, FULL SQLite durability for the final EOF, shutdown and exact-row reopen.
A separate encrypted-capture byte-pressure proof stays within the aggregate
budget and rejects callbacks after retirement. Removing EOF context separation
fails that proof. The paired PostgreSQL/WebSocket turn fixture now commits and
ACKs actual stopped evidence before expecting settled source watermark cleanup;
both completed and failed native turns pass. These remain inactive fixture
proofs, not live user-provider verification.
