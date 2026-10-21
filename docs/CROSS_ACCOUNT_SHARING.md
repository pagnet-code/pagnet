# Cross-account sharing and usage budgets

Status: v1 is implemented in coordinated client, server and web changes, pending compatible release and activation. V1 supports a dedicated pair of SDK service principals with bilateral human owner consent, isolated encrypted direct `ASK`/`REPLY`, six aggregate limits and an owner-visible usage snapshot. The SDK implements durable message reservations and event-driven enrollment and delivery recovery; these changes are not yet deployed.

The broader design below remains future work: sharing managed agents, approved actions/capabilities, multiparty shared networks and owner-enforced host execution profiles. Implementation status is not a claim that these changes are deployed. The v1 setup below describes the implemented contract; later requirements describe the target behavior unless explicitly identified as v1.

## Model and existing evidence

A **tenant** is an administrative ownership domain. A **network** is an explicit cryptographic trust domain owned by exactly one tenant. A **principal** is an agent or service owned by its own tenant and, for personal ownership, its account owner. Joining another tenant's network must not transfer that ownership. A jointly used network therefore has one accountable owner, even when participants belong to several tenants.

The repository already supplies the following foundations:

- [Network and tenant](../domain/network.go) and [principal](../domain/principal.go) models separate network ownership from principal ownership; the principal comment explicitly allows joining another tenant's network. This is a domain contract, not proof of a complete cross-account enrollment flow.
- [Network membership](../domain/membership.go) has active, suspended and revoked states and separate discovery, communication, invocation, event, task and operation permissions. Capabilities describe what a principal can do; permissions describe what it may do. Representative authority is defined as the intersection of owner authority and membership permissions.
- [Tenant membership storage](../../pagnet-server/internal/store/memberships.go) and [network membership storage](../../pagnet-server/internal/store/network_memberships.go) are different relationships. Current agent default network permissions include all eight permissions, including `operate`; an external invitation must not silently reuse that default.
- [Encryption documentation](../../pagnet-web/apps/docs/content/docs/encryption.md) describes network epochs, customer-side key holders, visible metadata and reliance on control-plane enrollment authorization. Retained keys cannot be remotely erased.
- [Private owner contexts](OWNER_CONTENT_CONTEXTS.md) protect personal representative permission details independently of network membership. [Bridge process binding](BRIDGE_PROCESS_BINDING.md) documents kernel process authentication and the separate filesystem boundary.
- [Federation transport](../fabric/federation/README.md) provides tested cryptographic components and explicitly identifies missing product integration. It is not evidence of a deployed entry-door service.

The general API baseline is a 1 MiB body cap on `/api/v1` and a shared per-IP create limiter of 120 requests per minute. That limiter is process-local; it is not durable multi-replica admission or a per-principal, per-grant or per-network usage policy. Neither general control supplies sharing budgets. V1 additionally enforces its six accepted pair limits through aggregate durable admission; the broader directional, owner/project and runtime budgets below remain future requirements.

## Edu–Conti v1 setup (coordinated release pending)

1. Each owner creates or selects their own SDK **service** principal and runs its SDK endpoint with its own credential and durable state directory (`sdk.Connect(ctx, sdk.ConfigFromEnv())`). Do not use a managed representative or reuse a private multiparty network. Conti gives Edu the service address `pagnet-share:v1:<Conti tenant UUID>:<Conti service UUID>` through a trusted channel; verify the peer and, before enrollment, compare identity fingerprints through that channel if required. Directory pins alone trust the server on first contact.
2. As the issuing account administrator, Edu opens **Settings → Sharing** (`/settings/sharing`), selects Edu's owned service, enters Conti's address and chooses expiry and all six limits. The UI calls `POST /api/v1/sharing-proposals`, atomically creating a dedicated network and invitation. The equivalent request body is below; keep the same `requestId` and body for retries. These example limits match the current UI defaults, not a measured safe workload preset.

   ```json
   {
     "requestId": "<new UUID>",
     "issuerPrincipalId": "<Edu service UUID>",
     "recipientTenantId": "<Conti tenant UUID>",
     "recipientPrincipalId": "<Conti service UUID>",
     "slug": "edu-conti",
     "name": "Edu–Conti SDK chat",
     "description": "Dedicated direct SDK conversation",
     "permissions": ["communicate"],
     "limits": {
       "maxMessageWireBytes": 16384,
       "maxMessagesPerMinute": 6,
       "maxMessagesPerDay": 100,
       "maxWireBytesPerDay": 1048576,
       "maxInFlight": 1,
       "maxTurnsPerThread": 8
     }
   }
   ```

3. Conti reviews the incoming invitation in Settings → Sharing and chooses **Accept consent only**. The API is `POST /api/v1/sharing-invitations/{invitationId}/accept` with `{"expectedVersion":1}`, authenticated as the recipient human owner (or the required organization administrator). Edu's proposal records issuer consent; Conti's acceptance records recipient consent. Neither operation alone delivers keys or enables messaging.
4. On each SDK endpoint, register `client.OnSharingMessage(handler)` to receive pair messages, or call `client.EnableSharingPairs()` for a send-only service. The SDK then reconciles grants on connection and server wakeups, enrolls both named endpoints and drains pending messages after reconnect without idle polling. `ListSharingPairs` and `EnrollSharingPair` remain available for explicit status and enrollment. Inspect the identity fingerprints through a trusted channel when the server directory alone is insufficient for the trust decision. Both endpoints must complete their key/proof steps before the pair is active.
5. Call `PrepareSharingMessage(ctx, SharingMessageRequest{GrantID: grantID, Parts: parts})`, then `SendPreparedSharingMessage(ctx, prepared)` for an encrypted ASK. The peer's registered handler receives it; `ReceiveSharingMessages(ctx, grantID, handler)` is also available for an explicit inbox drain. Prepare a response with the received message as `ReplyTo`, preserving correlation and consuming the same aggregate limits. Reuse the durable prepared message after an ambiguous send; use `GetSharingMessageReceipt` and `UnresolvedSharingMessages` for recovery. These APIs and automatic recovery require the matching client/server release before use; the generic network `Send` or capability invocation is not a substitute for pair admission.
6. Either owner can inspect `GET /api/v1/sharing-invitations/{invitationId}/usage` in the usage view: accepted limits, minute/day reset times, counts/bytes, in-flight reservations and lifetime totals. End participation with the invitation's revoke control (`POST /api/v1/sharing-invitations/{invitationId}/revoke`, `{"expectedVersion":1}`), subject to that owner's authorization. Revocation stops future admission; it cannot erase previously received plaintext or keys.

The server pair message contract is `POST /api/v1/sharing-pairs/{grantId}/messages`, with authenticated inbox, acknowledgement and receipt endpoints under the same grant. It accepts encrypted `ASK`/`REPLY` only, not actions, capability invocations or arbitrary host execution. A pair marked active establishes key readiness; it is not evidence that the coordinated messaging/recovery release is deployed.

## Future sharing actions and tenant membership

**Share an agent** invites a named, verified recipient principal and its owner to chat with an agent, use selected approved actions, or both. Both principal owners must accept the recipient, scope, expiry and limits before activation. Messages require chat permission, not a capability. Actions additionally require the selected capability revisions, validated inputs, destination policy and any owner approval. Public discovery is not an anonymous grant.

A direct share that promises isolation needs a separate cryptographic and content scope, for example a dedicated two-principal network with separately enrolled keys and history policy. Reusing an existing shared network epoch cannot make a conversation private from its other key holders. A proposed entry door is an action exposure policy within this model, not a third product action or a magical bridge across trust domains. Any mediator that reads internal content and releases approved results is trusted with that content and needs explicit owner authority, filtering and a restricted execution profile.

**Create shared network** admits selected foreign principals to a common communication and cryptographic trust domain. One tenant owns the network and controls admission and policy; each principal owner accepts participation and controls what their principal exposes. Membership does not merge private networks, tenants, hosts or accounts. Members must understand the shared epoch key boundary before enrollment. Use this action for project discussion, tasks and events whose participants accept that common content boundary.

**Tenant membership** is appropriate when a person should participate in organization administration and resources under its roles. It is broader than sharing an agent and is not required for independently owned agents to collaborate.

## Future Edu–Conti example and bilateral rights

Edu and Conti own separate accounts, tenants, private networks, representatives and hosts. Conti selects **Share an agent**, verifies Edu's recipient identity and chooses chat, `review_proposal`, or both, with an expiry and usage limits. Edu accepts for Edu's named principal. An isolated direct share uses its own content scope; it grants no access to Conti's private network epoch keys, participant inventory, hosts or filesystem. Conti's agent may release only information and results permitted by Conti's external execution profile.

An accepted one-way request authorizes its correlated response within the same scope and budgets. It must not deadlock because the responder lacks a separate invitation to initiate requests. One accepted chat invitation can allow both agents to initiate conversation when both owners accept that setting; reciprocal action rights do not follow. Conti calling an action on Edu's agent requires a separate Edu-issued action grant and acceptance. A reply cannot smuggle an action invocation or delegate authority to another principal.

Each grant records issuer and accepting owners, verified peer principals and tenants, destination, chat initiation directions, allowed action revisions, execution profile, limits, expiry, approval requirements and revocation version. Either owner can pause or end participation. Effective authority is the intersection of current owner authority, grant or membership, destination policy, operation scope and required approval. Authenticated origin and causal request identity must survive mediation; the mediator's internal authority cannot expand the external caller's authority.

For joint project work, Edu and Conti can instead create a dedicated shared network owned by one tenant, explicitly admit project agents and agree on permissions, key exposure and history before enrollment. Memberships need not have equal administration or reciprocal actions. If both people need equal control over admission and policy, a dedicated project tenant can own the network with both as administrators. Each account still owns its agents and hosts; this governance flow also needs implementation before it can be promised.

## Exactly twenty use cases

These cases retain the broader product design. Cases 01–03, 05, 07–13 and 16–19 are **future-only as described**: v1 does not execute review/calendar/submission actions, connect managed representatives or create multiparty project networks. Case 06 can use v1 only as direct SDK chat; submission actions remain future. Case 20 covers v1 direct-share revocation, with multiparty membership/history behavior still future. Cases 04, 14 and 15 describe existing relationship types, not new v1 sharing features.

| ID | Situation | Appropriate relationship |
| --- | --- | --- |
| 01 | Edu requests a proposal review from Conti's private assistant. | Share Conti's agent with approved review action |
| 02 | Edu and Conti's agents jointly plan a project and exchange tasks and events. | Dedicated shared network |
| 03 | Conti separately requests a calendar slot from Edu after granting proposal reviews. | Separate Edu-issued calendar action share |
| 04 | A new employee joins company administration and internal collaboration. | Tenant membership, then explicit network access |
| 05 | A contractor contributes to one project without company administration. | Dedicated shared network |
| 06 | A customer submits a support ticket to a vendor agent. | Share vendor agent for support chat or submission |
| 07 | Two companies jointly operate an incident room with shared updates. | Dedicated shared network |
| 08 | A monitoring provider sends only alerts into a customer's private operations network. | Share an ingestion agent with alert submission only |
| 09 | A data supplier sells access to one aggregate query capability. | Share supplier agent with approved query action |
| 10 | An auditor inspects approved evidence without browsing all internal participants. | Share evidence agent with approved evidence action |
| 11 | A family shares household planning agents while keeping personal assistants private. | Dedicated shared network |
| 12 | A research consortium shares project datasets and analysis agents. | Dedicated shared network |
| 13 | A developer publishes a discoverable formatter service for external callers. | Public discovery plus accepted agent share for formatter action |
| 14 | One person's laptop and desktop agents collaborate on private work. | Personal network with separately enrolled hosts |
| 15 | A company subsidiary needs actual parent-organization administration. | Tenant membership according to governance |
| 16 | A Telegram user asks their own representative to invoke a partner service. | Existing account binding plus accepted partner agent share |
| 17 | A friend requests a free-time summary without seeing a personal calendar. | Share personal agent with calendar-summary action |
| 18 | A release partner submits a build candidate but may not launch processes on the recipient's host. | Share submission agent with approved submission action |
| 19 | A temporary workshop gives agents a common discussion space until the event ends. | Expiring shared network memberships |
| 20 | A departing partner must lose future service and project access while prior records remain auditable. | Revoke shares and memberships; rotate affected network epochs |

## Ten representative decisions

“Tenant” below means adding the foreign person to the owning tenant, not changing principal ownership. Recommendations assume the circumstances in the use-case table and carry the same future-only labels; this is a design comparison, not a list of v1 controls.

| Case | Tenant membership | Shared network | Share an agent | Recommendation |
| --- | --- | --- | --- | --- |
| 01 Edu–Conti review | Excess administrative relationship | Use a dedicated two-principal scope for isolation | Chat and/or approved review action | Share an agent |
| 02 Joint project | Unnecessary organizational coupling | Common tasks, events and project participants | Fits a conversation or bounded actions | Create shared network |
| 03 Reverse calendar | Unnecessary | Does not follow from review permission | Separate Edu-issued action scope and consent; chat replies need no reverse action grant | Separate calendar action share |
| 04 Employee | Matches organizational belonging | Does not establish tenant role | Insufficient for administration | Tenant membership and selected networks |
| 05 Contractor | Use only if governance requires it | Matches bounded project collaboration | Fits direct chat or isolated deliverables | Shared project network |
| 06 Customer support | Inappropriate account administration | Use an isolated scope for a private support conversation | Accepted chat or submission with correlated replies | Share an agent |
| 07 Incident room | Companies remain independent | Common live collaboration domain | Useful for bounded alert intake | Create shared network |
| 09 Aggregate data | Unnecessary | A common epoch exposes its content to key holders | Approved query action and output limits in an isolated scope | Share an agent |
| 10 Auditor | Broader than evidence access | Shared keys conflict with selective evidence disclosure | Releases approved evidence into its own scope | Share an agent |
| 16 Telegram partner call | Channel binding grants no tenant role | Channel binding grants no membership | Own representative uses an accepted partner action grant | Telegram binding plus agent share |

## Security and operation boundaries

### Discovery, chat and actions have separate authority

Seeing a public principal, discovering a filtered catalog, or holding `discover` must not permit chat or actions. Chat admission checks accepted conversation permissions and reply correlation; it requires no capability. Action admission additionally checks the current capability revision and action grant, and revalidates authority before sensitive effects. A minimal action schema can be disclosed without admission to a private network. An old catalog result is not an authorization token. Denials must avoid leaking private participant names, tasks or capability metadata.

### Host launch and workspace access remain owner controlled

For this sharing design, foreign membership and agent sharing never confer host enrollment, launch, attach, stop, workspace browsing, path selection, or arbitrary filesystem access. Only the resource owner or an explicitly authorized existing administrative path can authorize host actions; personal representative launch retains the same-owner personal-host requirement evidenced by [its regression test](../../pagnet-server/internal/controlplane/representative_personal_host_test.go). This is not a claim that all current host APIs are owner-only: [host access code](../../pagnet-server/internal/controlplane/api_hosts.go) also has tenant administrator rules.

Future managed-agent conversations and actions must run under an owner-enforced restricted execution profile. V1 hostless SDK chat admits encrypted messages between two service endpoints and grants no managed runtime, host tool or workspace authority; activation of that mode does not require a daemon/runtime sandbox. An SDK application remains responsible for any processing it chooses to perform. A future mode that offers managed execution must enforce the following profile before activation. The owner provisions its worker and approved workspace in advance and explicitly bounds tools, readable data, writable paths, memory retrieval and persistence, outbound destinations, model/runtime access and approved effects. Chat alone can trigger model tool use or memory disclosure, so a chat permission is not sufficient execution containment. A request may select a validated business resource ID, not an arbitrary host path or shell command. Server authorization must bind the selected principal, host, workspace and operation to the owner's policy; the daemon must independently enforce the local workspace allowlist, canonical path and symlink containment, and runtime sandbox before effects. Missing enforcement must fail closed. Network `operate` cannot bypass these resource checks.

Bridge process binding proves which local process called; it does not prove that a requested file is allowed. Current Linux Landlock requirements and the documented lack of equivalent macOS filesystem isolation must remain visible. The current macOS `allow_all` profile cannot enforce this restricted external execution profile today and must not host externally triggered execution under this proposal. Unsupported platforms or runtimes must reject activation or execution until equivalent containment is verified. Do not claim portable filesystem containment or approve an untrusted sharing workload on the strength of a nonce, process ancestry, or server path validation alone.

### Shared keys limit selective confidentiality

Network encryption protects content from ordinary relay/storage inspection under the documented enrollment trust model. It does not make mutually untrusted members safe to share all content. A holder of a shared epoch key that obtains ciphertext protected by that key can decrypt it; routing permissions and hidden UI rows cannot cryptographically separate those members. Key access, including any authorized object-decryption access, must be evaluated alongside membership permissions.

Use separate cryptographic scopes where content must remain private. An approved projection must be deliberately released into the recipient's scope by an explicitly trusted mediator. A bridge does not change who holds an existing epoch key. It needs output filtering and least authority; encryption does not prevent it or an admitted participant from copying plaintext. Control-plane enrollment and delivered browser code remain trusted as documented today; independently owner-verified enrollment is additional work.

### Telegram identifies an account, not a sharing grant

The [current Telegram binding](../../pagnet-web/apps/docs/content/docs/representatives/telegram.md) pairs an authenticated private-chat sender to their own account through an expiring single-use code. A binding does not create a representative or launch one. Edu's Telegram message should reach Edu's representative; the representative then uses its separately accepted Conti agent share or shared membership. Never let a supplied Telegram ID, network name, deep link or conversational claim select another account's authority. Telegram and the control plane can read bot chat and replies; returning protected content to Telegram deliberately crosses that confidentiality boundary.

### Revocation, keys and history

Proposed share revocation must stop new admission, invalidate cached grants and catalogs, and fence queued work before effects. In-flight cancellation is best effort after an irreversible effect; report that distinction instead of promising rollback. Use bounded lifetimes, destination-side durable replay admission and idempotency so transport retries do not repeat effects. The federation transport alone does not supply those product guarantees.

Network revocation must deny future authorized traffic and enrollment, close applicable sessions, and rotate epochs when excluding a key holder from future content. It cannot revoke retained keys, plaintext or downloaded ciphertext. New membership must not automatically grant historical epoch keys; historical access needs an explicit owner decision and supported enrollment policy. Leaving and rejoining must not silently restore earlier grants or history access. Preserve audit metadata about issuer, caller, scope, revisions, admission, result and revocation without logging protected payloads. Lost old keys can make old content unreadable; rotation is not recovery.

## V1 usage contract and future usage controls

V1 accepts exactly six limits: `maxMessageWireBytes`, `maxMessagesPerMinute`, `maxMessagesPerDay`, `maxWireBytesPerDay`, `maxInFlight` and `maxTurnsPerThread`. These apply to aggregate pair traffic, including admitted replies; they are not six independent allowances per sender. The usage endpoint provides the current counters, in-flight reservations and reset times for that invitation. Wire bytes are the canonical serialized pair request, including its encrypted envelope and bound metadata, not plaintext, model tokens or provider spend. V1 is not a hard monetary cap, a general owner/project budget or a promise of separate uploaded/delivered fan-out quotas.

The remaining controls in this section are the broader target requirements; do not infer that v1 implements every rate/burst, queue, directional byte, execution-time or runtime policy described here.

### Measurement and policy

The server can measure encrypted envelope or wire bytes, message counts, sender/recipient identities, timing and delivery outcomes. It cannot infer plaintext size, meaning, token count or model cost from encrypted payloads. Name the accounting unit and protocol version explicitly: uploaded bytes are the serialized encrypted application envelope accepted from a sender; delivered bytes are that envelope sent to each authorized recipient. Transport framing and retransmission overhead must be separately measured if a wire-byte limit is offered, not silently called plaintext or application bytes. Reject oversize uploads before buffering the full body. Ciphertext padding and encryption overhead count toward the envelope cap. Observed encrypted size is not exact plaintext size; size and timing remain metadata side channels even with padding.

Each accepted share and shared-network membership needs enforceable limits for maximum encrypted bytes per message, message count per window, sustained rate and burst, directional uploaded and delivered byte budgets, finite queue depth, concurrent running requests, causal turns/loops, execution time and expiry. Apply the intersection of per-grant, peer, project/network and owner budgets so many shares cannot bypass an owner's cap. Each initiation direction, correlated reply, action result, attachment and event consumes its applicable limits; reply, cancellation and terminal-error allowances are bounded and reserved explicitly so exhaustion cannot strand admitted work; they are never an unmetered bypass. Fan-out charges upload once and delivery per recipient. Owner and project accounting must state which payer and principal are charged in each direction.

Use finite, versioned presets with explicit windows, reset times, byte units and advanced limits; do not imply a proposed preset is a measured safe default. Owners must accept limits and any increases. Lowering limits blocks new reservations immediately; already admitted work must reconcile against the new policy and stop before further effects when authority or remaining budgets no longer allow them. Enforce grant expiry and either owner's pause/revocation alongside usage admission.

### Durable admission, retry and reconciliation

Authenticate sender, peer, scope, policy version and causal parent before admission. Atomically and durably check current consent, expiry, revocation and all applicable aggregate counters, reserve delivery/reply and execution allowances, record a unique scoped idempotency key and payload digest, and enqueue the accepted operation. A concurrent request must not spend the same remaining budget. A denial creates no executable work. Reject rate, burst or temporary capacity exhaustion with HTTP `429` and `Retry-After` on REST admission, and an equivalent typed `retry_after` on other transports. Return a stable reason and reset time where authorized; expiry, revocation and unsupported execution profiles require correction rather than blind retry. Enforce finite queue depth and deadlines; never silently enqueue unlimited work. Clients must honor backoff and must not turn denials into retry storms. Multi-node races, storage failure and stale policy caches must fail closed; admission and its durable queue cannot disagree after a crash.

An identical retry with the same scoped key and digest returns the recorded admission/result without repeating action effects or consuming another logical message reservation. Reuse with a different digest is rejected. Retain dedupe records for at least the supported retry and queue lifetime; expired keys must not silently become reusable operation IDs. Specify acknowledgement and terminal states so a client can distinguish rejected, admitted, running, delivered, failed and cancelled work without guessing after a timeout. Delivery attempts and transport retries still consume measured transport resources and need their own bounded rate/byte allowance, even when logical usage is deduplicated.

Reserve before delivery or execution, reconcile actual usage and release unused reservations exactly once on terminal completion. Charge delivered application bytes when handed to an authenticated recipient connection, not when read by a human; retransmitted application deliveries are tracked and bounded separately. Durable reservation leases, crash recovery, cancellation and disconnected recipients must not leak capacity or refund work that already ran. Stop admission when accounting cannot be reconciled. Reconnects, restarts, window rollover, invitation replay, leave/rejoin and grant replacement must preserve aggregate spending and must not reset an owner's budget. Audit policy revisions and reservation adjustments without storing protected payloads.

### Runtime and privacy boundaries

Server limits bound relay and admitted work; the daemon and runtime must enforce tools, data, memory, destinations, concurrency, elapsed runtime and local resource limits before and during execution. Bind every run and delegated child to its authenticated causal root, finite turn/loop and time budgets, and remaining allowances. External initiation, tool calls, responses and agent-to-agent follow-ups cannot reset that root. A correlated response must be authenticated and bounded; arbitrary caller-supplied causal IDs do not grant new authority. Detect or bound ping-pong, recursive delegation and repeated retries even across services and hosts. Fence queued work and recheck policy before effects; revoke credentials and terminate workers when the profile requires stopping. Irreversible effects remain non-rollbackable.

Owners may add provider token/spend limits where the runtime or provider supplies reliable accounting and enforcement. Encrypted relay byte budgets are not a model-cost cap. Provider billing delays, in-flight generation, external tools and owner credentials can incur costs beyond a relay reservation; disclose the supported cost ceiling and any overshoot before acceptance. Do not advertise a hard monetary cap without an enforceable provider/runtime boundary.

Usage UI and audit records reveal metadata: peer and owner identifiers, scope/grant IDs, timestamps, directions, envelope sizes, counts, delivery state, policy revisions and blocked reasons. Keep this disclosure alongside encryption claims, with retention and access rules. Store no plaintext, prompts, tool inputs, memory or protected results in quota logs. Aggregated views and denials must not reveal another participant's private activity or remaining budgets to an unauthorized peer.

## Future frontend requirements

The primary flow is one **Share an agent** dialog: verified named recipient and owning account, chat initiation choice, approved actions, expiry and a finite usage preset. Show the agent's restricted execution profile and expose detailed directional byte/count/rate/burst/concurrency/turn/runtime limits under advanced controls. The acceptance view must show the same effective policy and distinguish chat replies, mutual chat initiation and reciprocal action rights. Editing or increasing authority requires the affected owners' acceptance; no unchecked default may silently grant `operate` or all permissions.

**Create shared network** must disclose its single accountable owner, participants, common epoch key/content boundary, selected permissions, history access, membership expiry and aggregate budgets before either owner accepts enrollment. Explain that a direct isolated conversation needs a separate scope; do not promise pairwise privacy inside this common epoch. Equal project administration needs the separate tenant governance flow.

Owners need usage and remaining-budget views with units, windows, pending reservations and freshness; pause/revoke controls; invitation and policy status; and concrete blocked reasons such as expired grant, unsupported execution profile, byte cap, rate limit or exhausted runtime allowance. Peers receive only reasons they are authorized to see. Clients must handle retries, reconnects and ambiguous admission through the durable operation status API. Future controls must remain labeled **proposed** until their corresponding release gates pass. V1 may expose its SDK-pair invitation, acceptance and usage controls against the matching server and SDK contract. Host enforcement is a release dependency for managed-agent/action execution, not for hostless SDK chat.

## Coordinated delivery and release gates

Apply these gates to the authority each offered mode provides. V1 hostless SDK chat requires compatible server, SDK and web contracts, consent, isolated key enrollment, aggregate admission and recovery verification. It does not require host runtime containment, action capability contracts or multiparty enrollment. Those are additional gates for future managed-agent/action/shared-network modes. Deployment may stage components with activation disabled; a frontend feature flag alone is not an authorization boundary.

1. **Backend contracts and migration.** Version consent/grant, scope/key enrollment, execution-profile and usage schemas; define exact accounting units, aggregation identities, limits, retry retention and lifecycle/status contracts. Ship durable atomic admission, dedupe, queue fencing, reservations, counters, policy invalidation, expiry and revocation first. Migrate existing memberships by preserving their recorded authority and marking them for explicit review; do not reinterpret all-eight defaults as accepted external shares or silently enroll foreign principals into isolated scopes. Backfill ownership, scope and audit references, reconcile counters/reservations with durable admitted work, and quarantine ambiguous records until owners reconfirm. Existing shared epoch data cannot become pairwise private by migration. Test rollback compatibility; never roll back to admission that ignores active grants or budget reservations.
2. **Client and host enforcement.** For v1, verify SDK identity/key enrollment, encrypted ASK/REPLY admission, durable retry IDs and recovery. For future managed execution, release compatible daemon/runtime support for authenticated origin, causal roots, scoped keys, exact envelope accounting, durable retry IDs, status recovery and independently enforced restricted profiles. Test real platform tool/data/memory/destination isolation, child execution, concurrency, turn/time termination, revoked queued work and effects. The current macOS `allow_all` path fails this gate. Backend negotiation must reject unsupported client/runtime versions and profiles rather than downgrade enforcement. Install and reconcile runtime policy before a share becomes executable; reconnecting older clients cannot bypass it.
3. **Web and acceptance flow.** Release the Share dialog, shared-network disclosure, both-owner acceptance, usage/status views and pause/revoke only against the versioned backend contract; managed-agent/action controls additionally require a compatible enforced host profile. Verify that displayed presets equal effective server/runtime limits and that changed scope/limits cannot race acceptance. A pending invitation sends no traffic or keys. Web, CLI and API calls must face the same checks; hiding a button does not secure an endpoint.
4. **Cross-component proof before activation.** For v1, prove bilateral owner consent, isolated two-service-principal enrollment, encrypted ASK/REPLY, all six aggregate limits, usage, retries, expiry/revocation and compatible SDK recovery across backend, SDK and web. Automatic event-driven recovery remains pending release work. For the future modes, additionally pass end-to-end tests across backend, client/daemon/runtime and web for Edu–Conti chat without capabilities, bounded one-way replies, mutual chat with no reciprocal action grant, independently accepted reverse actions, isolated two-principal scope, shared-network epoch disclosure, independent ownership, denied host control and Telegram account binding. Also test concurrent aggregate exhaustion, oversized ciphertext, fan-out and both byte directions, rate/burst, response reserve exhaustion, loop/runtime stops, duplicate retries, conflicting digests, crash/restart reconciliation, expiry/revocation before effects, historical-key policy and stale/unsupported clients. Confirm logs and blocked reasons contain only permitted metadata. Activation requires all three repositories' compatible releases and the tests applicable to the offered mode; federation fixtures alone do not satisfy it.
5. **Controlled activation and continuing reconciliation.** Enable only verified platform/runtime/mode combinations after schema migration, accounting reconciliation and owner acceptance. Record deployed backend/client/web contract versions, monitor admission-versus-usage drift, and automatically stop affected admissions on inconsistent counters or policy. Exercise pause/revoke, epoch rotation and crash recovery operationally. Expand actions, discovery and platforms only after their corresponding gates pass. Independently owner-verified enrollment remains separate cryptographic trust work.
