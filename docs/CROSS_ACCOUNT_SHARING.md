# Cross-account sharing: networks and entry doors

Status: design proposal. This document defines intended product behavior; it does not claim that cross-account invitations, entry-door grants, or remote bridge execution are integrated today.

## Model and existing evidence

A **tenant** is an administrative ownership domain. A **network** is an explicit cryptographic trust domain owned by exactly one tenant. A **principal** is an agent or service owned by its own tenant and, for personal ownership, its account owner. Joining another tenant's network must not transfer that ownership. A jointly used network therefore has one accountable owner, even when participants belong to several tenants.

The repository already supplies the following foundations:

- [Network and tenant](../domain/network.go) and [principal](../domain/principal.go) models separate network ownership from principal ownership; the principal comment explicitly allows joining another tenant's network. This is a domain contract, not proof of a complete cross-account enrollment flow.
- [Network membership](../domain/membership.go) has active, suspended and revoked states and separate discovery, communication, invocation, event, task and operation permissions. Capabilities describe what a principal can do; permissions describe what it may do. Representative authority is defined as the intersection of owner authority and membership permissions.
- [Tenant membership storage](../../pagnet-server/internal/store/memberships.go) and [network membership storage](../../pagnet-server/internal/store/network_memberships.go) are different relationships. Current agent default network permissions include all eight permissions, including `operate`; an external invitation must not silently reuse that default.
- [Encryption documentation](../../pagnet-web/apps/docs/content/docs/encryption.md) describes network epochs, customer-side key holders, visible metadata and reliance on control-plane enrollment authorization. Retained keys cannot be remotely erased.
- [Private owner contexts](OWNER_CONTENT_CONTEXTS.md) protect personal representative permission details independently of network membership. [Bridge process binding](BRIDGE_PROCESS_BINDING.md) documents kernel process authentication and the separate filesystem boundary.
- [Federation transport](../fabric/federation/README.md) provides tested cryptographic components and explicitly identifies missing product integration. It is not evidence of a deployed entry-door service.

## Three relationships

**Tenant membership** is appropriate when a person should participate in the organization's administration and resources under its roles. It is broader than sharing one service. It must not be required simply to collaborate with an independently owned agent.

**Shared network membership** admits selected foreign principals into a common communication and cryptographic trust domain. Members can collaborate directly according to explicit permissions. The owning tenant controls admission and network policy; each principal owner controls whether their principal participates and what it can expose. Membership does not merge private networks, tenants, hosts or accounts.

**An entry door** is a proposed directional grant to invoke selected capabilities of an agent or service. The receiving tenant owns that endpoint and a bridge that mediates access to its private network. The caller remains outside that private network. An entry door is not a third principal kind: the principal remains an agent or service; the door is its exposure policy and grant. The bridge terminates the authorized external request, checks policy, and performs a bounded internal operation using its own explicitly limited authority. It must not forward arbitrary destinations, caller-selected credentials or unrestricted tools.

Use a shared network for collaboration whose participants accept a common content trust boundary. Use an entry door for a bounded relationship across private domains. Tenant membership expresses organizational belonging.

## Edu–Conti example and bilateral rights

Assume Edu and Conti own separate accounts and tenants, private networks, representatives and hosts. Edu wants to ask Conti's assistant for a service. The default recommendation is a Conti-owned entry door exposing, for example, `review_proposal` to Edu's named principal. Edu's representative calls it with the approved input; Conti's bridge returns an approved result. Edu receives no Conti network epoch keys, participant inventory, host browsing or filesystem access.

Conti's grant to Edu does not authorize Conti to call Edu. A reverse service needs a separate Edu-owned door and grant. Each grant identifies issuer, accepted caller principal and owning tenant, destination principal, allowed capability revisions, limits, expiry, approval requirements and revocation version. Both principal owners must consent: one offers the service and the other accepts use by its principal. Either side can stop its own participation. A caller grant does not authorize delegation to third parties or reciprocal invocation.

If Edu and Conti instead want their assistants to collaborate freely on a project, they can create a dedicated shared network owned by one tenant and admit both principals explicitly. Keep each private network separate. Agree on membership permissions and content exposure before key enrollment; expose only project agents or constrained services. Two memberships still do not imply equal administration, equal host control, or reciprocal permissions.

If both people need equal authority over that project's admission and policy, create a dedicated project tenant, make Edu and Conti its administrators, and let it own the network. Each account still owns its own agents and hosts; project administration does not grant either person launch or filesystem authority on the other's host. Changing project administrators, keys, and membership is an explicit governance operation. The product needs to implement this invitation and role flow before it can promise equal control.

Effective invocation authority must satisfy every applicable constraint: authenticated caller, current caller-owner authority, current network membership or door grant, destination policy, operation scope, and any required approval. A bridge must preserve authenticated origin and delegation limits so its internal authority cannot turn an untrusted request into an unrestricted owner action.

## Exactly twenty use cases

| ID | Situation | Appropriate relationship |
| --- | --- | --- |
| 01 | Edu requests a proposal review from Conti's private assistant. | Conti entry door |
| 02 | Edu and Conti's agents jointly plan a project and exchange tasks and events. | Dedicated shared network |
| 03 | Conti separately requests a calendar slot from Edu after granting proposal reviews. | Independent reverse entry door |
| 04 | A new employee joins company administration and internal collaboration. | Tenant membership, then explicit network access |
| 05 | A contractor contributes to one project without company administration. | Dedicated shared network |
| 06 | A customer submits a support ticket to a vendor agent. | Vendor entry door |
| 07 | Two companies jointly operate an incident room with shared updates. | Dedicated shared network |
| 08 | A monitoring provider sends only alerts into a customer's private operations network. | Ingestion entry door |
| 09 | A data supplier sells access to one aggregate query capability. | Supplier entry door |
| 10 | An auditor inspects approved evidence without browsing all internal participants. | Evidence entry door |
| 11 | A family shares household planning agents while keeping personal assistants private. | Dedicated shared network |
| 12 | A research consortium shares project datasets and analysis agents. | Dedicated shared network |
| 13 | A developer publishes a discoverable formatter service for external callers. | Public discovery plus authenticated entry-door invocation |
| 14 | One person's laptop and desktop agents collaborate on private work. | Personal network with separately enrolled hosts |
| 15 | A company subsidiary needs actual parent-organization administration. | Tenant membership according to governance |
| 16 | A Telegram user asks their own representative to invoke a partner service. | Existing account binding plus partner entry door |
| 17 | A friend requests a free-time summary without seeing a personal calendar. | Personal calendar-summary entry door |
| 18 | A release partner submits a build candidate but may not launch processes on the recipient's host. | Submission entry door |
| 19 | A temporary workshop gives agents a common discussion space until the event ends. | Expiring shared network memberships |
| 20 | A departing partner must lose future service and project access while prior records remain auditable. | Revoke door grants and memberships; rotate affected network epochs |

## Ten representative decisions

“Tenant” below means adding the foreign person to the owning tenant, not changing principal ownership. Recommendations assume the circumstances in the use-case table.

| Case | Tenant membership | Shared network | Entry door | Recommendation |
| --- | --- | --- | --- | --- |
| 01 Edu–Conti review | Excess administrative relationship | Shares a wider content boundary than needed | Exposes only review | Entry door |
| 02 Joint project | Unnecessary organizational coupling | Direct tasks, events and project participants | Requires mediating each collaboration | Shared network |
| 03 Reverse calendar | Unnecessary | Does not follow from review permission | Independent issuer, scope and consent | Separate reverse door |
| 04 Employee | Matches organizational belonging | Does not establish tenant role | Insufficient for administration | Tenant membership and selected networks |
| 05 Contractor | Use only if governance requires it | Matches bounded project collaboration | Better only for isolated deliverables | Shared project network |
| 06 Customer support | Inappropriate account administration | Exposes unnecessary participant context | Bounded submission and response | Entry door |
| 07 Incident room | Companies remain independent | Common live collaboration domain | Useful for alert intake, insufficient for the full room | Shared network |
| 09 Aggregate data | Unnecessary | Risks broader content/key exposure | Enforces query and output limits | Entry door |
| 10 Auditor | Broader than evidence access | Shared keys conflict with selective evidence disclosure | Projects approved evidence | Entry door |
| 16 Telegram partner call | Channel binding grants no tenant role | Channel binding grants no membership | Own representative invokes under a separate grant | Telegram binding plus entry door |

## Security and operation boundaries

### Discovery is separate from invocation

Seeing a public principal, discovering a filtered catalog, or holding `discover` must not permit invocation. A door may disclose a minimal capability schema without admitting the caller to the destination network. Invocation must revalidate the current caller, destination, capability revision and grant at admission and before sensitive effects. An old catalog result is not an authorization token. Denials must avoid leaking private participant names, tasks or capability metadata.

### Host launch and workspace access remain owner controlled

For this sharing design, foreign membership and door invocation never confer host enrollment, launch, attach, stop, workspace browsing, path selection, or arbitrary filesystem access. Only the resource owner or an explicitly authorized existing administrative path can authorize host actions; personal representative launch retains the same-owner personal-host requirement evidenced by [its regression test](../../pagnet-server/internal/controlplane/representative_personal_host_test.go). This is not a claim that all current host APIs are owner-only: [host access code](../../pagnet-server/internal/controlplane/api_hosts.go) also has tenant administrator rules.

If a door needs execution, its owner provisions the worker and approved workspace in advance. A request may select a validated business resource ID, not an arbitrary host path or shell command. Server authorization must bind the selected principal, host, workspace and operation to the owner's policy; the daemon must independently enforce the local workspace allowlist, canonical path and symlink containment, and runtime sandbox before effects. Missing enforcement must fail closed. Network `operate` cannot bypass these resource checks.

Bridge process binding proves which local process called; it does not prove that a requested file is allowed. Current Linux Landlock requirements and the documented lack of equivalent macOS filesystem isolation must remain visible. Do not claim portable filesystem containment or approve an untrusted sharing workload on the strength of a nonce, process ancestry, or server path validation alone.

### Shared keys limit selective confidentiality

Network encryption protects content from ordinary relay/storage inspection under the documented enrollment trust model. It does not make mutually untrusted members safe to share all content. A holder of a shared epoch key that obtains ciphertext protected by that key can decrypt it; routing permissions and hidden UI rows cannot cryptographically separate those members. Key access, including any authorized object-decryption access, must be evaluated alongside membership permissions.

Use separate networks or a door that returns approved projections where content must remain private. The bridge is a trusted content boundary: it may decrypt internal data and deliberately release a result. It needs output filtering and least authority; encryption does not prevent it or an admitted participant from copying plaintext. Control-plane enrollment and delivered browser code remain trusted as documented today; independently owner-verified enrollment is additional work.

### Telegram identifies an account, not a sharing grant

The [current Telegram binding](../../pagnet-web/apps/docs/content/docs/representatives/telegram.md) pairs an authenticated private-chat sender to their own account through an expiring single-use code. A binding does not create a representative or launch one. Edu's Telegram message should reach Edu's representative; the representative then uses its separately authorized Conti door or shared membership. Never let a supplied Telegram ID, network name, deep link or conversational claim select another account's authority. Telegram and the control plane can read bot chat and replies; returning protected content to Telegram deliberately crosses that confidentiality boundary.

### Revocation, keys and history

Proposed door revocation must stop new admission, invalidate cached grants and catalogs, and fence queued work before effects. In-flight cancellation is best effort after an irreversible effect; report that distinction instead of promising rollback. Use bounded lifetimes, destination-side durable replay admission and idempotency so transport retries do not repeat effects. The federation transport alone does not supply those product guarantees.

Network revocation must deny future authorized traffic and enrollment, close applicable sessions, and rotate epochs when excluding a key holder from future content. It cannot revoke retained keys, plaintext or downloaded ciphertext. New membership must not automatically grant historical epoch keys; historical access needs an explicit owner decision and supported enrollment policy. Leaving and rejoining must not silently restore earlier grants or history access. Preserve audit metadata about issuer, caller, scope, revisions, admission, result and revocation without logging protected payloads. Lost old keys can make old content unreadable; rotation is not recovery.

## Phased delivery

1. **Verify and tighten boundaries.** Audit server and daemon authorization for foreign principals, host launch, workspace access and key enrollment. Record current behavior with tests. Add explicit external permission selection rather than all-eight defaults. Keep invitations disabled where ownership or filesystem enforcement is incomplete.
2. **Deliver explicit shared-network consent.** Add invitation/acceptance, network-owner and principal-owner checks, constrained membership grants, expiry and clear key/history disclosure. Verify independent tenant ownership, denied host access, discovery versus invocation and revocation with epoch rotation. A shared network remains owned by one tenant.
3. **Deliver one directional door.** Implement an agent/service exposure policy, bilateral acceptance, authenticated caller attribution, bounded capability schemas, destination checks, output policy, approval, quotas, expiry, audit and replay protection. Start with one bounded operation. Complete remote bridge integration where needed; do not present existing federation fixtures as the deployed path.
4. **Exercise Edu–Conti end to end.** Verify both independent directions, denied ungranted capabilities, no private discovery or keys, owner-only resource actions, Telegram account binding, revoked queued calls and historical-key behavior. Run real platform filesystem checks for any offered execution workload.
5. **Expand deliberately.** Add filtered discovery and more service patterns after the enforcement tests pass. Pursue independently owner-verified enrollment as a separate cryptographic trust improvement. Product language must distinguish shared participation, organizational membership and scoped service use throughout.
