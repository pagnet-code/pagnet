# Persistent local MCP catalog

This catalog implements the MCP adapter's catalog port using the real local
registry. Explicit `Bootstrap` creates a signed binding checkpoint; subsequent
starts use `Open`. Missing or unauthentic state does not trigger initialization.

The operator supplies a genuinely authenticated registry owner, exact local
endpoint revision and binding, a stable protector/key reference, finite limits,
and a nonzero `BindingDigest`. The digest must cover the selected provider
address/profile and credential **principal selector**, without including token
bytes. It is private authenticated configuration, never a public descriptor.
Changing the provider or principal under the same binding fails on reopen;
use an explicit new binding/ref migration. Credential rotation for the same
principal is handled by the adapter's credential provider. Encryption key
rotation requires an explicit migration, not a different key passed to `Open`.

A provider snapshot applies signed offer publications/retirements, the private
selector projection, and search outbox entries in one FULL SQLite transaction.
The projection has signed root/store-bound history associated with exact public
ledger head ranges. Reopen verifies history and materialized mappings together.
An exact request retry returns the original result; conflicting content fails.
Pagination uses generation-bound cursors, and invocation resolves a single exact
remembered offer/revision. Description and discovery never start a runtime.

Names-only removal permanently retires that offer reference. Reappearance gets
a new reference; the catalog does not infer semantic renames. A changed schema
for a still-present tool advances its revision without changing its reference.
Foreign public descriptor imports cannot establish a local callable selector.

Use one catalog instance per adapter; that adapter serializes synchronization.
Independent instances are fenced by the persisted projection generation and must
refresh `Current` after a stale-generation failure. The bounded cache contains
only names/fingerprints and encrypted projection rows; canonical schemas are
loaded from the signed registry for an exact offer.

Selector metadata and the configuration checkpoint use the injected protector.
Canonical schemas remain in the trusted local privatefs registry; they are not
claimed to be encrypted at rest. Remote encrypted descriptor relay is a separate
composition responsibility. Retired references and signed history consume finite
configured budgets; exhaustion rejects the entire snapshot instead of silently
truncating it. No unlimited history or output guarantee is made.

Removing all private projection tables and their format marker while restoring
matching old budgets and signed state can be indistinguishable from an older
backup. This is not universal rollback detection. `Open` still requires the
previously initialized binding and never silently bootstraps missing state.
