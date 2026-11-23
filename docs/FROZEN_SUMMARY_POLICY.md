# Local frozen summary policy foundation

A responder profile may select `FrozenSummaryApprovalID` only for the
`sdk_project_v2` contract (including the existing implicit V2 contract). The
selection must be a canonical nonzero approval UUID. The selection is fixed at
first publication of `profile.json`: adding, replacing, or clearing it later is
rejected. Existing profiles without this field retain their generic policy and
omit it when saved. Profile JSON decoding remains strict, so an older binary
rejects a profile containing the new field.

`run.lock` remains the nonblocking lifecycle lock held by a running responder.
`policy.lock` is a separate exclusive cross-process lock with context-aware
waiting. Code needing both must acquire `run.lock` before `policy.lock`, and
must never acquire `run.lock` while holding `policy.lock`. `SaveProfile` takes
`policy.lock` internally; callers already holding it use the internal locked
save operation. Approval disable takes the profile's `policy.lock` before the
approval-directory lock. Lock files must not be removed or replaced while in use.

`DisableProfile` and the existing CLI disable operation take only `policy.lock`,
reload the current profile, disable its ledger budget, and atomically persist
`Disabled=true`. This works while a responder holds `run.lock`. A persistence
failure leaves the ledger disabled. This is ordered fail-closed persistence,
not a transaction across SQLite and the profile file. Previously claimed calls
can still complete. A stale profile save cannot re-enable a disabled profile;
metadata retirement updates may preserve the disabled state.

Create a frozen summary responder through the owner CLI in two steps:

```sh
pagnet text-bridge frozen-summary reserve --name historical-helper --request-id UUID
# Create a V2 sharing project in the owner UI with that service in its roster.
# Keep the project pending or enrolling until approval completes.
pagnet text-bridge frozen-summary approve --service SERVICE_UUID --project PROJECT_UUID \
  --frozen-summary-file /private/summary.txt --provider-origin https://provider.example \
  --model MODEL --key-file /private/provider-key --calls-per-day 5 \
  --expires-at 2027-01-01T00:00:00Z --historical-source-label "Historical notes"
pagnet text-bridge frozen-summary status --service SERVICE_UUID
pagnet text-bridge run --service SERVICE_UUID
pagnet text-bridge frozen-summary disable --service SERVICE_UUID
```

Reservation creates a fresh personal service and private local reservation, with
no profile, SDK connection, or runtime. `--request-id` identifies a durable local
creation journal; replaying a completed unused reservation returns the same
service. An uncertain creation is never retried. Inspect Services to reconcile
it. A new request ID authorizes a new service creation.

Approval requires the local reservation, a private bounded UTF-8 summary source,
explicit project allowlist, positive daily allowance and future RFC3339 expiry.
It captures immutable instructions; later changes to the source file do not
change the approved responder. Generic `enable` does not accept frozen policy
flags, and existing profiles cannot be converted.

The durable immutable approval record is the authorization boundary. After that
write, authenticated owner checks require a standard personal service owned by
the current account, full management visibility, and an empty endpoint history,
including offline endpoints. Each allowed project must be V2, pending or
enrolling, and contain the service on the owner's roster side. This proves that
preapproval project messages could not have been admitted. Activity after the
approval record is postapproval activity. The CLI does not use message header
timestamps as an admission boundary.

Approval writes its ledger and publishes the complete selected profile last.
Failure or interruption after approval starts retires that attempt without a
runnable profile; it cannot be edited or retried. Create a new reservation.
Status contains only owner-safe metadata. Disable cancels an unused reservation
or retires the selected approval and disables its ledger/profile, even while a
runtime holds `run.lock`. It does not undo calls already claimed.
