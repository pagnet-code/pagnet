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

This phase does not select a frozen summary provider at runtime or change bridge
dispatch. It provides no activation or readiness guarantee.
