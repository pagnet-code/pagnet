Managed Gateway admission is dormant infrastructure. `GatewayAdmission` binds
one authenticated ASK descriptor to an owner, installation, grant, policy,
target definition and exact worker configuration. Validation checks structure;
it does not authenticate the ASK, installation, sender or executable grant.

The sessionworker journal retains Gateway provenance in its own bounded table.
Operation IDs and ASK IDs are independently unique. Identical retries return
the original reservation; changed descriptors conflict. Reservations survive
worker restart as `unknown` and never authorize repeating a native effect.
There is no pruning: exhaustion fails closed rather than permitting reuse.
No input bodies, capability secrets or native result bodies are stored here.

The capability installer and admission methods are private, with no production
callers. Cloud command IDs, sequence history and dispatch proofs are unchanged.
A journal reservation is not native acceptance. Receipt types describe data;
no receipt authentication or result delivery is implemented in this phase.

The next unit must authenticate owner installation, pin and verify the exact
existing live endpoint, serialize admission with owner operations, and submit
without activation, restart, resume or endpoint replacement. It must bound and
authenticate terminal results and return unknown for ambiguous acceptance or
endpoint death. No daemon route, provider bridge, launch or readiness interface
may expose this journal-only phase as executable work.
