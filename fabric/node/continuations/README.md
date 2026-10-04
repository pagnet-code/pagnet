Trusted node composition supplies the real continuation Store, immutable extension
manifests, an exact identity resolver, a historical-admission authority, a private
capability notification sink and a target effect-evidence verifier. No default
cloud identity, serialized authenticated context, business approval policy or
caller-supplied completed flag is accepted.

The engine Save port persists the immutable original bytes and caller provenance,
canonical plan evidence, current transformed PipelineState and DEFER constraints.
Manifests are copied, sorted and compiled at construction; their exact commitment
must match the engine revision. State JSON grammar has configurable finite
SnapshotLimits (default8MiB/64depth/65536members); select compatible Store quotas
for larger deployments. Changed expiry on ambiguous DEFER retries is rejected:
durable engine stage-response replay must retain the original decision.

After a known durable Create, notification failure retains the committed ID
alongside a structured redacted error; it never pretends persistence failed.
Only new secret issuance enters the private notification sink. Exact Create retry
returns the existing identity and does not repeat delivery or recreate a secret.
An authenticated allowed resumer may explicitly rotate a still-pending capability.
Rotation returns metadata revision/delivery state, even if notification fails, so
the private operator can retry rotation without publishing the capability. Claims
and original snapshots never enter public result JSON; only receipt metadata,
stored bounded outcome and an optional new DeferredID do.

Resume first authenticates capability possession plus exact permitted resumer and
atomically claims. Fresh=false returns stored evidence, never restores identity
or enters the engine. A fresh claim reaches the mandatory historical authority
port, which must validate the original issuer/identity/provenance and exact bytes.
Prior local authenticated admission is historical evidence, not current endpoint
permission. Engines consume an in-process single-use ResumePermit and rerun
current final dispatch validators; this adapter cannot synthesize cloud admission.

Target unary and checked terminal stream evidence is captured inside Downstream,
before response/completion hooks. The explicit trusted adapter verifier owns effect
interpretation. Arbitrary success output does not prove effects. Cache/RESPOND with
no target call is reported as local NoTarget evidence; cancellation, timeout,
premature EOF and Close are unknown unless that verifier can independently confirm
a concrete original target receipt. Later hook rejection never overwrites a
committed target completion. Streams remain pull-driven without transcript buffers.
Close cancels the producer, joins in-flight Next, and settles abandonment only when
no genuine target settlement already committed. Settlement persistence has its own
finite timeout after consumer cancellation; failure leaves the claim uncertain.
No ambiguous claim or settlement grants automatic target replay.
