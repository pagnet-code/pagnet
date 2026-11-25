# Source-v2 public key evidence

The S fixtures freeze canonical source-v2 binding and public evidence transcript
bytes, their domain-separated binding hash, and their SHA-256 evidence digest.
All values are public test data; the evidence digest fields are synthetic.
Target evidence remains in `direct_key_evidence_v1/P`.

The initial V2 evidence contract accepts role S and generation one only. Binding,
prepare, PoP and credential protocols must all explicitly select source-v2.
Generation two and rollover are unsupported. A binding hash accepts only exact
canonical source-v2 subject bytes, without predecessor or previous credential.

`effectiveExpiresAt` equals `credentialExpiresAt` and cannot exceed either
`authorizationExpiresAt` or budget expiry. It intentionally extends beyond the
short enrollment deadline. Consumers must compare these public values against
retained binding and credential evidence and independently enforce authority.
The channel descriptor is unchanged and commits this transcript via its evidence
digest.
