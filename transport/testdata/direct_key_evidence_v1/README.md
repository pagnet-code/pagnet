# Public direct key evidence v1 fixtures

Each role directory contains an exact canonical public `binding.json`, its fixed
lowercase `binding_hash.txt`, and the canonical `transcript.json` and `digest.txt`
that commit that binding hash. The identifiers and host metadata are synthetic;
these fixtures contain no credentials, private keys or secret-derived columns.

The binding subjects use their respective S/P protocol field order. Their IDs,
intent, principal and endpoint match the evidence transcript. S also carries the
matching proposal, grant, authority and budget fields required by its subject.

Hash expectations were calculated independently with Python `hashlib.sha256`:

- `binding_hash.txt`: SHA-256 of the UTF-8 bytes
  `pagnet/direct-key-evidence/binding/v1/` followed by exact `binding.json` bytes.
- `digest.txt`: SHA-256 of exact `transcript.json` bytes.

All four files per role exclude a trailing newline. Tests compare the serializer
and hash helpers to these fixed expectations and reject leading, interior and
trailing whitespace in each binding subject.
