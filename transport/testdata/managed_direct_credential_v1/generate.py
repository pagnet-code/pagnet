"""Reproduce public golden vectors independently; requires Python cryptography.

Run from any directory. Only public wire messages and one-way digests are written.
The fixed private inputs are test-only values shared with the Go fixture.
"""
import base64
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = Path(__file__).resolve().parent
PREFIX = b"pagnet/managed-direct-credential/"
pop_raw = (ROOT.parent / "managed_endpoint_pop_v1/challenge.json").read_bytes()
proof_raw = (ROOT.parent / "managed_endpoint_pop_v1/proof.json").read_bytes()
pop = json.loads(pop_raw)
proof = json.loads(proof_raw)
server = X25519PrivateKey.from_private_bytes(bytes([0x53]) * 32)
host = X25519PrivateKey.from_private_bytes(bytes([0x31]) * 32)
issue = {
    "protocolVersion": "managed_direct_credential_v1",
    "suite": pop["suite"],
    "credentialId": "10000000-0000-4000-8000-00000000001b",
    "channelGeneration": 2,
    "nonce": base64.b64encode(bytes([0x64]) * 32).decode(),
    "serverEphemeralX25519": server.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex(),
    "issuedAt": "2026-11-24T12:00:00Z",
    "installExpiresAt": "2026-11-24T12:01:00Z",
    "credentialExpiresAt": "2026-11-24T12:04:00Z",
    "pop": pop,
    "popReceipt": {
        "challengeId": proof["challengeId"],
        "transcriptHash": proof["transcriptHash"],
        "proofDigest": hashlib.sha256(proof_raw).hexdigest(),
    },
    "budget": {
        "agreementId": "10000000-0000-4000-8000-00000000001c",
        "acceptedRevision": 3,
        "termsDigest": "ef" * 32,
        "expiresAt": "2026-11-24T12:05:00Z",
    },
}

def wire(value):
    return json.dumps(value, separators=(",", ":")).encode()

raw = wire(issue)
transcript = hashlib.sha256(PREFIX + b"transcript/v1/" + raw).digest()
shared = server.exchange(host.public_key())

def derive(label):
    return HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=base64.b64decode(issue["nonce"]),
        info=PREFIX + label + b"/v1/" + transcript,
    ).derive(shared)

secret = derive(b"credential-secret")
install = derive(b"install-key")
confirmation = hmac.new(
    install, PREFIX + b"host-install/v1/" + transcript, hashlib.sha256
).digest()
ack = {
    "protocolVersion": issue["protocolVersion"],
    "suite": issue["suite"],
    "credentialId": issue["credentialId"],
    "transcriptHash": transcript.hex(),
    "hostConfirmation": confirmation.hex(),
}
artifacts = {
    "issue.json": raw,
    "ack.json": wire(ack),
    "transcript_hash.txt": transcript.hex().encode(),
    "credential_hash.txt": hashlib.sha256(
        PREFIX + b"credential-hash/v1/" + transcript + secret
    ).hexdigest().encode(),
    "install_verifier.txt": hashlib.sha256(
        PREFIX + b"install-verifier/v1/" + transcript + confirmation
    ).hexdigest().encode(),
}
for name, data in artifacts.items():
    if (ROOT / name).exists() and (ROOT / name).read_bytes() != data:
        raise ValueError("Independent vector differs: " + name)
    (ROOT / name).write_bytes(data)
print("Five public golden artifacts verified independently.")
