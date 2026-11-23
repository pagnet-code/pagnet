//go:build linux || darwin

package daemon

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

func sourceProveFixture(t *testing.T) (*NativeShareSourceHolderStore, transport.HostSessionPayload, transport.NativeShareSourcePreparedPayload, transport.NativeShareSourceProvePayload, []byte) {
	t.Helper()
	holder, session, prepare := sourcePrepareExecutorFixture(t)
	executor, err := NewNativeShareSourcePrepareExecutor(holder.registry, sourcePrepareExecutorNow)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := executor.Prepare(prepare.Enrollment.Subject.ServerURL, session, prepare)
	if err != nil {
		t.Fatal(err)
	}
	p := transport.NativeShareSourceProvePayload{NativeShareSourceChallengeContext: transport.NativeShareSourceChallengeContext{
		Version: transport.NativeShareSourceVersion, EnrollmentID: prepare.Enrollment.EnrollmentID, CommandID: domain.NewID(), EnrollmentDigest: prepared.EnrollmentDigest, DescriptorFingerprint: prepared.Descriptor.Fingerprint, ChallengeID: domain.NewID(), ExpiresAt: prepare.Enrollment.ExpiresAt,
	}}
	plain := bytes.Repeat([]byte{0xa7}, 32)
	public, err := hex.DecodeString(prepared.Descriptor.X25519)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := p.ChallengeAAD()
	if err != nil {
		t.Fatal(err)
	}
	p.Challenge.Enc, p.Challenge.Ciphertext, err = crypto.WrapKey(public, []byte(transport.NativeShareSourceChallengeInfo), aad, plain)
	if err != nil {
		t.Fatal(err)
	}
	return holder, session, prepared, p, plain
}

func TestNativeShareSourceProveRestartRetryNoPlaintext(t *testing.T) {
	holder, session, prepared, request, plain := sourceProveFixture(t)
	executor, err := NewNativeShareSourceProveExecutor(holder.registry, sourcePrepareExecutorNow)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := prepared.Prepare.Enrollment.Subject.ServerURL
	first, err := executor.Prove(endpoint, session, request)
	if err != nil || !bytes.Equal(first.Challenge, plain) {
		t.Fatal("proof failed", err)
	}
	hash, err := first.ChallengeHash()
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := hex.DecodeString(prepared.Descriptor.Ed25519)
	if err := first.Verify(request, hash, prepared.Descriptor.Fingerprint, signer, sourcePrepareExecutorNow()); err != nil {
		t.Fatal(err)
	}
	raw, err := first.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	var retained, requestDigest []byte
	var receipt string
	if err := holder.registry.db.QueryRow(`SELECT request,request_digest,receipt_digest FROM native_source_prove_journal`).Scan(&retained, &requestDigest, &receipt); err != nil {
		t.Fatal(err)
	}
	expected, _ := request.CanonicalBytes()
	expectedReceipt, _ := first.ReceiptDigest()
	if !bytes.Equal(retained, expected) || len(requestDigest) != 32 || receipt != expectedReceipt {
		t.Fatal("incorrect durable receipt")
	}
	root := holder.registry.root
	reopened := sourcePrepareReopen(t, holder)
	executor, err = NewNativeShareSourceProveExecutor(reopened.holder.registry, sourcePrepareExecutorNow)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := executor.Prove(endpoint, session, request)
	retryRaw, _ := retry.CanonicalBytes()
	if err != nil || !bytes.Equal(raw, retryRaw) {
		t.Fatal("restart changed proof", err)
	}
	// An interrupted operation with only a durable reservation regenerates exactly.
	if _, err := reopened.holder.registry.db.Exec(`UPDATE native_source_prove_journal SET receipt_digest=NULL`); err != nil {
		t.Fatal(err)
	}
	retry, err = executor.Prove(endpoint, session, request)
	retryRaw, _ = retry.CanonicalBytes()
	if err != nil || !bytes.Equal(raw, retryRaw) {
		t.Fatal("reserved retry changed proof", err)
	}
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, plain) || bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(plain))) || bytes.Contains(data, raw) {
			t.Errorf("plaintext persisted in %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeShareSourceProveRejectsChangedRequest(t *testing.T) {
	for _, change := range []string{"command", "enrollment", "challenge", "digest", "fingerprint", "ciphertext", "enc", "expiry"} {
		t.Run(change, func(t *testing.T) {
			holder, session, prepared, request, _ := sourceProveFixture(t)
			executor, err := NewNativeShareSourceProveExecutor(holder.registry, sourcePrepareExecutorNow)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := prepared.Prepare.Enrollment.Subject.ServerURL
			if _, err := executor.Prove(endpoint, session, request); err != nil {
				t.Fatal(err)
			}
			request.Challenge.Enc = bytes.Clone(request.Challenge.Enc)
			request.Challenge.Ciphertext = bytes.Clone(request.Challenge.Ciphertext)
			switch change {
			case "command":
				request.CommandID = domain.NewID()
			case "enrollment":
				request.EnrollmentID = domain.NewID()
			case "challenge":
				request.ChallengeID = domain.NewID()
			case "digest":
				request.EnrollmentDigest = string(bytes.Repeat([]byte("b"), 64))
			case "fingerprint":
				request.DescriptorFingerprint = string(bytes.Repeat([]byte("b"), 64))
			case "ciphertext":
				request.Challenge.Ciphertext[0] ^= 1
			case "enc":
				request.Challenge.Enc[0] ^= 1
			case "expiry":
				request.ExpiresAt = "2027-01-02T03:04:04Z"
			}
			if reply, err := executor.Prove(endpoint, session, request); err == nil || reply.Challenge != nil {
				t.Fatal("changed request accepted")
			}
		})
	}
}

func TestNativeShareSourceProveRejectsStaleAndExpired(t *testing.T) {
	for _, change := range []string{"boot", "epoch", "runner", "admission", "host", "tenant", "account", "credential", "ownership", "endpoint", "expired", "zero time", "unfinished prepare", "changed installation", "changed descriptor", "changed prepare digest", "corrupt receipt"} {
		t.Run(change, func(t *testing.T) {
			holder, session, prepared, request, _ := sourceProveFixture(t)
			current := sourcePrepareExecutorNow()
			executor, err := NewNativeShareSourceProveExecutor(holder.registry, func() time.Time { return current })
			if err != nil {
				t.Fatal(err)
			}
			endpoint := prepared.Prepare.Enrollment.Subject.ServerURL
			if _, err := executor.Prove(endpoint, session, request); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "boot":
				session.BootID = "other"
			case "epoch":
				session.RunnerEpoch = session.RunnerEpoch.Add(time.Second)
			case "runner":
				session.RunnerID = string(domain.NewID())
			case "admission":
				session.NativeAdmissionID = string(domain.NewID())
			case "host":
				session.HostID = string(domain.NewID())
			case "tenant":
				session.TenantID = string(domain.NewID())
			case "account":
				session.AccountID = string(domain.NewID())
			case "credential":
				session.HostCredentialID = "other"
			case "ownership":
				session.OwnershipScope = "other"
			case "endpoint":
				endpoint = "https://different.example"
			case "expired":
				current, _ = time.Parse(time.RFC3339Nano, request.ExpiresAt)
			case "zero time":
				current = time.Time{}
			case "unfinished prepare":
				_, err = holder.registry.db.Exec(`UPDATE native_source_prepare_journal SET prepared=NULL`)
			case "changed installation":
				_, err = holder.registry.db.Exec(`UPDATE native_registry_metadata SET value=? WHERE name='installation_id'`, domain.NewID())
			case "changed descriptor":
				_, err = holder.registry.db.Exec(`UPDATE native_source_holder_enrollments SET descriptor=X'00'`)
			case "changed prepare digest":
				_, err = holder.registry.db.Exec(`UPDATE native_source_prepare_journal SET request_digest=zeroblob(32)`)
			case "corrupt receipt":
				_, err = holder.registry.db.Exec(`UPDATE native_source_prove_journal SET receipt_digest=?`, string(bytes.Repeat([]byte("b"), 64)))
			}
			if err != nil {
				t.Fatal(err)
			}
			if reply, err := executor.Prove(endpoint, session, request); err == nil || reply.Challenge != nil {
				t.Fatal("stale proof accepted")
			}
		})
	}
}

func TestNativeShareSourceProveFailedOpenRetainsReservation(t *testing.T) {
	holder, session, prepared, request, _ := sourceProveFixture(t)
	executor, err := NewNativeShareSourceProveExecutor(holder.registry, sourcePrepareExecutorNow)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := prepared.Prepare.Enrollment.Subject.ServerURL
	changed := request
	changed.Challenge.Ciphertext = bytes.Clone(request.Challenge.Ciphertext)
	changed.Challenge.Ciphertext[0] ^= 1
	if _, err := executor.Prove(endpoint, session, changed); err == nil {
		t.Fatal("invalid ciphertext accepted")
	}
	var count int
	if err := holder.registry.db.QueryRow(`SELECT COUNT(*) FROM native_source_prove_journal WHERE receipt_digest IS NULL`).Scan(&count); err != nil || count != 1 {
		t.Fatal("reservation lost", err)
	}
	if reply, err := executor.Prove(endpoint, session, request); err == nil || reply.Challenge != nil {
		t.Fatal("uncertain command reused")
	}
}
