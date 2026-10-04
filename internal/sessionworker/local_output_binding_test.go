//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestLocalOutputHeadBindsGenuineDomainAndPhysicalCaptureAuthority(t *testing.T) {
	f := newLocalAuthorityFixture(t)
	foreign := newLocalAuthorityFixture(t)
	key := bytes.Repeat([]byte{19}, 32)
	directory := filepath.Join(t.TempDir(), "native-owner")
	input := encoderCapture(1, "genuine-generation", "private local output")
	ciphertext, err := sealOutputSpoolBound(key, f.scope, directory, input)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ciphertext)
	if bytes.Contains(ciphertext, []byte(input.Text)) {
		t.Fatal("local original output persisted plaintext")
	}
	opened, err := openOutputSpoolBound(key, f.scope, directory, input.Source.NativeGeneration, input.Source.Sequence, ciphertext)
	if err != nil || opened.Text != input.Text || !bytes.Equal(opened.Origin, input.Origin) {
		t.Fatal("genuine local output changed", err)
	}
	clear(opened.Key)
	for _, test := range []struct {
		name                  string
		authority             any
		directory, generation string
		sequence              int64
	}{
		{"different retained domain", foreign.scope, directory, input.Source.NativeGeneration, 1},
		{"zero cloud identity", Scope{}, directory, input.Source.NativeGeneration, 1},
		{"different physical directory", f.scope, directory + "-other", input.Source.NativeGeneration, 1},
		{"different native generation", f.scope, directory, "other-generation", 1},
		{"different command ordinal", f.scope, directory, input.Source.NativeGeneration, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			if value, err := openOutputSpoolBound(key, test.authority, test.directory, test.generation, test.sequence, ciphertext); err == nil {
				clear(value.Key)
				t.Fatal("local encrypted output accepted another authority")
			}
		})
	}
}

func TestCloudOutputHeadAADRemainsItsExactOriginalRepresentation(t *testing.T) {
	scope := testScope()
	directory := filepath.Join(t.TempDir(), "worker")
	want, err := canonicalNativeJSON(struct {
		Domain                string
		Scope                 Scope
		Directory, Generation string
		Sequence              int64
	}{NativeOutputStreamCaptureFormat, scope, directory, "original-generation", 17})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(outputSpoolAADBound(scope, directory, "original-generation", 17), want) {
		t.Fatal("existing Cloud ciphertext authentication bytes changed")
	}
}
