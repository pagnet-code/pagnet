//go:build linux || darwin

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLocalA2ACardRejectsFIFOAndSymlinkWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "card.json")
	raw := []byte(`{"name":"explicit card","metadata":{"n":9007199254740993}}`)
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	actual, e := readLocalA2ACard(path)
	if e != nil || !bytes.Equal(actual, raw) {
		t.Fatal("card rewritten", e, string(actual))
	}
	pipe := filepath.Join(dir, "pipe")
	if e := unix.Mkfifo(pipe, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := readLocalA2ACard(pipe); e == nil {
		t.Fatal("FIFO accepted")
	}
	link := filepath.Join(dir, "link")
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e := readLocalA2ACard(link); e == nil {
		t.Fatal("symlink accepted")
	}
	for _, invalid := range [][]byte{bytes.Repeat([]byte(" "), (24<<10)+1), []byte(`{"name":"one","name":"two"}`), []byte(`{} {}`)} {
		if e := os.WriteFile(path, invalid, 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := readLocalA2ACard(path); e == nil {
			t.Fatal("unbounded/ambiguous card accepted")
		}
	}
}
