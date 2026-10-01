package main

import "testing"

func TestPersistentInputCaptureRequiresExplicitOptIn(t *testing.T) {
	body := "header\nprotected full body\nsecond line"
	s := &session{}
	t.Setenv("PAGNET_FAKE_CAPTURE_INPUT", "")
	capturePersistentInput(s, body)
	if s.CapturedInput != "" {
		t.Fatal("recorded full input without opt-in")
	}
	t.Setenv("PAGNET_FAKE_CAPTURE_INPUT", "1")
	capturePersistentInput(s, body)
	if s.CapturedInput != body {
		t.Fatal("capture lost multiline native input")
	}
	t.Setenv("PAGNET_FAKE_CAPTURE_INPUT", "0")
	capturePersistentInput(s, body)
	if s.CapturedInput != "" {
		t.Fatal("disabled capture retained previous protected input")
	}
}
