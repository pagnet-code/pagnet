package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/pagnet-code/pagnet/domain"
)

const maxFakeInteractionOptionsBytes = 128 << 10

// The file knob avoids delimiters in the fixture's comma-separated runtime env.
// It changes only where the original native process reads its observed options.
func persistentInteractionOptions() ([]domain.RuntimeInteractionOption, error) {
	inline, path := os.Getenv("PAGNET_FAKE_INTERACTION_OPTIONS"), os.Getenv("PAGNET_FAKE_INTERACTION_OPTIONS_FILE")
	if inline == "" && path == "" {
		return nil, nil
	}
	if inline != "" && path != "" {
		return nil, errors.New("conflicting fake native option fixtures")
	}
	raw := []byte(inline)
	if path != "" {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("fake native option fixture is not a regular file")
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, errors.New("fake native option fixture unavailable")
		}
		raw, err = io.ReadAll(io.LimitReader(f, maxFakeInteractionOptionsBytes+1))
		f.Close()
		if err != nil {
			return nil, errors.New("fake native option fixture unreadable")
		}
	}
	if len(raw) > maxFakeInteractionOptionsBytes {
		return nil, errors.New("fake native option fixture exceeds bound")
	}
	var options []domain.RuntimeInteractionOption
	if json.Unmarshal(raw, &options) != nil || !domain.ValidRuntimeInteractionOptions(options) {
		return nil, errors.New("invalid fake native permission options")
	}
	return options, nil
}
