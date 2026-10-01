package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type serviceRunnerProfile struct {
	Service    string `json:"service"`
	Server     string `json:"server"`
	Credential string `json:"credential"`
	Model      string `json:"model"`
	Adapter    string `json:"adapter"`
}

func loadServiceRunnerProfile(path, service string) (serviceRunnerProfile, error) {
	var saved serviceRunnerProfile
	f, err := os.Open(path)
	if err != nil {
		return saved, errors.New("no valid local service setup; use the one-time command from Services")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return saved, errors.New("local service profile must be a regular file")
	}
	// Unix ownership is meaningful; other platforms use the SDK state directory's
	// account access controls, just as the durable endpoint keyring does.
	if err := validateServiceProfileOwner(info); err != nil {
		return saved, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return saved, errors.New("invalid local service profile")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&saved) != nil || decoder.Decode(new(any)) != io.EOF || saved.Service != service {
		return saved, errors.New("invalid local service profile")
	}
	return saved, nil
}

func saveServiceRunnerProfile(path string, v serviceRunnerProfile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".jev-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		err = json.NewEncoder(f).Encode(v)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
