// Package externalprofile stores independent MCP credentials only on their host.
package externalprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/externalbridge"
	"github.com/pagnet-code/pagnet/sdk"
)

type Profile struct {
	Version          int      `json:"version"`
	Principal        string   `json:"principal"`
	Network          string   `json:"network"`
	Server           string   `json:"server"`
	Credential       string   `json:"credential"`
	Grants           []string `json:"grants,omitempty"`
	MessagingTargets []string `json:"messagingTargets,omitempty"`
}

func (p Profile) Validate() error {
	if p.Version != 1 {
		return errors.New("invalid external bridge profile version")
	}
	if _, err := domain.ParseID(p.Principal); err != nil {
		return errors.New("invalid external bridge principal")
	}
	if !strings.HasPrefix(p.Credential, "pgn_act_v1_") && !strings.HasPrefix(p.Credential, "pgn_epd_v1_") {
		return errors.New("external bridge requires a principal activation or endpoint credential")
	}
	if strings.ContainsAny(p.Credential, "\r\n\x00 \t") {
		return errors.New("invalid external principal credential encoding")
	}
	if len(p.Credential) > 4096 || len(p.Grants) > 64 || len(p.MessagingTargets) > 64 {
		return errors.New("external bridge profile exceeds bounds")
	}
	u, err := url.Parse(p.Server)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("external profile server must not contain credentials or query parameters")
	}
	if err := (sdk.Config{Server: p.Server, Credential: p.Credential}).Validate(); err != nil {
		return errors.New("invalid external bridge server configuration")
	}
	if _, err := externalbridge.New(nil, externalbridge.Config{Network: p.Network, Grants: p.Grants, MessagingTargets: p.MessagingTargets}); err != nil {
		return errors.New("invalid external bridge network or grants")
	}
	return nil
}
func Path(state, name string) (string, error) {
	if !domain.ValidRuntimeProfileName(name) {
		return "", errors.New("profile name must be a lowercase identifier")
	}
	return filepath.Join(state, "external-profiles", name+".json"), nil
}
func Load(path string) (Profile, error) {
	var p Profile
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return p, errors.New("external profile must be a private regular file")
	}
	if err := owner(before); err != nil {
		return p, err
	}
	f, err := os.Open(path)
	if err != nil {
		return p, errors.New("cannot read external profile")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return p, errors.New("external profile changed during read")
	}
	if err := owner(after); err != nil {
		return p, err
	}
	data, err := io.ReadAll(io.LimitReader(f, 32769))
	if err != nil || len(data) > 32768 {
		return p, errors.New("invalid external profile size")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&p) != nil || dec.Decode(new(any)) != io.EOF {
		return p, errors.New("invalid external profile")
	}
	return p, p.Validate()
}
func SaveNew(path string, p Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("cannot create external profile directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe external profile directory")
	}
	if err := owner(info); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return errors.New("cannot open external profile directory")
	}
	defer root.Close()
	f, err := root.OpenFile(filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("external profile already exists or cannot be created")
	}
	created := false
	defer func() {
		f.Close()
		if !created {
			root.Remove(filepath.Base(path))
		}
	}()
	info, err = f.Stat()
	if err != nil {
		return err
	}
	if err := owner(info); err != nil {
		return err
	}
	if err := json.NewEncoder(f).Encode(p); err != nil {
		return errors.New("cannot write external profile")
	}
	if err := f.Sync(); err != nil {
		return errors.New("cannot persist external profile")
	}
	if err := f.Close(); err != nil {
		return err
	}
	created = true
	return nil
}

func ReadSecret(path string) (string, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return "", errors.New("runtime token must be a private regular file")
	}
	if err := owner(before); err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("runtime token unavailable")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return "", errors.New("runtime token changed during read")
	}
	if err := owner(after); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return "", errors.New("runtime token exceeds bounds")
	}
	return strings.TrimSpace(string(data)), nil
}

// SaveBinding uses the same owner-only storage policy without interpreting
// provider-specific fields. Existing entries are never silently overwritten.
func SaveBinding(path string, v any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe connection directory")
	}
	if err := owner(info); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.OpenFile(filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("connection record already exists or cannot be created")
	}
	good := false
	defer func() {
		f.Close()
		if !good {
			root.Remove(filepath.Base(path))
		}
	}()
	info, err = f.Stat()
	if err != nil {
		return err
	}
	if err := owner(info); err != nil {
		return err
	}
	if err := json.NewEncoder(f).Encode(v); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	good = true
	return nil
}
func LoadBinding(path string, v any) error {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return errors.New("invalid private connection record")
	}
	if err := owner(before); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return errors.New("cannot read connection record")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return errors.New("connection record changed during read")
	}
	if err := owner(after); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(f, 32769))
	if err != nil || len(data) > 32768 {
		return errors.New("invalid connection record")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil || dec.Decode(new(any)) != io.EOF {
		return errors.New("invalid connection record")
	}
	return nil
}
