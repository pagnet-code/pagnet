package crypto

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
)

// ContextKeyring owns customer-side epochs for an explicitly attested content
// context. It never participates in network membership or NKA enrollment.
type ContextKeyring struct {
	Context              e2ee.ProtectedContext `json:"context"`
	LastPrepareCommandID string                `json:"last_prepare_command_id,omitempty"`
	Epochs               []KeyEpoch            `json:"epochs"`
}

func (k *ContextKeyring) String() string { return "ContextKeyring{private keys omitted}" }
func (k *ContextKeyring) ActiveEpoch() (KeyEpoch, error) {
	var result *KeyEpoch
	for _, e := range k.Epochs {
		if e.State == EpochActive && (result == nil || e.CreatedAt.After(result.CreatedAt)) {
			copy := e
			result = &copy
		}
	}
	if result == nil {
		return KeyEpoch{}, errors.New("context key epoch unavailable")
	}
	result.Key = append([]byte(nil), result.Key...)
	return *result, nil
}
func (k *ContextKeyring) EpochByID(id string) (KeyEpoch, bool) {
	for _, e := range k.Epochs {
		if e.ID == id && e.State != EpochRevoked {
			e.Key = append([]byte(nil), e.Key...)
			return e, true
		}
	}
	return KeyEpoch{}, false
}
func (k *ContextKeyring) Activate(now time.Time) (KeyEpoch, error) {
	if e, err := k.ActiveEpoch(); err == nil {
		return e, nil
	}
	if len(k.Epochs) != 0 {
		return KeyEpoch{}, errors.New("protected context has no usable active epoch")
	}
	e, err := mintEpoch(now)
	if err != nil {
		return KeyEpoch{}, err
	}
	k.Epochs = append(k.Epochs, *e)
	return k.ActiveEpoch()
}
func (k *ContextKeyring) Rotate(now time.Time) (KeyEpoch, error) {
	if _, err := k.ActiveEpoch(); err != nil {
		return KeyEpoch{}, err
	}
	e, err := mintEpoch(now)
	if err != nil {
		return KeyEpoch{}, err
	}
	for i := range k.Epochs {
		if k.Epochs[i].State == EpochActive {
			k.Epochs[i].State = EpochRotated
		}
	}
	k.Epochs = append(k.Epochs, *e)
	return k.ActiveEpoch()
}
func (k *ContextKeyring) Revoke(id string) error {
	for i := range k.Epochs {
		if k.Epochs[i].ID == id {
			k.Epochs[i].State = EpochRevoked
			return nil
		}
	}
	return errors.New("context key epoch unavailable")
}
func contextKeyringPath(state string, c e2ee.ProtectedContext) (string, error) {
	if c.Validate() != nil || runtime.GOOS == "windows" {
		return "", errors.New("protected context storage unavailable")
	}
	return filepath.Join(state, "e2ee", "contexts", c.ID, "keyring.json"), nil
}
func contextPrivateDirectory(path string) error {
	// Never follow a substituted directory/symlink into an unrelated key store.
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err = os.Mkdir(path, 0700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("protected context directory is not private")
	}
	return validateContextFileOwner(info)
}
func SaveContextKeyring(state string, k *ContextKeyring) error {
	path, err := contextKeyringPath(state, k.Context)
	if err != nil {
		return err
	}
	for _, dir := range []string{filepath.Join(state, "e2ee"), filepath.Join(state, "e2ee", "contexts"), filepath.Dir(path)} {
		if err = contextPrivateDirectory(dir); err != nil {
			return err
		}
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || validateContextFileOwner(info) != nil {
			return errors.New("protected context key file is not private")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	raw, err := json.Marshal(k)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, raw)
}
func LoadContextKeyring(state string, c e2ee.ProtectedContext) (*ContextKeyring, error) {
	path, err := contextKeyringPath(state, c)
	if err != nil {
		return nil, err
	}
	for _, dir := range []string{filepath.Join(state, "e2ee"), filepath.Join(state, "e2ee", "contexts"), filepath.Dir(path)} {
		info, err := os.Lstat(dir)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode().Perm()&0077 != 0 || validateContextFileOwner(info) != nil {
			return nil, errors.New("protected context directory is not private")
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 || validateContextFileOwner(info) != nil {
		return nil, errors.New("protected context key file is not private")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var k ContextKeyring
	if json.Unmarshal(raw, &k) != nil || k.Context != c {
		return nil, errors.New("protected context key binding invalid")
	}
	seen := map[string]bool{}
	for _, e := range k.Epochs {
		if e.ID == "" || seen[e.ID] || len(e.Key) != 32 || (e.State != EpochActive && e.State != EpochRotated && e.State != EpochRevoked) {
			return nil, errors.New("protected context epochs invalid")
		}
		seen[e.ID] = true
	}
	return &k, nil
}
