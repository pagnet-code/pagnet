// Package inbox provides a private, encrypted, bounded durable message inbox.
// Callers may acknowledge a delivery only after Put returns nil. Records are
// immutable and are never evicted; reaching a bound leaves delivery retryable.
package inbox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

var (
	ErrConflict = errors.New("inbox: duplicate has different contents")
	ErrFull     = errors.New("inbox: capacity exceeded")
	ErrCorrupt  = errors.New("inbox: corrupt state")
	ErrPrivate  = errors.New("inbox: state must be private and owned by the current user")
	ErrLocked   = errors.New("inbox: already owned by another process")
	ErrClosed   = errors.New("inbox: closed or failed; reopen required")
)

type Key struct {
	NetworkID   string `json:"networkId"`
	PrincipalID string `json:"principalId"`
	MessageID   string `json:"messageId"`
}

// Limits are fixed for the lifetime of a Store. Zero selects the default.
// TotalBytes counts plaintext payload bytes, including all retained records.
type Limits struct {
	MaxRecords      int
	MaxPayloadBytes int
	MaxTotalBytes   int64
}

type diskRecord struct {
	Key    Key    `json:"key"`
	Sealed []byte `json:"sealed"`
}

type Store struct {
	mu     sync.Mutex
	dir    *os.File
	lock   *os.File
	aead   cipher.AEAD
	limits Limits
	keys   map[Key]string
	total  int64
	failed bool
}

func normalizeLimits(l Limits) (Limits, error) {
	if l.MaxRecords == 0 {
		l.MaxRecords = 1024
	}
	if l.MaxPayloadBytes == 0 {
		l.MaxPayloadBytes = 1 << 20
	}
	if l.MaxTotalBytes == 0 {
		l.MaxTotalBytes = 64 << 20
	}
	if l.MaxRecords < 1 || l.MaxRecords > 100000 || l.MaxPayloadBytes < 1 || l.MaxPayloadBytes > 16<<20 || l.MaxTotalBytes < 1 || l.MaxTotalBytes > 1<<30 {
		return l, errors.New("inbox: invalid limits")
	}
	return l, nil
}

// Open acquires exclusive ownership until Close. The random local encryption
// key is created once and synced before records can be committed. It is never
// regenerated for an inbox containing records.
func Open(path string, limits Limits) (_ *Store, err error) {
	limits, err = normalizeLimits(limits)
	if err != nil {
		return nil, err
	}
	dir, err := openDirectory(path)
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, limits: limits, keys: make(map[Key]string)}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	s.lock, err = acquireLock(dir)
	if err != nil {
		return nil, err
	}
	names, err := directoryNames(dir)
	if err != nil {
		return nil, err
	}
	hasRecords := false
	for _, name := range names {
		if strings.HasSuffix(name, ".record") {
			hasRecords = true
		}
	}
	secret, err := readPrivate(dir, "key", 32)
	if errors.Is(err, os.ErrNotExist) {
		if hasRecords {
			return nil, ErrCorrupt
		}
		secret = make([]byte, 32)
		if _, err = rand.Read(secret); err != nil {
			return nil, err
		}
		err = writeAtomic(dir, "key", secret)
	}
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	if len(secret) != 32 {
		return nil, ErrCorrupt
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	s.aead, err = cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		switch {
		case name == "key" || name == "lock":
		case strings.HasPrefix(name, ".tmp-"):
			// Only uncommitted temporary files can be removed after a crash.
			if err = removeTemporary(dir, name); err != nil {
				return nil, err
			}
		case strings.HasSuffix(name, ".record"):
			var key Key
			var payload []byte
			key, payload, err = s.read(name)
			if err != nil {
				return nil, err
			}
			if _, exists := s.keys[key]; exists {
				clear(payload)
				return nil, ErrCorrupt
			}
			s.keys[key] = name
			s.total += int64(len(payload))
			clear(payload)
			if len(s.keys) > limits.MaxRecords || s.total > limits.MaxTotalBytes {
				return nil, ErrFull
			}
		default:
			return nil, ErrCorrupt
		}
	}
	if err = dir.Sync(); err != nil {
		return nil, err
	}
	return s, nil
}

func keyData(key Key) ([]byte, error) {
	for _, v := range []string{key.NetworkID, key.PrincipalID, key.MessageID} {
		if v == "" || len(v) > 1024 || !utf8.ValidString(v) || strings.ContainsRune(v, '\x00') {
			return nil, errors.New("inbox: invalid key")
		}
	}
	return json.Marshal(key)
}
func recordName(aad []byte) string {
	sum := sha256.Sum256(aad)
	return hex.EncodeToString(sum[:]) + ".record"
}
func (s *Store) read(name string) (Key, []byte, error) {
	raw, err := readPrivate(s.dir, name, int64(s.limits.MaxPayloadBytes)*2+16384)
	if err != nil {
		return Key{}, nil, err
	}
	var r diskRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return Key{}, nil, ErrCorrupt
	}
	aad, err := keyData(r.Key)
	if err != nil || recordName(aad) != name || len(r.Sealed) < s.aead.NonceSize()+s.aead.Overhead() {
		return Key{}, nil, ErrCorrupt
	}
	plain, err := s.aead.Open(nil, r.Sealed[:s.aead.NonceSize()], r.Sealed[s.aead.NonceSize():], aad)
	if err != nil {
		return Key{}, nil, ErrCorrupt
	}
	if len(plain) > s.limits.MaxPayloadBytes {
		clear(plain)
		return Key{}, nil, ErrFull
	}
	return r.Key, plain, nil
}

// Put durably inserts payload. An identical duplicate succeeds with created=false;
// changing any byte returns ErrConflict. No capacity failure evicts a record.
func (s *Store) Put(key Key, payload []byte) (created bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == nil || s.failed {
		return false, ErrClosed
	}
	aad, err := keyData(key)
	if err != nil {
		return false, err
	}
	if len(payload) > s.limits.MaxPayloadBytes {
		return false, ErrFull
	}
	if name, ok := s.keys[key]; ok {
		_, old, err := s.read(name)
		if err != nil {
			s.failed = true
			return false, err
		}
		defer clear(old)
		if !bytes.Equal(old, payload) {
			return false, ErrConflict
		}
		return false, nil
	}
	if len(s.keys) >= s.limits.MaxRecords || int64(len(payload)) > s.limits.MaxTotalBytes-s.total {
		return false, ErrFull
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return false, err
	}
	sealed := s.aead.Seal(nonce, nonce, payload, aad)
	raw, err := json.Marshal(diskRecord{Key: key, Sealed: sealed})
	if err != nil {
		return false, err
	}
	name := recordName(aad)
	if err := writeAtomic(s.dir, name, raw); err != nil {
		// Rename may have succeeded before a sync error. Reopen before retrying.
		s.failed = true
		return false, err
	}
	s.keys[key] = name
	s.total += int64(len(payload))
	return true, nil
}

func (s *Store) Get(key Key) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == nil || s.failed {
		return nil, ErrClosed
	}
	name, ok := s.keys[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	_, payload, err := s.read(name)
	if err != nil {
		s.failed = true
	}
	return payload, err
}

func (s *Store) List() ([]Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == nil || s.failed {
		return nil, ErrClosed
	}
	keys := make([]Key, 0, len(s.keys))
	for key := range s.keys {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, _ := keyData(keys[i])
		b, _ := keyData(keys[j])
		return bytes.Compare(a, b) < 0
	})
	return keys, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	if s.lock != nil {
		errs = append(errs, s.lock.Close())
		s.lock = nil
	}
	if s.dir != nil {
		errs = append(errs, s.dir.Close())
		s.dir = nil
	}
	s.aead = nil
	return errors.Join(errs...)
}

func directoryNames(dir *os.File) ([]string, error) {
	if _, err := dir.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("inbox: list state: %w", err)
	}
	sort.Strings(names)
	return names, nil
}
