// Package durable provides encrypted, bounded, at-least-once CloudEvent delivery.
// Durable receipts and volatile node ingress are deliberately separate boundaries.
package durable

import (
	"context"
	"time"

	"github.com/cloudevents/sdk-go/v2/event"
)

type Scope struct {
	Audience string `json:"audience"`
	Domain   string `json:"domain"`
}
type KeyReference struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// DataProtector uses operator-supplied stable keys. Returned slices are owned by
// the caller. Implementations must authenticate the entire AAD, not log inputs,
// and enforce their own finite output bounds. Keys never belong in event metadata.
type DataProtector interface {
	Reference() KeyReference
	Seal(aad, plaintext []byte) ([]byte, error)
	Open(aad, ciphertext []byte) ([]byte, error)
}
type Subscription struct {
	ID    string   `json:"id"`
	Types []string `json:"types"`
}
type Config struct {
	Subscriptions             []Subscription `json:"subscriptions"`
	MaxSubscriptions          int            `json:"maxSubscriptions"`
	MaxFanout                 int            `json:"maxFanout"`
	MaxRows                   int64          `json:"maxRows"`
	MaxBytes                  int64          `json:"maxBytes"`
	MaxDatabaseBytes          int64          `json:"maxDatabaseBytes"`
	MaxEventBytes             int            `json:"maxEventBytes"`
	MaxCipherBytes            int            `json:"maxCipherBytes"`
	MaxPendingPerSubscription int64          `json:"maxPendingPerSubscription"`
	MaxAttempts               int            `json:"maxAttempts"`
	LeaseTTL                  time.Duration  `json:"leaseTTL"`
	RetryDelay                time.Duration  `json:"retryDelay"`
	DeliveryTTL               time.Duration  `json:"deliveryTTL"`
	DedupTTL                  time.Duration  `json:"dedupTTL"`
}

func DefaultConfig(subs []Subscription) Config {
	return Config{Subscriptions: subs, MaxSubscriptions: 128, MaxFanout: 128, MaxRows: 65536, MaxBytes: 64 << 20, MaxDatabaseBytes: 128 << 20, MaxEventBytes: 1 << 20, MaxCipherBytes: (1 << 20) + 4096, MaxPendingPerSubscription: 4096, MaxAttempts: 8, LeaseTTL: 30 * time.Second, RetryDelay: time.Second, DeliveryTTL: 24 * time.Hour, DedupTTL: 7 * 24 * time.Hour}
}

type Receipt struct {
	Source      string    `json:"source"`
	ID          string    `json:"id"`
	Digest      string    `json:"digest"`
	CommittedAt time.Time `json:"committedAt"`
	Duplicate   bool      `json:"duplicate"`
}
type Claim struct {
	Subscription string
	Source       string
	ID           string
	Worker       string
	Generation   int64
	Token        string
}
type Delivery struct {
	Claim      Claim
	Event      event.Event
	Digest     string
	Attempt    int
	LeaseUntil time.Time
}
type State struct {
	Pending, Claimed, Acknowledged, Failed int64
	Rows, Bytes                            int64
}

// Store API uses FULL commits. A failed commit may be ambiguous; retry Publish
// with the exact (source,id,bytes), never mint a new ID to hide uncertainty.
type Publisher interface {
	Publish(context.Context, event.Event) (Receipt, error)
}
type Handler func(context.Context, event.Event) error
