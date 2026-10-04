package registry

import (
	"github.com/pagnet-code/pagnet/fabric/search"
	"strconv"
)

const OutboxReplayFormat = "registry.outbox-sequence.v1"

// OutboxReplayOrder explicitly enables bounded historical-hash compaction only
// for this authenticated monotonic registry source. Opaque revisions are never
// compared as clocks. Publish still requires the authoritative CommitIndex.
func OutboxReplayOrder() *search.ReplayOrder {
	return &search.ReplayOrder{Format: OutboxReplayFormat, Sequence: func(cursor string) (uint64, error) {
		n, e := strconv.ParseUint(cursor, 10, 63)
		if e != nil || n == 0 || strconv.FormatUint(n, 10) != cursor {
			return 0, invalid("invalid monotonic registry outbox cursor")
		}
		return n, nil
	}}
}
func (s *Store) IndexConfig() search.Config {
	return search.Config{Commit: s.CommitIndex, ReplayOrder: OutboxReplayOrder()}
}
func validSourceOrder(format string, sequence, watermark, floor uint64) bool {
	if format == "" {
		return sequence == 0 && floor == 0
	}
	return format == OutboxReplayFormat && sequence == watermark && floor <= sequence
}
