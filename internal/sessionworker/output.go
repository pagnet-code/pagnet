package sessionworker

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/google/uuid"
)

const maxOutputBytes = 2 << 20
const maxOutputRecord = maxFrame * 3 / 4
const maxOutputRecords = 8192

type OutputRecord struct {
	Sequence         int64           `json:"sequence"`
	NativeGeneration string          `json:"nativeGeneration"`
	Origin           json.RawMessage `json:"origin,omitempty"`
	Kind             string          `json:"kind"`
	Data             json.RawMessage `json:"data"`
}
type OutputPage struct {
	ReplayGeneration string         `json:"replayGeneration"`
	Records          []OutputRecord `json:"records"`
	RetiredThrough   int64          `json:"retiredThrough"`
	NextSequence     int64          `json:"nextSequence"`
	Gap              bool           `json:"gap"`
}

// OutputReplay is worker-owned, bounded memory. Controller replacement does not
// replace the worker or this replay. Worker replacement gets a different replay
// generation and explicitly reports a gap; raw terminal echo never needs fsync.
type OutputReplay struct {
	mu                 sync.Mutex
	generation         string
	records            [maxOutputRecords]OutputRecord
	head, count, total int
	next, retired      int64
}

func NewOutputReplay() *OutputReplay { return &OutputReplay{generation: uuid.NewString(), next: 1} }
func validOutput(generation string, origin json.RawMessage, kind string, data json.RawMessage) bool {
	size := len(origin) + len(data) + len(generation) + len(kind)
	if generation == "" || len(generation) > 256 || len(origin) > 8192 || (len(origin) > 0 && !json.Valid(origin)) || (kind != "terminal" && kind != "session") || size > maxOutputRecord || !json.Valid(data) {
		return false
	}
	// Account for actual JSON metadata and worst-case sequence width. A record
	// admitted here must always fit one bounded replay page, not remain hidden
	// forever because raw field lengths omitted serialization overhead.
	encoded, err := json.Marshal(OutputRecord{Sequence: 9223372036854775806, NativeGeneration: generation, Origin: origin, Kind: kind, Data: data})
	return err == nil && len(encoded) <= maxFrame*3/4

}
func outputSize(record OutputRecord) int {
	return len(record.Origin) + len(record.Data) + len(record.NativeGeneration) + len(record.Kind)
}
func (r *OutputReplay) Append(generation string, origin json.RawMessage, kind string, data json.RawMessage) (int64, error) {
	if !validOutput(generation, origin, kind, data) {
		return 0, errors.New("invalid or oversized worker output")
	}
	record := OutputRecord{NativeGeneration: generation, Origin: append(json.RawMessage(nil), origin...), Kind: kind, Data: append(json.RawMessage(nil), data...)}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.next == 9223372036854775807 {
		return 0, errors.New("worker output sequence exhausted")
	}
	size := outputSize(record)
	for r.count > 0 && (r.count == maxOutputRecords || r.total+size > maxOutputBytes) {
		old := r.records[r.head]
		r.total -= outputSize(old)
		r.retired = old.Sequence
		r.records[r.head] = OutputRecord{}
		r.head = (r.head + 1) % maxOutputRecords
		r.count--
	}
	record.Sequence = r.next
	r.next++
	r.records[(r.head+r.count)%maxOutputRecords] = record
	r.count++
	r.total += size
	return record.Sequence, nil
}
func (r *OutputReplay) Replay(expectedGeneration string, after int64, limit int) (OutputPage, error) {
	if after < 0 || limit < 1 || limit > 64 {
		return OutputPage{}, errors.New("invalid replay cursor or bound")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	page := OutputPage{ReplayGeneration: r.generation, NextSequence: r.next, RetiredThrough: r.retired}
	if expectedGeneration != "" && expectedGeneration != r.generation {
		page.Gap = true
		after = 0
	}
	if after < r.retired || after >= r.next {
		page.Gap = true
		if after >= r.next {
			after = 0
		}
	}
	bytes := 0
	for i := 0; i < r.count && len(page.Records) < limit; i++ {
		record := r.records[(r.head+i)%maxOutputRecords]
		if record.Sequence <= after {
			continue
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return page, err
		}
		if bytes+len(encoded) > maxFrame*3/4 {
			break
		}
		bytes += len(encoded)
		record.Origin = append(json.RawMessage(nil), record.Origin...)
		record.Data = append(json.RawMessage(nil), record.Data...)
		page.Records = append(page.Records, record)
	}
	return page, nil
}
func (o *SessionOwner) outputReplay() *OutputReplay {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.output == nil {
		o.output = NewOutputReplay()
	}
	return o.output
}
