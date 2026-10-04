package federation

import (
	"context"
	"sync"
	"time"
)

// RelayLimits apply to the combined two directions. The caller explicitly owns
// and selects both connections/routes; no semantic discovery or fallback occurs.
type RelayLimits struct {
	MaxPackets uint64
	MaxBytes   uint64
	Lifetime   time.Duration
}

func (l RelayLimits) valid() bool {
	return l.MaxPackets > 0 && l.MaxPackets <= 2*MaxChannelRecords && l.MaxBytes > 0 && l.MaxBytes <= 256<<20 && l.Lifetime > 0 && l.Lifetime <= 10*time.Minute
}

// RelayOpaque forwards closed-profile ciphertext only, synchronously. It never
// has keys, a private caller, references, queries, descriptors or application
// credentials. The opaque routing/traffic volume/timing are NOT concealed.
// On either direction ending, it closes both owned streams and joins its loops.
// No stored packet is retried or reconstructed after uncertain transport loss.
func RelayOpaque(ctx context.Context, source, destination PacketStream, channel ChannelBinding, limits RelayLimits) error {
	if ctx == nil || source == nil || destination == nil || !limits.valid() || channel.ID == ([32]byte{}) || channel.SourceRoute == ([32]byte{}) || channel.DestinationRoute == ([32]byte{}) || channel.SourceRoute == channel.DestinationRoute {
		return protocolError()
	}
	run, cancel := context.WithTimeout(ctx, limits.Lifetime)
	defer cancel()
	var mu sync.Mutex
	var packets, bytes uint64
	reserve := func(p Packet) error {
		raw, e := EncodePacket(p)
		if e != nil {
			return e
		}
		n := uint64(len(raw))
		clear(raw)
		mu.Lock()
		defer mu.Unlock()
		if packets >= limits.MaxPackets || n > limits.MaxBytes-bytes {
			return protocolError()
		}
		packets++
		bytes += n
		return nil
	}
	results := make(chan error, 2)
	forward := func(in, out PacketStream, direction uint8, route [32]byte) {
		var ordinal uint64
		for {
			p, e := in.Read(run)
			if e != nil {
				results <- e
				return
			}
			if p.Channel != channel.ID || p.Route != route || p.Direction != direction || p.Ordinal != ordinal {
				results <- protocolError()
				return
			}
			if e = reserve(p); e != nil {
				results <- e
				return
			}
			if e = out.Write(run, p); e != nil {
				results <- e
				return
			}
			ordinal++
		}
	}
	go forward(source, destination, 1, channel.DestinationRoute)
	go forward(destination, source, 2, channel.SourceRoute)
	first := <-results
	cancel()
	_ = source.Close()
	_ = destination.Close()
	<-results
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return first
}
