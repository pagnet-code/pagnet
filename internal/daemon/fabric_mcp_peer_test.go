//go:build linux || darwin

package daemon

import (
	"path/filepath"
	"testing"
	"time"
)

// Real socket authentication reaches the per-instance reservation before the
// kernel rejects the unrelated process. Repeated refusal must return every
// reserved slot rather than permanently exhausting a live agent's allowance.
func TestBridgeRejectedKernelPeerReleasesInstanceReservation(t *testing.T) {
	d, _ := newBridgeE2EDaemon(t)
	instance := launchFakeEndpoint(t, d, "worker")
	row, ok, err := d.state.GetInstance(instance)
	if err != nil || !ok {
		t.Fatal(err)
	}
	nonce := d.currentBridgeNonce(instance)
	if nonce == "" {
		t.Fatal("genuine activation nonce missing")
	}
	for i := 0; i < bridgeMaxConnsPerInst+1; i++ {
		client := bridgeDial(t, filepath.Join(d.StateDir, bridgeSocketName))
		response := client.authFull(t, instance, row.NetworkID, nonce, "worker")
		assertBridgeError(t, response, "peer process verification failed")
		client.conn.Close()
		deadline := time.Now().Add(time.Second)
		for {
			d.bridgeConnMu.Lock()
			count := d.bridgeConnsInst[instance]
			d.bridgeConnMu.Unlock()
			if count == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("kernel rejection leaked per-instance connection reservation")
			}
			time.Sleep(time.Millisecond)
		}
	}
}
