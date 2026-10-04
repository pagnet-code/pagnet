package sessionworker

import (
	"path/filepath"
	"reflect"
	"strings"

	"github.com/pagnet-code/pagnet/e2ee"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
)

// Keys are held only by the original producer. Reconnect delivery uses the
// already committed ciphertext, never a key loaded under a new admission.
type nativeTaskContentPin struct {
	descriptor string
	key        [32]byte
	available  bool
}

func taskPinID(source NativeTurnSource) string {
	return source.NativeGeneration + "\x00" + source.LogicalTurnID
}
func (o *SessionOwner) pinOriginalTaskContent(source NativeTurnSource) {
	if source.SourceTask == nil && source.SourceInvocation == nil {
		return
	}
	id := taskPinID(source)
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.taskContentPins == nil {
		o.taskContentPins = map[string]nativeTaskContentPin{}
	}
	if _, exists := o.taskContentPins[id]; exists {
		return
	}
	pin := nativeTaskContentPin{descriptor: sourceContentDescriptor(&source)}
	aad, valid := sourceContentAAD(&source)
	// Key pinning is object-scoped. Input classification is separately fenced
	// by dispatch/BindNativeTurn before a native request can consume this pin.
	if source.SourceTask != nil && source.SourceInvocation == nil {
		aad, valid = source.SourceTask.InputAAD, true
	}
	if !valid {
		o.taskContentPins[id] = pin
		return
	}
	// Failure is retained as an unavailable source capability: a later epoch
	// must never silently substitute for the original accepted descriptor.
	pin.key, pin.available = loadOriginalTaskKey(o.spec, aad)
	o.taskContentPins[id] = pin
}
func loadOriginalTaskKey(spec NativeSpec, aad e2ee.AAD) ([32]byte, bool) {
	if (aad.ObjectType != e2ee.ObjectTypeTask && aad.ObjectType != e2ee.ObjectTypeInvocationInput) || aad.ObjectID == "" || aad.KeyEpochID == "" || aad.NativeContent != nil || aad.ValidateScope() != nil {
		return [32]byte{}, false
	}
	var epoch hostcrypto.KeyEpoch
	if aad.ProtectedContext != nil {
		if !reflect.DeepEqual(spec.ProtectedContext, aad.ProtectedContext) || !filepath.IsAbs(spec.ContextStateDir) {
			return [32]byte{}, false
		}
		ring, err := hostcrypto.LoadContextKeyring(spec.ContextStateDir, *aad.ProtectedContext)
		if err != nil {
			return [32]byte{}, false
		}
		var found bool
		epoch, found = ring.EpochByID(aad.KeyEpochID)
		if !found {
			return [32]byte{}, false
		}
	} else {
		if aad.TenantID != spec.NetworkTenantID || aad.NetworkID != spec.NetworkID || !filepath.IsAbs(spec.NetworkStateDir) {
			return [32]byte{}, false
		}
		ring, err := hostcrypto.LoadKeyring(spec.NetworkStateDir, aad.NetworkID)
		if err != nil {
			return [32]byte{}, false
		}
		var found bool
		epoch, found = ring.EpochByID(aad.KeyEpochID)
		if !found || epoch.State == hostcrypto.EpochRevoked {
			return [32]byte{}, false
		}
	}
	key, err := epoch.KeyArray()
	return key, err == nil
}
func (o *SessionOwner) originalTaskContentPin(source *NativeTurnSource) ([32]byte, bool) {
	if source == nil || (source.SourceTask == nil && source.SourceInvocation == nil) {
		return [32]byte{}, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	pin, exists := o.taskContentPins[taskPinID(*source)]
	return pin.key, exists && pin.available && pin.descriptor == sourceContentDescriptor(source)
}
func (o *SessionOwner) releaseNativeTaskPins(generation string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for id, pin := range o.taskContentPins {
		if strings.HasPrefix(id, generation+"\x00") {
			clear(pin.key[:])
			o.taskContentPins[id] = pin
			delete(o.taskContentPins, id)
		}
	}
}

func (o *SessionOwner) releaseNativeTaskTurnPin(source *NativeTurnSource) {
	if source == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	id := taskPinID(*source)
	if pin, exists := o.taskContentPins[id]; exists {
		clear(pin.key[:])
		o.taskContentPins[id] = pin
		delete(o.taskContentPins, id)
	}
}
