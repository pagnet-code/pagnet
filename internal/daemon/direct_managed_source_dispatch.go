package daemon

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"strings"

	"github.com/pagnet-code/pagnet/transport"
)

var directManagedSourceQueryKeys = [3]string{"direct_managed_source_prepare", "direct_managed_source_pop", "direct_managed_source_credential"}
var directManagedSourceProtocolsV2 = [3]string{transport.DirectManagedSourcePrepareProtocolV2, transport.DirectManagedSourcePoPProtocolV2, transport.DirectManagedSourceCredentialProtocolV2}
var directManagedSourceProtocolsV1 = [3]string{transport.DirectManagedSourcePrepareProtocol, transport.DirectManagedSourcePoPProtocol, transport.DirectManagedSourceCredentialProtocol}

func (c *NativeObservationConnection) captureDirectManagedSourceOffers(q url.Values) {
	c.offeredDirectManagedSourceV2 = [3]string{}
	c.offeredDirectManagedSourceCredential = ""
	for i, key := range directManagedSourceQueryKeys {
		values := q[key]
		if len(values) == 1 && values[0] == directManagedSourceProtocolsV2[i] {
			c.offeredDirectManagedSourceV2[i] = values[0]
		}
	}
	c.offeredDirectManagedSourcePrepare = len(q[directManagedSourceQueryKeys[0]]) == 1 && q.Get(directManagedSourceQueryKeys[0]) == directManagedSourceProtocolsV1[0]
	c.offeredDirectManagedSourcePoP = len(q[directManagedSourceQueryKeys[1]]) == 1 && q.Get(directManagedSourceQueryKeys[1]) == directManagedSourceProtocolsV1[1]
	if len(q[directManagedSourceQueryKeys[2]]) == 1 && q.Get(directManagedSourceQueryKeys[2]) == directManagedSourceProtocolsV1[2] {
		c.offeredDirectManagedSourceCredential = directManagedSourceProtocolsV1[2]
	}
}

func (c *NativeObservationConnection) validDirectManagedSourceSelection(features []string) bool {
	var v1, v2 [3]int
	for _, feature := range features {
		recognized := false
		for i := range v2 {
			if feature == directManagedSourceProtocolsV1[i] {
				v1[i]++
				recognized = true
			}
			if feature == directManagedSourceProtocolsV2[i] {
				v2[i]++
				recognized = true
			}
		}
		if strings.HasPrefix(feature, "direct_managed_source_") && !recognized {
			return false
		}
	}
	anyV2 := v2 != [3]int{}
	for i := range v2 {
		if v1[i] > 1 || v2[i] > 1 {
			return false
		}
		if anyV2 && (v1[i] != 0 || v2[i] != 1 || c.offeredDirectManagedSourceV2[i] != directManagedSourceProtocolsV2[i]) {
			return false
		}
	}
	if v1[2] == 1 && (c.offeredDirectManagedSourceCredential != directManagedSourceProtocolsV1[2] || v1[0] != 1 || v1[1] != 1) {
		return false
	}
	return true
}

type directManagedSourceDispatch struct {
	v1      []func(transport.Envelope) bool
	v2      []func(transport.Envelope) bool
	closeV2 func()
}

func (d *directManagedSourceDispatch) close() {
	if d.closeV2 != nil {
		d.closeV2()
	}
}

// Reserved messages are always consumed, including malformed and unnegotiated
// payloads. Read protocolVersion before invoking any version-specific decoder.
func (d *directManagedSourceDispatch) handle(env transport.Envelope) bool {
	index := -1
	for i, typ := range []string{transport.MsgDirectManagedSourcePrepare, transport.MsgDirectManagedSourcePoP, transport.MsgDirectManagedSourceCredential} {
		if env.Type == typ {
			index = i
		}
	}
	if index < 0 {
		return false
	}
	version, ok := directManagedSourceProtocolVersion(env.Payload)
	if !ok {
		return true
	}
	var handlers []func(transport.Envelope) bool
	switch version {
	case directManagedSourceProtocolsV1[index]:
		handlers = d.v1
	case directManagedSourceProtocolsV2[index]:
		handlers = d.v2
	default:
		return true
	}
	if len(handlers) == 3 && handlers[index] != nil {
		handlers[index](env)
	}
	return true
}

func directManagedSourceProtocolVersion(raw []byte) (string, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return "", false
	}
	version, count := "", 0
	for decoder.More() {
		keyStart := decoder.InputOffset()
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return "", false
		}
		keyEnd := decoder.InputOffset()
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return "", false
		}
		if strings.EqualFold(key, "protocolVersion") {
			keyRaw := bytes.TrimSpace(raw[keyStart:keyEnd])
			keyRaw = bytes.TrimSpace(bytes.TrimPrefix(keyRaw, []byte(",")))
			if !bytes.Equal(keyRaw, []byte(`"protocolVersion"`)) {
				return "", false
			}
			if key != "protocolVersion" || json.Unmarshal(value, &version) != nil {
				return "", false
			}
			canonical, _ := json.Marshal(version)
			if !bytes.Equal(value, canonical) {
				return "", false
			}
			count++
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return "", false
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		return "", false
	}
	return version, count == 1
}
