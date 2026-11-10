package daemon

import "github.com/pagnet-code/pagnet/transport"

func marshalNativeWorkerRecord(value any) ([]byte, error) {
	var contracts any
	switch v := value.(type) {
	case *NativeWorkerRecord:
		if v != nil {
			return marshalNativeWorkerRecord(*v)
		}
	case NativeWorkerRecord:
		contracts = v.Ownership
	case nativeWorkerGC:
		sources, aads, err := transport.NativeAccountJSONContracts(v.Ownership)
		if err != nil {
			return nil, err
		}
		deletionSources, deletionAADs, err := transport.NativeAccountJSONContracts(v.DeletionProof)
		if err != nil {
			return nil, err
		}
		return transport.MarshalNativeAccountJSON(value, append(sources, deletionSources...), append(aads, deletionAADs...))
	default:
		contracts = value
	}
	sources, aads, err := transport.NativeAccountJSONContracts(contracts)
	if err != nil {
		return nil, err
	}
	return transport.MarshalNativeAccountJSON(value, sources, aads)
}
