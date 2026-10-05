package fabricservices

import (
	"reflect"
	"unicode/utf8"
)

// Bound structured private operator input BEFORE JSON serialization allocates.
// The official SDK card has typed nested fields and extension maps. A finite
// visited-node/depth budget also rejects cycles and unsupported custom values.
func boundedValue(v any, maxBytes, maxNodes int) bool {
	bytes, nodes := 0, 0
	var visit func(reflect.Value, int) bool
	visit = func(v reflect.Value, depth int) bool {
		nodes++
		if nodes > maxNodes || depth > 32 {
			return false
		}
		if !v.IsValid() {
			return true
		}
		switch v.Kind() {
		case reflect.Interface, reflect.Pointer:
			if v.IsNil() {
				return true
			}
			return visit(v.Elem(), depth+1)
		case reflect.String:
			bytes += v.Len()
			return bytes <= maxBytes && utf8.ValidString(v.String())
		case reflect.Slice, reflect.Array:
			if v.Type().Elem().Kind() == reflect.Uint8 {
				bytes += v.Len()
				return bytes <= maxBytes
			}
			if v.Len() > maxNodes {
				return false
			}
			for n := 0; n < v.Len(); n++ {
				if !visit(v.Index(n), depth+1) {
					return false
				}
			}
		case reflect.Map:
			if v.Len() > maxNodes {
				return false
			}
			it := v.MapRange()
			for it.Next() {
				if !visit(it.Key(), depth+1) || !visit(it.Value(), depth+1) {
					return false
				}
			}
		case reflect.Struct:
			for n := 0; n < v.NumField(); n++ {
				if v.Type().Field(n).PkgPath == "" && !visit(v.Field(n), depth+1) {
					return false
				}
			}
		case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
			bytes += 8
		default:
			return false
		}
		return bytes <= maxBytes
	}
	return visit(reflect.ValueOf(v), 0)
}
