package canon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"sort"
)

// jsonUnmarshal decodes JSON keeping numbers as json.Number. Plain float64
// decoding silently collapses distinct large integers (anything past 2^53)
// onto the same float — which could make two genuinely different values
// compare equal. Exactness is non-negotiable here.
//
// It also rejects trailing content after the first JSON value: a decoder that
// stops at the first value would treat `{...}{injected}` as equal to `{...}`,
// hiding whatever follows.
func jsonUnmarshal(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing content after JSON value")
	}
	return out, nil
}

// toBigFloat converts a numeric JSON value (float64 or json.Number) to an
// exact-enough big.Float for comparison. 256 bits of mantissa comfortably
// exceeds anything a cloud API round-trips.
func toBigFloat(v any) (*big.Float, bool) {
	switch t := v.(type) {
	case float64:
		return new(big.Float).SetPrec(256).SetFloat64(t), true
	case json.Number:
		f, _, err := big.ParseFloat(string(t), 10, 256, big.ToNearestEven)
		if err != nil {
			return nil, false
		}
		return f, true
	}
	return nil, false
}

// DeepEqual compares two decoded-JSON values (map[string]any, []any, string,
// json.Number/float64, bool, nil). Map key order is irrelevant by
// construction; slice order is significant. Anything of an unexpected dynamic
// type compares unequal unless identical — conservative by design.
func DeepEqual(a, b any) bool {
	if af, aok := toBigFloat(a); aok {
		bf, bok := toBigFloat(b)
		return bok && af.Cmp(bf) == 0
	}
	switch av := a.(type) {
	case nil:
		return b == nil
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !DeepEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, v := range av {
			bvv, ok := bv[k]
			if !ok || !DeepEqual(v, bvv) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// Compact renders v as compact JSON with sorted object keys (encoding/json
// sorts map keys). Used as a stable sort key and equality token.
func Compact(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// Decoded-JSON values always marshal; if not, make the token unique
		// so nothing accidentally compares equal.
		return "!unmarshalable!"
	}
	return string(b)
}

// Pretty renders v as indented JSON with sorted object keys, for --explain.
func Pretty(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "<unrenderable>"
	}
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "  "); err != nil {
		return string(b)
	}
	return out.String()
}

// sortSliceCanonical returns a copy of s sorted by each element's canonical
// JSON encoding — a deterministic order for set comparison.
func sortSliceCanonical(s []any) []any {
	out := make([]any, len(s))
	copy(out, s)
	sort.SliceStable(out, func(i, j int) bool {
		return Compact(out[i]) < Compact(out[j])
	})
	return out
}

// IsEmptyCollection reports whether v is nil, an empty map, or an empty slice.
func IsEmptyCollection(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case map[string]any:
		return len(t) == 0
	case []any:
		return len(t) == 0
	default:
		return false
	}
}
