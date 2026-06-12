package canon

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

func init() {
	register("generic_json", genericJSON)
	register("set_list", setList)
	register("scalar_coercion", scalarCoercion)
	register("dns_name", dnsName)
	register("empty_collection", emptyCollection)
}

// genericJSON: both sides are strings containing JSON *containers* (object or
// array) that are structurally identical — only whitespace and object key
// order differ. Array order remains significant: without domain knowledge we
// cannot assume any array is a set.
func genericJSON(before, after any, _ map[string]any) Result {
	bv, bOK := parseJSONContainer(before)
	av, aOK := parseJSONContainer(after)
	if !bOK || !aOK {
		return notEqual("one or both sides are not JSON objects/arrays")
	}
	res := Result{
		Equal:       DeepEqual(bv, av),
		BeforeCanon: Pretty(bv),
		AfterCanon:  Pretty(av),
	}
	if res.Equal {
		res.Detail = "both sides decode to identical JSON structures; only whitespace and object key order differ"
	} else {
		res.Detail = "the decoded JSON structures genuinely differ — treated as a real change"
	}
	return res
}

func parseJSONContainer(v any) (any, bool) {
	s, ok := v.(string)
	if !ok {
		return nil, false
	}
	trimmed := strings.TrimSpace(s)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil, false
	}
	out, err := jsonUnmarshal([]byte(trimmed))
	if err != nil {
		return nil, false
	}
	switch out.(type) {
	case map[string]any, []any:
		return out, true
	default:
		return nil, false
	}
}

// setList: both sides are lists whose order is not semantically meaningful
// (the catalog only routes attributes with documented set semantics here).
// Comparison is multiset equality — multiplicity still matters, so a
// duplicated element never silently equals a single one.
func setList(before, after any, _ map[string]any) Result {
	bs, bOK := before.([]any)
	as, aOK := after.([]any)
	if !bOK || !aOK {
		return notEqual("one or both sides are not lists")
	}
	if len(bs) != len(as) {
		return Result{
			Equal:       false,
			BeforeCanon: Pretty(sortSliceCanonical(bs)),
			AfterCanon:  Pretty(sortSliceCanonical(as)),
			Detail:      fmt.Sprintf("element counts differ (%d vs %d) — a real membership change", len(bs), len(as)),
		}
	}
	sb := sortSliceCanonical(bs)
	sa := sortSliceCanonical(as)
	res := Result{
		Equal:       DeepEqual(sb, sa),
		BeforeCanon: Pretty(sb),
		AfterCanon:  Pretty(sa),
	}
	if res.Equal {
		res.Detail = fmt.Sprintf("same %d element(s), only the order differs; this attribute has set semantics", len(bs))
	} else {
		res.Detail = "element membership differs after order-insensitive comparison — a real change"
	}
	return res
}

// scalarCoercion: "80" vs 80, "true" vs true. Only exact numeric equality and
// exact lowercase "true"/"false" qualify; anything looser ("1" vs true,
// "TRUE", padded strings) fails closed.
func scalarCoercion(before, after any, _ map[string]any) Result {
	if eq, detail := coercedScalarEqual(before, after); eq {
		return Result{
			Equal:       true,
			BeforeCanon: Compact(before),
			AfterCanon:  Compact(after),
			Detail:      detail,
		}
	}
	return notEqual("values are not equal under strict string/number/bool coercion")
}

func coercedScalarEqual(a, b any) (bool, string) {
	// string <-> number (float64 or json.Number)
	if s, n, ok := stringNumberPair(a, b); ok {
		if strings.TrimSpace(s) != s || s == "" {
			return false, ""
		}
		sf, _, err := big.ParseFloat(s, 10, 256, big.ToNearestEven)
		if err != nil {
			return false, ""
		}
		nf, nok := toBigFloat(n)
		if nok && sf.Cmp(nf) == 0 {
			return true, fmt.Sprintf("%q (string) and %s (number) are the same value; the type was coerced by the provider or API", s, Compact(n))
		}
		return false, ""
	}
	// string <-> bool
	if s, bl, ok := stringBoolPair(a, b); ok {
		if (s == "true" && bl) || (s == "false" && !bl) {
			return true, fmt.Sprintf("%q (string) and %v (bool) are the same value; the type was coerced by the provider or API", s, bl)
		}
		return false, ""
	}
	return false, ""
}

func isJSONNumber(v any) bool {
	switch v.(type) {
	case float64, json.Number:
		return true
	}
	return false
}

func stringNumberPair(a, b any) (string, any, bool) {
	if s, ok := a.(string); ok && isJSONNumber(b) {
		return s, b, true
	}
	if s, ok := b.(string); ok && isJSONNumber(a) {
		return s, a, true
	}
	return "", nil, false
}

func stringBoolPair(a, b any) (string, bool, bool) {
	if s, ok := a.(string); ok {
		if bl, ok := b.(bool); ok {
			return s, bl, true
		}
	}
	if s, ok := b.(string); ok {
		if bl, ok := a.(bool); ok {
			return s, bl, true
		}
	}
	return "", false, false
}

// dnsName: Route 53 normalises record and zone names to lowercase, strips the
// trailing dot, and stores the wildcard label as the octal escape \052.
func dnsName(before, after any, _ map[string]any) Result {
	bs, bOK := before.(string)
	as, aOK := after.(string)
	if !bOK || !aOK {
		return notEqual("one or both sides are not strings")
	}
	nb := normalizeDNSName(bs)
	na := normalizeDNSName(as)
	res := Result{
		Equal:       nb == na,
		BeforeCanon: nb,
		AfterCanon:  na,
	}
	if res.Equal {
		var diffs []string
		if strings.TrimSuffix(bs, ".") != bs || strings.TrimSuffix(as, ".") != as {
			diffs = append(diffs, "trailing dot")
		}
		if strings.ToLower(bs) != bs || strings.ToLower(as) != as {
			diffs = append(diffs, "letter case")
		}
		if strings.Contains(bs, `\052`) || strings.Contains(as, `\052`) {
			diffs = append(diffs, `wildcard escaping (\052 vs *)`)
		}
		if len(diffs) == 0 {
			diffs = append(diffs, "formatting")
		}
		res.Detail = fmt.Sprintf("%q and %q are the same DNS name; only %s differs — DNS names are case-insensitive and Route 53 stores them normalised", bs, as, strings.Join(diffs, " and "))
	} else {
		res.Detail = "the names differ even after DNS normalisation — a real change"
	}
	return res
}

func normalizeDNSName(s string) string {
	out := strings.TrimSuffix(s, ".")
	out = strings.ToLower(out)
	out = strings.ReplaceAll(out, `\052`, "*")
	return out
}

// emptyCollection: nil, {}, and [] are all "no elements". Routed only to
// attributes where the provider documents this churn (tags, tags_all).
// With opts {"empty_string": true}, "" also counts as empty.
func emptyCollection(before, after any, opts map[string]any) Result {
	empty := func(v any) bool {
		if IsEmptyCollection(v) {
			return true
		}
		if es, _ := opts["empty_string"].(bool); es {
			if s, ok := v.(string); ok && s == "" {
				return true
			}
		}
		return false
	}
	if empty(before) && empty(after) {
		return Result{
			Equal:       true,
			BeforeCanon: Compact(before),
			AfterCanon:  Compact(after),
			Detail:      "both sides are empty (null vs empty collection) — there are no elements either way, so nothing changes in AWS",
		}
	}
	return notEqual("at least one side is non-empty — a real change")
}
