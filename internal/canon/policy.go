package canon

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func init() {
	register("aws_policy_json", awsPolicyJSON)
}

// awsPolicyJSON canonicalises AWS policy documents (IAM, S3 bucket, KMS key,
// SQS/SNS resource policies, assume-role trust policies). It encodes only
// documented, semantics-preserving AWS normalisations:
//
//   - JSON whitespace and object key order are insignificant.
//   - A single Statement object is equivalent to a one-element Statement array.
//   - Statement order is insignificant (statements are evaluated independently;
//     IAM is deny-overrides regardless of order).
//   - Action/NotAction/Resource/NotResource accept a scalar or an array; the
//     array is a set (order-insensitive, duplicates redundant).
//   - Action/NotAction names are case-insensitive per the IAM policy grammar.
//     (Resource ARNs are case-sensitive and are NOT case-folded.)
//   - Principal/NotPrincipal map values are scalar-or-set; in an *Allow*
//     statement "Principal": "*" is equivalent to {"AWS": "*"} (S3 rewrites one
//     form to the other for public-read policies). The collapse is gated on
//     Effect == "Allow": under Deny the two forms deny different principal sets,
//     and NotPrincipal never gets it either — see normalizePrincipal.
//   - Condition values are scalar-or-set; AWS stores condition values as
//     strings, so bools/numbers written by jsonencode() are coerced to their
//     string forms before comparing. Condition value *case* is preserved
//     (operators like StringEquals are case-sensitive).
//
// Anything that does not parse as a JSON object fails closed (not equal).
func awsPolicyJSON(before, after any, _ map[string]any) Result {
	bDoc, bErr := parsePolicyDoc(before)
	aDoc, aErr := parsePolicyDoc(after)
	if bErr != nil || aErr != nil {
		return notEqual("one or both sides are not parseable JSON policy documents")
	}
	nb := normalizePolicyValue(bDoc, "", ctxNone)
	na := normalizePolicyValue(aDoc, "", ctxNone)
	res := Result{
		Equal:       DeepEqual(nb, na),
		BeforeCanon: Pretty(nb),
		AfterCanon:  Pretty(na),
	}
	if res.Equal {
		res.Detail = "after sorting statements, treating Action/Resource/Principal/Condition values as sets, " +
			"case-folding action names, and normalising scalar-vs-single-element-array, both documents are identical"
	} else {
		res.Detail = "documents still differ after policy canonicalisation — treated as a real change"
	}
	return res
}

func parsePolicyDoc(v any) (map[string]any, error) {
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("not a string")
	}
	doc, err := jsonUnmarshal([]byte(s))
	if err != nil {
		return nil, err
	}
	m, ok := doc.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("top level is not a JSON object")
	}
	return m, nil
}

type policyCtx int

const (
	ctxNone            policyCtx = iota
	ctxConditionValues           // leaf values under Condition.<operator>.<key>
)

var policySetKeys = map[string]bool{
	"Action":      true,
	"NotAction":   true,
	"Resource":    true,
	"NotResource": true,
}

var actionCaseInsensitive = map[string]bool{
	"Action":    true,
	"NotAction": true,
}

// normalizePolicyValue rewrites a decoded policy document into a canonical
// shape. key is the object key this value sits under ("" at top level).
func normalizePolicyValue(v any, key string, ctx policyCtx) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		// A statement's Effect governs the "*" ≡ {"AWS":"*"} Principal collapse:
		// it is semantics-preserving only for Allow. Under Deny the two forms
		// deny different principal sets ("*" denies everyone, including anonymous
		// requests; {"AWS":"*"} denies only AWS account principals), so collapsing
		// them there would silently change what the policy denies. A missing or
		// non-"Allow" Effect fails closed (no collapse).
		effect, _ := t["Effect"].(string)
		for k, sub := range t {
			switch {
			case k == "Statement":
				out[k] = normalizeSet(toSlice(sub), func(e any) any {
					return normalizePolicyValue(e, k, ctxNone)
				})
			case policySetKeys[k]:
				out[k] = normalizeSet(toSlice(sub), func(e any) any {
					if s, ok := e.(string); ok && actionCaseInsensitive[k] {
						return strings.ToLower(s)
					}
					return normalizePolicyValue(e, k, ctxNone)
				})
			case k == "Principal" || k == "NotPrincipal":
				out[k] = normalizePrincipal(sub, k == "Principal" && effect == "Allow")
			case k == "Condition":
				out[k] = normalizeCondition(sub)
			default:
				out[k] = normalizePolicyValue(sub, k, ctx)
			}
		}
		return out
	case []any:
		if ctx == ctxConditionValues {
			return normalizeSet(t, coerceConditionLeaf)
		}
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = normalizePolicyValue(e, key, ctx)
		}
		return out
	default:
		if ctx == ctxConditionValues {
			return coerceConditionLeaf(t)
		}
		return v
	}
}

// normalizePrincipal handles Principal/NotPrincipal:
//   - map values are scalar-or-set
//   - bare account IDs in AWS principals expand to root ARNs
//   - "*" ≡ {"AWS": "*"} collapse, controlled by allowStarCollapse, which the
//     caller sets true ONLY for an Allow statement's Principal. It is wrong for
//     NotPrincipal and for any Deny statement: there the two forms cover
//     different principal sets ("*" is everyone, including anonymous;
//     {"AWS": "*"} is only AWS account principals), so conflating them would
//     change what the statement excludes or denies.
func normalizePrincipal(v any, allowStarCollapse bool) any {
	if s, ok := v.(string); ok {
		return s // "*" or an account/ARN scalar stays as-is
	}
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	// {"AWS": "*"} (including ["*"] form) collapses to "*" — documented AWS equivalence.
	if allowStarCollapse && len(m) == 1 {
		if aws, ok := m["AWS"]; ok {
			vals := toSlice(aws)
			if len(vals) == 1 {
				if s, ok := vals[0].(string); ok && s == "*" {
					return "*"
				}
			}
		}
	}
	out := make(map[string]any, len(m))
	for pk, pv := range m {
		norm := func(e any) any { return e }
		if pk == "AWS" {
			norm = normalizeAWSPrincipal
		}
		out[pk] = normalizeSet(toSlice(pv), norm)
	}
	return out
}

// normalizeAWSPrincipal: a bare 12-digit account ID principal is documented
// shorthand for that account's root ARN; KMS and IAM store the ARN form,
// which is a classic perma-diff source.
func normalizeAWSPrincipal(e any) any {
	s, ok := e.(string)
	if !ok || len(s) != 12 {
		return e
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return e
		}
	}
	return "arn:aws:iam::" + s + ":root"
}

// normalizeCondition handles Condition: {operator: {conditionKey: values}}.
// Values are scalar-or-set; leaf scalars are coerced to strings, because AWS
// stores all condition values as strings (jsonencode(true) round-trips as "true").
func normalizeCondition(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	out := make(map[string]any, len(m))
	for op, keys := range m {
		km, ok := keys.(map[string]any)
		if !ok {
			out[op] = keys // unexpected shape: keep verbatim, fails comparison if differing
			continue
		}
		ko := make(map[string]any, len(km))
		for ck, cv := range km {
			ko[ck] = normalizeSet(toSlice(cv), coerceConditionLeaf)
		}
		out[op] = ko
	}
	return out
}

func coerceConditionLeaf(v any) any {
	switch t := v.(type) {
	case bool:
		return strconv.FormatBool(t)
	case json.Number:
		return string(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return v
	}
}

// toSlice wraps a scalar (or object) into a one-element slice; a slice is
// copied. Encodes AWS's "scalar is shorthand for a single-element list".
func toSlice(v any) []any {
	if s, ok := v.([]any); ok {
		out := make([]any, len(s))
		copy(out, s)
		return out
	}
	return []any{v}
}

// normalizeSet maps each element then sorts by canonical encoding and drops
// exact duplicates — set semantics. Only *identical* canonical elements are
// merged, so this can never conflate two distinct values.
func normalizeSet(s []any, norm func(any) any) []any {
	mapped := make([]any, len(s))
	for i, e := range s {
		mapped[i] = norm(e)
	}
	mapped = sortSliceCanonical(mapped)
	out := mapped[:0]
	var prev string
	for i, e := range mapped {
		c := Compact(e)
		if i == 0 || c != prev {
			out = append(out, e)
		}
		prev = c
	}
	return out
}
