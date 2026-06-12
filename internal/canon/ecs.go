package canon

import (
	"encoding/json"
	"strconv"
)

func init() {
	register("ecs_container_definitions", ecsContainerDefinitions)
}

// containerDefaults are values the ECS API injects into a registered task
// definition when the field was omitted. Removing a field whose value exactly
// equals its API default is semantics-preserving: omitting it and setting it
// to the default register identical task definitions. This mirrors the AWS
// provider's own equivalency normalisation for container_definitions.
var containerDefaults = map[string]any{
	"cpu":                   float64(0),
	"essential":             true,
	"environment":           []any{},
	"secrets":               []any{},
	"mountPoints":           []any{},
	"portMappings":          []any{},
	"volumesFrom":           []any{},
	"systemControls":        []any{},
	"dockerSecurityOptions": []any{},
	"links":                 []any{},
}

// containerSetLists are container fields with set semantics, sorted by their
// elements' canonical encoding before comparing.
var containerSetLists = []string{
	"environment", "secrets", "mountPoints", "volumesFrom",
	"portMappings", "ulimits", "systemControls",
}

// keyedLastWinsLists maps container fields whose entries are keyed and where
// the runtime resolves duplicate keys by position (last occurrence wins) to
// their key field. Sorting such a list with duplicate keys would equate two
// orderings that produce DIFFERENT effective values — so when duplicates
// exist, order is preserved and the comparison stays order-sensitive
// (conservative). ulimits is included: Docker/runc apply rlimits
// sequentially, so the last duplicate-name ulimit wins. portMappings is NOT:
// duplicate mappings are distinct publications, not overrides.
var keyedLastWinsLists = map[string]string{
	"environment":    "name",
	"secrets":        "name",
	"systemControls": "namespace",
	"ulimits":        "name",
}

// ecsContainerDefinitions canonicalises the container_definitions JSON of an
// aws_ecs_task_definition. The ECS API rewrites the document on registration:
// it reorders fields, sorts nothing, injects defaults, and stringifies
// environment values. Normalisations applied (all documented API behaviour):
//
//   - object key order / whitespace: insignificant (JSON)
//   - containers sorted by name (registration order has no runtime meaning;
//     container dependencies are explicit via dependsOn/links)
//   - environment/secrets/mountPoints/volumesFrom/portMappings/ulimits/
//     systemControls sorted canonically — except that keyed lists
//     (environment/secrets/systemControls/ulimits) keep their order whenever
//     duplicate keys exist, because there the runtime resolves duplicates
//     positionally (last wins) and order IS meaningful
//   - environment variable values coerced to strings (the API stores all
//     env values as strings: 80 -> "80")
//   - portMappings "protocol": "tcp" dropped (the documented API default)
//   - fields exactly equal to their API-injected default dropped
//
// Anything outside these rules — an image change, a new env var, a changed
// command — survives normalisation and compares unequal.
func ecsContainerDefinitions(before, after any, _ map[string]any) Result {
	bc, bOK := parseContainers(before)
	ac, aOK := parseContainers(after)
	if !bOK || !aOK {
		return notEqual("one or both sides are not a JSON array of container definitions")
	}
	if len(bc) != len(ac) {
		return notEqual("container counts differ — a real change")
	}
	nb := normalizeContainers(bc)
	na := normalizeContainers(ac)
	res := Result{
		Equal:       DeepEqual(nb, na),
		BeforeCanon: Pretty(nb),
		AfterCanon:  Pretty(na),
	}
	if res.Equal {
		res.Detail = "after sorting containers and their set-valued fields, stringifying environment values, and dropping API-injected defaults, both definitions are identical"
	} else {
		res.Detail = "definitions still differ after ECS canonicalisation — a real change"
	}
	return res
}

func parseContainers(v any) ([]any, bool) {
	s, ok := v.(string)
	if !ok {
		return nil, false
	}
	out, err := jsonUnmarshal([]byte(s))
	if err != nil {
		return nil, false
	}
	arr, ok := out.([]any)
	if !ok {
		return nil, false
	}
	for _, c := range arr {
		if _, ok := c.(map[string]any); !ok {
			return nil, false
		}
	}
	return arr, true
}

func normalizeContainers(containers []any) []any {
	out := make([]any, len(containers))
	for i, c := range containers {
		m, ok := c.(map[string]any)
		if !ok {
			// parseContainers guarantees maps; if that invariant ever breaks,
			// keep the raw value so the comparison fails closed (not equal)
			// rather than panicking.
			out[i] = c
			continue
		}
		out[i] = normalizeContainer(m)
	}
	return sortSliceCanonical(out)
}

func normalizeContainer(c map[string]any) map[string]any {
	n := make(map[string]any, len(c))
	for k, v := range c {
		n[k] = v
	}

	// Stringify environment values before sorting, so "80" and 80 sort identically.
	if env, ok := n["environment"].([]any); ok {
		n["environment"] = stringifyEnvValues(env)
	}

	// Drop the documented per-port-mapping default before sorting.
	if pms, ok := n["portMappings"].([]any); ok {
		n["portMappings"] = normalizePortMappings(pms)
	}

	for _, f := range containerSetLists {
		lv, ok := n[f].([]any)
		if !ok {
			continue
		}
		if keyField, keyed := keyedLastWinsLists[f]; keyed && hasDuplicateKey(lv, keyField) {
			continue // last-wins semantics: order is meaningful, keep it
		}
		n[f] = sortSliceCanonical(lv)
	}

	// Drop fields exactly equal to their API-injected default.
	for k, def := range containerDefaults {
		if v, ok := n[k]; ok && DeepEqual(v, def) {
			delete(n, k)
		}
	}
	return n
}

// hasDuplicateKey reports whether two entries of the list share the same
// value for keyField. Entries that aren't maps or lack the key count as
// duplicates of each other — unknown shapes must fail toward "don't sort".
func hasDuplicateKey(list []any, keyField string) bool {
	seen := map[string]bool{}
	odd := false
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			if odd {
				return true
			}
			odd = true
			continue
		}
		k, ok := m[keyField].(string)
		if !ok {
			if odd {
				return true
			}
			odd = true
			continue
		}
		if seen[k] {
			return true
		}
		seen[k] = true
	}
	return false
}

func stringifyEnvValues(env []any) []any {
	out := make([]any, len(env))
	for i, e := range env {
		m, ok := e.(map[string]any)
		if !ok {
			out[i] = e
			continue
		}
		ne := make(map[string]any, len(m))
		for k, v := range m {
			ne[k] = v
		}
		switch t := ne["value"].(type) {
		case json.Number:
			ne["value"] = string(t)
		case float64:
			ne["value"] = strconv.FormatFloat(t, 'f', -1, 64)
		case bool:
			ne["value"] = strconv.FormatBool(t)
		}
		out[i] = ne
	}
	return out
}

func normalizePortMappings(pms []any) []any {
	out := make([]any, len(pms))
	for i, pm := range pms {
		m, ok := pm.(map[string]any)
		if !ok {
			out[i] = pm
			continue
		}
		n := make(map[string]any, len(m))
		for k, v := range m {
			n[k] = v
		}
		if p, ok := n["protocol"].(string); ok && p == "tcp" {
			delete(n, "protocol")
		}
		out[i] = n
	}
	return out
}
