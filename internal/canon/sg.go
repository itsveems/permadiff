package canon

import "fmt"

func init() {
	register("sg_rules", sgRules)
}

// sgRules canonicalises aws_security_group ingress/egress rule blocks.
// These attributes are sets: rule order carries no meaning, and the inner
// cidr_blocks / security_groups lists are sets too. A null description and
// an empty-string description are equivalent (the API returns "" for unset).
//
// If the rules differ ONLY by description text, that is a real change, but we
// attach a note about the well-known quirk: inline rule descriptions are part
// of the rule's identity, so "just editing a description" recreates the rule.
func sgRules(before, after any, _ map[string]any) Result {
	bs, bOK := before.([]any)
	as, aOK := after.([]any)
	if !bOK || !aOK {
		return notEqual("one or both sides are not lists of rule blocks")
	}

	nb := normalizeRules(bs, false)
	na := normalizeRules(as, false)
	res := Result{
		BeforeCanon: Pretty(nb),
		AfterCanon:  Pretty(na),
	}
	if len(bs) == len(as) && DeepEqual(nb, na) {
		res.Equal = true
		res.Detail = fmt.Sprintf("same %d rule(s); only rule order and/or inner CIDR/security-group list order differs — security group rules are sets, order is never meaningful", len(bs))
		return res
	}

	// Not equal. Check whether descriptions are the only difference, to
	// attach the ForceNew advisory.
	if len(bs) == len(as) {
		sb := normalizeRules(bs, true)
		sa := normalizeRules(as, true)
		if DeepEqual(sb, sa) {
			res.Detail = "rules differ only in description text — a real change"
			res.Note = "description is part of an inline rule's identity: this plan will delete and recreate the affected rule(s), briefly removing them. Consider standalone aws_vpc_security_group_ingress_rule/egress_rule resources, which update descriptions in place."
			return res
		}
	}
	res.Detail = "rule membership genuinely differs after order-insensitive comparison — a real change"
	return res
}

// normalizeRules canonicalises a rule list: inner set-lists sorted, null
// description folded to "", and the rules themselves sorted canonically.
// stripDescriptions removes descriptions entirely (for the only-difference probe).
func normalizeRules(rules []any, stripDescriptions bool) []any {
	innerSets := []string{"cidr_blocks", "ipv6_cidr_blocks", "prefix_list_ids", "security_groups"}
	out := make([]any, len(rules))
	for i, r := range rules {
		m, ok := r.(map[string]any)
		if !ok {
			out[i] = r
			continue
		}
		n := make(map[string]any, len(m))
		for k, v := range m {
			n[k] = v
		}
		for _, f := range innerSets {
			if lv, ok := n[f].([]any); ok {
				n[f] = sortSliceCanonical(lv)
			}
		}
		if d, ok := n["description"]; ok && d == nil {
			n["description"] = ""
		}
		if stripDescriptions {
			delete(n, "description")
		}
		out[i] = n
	}
	return sortSliceCanonical(out)
}
