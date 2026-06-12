// Package plan parses the output of `terraform show -json <planfile>`.
//
// Only the fields this tool needs are modelled; unknown fields are ignored so
// the parser tolerates format_version drift across Terraform releases.
package plan

import (
	"encoding/json"
	"fmt"
	"io"
)

// Plan is the subset of the Terraform plan representation we consume.
type Plan struct {
	FormatVersion    string           `json:"format_version"`
	TerraformVersion string           `json:"terraform_version"`
	ResourceChanges  []ResourceChange `json:"resource_changes"`

	// Probes for misuse detection only: a state document (`terraform show
	// -json` without a plan file) has top-level "values" and no plan keys.
	Values        json.RawMessage `json:"values"`
	PlannedValues json.RawMessage `json:"planned_values"`
}

// ResourceChange is one entry of resource_changes.
type ResourceChange struct {
	Address       string `json:"address"`
	ModuleAddress string `json:"module_address"`
	Mode          string `json:"mode"` // "managed" or "data"
	Type          string `json:"type"`
	Name          string `json:"name"`
	ProviderName  string `json:"provider_name"`
	Change        Change `json:"change"`
}

// Change holds the before/after attribute objects for a resource change.
type Change struct {
	Actions         []string       `json:"actions"`
	Before          map[string]any `json:"before"`
	After           map[string]any `json:"after"`
	AfterUnknown    map[string]any `json:"after_unknown"`
	BeforeSensitive any            `json:"before_sensitive"`
	AfterSensitive  any            `json:"after_sensitive"`
}

// Load reads and decodes a plan JSON document.
func Load(r io.Reader) (*Plan, error) {
	var p Plan
	dec := json.NewDecoder(r)
	dec.UseNumber() // exact numbers: float64 collapses distinct large integers
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decoding plan JSON: %w (is this the output of `terraform show -json <planfile>`?)", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing content after the plan JSON document — the input looks corrupted or concatenated")
	}
	if p.FormatVersion == "" {
		return nil, fmt.Errorf("input has no format_version: expected `terraform show -json` output, not a raw plan file or state file")
	}
	if p.ResourceChanges == nil && p.PlannedValues == nil && p.Values != nil {
		return nil, fmt.Errorf("input looks like `terraform show -json` of a STATE, not a plan — run `terraform plan -out=plan.tfplan && terraform show -json plan.tfplan`")
	}
	return &p, nil
}

// IsUpdate reports whether the change is a pure in-place update — the only
// action kind this tool analyses for perma-diffs.
func (c Change) IsUpdate() bool {
	return len(c.Actions) == 1 && c.Actions[0] == "update"
}

// IsNoOp reports whether Terraform itself already classified this as no-op.
func (c Change) IsNoOp() bool {
	return len(c.Actions) == 1 && c.Actions[0] == "no-op"
}

// IsRead reports a data-source read (not a change to infrastructure).
func (c Change) IsRead() bool {
	return len(c.Actions) == 1 && c.Actions[0] == "read"
}

// ActionLabel renders the action list the way terraform's UI does.
func (c Change) ActionLabel() string {
	switch {
	case len(c.Actions) == 1:
		return c.Actions[0]
	case len(c.Actions) == 2 && c.Actions[0] == "create" && c.Actions[1] == "delete":
		return "replace (create then destroy)"
	case len(c.Actions) == 2 && c.Actions[0] == "delete" && c.Actions[1] == "create":
		return "replace (destroy then create)"
	default:
		return fmt.Sprintf("%v", c.Actions)
	}
}

// UnknownTop reports whether top-level attribute attr is marked unknown
// ("known after apply") in after_unknown. Terraform encodes this as either
// `true` for a wholly-unknown attribute or a nested object/array with some
// unknown leaves; both count as "this attribute's final value is unknown".
func (c Change) UnknownTop(attr string) bool {
	v, ok := c.AfterUnknown[attr]
	if !ok {
		return false
	}
	return anyUnknown(v)
}

func anyUnknown(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case map[string]any:
		for _, sub := range t {
			if anyUnknown(sub) {
				return true
			}
		}
		return false
	case []any:
		for _, sub := range t {
			if anyUnknown(sub) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// WhollyUnknown reports whether attr is marked unknown as a whole — the bare
// `true` form — with no concrete after value. Only then can a computed-churn
// pattern speak for the attribute: a partially-unknown composite (nested
// shape with some unknown leaves) still has known leaves that may have really
// changed, and those must be compared, not waved through.
func (c Change) WhollyUnknown(attr string) bool {
	v, ok := c.AfterUnknown[attr]
	if !ok {
		return false
	}
	b, isBool := v.(bool)
	if !isBool || !b {
		return false
	}
	_, hasAfter := c.After[attr]
	return !hasAfter
}

// SensitiveTop reports whether top-level attribute attr is marked sensitive
// on either side, so renderers can redact its values.
func (c Change) SensitiveTop(attr string) bool {
	return sensitiveIn(c.BeforeSensitive, attr) || sensitiveIn(c.AfterSensitive, attr)
}

func sensitiveIn(side any, attr string) bool {
	// Terraform can mark the WHOLE object sensitive with a bare `true`
	// (common for data sources and some providers) — then every attribute
	// is sensitive.
	if b, ok := side.(bool); ok {
		return b
	}
	m, ok := side.(map[string]any)
	if !ok {
		return false
	}
	v, ok := m[attr]
	if !ok {
		return false
	}
	return anyUnknown(v) // same truthy-anywhere semantics as unknown marks
}
