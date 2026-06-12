package plan

import (
	"strings"
	"testing"
)

const minimalPlan = `{
  "format_version": "1.2",
  "terraform_version": "1.7.5",
  "resource_changes": []
}`

func TestLoadValid(t *testing.T) {
	p, err := Load(strings.NewReader(minimalPlan))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.TerraformVersion != "1.7.5" {
		t.Errorf("TerraformVersion = %q", p.TerraformVersion)
	}
}

func TestLoadTrailingNewlineAccepted(t *testing.T) {
	if _, err := Load(strings.NewReader(minimalPlan + "\n\n")); err != nil {
		t.Errorf("trailing whitespace must be accepted: %v", err)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := []struct {
		name, input, wantSubstr string
	}{
		{"malformed JSON", `{"format_version":`, "decoding plan JSON"},
		{"missing format_version", `{"resource_changes": []}`, "no format_version"},
		{"trailing garbage", minimalPlan + `GARBAGE`, "trailing content"},
		{"concatenated documents", minimalPlan + minimalPlan, "trailing content"},
		{"state document", `{"format_version":"1.0","terraform_version":"1.7.5","values":{"root_module":{}}}`, "STATE, not a plan"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(strings.NewReader(tc.input))
			if err == nil {
				t.Fatalf("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error %q does not mention %q", err, tc.wantSubstr)
			}
		})
	}
}

func TestActionHelpers(t *testing.T) {
	cases := []struct {
		actions   []string
		isUpdate  bool
		wantLabel string
	}{
		{[]string{"update"}, true, "update"},
		{[]string{"create"}, false, "create"},
		{[]string{"delete"}, false, "delete"},
		{[]string{"create", "delete"}, false, "replace (create then destroy)"},
		{[]string{"delete", "create"}, false, "replace (destroy then create)"},
		{[]string{"no-op"}, false, "no-op"},
	}
	for _, tc := range cases {
		c := Change{Actions: tc.actions}
		if c.IsUpdate() != tc.isUpdate {
			t.Errorf("%v: IsUpdate = %v", tc.actions, c.IsUpdate())
		}
		if got := c.ActionLabel(); got != tc.wantLabel {
			t.Errorf("%v: ActionLabel = %q, want %q", tc.actions, got, tc.wantLabel)
		}
	}
}

func TestSensitiveTopShapes(t *testing.T) {
	cases := []struct {
		name          string
		before, after any
		attr          string
		wantSensitive bool
	}{
		{"map form true", map[string]any{"password": true}, map[string]any{}, "password", true},
		{"map form absent", map[string]any{}, map[string]any{}, "password", false},
		{"whole-object bool true (before)", true, map[string]any{}, "anything", true},
		{"whole-object bool true (after)", map[string]any{}, true, "anything", true},
		{"whole-object bool false", false, false, "anything", false},
		{"nested array with truthy leaf", map[string]any{"creds": []any{false, true}}, map[string]any{}, "creds", true},
		{"nested map all false", map[string]any{"creds": map[string]any{"a": false}}, map[string]any{}, "creds", false},
		{"junk shape", "true", "yes", "anything", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Change{BeforeSensitive: tc.before, AfterSensitive: tc.after}
			if got := c.SensitiveTop(tc.attr); got != tc.wantSensitive {
				t.Errorf("SensitiveTop(%s) = %v, want %v", tc.attr, got, tc.wantSensitive)
			}
		})
	}
}

func TestUnknownHelpers(t *testing.T) {
	c := Change{
		After: map[string]any{"partial": "known-part"},
		AfterUnknown: map[string]any{
			"whole":    true,
			"partial":  map[string]any{"leaf": true},
			"allfalse": map[string]any{"leaf": false},
		},
	}
	if !c.UnknownTop("whole") || !c.WhollyUnknown("whole") {
		t.Errorf("whole should be unknown and wholly unknown")
	}
	if !c.UnknownTop("partial") {
		t.Errorf("partial should count as unknown (truthy leaf)")
	}
	if c.WhollyUnknown("partial") {
		t.Errorf("partial must NOT be wholly unknown — known leaves exist")
	}
	if c.UnknownTop("allfalse") || c.WhollyUnknown("allfalse") {
		t.Errorf("allfalse has no truthy leaves")
	}
	if c.UnknownTop("absent") || c.WhollyUnknown("absent") {
		t.Errorf("absent attribute is not unknown")
	}
}
