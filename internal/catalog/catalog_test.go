package catalog

import (
	"os"
	"testing"
)

func TestDefaultCatalogLoadsAndValidates(t *testing.T) {
	c, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	if len(c.Patterns) < 10 {
		t.Fatalf("expected at least 10 seed patterns, got %d", len(c.Patterns))
	}
}

func TestMatchingPrecedence(t *testing.T) {
	c, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	cases := []struct {
		resType, attr string
		wantID        string
		computed      bool
	}{
		{"aws_iam_policy", "policy", "iam-policy-json", false},
		{"aws_iam_role", "assume_role_policy", "iam-assume-role-policy", false},
		{"aws_s3_bucket_policy", "policy", "s3-bucket-policy-json", false},
		{"aws_kms_key", "policy", "kms-key-policy-json", false},
		{"aws_sqs_queue", "policy", "resource-policy-json", false},
		{"aws_security_group", "ingress", "sg-inline-rules", false},
		{"aws_security_group_rule", "cidr_blocks", "sg-rule-cidr-sets", false},
		{"aws_ecs_task_definition", "container_definitions", "ecs-container-definitions", false},
		{"aws_route53_record", "name", "route53-name-normalization", false},
		{"aws_lambda_function", "tags", "tags-empty-vs-null", false},
		{"aws_instance", "vpc_security_group_ids", "aws-set-semantic-lists", false},
		// generic fallbacks pick up anything else on aws_* resources
		{"aws_sfn_state_machine", "definition", "generic-type-coercion", false}, // first canonical "*" match; classifier tries next on no-op failure
		// computed entries
		{"aws_instance", "tags_all", "tags-all-computed-churn", true},
		{"aws_ecs_task_definition", "revision", "ecs-task-definition-computed", true},
		{"aws_iam_role", "arn", "generic-computed-churn", true},
	}
	for _, tc := range cases {
		var got *Pattern
		if tc.computed {
			got = c.FindComputed(tc.resType, tc.attr)
		} else {
			got = c.FindCanonical(tc.resType, tc.attr)
		}
		if got == nil {
			t.Errorf("(%s, %s): no pattern matched, want %s", tc.resType, tc.attr, tc.wantID)
			continue
		}
		if got.ID != tc.wantID {
			t.Errorf("(%s, %s): matched %s, want %s", tc.resType, tc.attr, got.ID, tc.wantID)
		}
	}
}

func TestNonAWSResourceMatchesNothing(t *testing.T) {
	c, _ := LoadDefault()
	if p := c.FindCanonical("google_storage_bucket", "labels"); p != nil {
		t.Errorf("non-AWS resource matched %s; v1 catalog must be AWS-only", p.ID)
	}
}

func TestExtraCatalogOverridesByID(t *testing.T) {
	dir := t.TempDir()
	extra := dir + "/extra.yaml"
	y := `
patterns:
  - id: iam-policy-json
    title: overridden
    confidence: medium
    canonicalizer: generic_json
    why: override test
    match:
      resource_types: [aws_iam_policy]
      attributes: [policy]
`
	if err := os.WriteFile(extra, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := LoadWithExtra(extra)
	if err != nil {
		t.Fatalf("LoadWithExtra: %v", err)
	}
	var count int
	for _, p := range c.Patterns {
		if p.ID == "iam-policy-json" {
			count++
			if p.Title != "overridden" {
				t.Errorf("extra pattern should shadow the built-in, got title %q", p.Title)
			}
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 pattern with id iam-policy-json after override, got %d", count)
	}
}

func TestExcludeAttributesWinOverAttributes(t *testing.T) {
	y := `
patterns:
  - id: broad-json
    title: test
    confidence: high
    canonicalizer: generic_json
    why: test
    match:
      resource_types: ["aws_*"]
      attributes: ["*"]
      exclude_attributes: [user_data, "secret_*"]
`
	c, err := Parse([]byte(y), "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p := c.FindCanonical("aws_instance", "user_data"); p != nil {
		t.Errorf("user_data should be excluded, matched %s", p.ID)
	}
	if p := c.FindCanonical("aws_secretsmanager_secret_version", "secret_string"); p != nil {
		t.Errorf("secret_string should be excluded by glob, matched %s", p.ID)
	}
	if p := c.FindCanonical("aws_sfn_state_machine", "definition"); p == nil {
		t.Errorf("definition should still match")
	}
}

func TestParseRejectsBadEntries(t *testing.T) {
	bad := []string{
		"patterns:\n  - title: no id\n    confidence: high\n    canonicalizer: generic_json\n    why: x\n    match: {resource_types: [a], attributes: [b]}\n",
		"patterns:\n  - id: x\n    confidence: wild-guess\n    canonicalizer: generic_json\n    why: x\n    match: {resource_types: [a], attributes: [b]}\n",
		"patterns:\n  - id: x\n    confidence: high\n    canonicalizer: does_not_exist\n    why: x\n    match: {resource_types: [a], attributes: [b]}\n",
		"patterns:\n  - id: x\n    confidence: high\n    canonicalizer: generic_json\n    why: x\n    match: {resource_types: [], attributes: [b]}\n",
		"patterns:\n  - id: x\n    confidence: high\n    canonicalizer: generic_json\n    match: {resource_types: [a], attributes: [b]}\n",
		// malformed glob (unclosed character class) must be rejected, not silently dead
		"patterns:\n  - id: x\n    confidence: high\n    canonicalizer: generic_json\n    why: x\n    match: {resource_types: [\"aws_[iam\"], attributes: [b]}\n",
	}
	for i, y := range bad {
		if _, err := Parse([]byte(y), "test"); err == nil {
			t.Errorf("bad catalog %d accepted; want validation error", i)
		}
	}
}
