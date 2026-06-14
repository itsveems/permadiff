package classify

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/itsveems/permadiff/internal/catalog"
	"github.com/itsveems/permadiff/internal/plan"
)

func loadFixture(t *testing.T, name string) *Report {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	p, err := plan.Load(f)
	if err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	cat, err := catalog.LoadDefault()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	return Analyze(p, cat)
}

type classCase struct {
	fixture   string
	address   string
	wantClass Class
	wantConf  catalog.Confidence // checked when non-empty
	noopAttrs []string           // attributes that must be flagged no-op
	realAttrs []string           // attributes that must stay real
	wantNote  bool
}

// The single most important table in this repository. Every wantClass:
// ClassReal entry is a false-positive guard: a change that superficially
// resembles a perma-diff but is real, and must never be labelled noise.
func TestClassification(t *testing.T) {
	cases := []classCase{
		// 1. IAM policy JSON reordering
		{fixture: "iam_policy.json", address: "aws_iam_policy.noop", wantClass: ClassNoise, wantConf: catalog.High, noopAttrs: []string{"policy"}},
		{fixture: "iam_policy.json", address: "aws_iam_policy.real", wantClass: ClassReal, realAttrs: []string{"policy"}},
		{fixture: "iam_policy.json", address: "aws_iam_role.trust_noop", wantClass: ClassNoise, wantConf: catalog.High, noopAttrs: []string{"assume_role_policy"}},
		{fixture: "iam_policy.json", address: "aws_iam_role.trust_real", wantClass: ClassReal, realAttrs: []string{"assume_role_policy"}},
		// mixed: one noisy attribute + one real attribute = REAL resource
		{fixture: "iam_policy.json", address: "aws_iam_role.mixed", wantClass: ClassReal, noopAttrs: []string{"assume_role_policy"}, realAttrs: []string{"max_session_duration"}},

		// 2. S3 bucket policy
		{fixture: "s3_kms_policy.json", address: "aws_s3_bucket_policy.noop", wantClass: ClassNoise, wantConf: catalog.High, noopAttrs: []string{"policy"}},
		{fixture: "s3_kms_policy.json", address: "aws_s3_bucket_policy.real", wantClass: ClassReal, realAttrs: []string{"policy"}},
		// "*" ≡ {"AWS":"*"} collapses only under Allow. Under Deny the two forms
		// deny different principals, so a DenyInsecureTransport rewritten this way
		// is a REAL security change, not normalisation noise.
		{fixture: "s3_kms_policy.json", address: "aws_s3_bucket_policy.deny_principal_real", wantClass: ClassReal, realAttrs: []string{"policy"}},

		// 3. KMS key policy (bare account id vs root ARN)
		{fixture: "s3_kms_policy.json", address: "aws_kms_key.noop", wantClass: ClassNoise, wantConf: catalog.High, noopAttrs: []string{"policy"}},
		{fixture: "s3_kms_policy.json", address: "aws_kms_key.real", wantClass: ClassReal, realAttrs: []string{"policy"}},

		// 4. Security group rules
		{fixture: "security_group.json", address: "aws_security_group.noop", wantClass: ClassNoise, wantConf: catalog.High, noopAttrs: []string{"ingress"}},
		{fixture: "security_group.json", address: "aws_security_group.real", wantClass: ClassReal, realAttrs: []string{"ingress"}},
		{fixture: "security_group.json", address: "aws_security_group.desc_only", wantClass: ClassReal, realAttrs: []string{"ingress"}, wantNote: true},

		// 5. tags / tags_all
		{fixture: "tags.json", address: "aws_lambda_function.noop_tags", wantClass: ClassNoise, wantConf: catalog.High, noopAttrs: []string{"tags", "tags_all"}},
		{fixture: "tags.json", address: "aws_lambda_function.real_tags", wantClass: ClassReal, realAttrs: []string{"tags", "tags_all"}},
		// computed-only churn is never better than medium -> stays with real changes
		{fixture: "tags.json", address: "aws_instance.tags_all_unknown", wantClass: ClassLikelyNoise, wantConf: catalog.Medium, noopAttrs: []string{"tags_all"}},
		// PARTIALLY unknown attribute with a real known-leaf change: computed
		// patterns must not wave it through
		{fixture: "tags.json", address: "aws_instance.tags_all_partial_unknown_real", wantClass: ClassReal, realAttrs: []string{"tags", "tags_all"}},

		// 6. ECS task definitions
		{fixture: "ecs.json", address: "aws_ecs_task_definition.noop", wantClass: ClassNoise, wantConf: catalog.High, noopAttrs: []string{"container_definitions", "revision", "arn"}},
		{fixture: "ecs.json", address: "aws_ecs_task_definition.real", wantClass: ClassReal, realAttrs: []string{"container_definitions"}},

		// 7. Type coercion
		{fixture: "misc.json", address: "aws_lb_target_group.coercion_noop", wantClass: ClassNoise, wantConf: catalog.High, noopAttrs: []string{"port"}},
		{fixture: "misc.json", address: "aws_lb_target_group.coercion_real", wantClass: ClassReal, realAttrs: []string{"port"}},

		// 8. Route 53 names
		{fixture: "route53.json", address: "aws_route53_record.noop", wantClass: ClassNoise, wantConf: catalog.High, noopAttrs: []string{"name", "fqdn", "id"}},
		{fixture: "route53.json", address: "aws_route53_record.wildcard_noop", wantClass: ClassNoise, wantConf: catalog.High, noopAttrs: []string{"name"}},
		{fixture: "route53.json", address: "aws_route53_record.real", wantClass: ClassReal, realAttrs: []string{"name"}},

		// set-semantic lists
		{fixture: "misc.json", address: "aws_instance.sg_order_noop", wantClass: ClassNoise, wantConf: catalog.High, noopAttrs: []string{"vpc_security_group_ids"}},
		{fixture: "misc.json", address: "aws_instance.sg_swap_real", wantClass: ClassReal, realAttrs: []string{"vpc_security_group_ids"}},

		// 10. generic JSON attributes
		{fixture: "misc.json", address: "aws_sfn_state_machine.json_noop", wantClass: ClassNoise, wantConf: catalog.High, noopAttrs: []string{"definition"}},
		{fixture: "misc.json", address: "aws_sfn_state_machine.json_real", wantClass: ClassReal, realAttrs: []string{"definition"}},

		// byte-sensitive attribute: structurally-equal JSON in user_data is
		// still a real change (different bytes reach cloud-init)
		{fixture: "misc.json", address: "aws_instance.user_data_json_real", wantClass: ClassReal, realAttrs: []string{"user_data"}},
		// verbatim-bytes attribute: SSM stores the parameter value as exact
		// bytes; reformatted JSON is a real change (generic_json must not match)
		{fixture: "misc.json", address: "aws_ssm_parameter.json_value_real", wantClass: ClassReal, realAttrs: []string{"value"}},

		// sensitive values still classify, but are flagged for redaction
		{fixture: "misc.json", address: "aws_db_instance.sensitive_real", wantClass: ClassReal, realAttrs: []string{"password"}},

		// resource policies sharing the IAM grammar (SQS et al.)
		{fixture: "coverage.json", address: "aws_sqs_queue.policy_noop", wantClass: ClassNoise, wantConf: catalog.High, noopAttrs: []string{"policy"}},
		{fixture: "coverage.json", address: "aws_sqs_queue.policy_real", wantClass: ClassReal, realAttrs: []string{"policy"}},

		// standalone security_group_rule CIDR set ordering
		{fixture: "coverage.json", address: "aws_security_group_rule.cidr_order_noop", wantClass: ClassNoise, wantConf: catalog.High, noopAttrs: []string{"cidr_blocks"}},
		{fixture: "coverage.json", address: "aws_security_group_rule.cidr_change_real", wantClass: ClassReal, realAttrs: []string{"cidr_blocks"}},

		// generic computed churn: arn/id flipping unknown with nothing else
		// changed is at best MEDIUM (all-computed cap) — never noise
		{fixture: "coverage.json", address: "aws_iam_openid_connect_provider.computed_only", wantClass: ClassLikelyNoise, wantConf: catalog.Medium, noopAttrs: []string{"arn", "id"}},
		// an unknown flip on an attribute no computed pattern covers stays real
		{fixture: "coverage.json", address: "aws_lambda_function.unknown_unexplained_real", wantClass: ClassReal, realAttrs: []string{"last_modified"}},
	}

	reports := map[string]*Report{}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.fixture+"/"+tc.address, func(t *testing.T) {
			rep, ok := reports[tc.fixture]
			if !ok {
				rep = loadFixture(t, tc.fixture)
				reports[tc.fixture] = rep
			}
			rr := rep.Find(tc.address)
			if rr == nil {
				t.Fatalf("resource %s not in report", tc.address)
			}
			if rr.Class != tc.wantClass {
				t.Errorf("class = %s, want %s (findings: %+v)", rr.Class, tc.wantClass, summarize(rr))
			}
			if tc.wantConf != "" && rr.Confidence != tc.wantConf {
				t.Errorf("confidence = %s, want %s", rr.Confidence, tc.wantConf)
			}
			for _, attr := range tc.noopAttrs {
				if f := findAttr(rr, attr); f == nil || !f.NoOp {
					t.Errorf("attribute %s should be a no-op finding", attr)
				}
			}
			for _, attr := range tc.realAttrs {
				if f := findAttr(rr, attr); f == nil || f.NoOp {
					t.Errorf("attribute %s must stay a REAL change", attr)
				}
			}
			if tc.wantNote {
				any := false
				for _, f := range rr.Findings {
					if f.Note != "" {
						any = true
					}
				}
				if !any {
					t.Errorf("expected an advisory note on some finding")
				}
			}
		})
	}
}

func findAttr(rr *ResourceReport, attr string) *AttrFinding {
	for i := range rr.Findings {
		if rr.Findings[i].Attribute == attr {
			return &rr.Findings[i]
		}
	}
	return nil
}

func summarize(rr *ResourceReport) []string {
	var out []string
	for _, f := range rr.Findings {
		state := "real"
		if f.NoOp {
			state = "noop/" + string(f.Confidence)
		}
		out = append(out, f.Attribute+"="+state)
	}
	return out
}

func TestActionsAndSkips(t *testing.T) {
	rep := loadFixture(t, "actions.json")
	if rep.Total != 3 {
		t.Fatalf("Total = %d, want 3 (no-op and data read must be skipped)", rep.Total)
	}
	if rep.Noise != 0 || rep.LikelyNoise != 0 || rep.Real != 3 {
		t.Errorf("noise/likely/real = %d/%d/%d, want 0/0/3", rep.Noise, rep.LikelyNoise, rep.Real)
	}
	for _, addr := range []string{"aws_vpc.untouched", "data.aws_caller_identity.current"} {
		if rep.Find(addr) != nil {
			t.Errorf("%s should not appear in the report", addr)
		}
	}
	if rr := rep.Find("aws_instance.replaced"); rr == nil || rr.Analyzed {
		t.Errorf("replace must be listed plainly, not analysed: %+v", rr)
	}
}

func TestSensitiveFlagPropagates(t *testing.T) {
	rep := loadFixture(t, "misc.json")
	rr := rep.Find("aws_db_instance.sensitive_real")
	f := findAttr(rr, "password")
	if f == nil || !f.Sensitive {
		t.Fatalf("password finding must carry Sensitive=true")
	}
}

// Terraform can mark a change's whole object sensitive with a bare boolean
// (before_sensitive: true). Every finding must then be sensitive.
func TestWholeObjectBooleanSensitivity(t *testing.T) {
	rep := loadFixture(t, "misc.json")
	rr := rep.Find("aws_secretsmanager_secret_version.bool_sensitive")
	if rr == nil {
		t.Fatal("bool_sensitive resource missing from report")
	}
	f := findAttr(rr, "secret_string")
	if f == nil || !f.Sensitive {
		t.Fatalf("secret_string must carry Sensitive=true under boolean whole-object sensitivity")
	}
}

func TestHeadlineCounts(t *testing.T) {
	rep := loadFixture(t, "iam_policy.json")
	// 5 updates: 2 noise (noop, trust_noop), 3 real (real, trust_real, mixed)
	if rep.Total != 5 || rep.Noise != 2 || rep.RealTotal() != 3 {
		t.Errorf("total/noise/real = %d/%d/%d, want 5/2/3", rep.Total, rep.Noise, rep.RealTotal())
	}
}
