package render

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/itsveems/permadiff/internal/catalog"
	"github.com/itsveems/permadiff/internal/classify"
	"github.com/itsveems/permadiff/internal/plan"
)

func reportFromFixture(t *testing.T, name string) *classify.Report {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "classify", "testdata", name))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	p, err := plan.Load(f)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cat, err := catalog.LoadDefault()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	return classify.Analyze(p, cat)
}

func TestTerminalOutputShowsEverything(t *testing.T) {
	rep := reportFromFixture(t, "iam_policy.json")
	var buf bytes.Buffer
	Terminal(&buf, rep, Style{Enabled: false})
	out := buf.String()

	for _, want := range []string{
		"5 changes",
		"2 perma-diff no-ops (with fixes)",
		"3 real changes",
		"aws_iam_policy.noop",
		"aws_iam_policy.real",
		"aws_iam_role.trust_noop",
		"aws_iam_role.trust_real",
		"aws_iam_role.mixed",
		"IAM policy JSON normalisation",
		"fix:",
		"--explain",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q\n---\n%s", want, out)
		}
	}
	// The mixed resource must disclose its noisy attribute without hiding the real one.
	if !strings.Contains(out, "max_session_duration") {
		t.Errorf("mixed resource's real attribute missing from output")
	}
}

func TestSensitiveValuesNeverRendered(t *testing.T) {
	rep := reportFromFixture(t, "misc.json")
	// covers both map-form (password) and whole-object boolean form
	// (secret_string) sensitivity marks
	secrets := []string{
		"correct-horse-battery", "staple-battery-horse",
		"whole-object-secret-before", "whole-object-secret-after",
	}

	var term, md, exp bytes.Buffer
	Terminal(&term, rep, Style{Enabled: true})
	Markdown(&md, rep)
	Explain(&exp, rep.Find("aws_db_instance.sensitive_real"), Style{Enabled: false})

	var exp2 bytes.Buffer
	Explain(&exp2, rep.Find("aws_secretsmanager_secret_version.bool_sensitive"), Style{Enabled: false})

	for name, out := range map[string]string{
		"terminal":     term.String(),
		"markdown":     md.String(),
		"explain":      exp.String(),
		"explain-bool": exp2.String(),
	} {
		for _, secret := range secrets {
			if strings.Contains(out, secret) {
				t.Errorf("%s output leaks sensitive value %q", name, secret)
			}
		}
	}
	if !strings.Contains(term.String(), "redacted") {
		t.Errorf("terminal output should mark redacted values")
	}
}

// Canonicalizer detail strings can embed raw attribute values (dns_name and
// scalar_coercion quote them). Explain must redact details for sensitive
// attributes even when a pattern matched.
func TestExplainRedactsSensitiveAttemptDetails(t *testing.T) {
	rr := &classify.ResourceReport{
		Address:  "aws_db_instance.creds",
		Action:   "update",
		Analyzed: true,
		Class:    classify.ClassReal,
		Findings: []classify.AttrFinding{{
			Attribute: "password",
			Sensitive: true,
			Attempts: []classify.Attempt{{
				PatternID: "generic-type-coercion",
				Equal:     false,
				Detail:    `"super-secret-value" is not equal under coercion`,
			}},
		}},
	}
	var buf bytes.Buffer
	Explain(&buf, rr, Style{Enabled: false})
	out := buf.String()
	if strings.Contains(out, "super-secret-value") {
		t.Errorf("explain leaked a sensitive value via attempt detail:\n%s", out)
	}
	if !strings.Contains(out, "redacted") {
		t.Errorf("explain should say the detail was redacted:\n%s", out)
	}
}

func TestMarkdownStructure(t *testing.T) {
	rep := reportFromFixture(t, "tags.json")
	var buf bytes.Buffer
	Markdown(&buf, rep)
	out := buf.String()
	for _, want := range []string{
		"## permadiff — plan noise report",
		"### 🔇 Perma-diff noise (1)",
		"### ⚠️ Real changes (3)",
		"<details>",
		"aws_lambda_function.noop_tags",
		"possible perma-diff (medium confidence)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q\n---\n%s", want, out)
		}
	}
}

func TestExplainShowsReasoningAndFix(t *testing.T) {
	rep := reportFromFixture(t, "iam_policy.json")
	var buf bytes.Buffer
	Explain(&buf, rep.Find("aws_iam_policy.noop"), Style{Enabled: false})
	out := buf.String()
	for _, want := range []string{
		"verdict: perma-diff noise",
		"pattern iam-policy-json",
		"proved semantically equal",
		"canonicalised before:",
		"canonicalised after:",
		"recommended fix",
		"jsonencode",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("explain missing %q\n---\n%s", want, out)
		}
	}
}

func TestExplainNonUpdate(t *testing.T) {
	rep := reportFromFixture(t, "actions.json")
	var buf bytes.Buffer
	Explain(&buf, rep.Find("aws_instance.replaced"), Style{Enabled: false})
	if !strings.Contains(buf.String(), "not an in-place update") {
		t.Errorf("explain for a replace should say it is not analysed:\n%s", buf.String())
	}
}

// Addresses and attribute names come from the plan file — in CI they can be
// attacker-influenced (for_each keys). They must not break out of markdown
// code spans, inject HTML into <summary>, or smuggle ANSI escapes into the
// terminal.
func TestHostileAddressEscaping(t *testing.T) {
	hostile := "aws_s3_bucket.b[\"</code><script>alert(1)</script>`whoami`\x1b[31m\"]"
	rr := classify.ResourceReport{
		Address:  hostile,
		Type:     "aws_s3_bucket",
		Action:   "update",
		Analyzed: true,
		Class:    classify.ClassNoise,
		Findings: []classify.AttrFinding{{Attribute: "tags`", NoOp: true}},
	}
	rep := &classify.Report{Resources: []classify.ResourceReport{rr}, Total: 1, Noise: 1}

	var md, term bytes.Buffer
	Markdown(&md, rep)
	Terminal(&term, rep, Style{Enabled: false})

	if strings.Contains(md.String(), "<script>") {
		t.Errorf("markdown output contains raw <script> from address:\n%s", md.String())
	}
	if strings.Contains(md.String(), "`whoami`") {
		t.Errorf("markdown output lets address close a code span:\n%s", md.String())
	}
	if strings.Contains(term.String(), "\x1b[31m") {
		t.Errorf("terminal output passes through ANSI escapes from address")
	}
}

func TestNoColorMeansNoEscapes(t *testing.T) {
	rep := reportFromFixture(t, "iam_policy.json")
	var buf bytes.Buffer
	Terminal(&buf, rep, Style{Enabled: false})
	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("disabled style must not emit ANSI escapes")
	}
}
