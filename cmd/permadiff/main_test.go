package main

import (
	"bytes"
	"errors"
	"flag"
	"strings"
	"testing"
)

const fixture = "../../internal/classify/testdata/iam_policy.json"

func TestRunFile(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{fixture}, strings.NewReader(""), &out, false, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), "perma-diff no-ops") {
		t.Errorf("missing headline:\n%s", out.String())
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Errorf("non-TTY run must not emit ANSI escapes")
	}
}

func TestRunStdin(t *testing.T) {
	plan := `{"format_version":"1.2","terraform_version":"1.7.5","resource_changes":[]}`
	var out bytes.Buffer
	if err := run(nil, strings.NewReader(plan), &out, false, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), "no changes") {
		t.Errorf("empty plan should report no changes:\n%s", out.String())
	}
}

func TestRunMarkdownFormat(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"--format=markdown", fixture}, strings.NewReader(""), &out, false, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), "## permadiff") {
		t.Errorf("markdown header missing")
	}
}

func TestRunExplain(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"--explain", "aws_iam_policy.noop", fixture}, strings.NewReader(""), &out, false, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), "verdict: perma-diff noise") {
		t.Errorf("explain verdict missing:\n%s", out.String())
	}
}

func TestRunErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		in   string
		want string
	}{
		{"unknown format", []string{"--format=xml", fixture}, "", "unknown --format"},
		{"missing explain address", []string{"--explain", "aws_nope.x", fixture}, "", "not found"},
		{"two file args", []string{"a.json", "b.json"}, "", "at most one"},
		{"bad stdin", nil, "not json", "decoding plan JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := run(tc.args, strings.NewReader(tc.in), &out, false, false)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// Regression: with no plan file and an interactive stdin (stdinTTY=true),
// the tool must fail fast with guidance, never block reading from the terminal.
func TestRunNoPlanOnTTYFailsFast(t *testing.T) {
	var out bytes.Buffer
	// strings.Reader stands in for the terminal; the stdinTTY=true flag is what
	// makes run refuse to read it. If the guard regressed, this would hang.
	err := run([]string{"--explain", "aws_iam_policy.app"}, strings.NewReader(""), &out, false, true)
	if err == nil || !strings.Contains(err.Error(), "no plan given") {
		t.Errorf("want a 'no plan given' error, got %v", err)
	}
}

func TestRunHelpIsErrHelp(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"-h"}, strings.NewReader(""), &out, false, false)
	if !errors.Is(err, flag.ErrHelp) {
		t.Errorf("-h should surface flag.ErrHelp (main exits 0 on it), got %v", err)
	}
}

func TestRunVersion(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"--version"}, strings.NewReader(""), &out, false, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), "permadiff") {
		t.Errorf("version output: %q", out.String())
	}
}

func TestEffectiveVersion(t *testing.T) {
	cases := []struct {
		name, ldflags, buildInfo, want string
	}{
		{"ldflags wins over build info", "v0.1.0", "v9.9.9", "v0.1.0"},
		{"go install of a tagged version", "dev", "v0.1.0", "v0.1.0"},
		{"go install @latest pseudo-version", "dev", "v0.0.0-20260101000000-abcdef0", "v0.0.0-20260101000000-abcdef0"},
		{"local build reports devel falls back", "dev", "(devel)", "dev"},
		{"no build info version falls back", "dev", "", "dev"},
	}
	for _, c := range cases {
		if got := effectiveVersion(c.ldflags, c.buildInfo); got != c.want {
			t.Errorf("%s: effectiveVersion(%q, %q) = %q, want %q", c.name, c.ldflags, c.buildInfo, got, c.want)
		}
	}
}

// FuzzRun feeds arbitrary bytes through the whole pipeline (parse -> classify
// -> render) the way a `terraform show -json` pipe would. The contract is
// simple: permadiff must never panic on any input — it returns a report or an
// error. Run the fuzzer with: go test -run=x -fuzz=FuzzRun ./cmd/permadiff
func FuzzRun(f *testing.F) {
	f.Add([]byte(`{"format_version":"1.2","resource_changes":[]}`))
	f.Add([]byte(`{"resource_changes":[{"address":"aws_x.y","change":{"actions":["update"],"before":{"policy":"{}"},"after":{"policy":"{ }"}}}]}`))
	f.Add([]byte(`{"resource_changes":[{"address":"a","change":{"actions":["update"],"before":null,"after":null,"after_unknown":true}}]}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		var out bytes.Buffer
		// "-" reads the plan from the provided reader; the only invariant under
		// test is that this never panics, whatever the bytes are.
		_ = run([]string{"-"}, bytes.NewReader(data), &out, false, false)
	})
}
