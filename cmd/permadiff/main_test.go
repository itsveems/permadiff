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
	if err := run([]string{fixture}, strings.NewReader(""), &out, false); err != nil {
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
	if err := run(nil, strings.NewReader(plan), &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), "no changes") {
		t.Errorf("empty plan should report no changes:\n%s", out.String())
	}
}

func TestRunMarkdownFormat(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"--format=markdown", fixture}, strings.NewReader(""), &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), "## permadiff") {
		t.Errorf("markdown header missing")
	}
}

func TestRunExplain(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"--explain", "aws_iam_policy.noop", fixture}, strings.NewReader(""), &out, false); err != nil {
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
			err := run(tc.args, strings.NewReader(tc.in), &out, false)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestRunHelpIsErrHelp(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"-h"}, strings.NewReader(""), &out, false)
	if !errors.Is(err, flag.ErrHelp) {
		t.Errorf("-h should surface flag.ErrHelp (main exits 0 on it), got %v", err)
	}
}

func TestRunVersion(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"--version"}, strings.NewReader(""), &out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), "permadiff") {
		t.Errorf("version output: %q", out.String())
	}
}
