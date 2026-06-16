// permadiff reads `terraform show -json <planfile>` output and separates
// perma-diff noise (semantic no-op updates caused by provider/API
// normalisation) from real changes — explaining each no-op and suggesting the
// fix. Fully offline and deterministic: rule-based against a YAML catalog,
// no network, no telemetry.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/itsveems/permadiff/internal/catalog"
	"github.com/itsveems/permadiff/internal/classify"
	"github.com/itsveems/permadiff/internal/plan"
	"github.com/itsveems/permadiff/internal/render"
)

var version = "dev" // overridden via -ldflags "-X main.version=..."

const usage = `permadiff — find perma-diffs (semantic no-ops) in a Terraform plan

usage:
  terraform show -json plan.tfplan | permadiff [flags]
  permadiff [flags] plan.json

flags:
  --format string    output format: terminal | markdown   (default "terminal")
  --explain string   show full canonicalisation reasoning + fix for one
                     resource address (e.g. aws_iam_policy.app)
  --catalog string   extra pattern catalog YAML; its patterns take precedence
                     over the built-in catalog
  --no-color         disable colours (also honours NO_COLOR and non-TTY pipes)
  --color            force colours even when piping
  --version          print version and exit

The tool shows every change. It never suppresses anything: it only explains
which in-place updates are provider-normalisation noise, and how to fix them.
`

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, isCharDevice(os.Stdout), isCharDevice(os.Stdin)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return // -h/--help: usage already printed, exit 0
		}
		fmt.Fprintf(os.Stderr, "permadiff: %v\n", err)
		os.Exit(1)
	}
}

// isCharDevice reports whether f is an interactive terminal rather than a pipe
// or regular file. Used both to decide on colour for stdout and to refuse to
// block on an empty stdin when no plan file was given.
func isCharDevice(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func run(args []string, stdin io.Reader, stdout io.Writer, stdoutTTY, stdinTTY bool) error {
	fs := flag.NewFlagSet("permadiff", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	var (
		format      = fs.String("format", "terminal", "")
		explainAddr = fs.String("explain", "", "")
		catalogPath = fs.String("catalog", "", "")
		noColor     = fs.Bool("no-color", false, "")
		forceColor  = fs.Bool("color", false, "")
		showVersion = fs.Bool("version", false, "")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Fprintf(stdout, "permadiff %s\n", version)
		return nil
	}

	in, name, err := openInput(fs.Args(), stdin, stdinTTY)
	if err != nil {
		return err
	}
	defer in.Close()

	p, err := plan.Load(in)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	cat, err := catalog.LoadWithExtra(*catalogPath)
	if err != nil {
		return err
	}
	rep := classify.Analyze(p, cat)

	st := render.Style{Enabled: colorEnabled(stdoutTTY, *noColor, *forceColor)}

	if *explainAddr != "" {
		rr := rep.Find(*explainAddr)
		if rr == nil {
			return fmt.Errorf("address %q not found among the plan's changes (no-ops and data reads are excluded)", *explainAddr)
		}
		render.Explain(stdout, rr, st)
		return nil
	}

	switch *format {
	case "terminal", "":
		render.Terminal(stdout, rep, st)
	case "markdown", "md":
		render.Markdown(stdout, rep)
	default:
		return fmt.Errorf("unknown --format %q (valid: terminal, markdown)", *format)
	}
	return nil
}

// openInput returns the plan JSON stream: an explicit file path, "-", or
// stdin when input is piped in. With no argument and an interactive terminal
// on stdin there is nothing to read, so it errors rather than blocking forever.
func openInput(args []string, stdin io.Reader, stdinTTY bool) (io.ReadCloser, string, error) {
	switch {
	case len(args) > 1:
		return nil, "", fmt.Errorf("expected at most one plan file argument, got %d", len(args))
	case len(args) == 1 && args[0] != "-":
		f, err := os.Open(args[0])
		if err != nil {
			return nil, "", err
		}
		return f, args[0], nil
	case len(args) == 0 && stdinTTY:
		return nil, "", errors.New("no plan given — append a plan file (permadiff [flags] plan.json) or pipe one in (terraform show -json plan.tfplan | permadiff). Run permadiff --help for usage")
	default: // piped stdin, or an explicit "-"
		return io.NopCloser(stdin), "stdin", nil
	}
}

func colorEnabled(isTTY, noColor, forceColor bool) bool {
	if noColor {
		return false
	}
	if forceColor {
		return true
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return isTTY
}
