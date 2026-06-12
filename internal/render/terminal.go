// Package render turns a classification report into terminal or markdown
// output. Renderers never decide anything — they only present what classify
// concluded, redacting sensitive values.
package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/itsveems/permadiff/internal/classify"
)

// Terminal writes the default colourised report.
func Terminal(w io.Writer, rep *classify.Report, st Style) {
	fmt.Fprintf(w, "\n%s  %s\n", st.BoldCyan("permadiff"), headline(rep, st))

	noise := filter(rep, classify.ClassNoise)
	if len(noise) > 0 {
		fmt.Fprintf(w, "\n%s %s\n%s\n",
			st.Bold(fmt.Sprintf("PERMA-DIFF NOISE (%d)", rep.Noise)),
			st.Dim("— semantically identical before and after; nothing changes in AWS"),
			st.Dim(strings.Repeat("─", 78)))
		for _, rr := range noise {
			renderNoiseResource(w, rr, st)
		}
	}

	real := append(filter(rep, classify.ClassReal), filter(rep, classify.ClassLikelyNoise)...)
	sortByAddress(real)
	if len(real) > 0 {
		fmt.Fprintf(w, "\n%s %s\n%s\n",
			st.Bold(fmt.Sprintf("REAL CHANGES (%d)", rep.RealTotal())),
			st.Dim("— review as usual; nothing here is suppressed"),
			st.Dim(strings.Repeat("─", 78)))
		for _, rr := range real {
			renderRealResource(w, rr, st)
		}
	}

	if rep.Total == 0 {
		fmt.Fprintf(w, "\n%s\n", st.Dim("Plan contains no changes."))
	}
	fmt.Fprintf(w, "\n%s\n\n", st.Dim("↳ permadiff --explain <address> shows the full canonicalisation reasoning and HCL fixes."))
}

func headline(rep *classify.Report, st Style) string {
	if rep.Total == 0 {
		return st.Bold("0 changes")
	}
	noisePart := plural(rep.Noise, "perma-diff no-op")
	if rep.Noise > 0 {
		noisePart += " (with fixes)"
	}
	return fmt.Sprintf("%s: %s · %s",
		st.Bold(plural(rep.Total, "change")),
		st.Green(noisePart),
		st.Yellow(plural(rep.RealTotal(), "real change")))
}

func renderNoiseResource(w io.Writer, rr classify.ResourceReport, st Style) {
	fmt.Fprintf(w, "\n  %s %s\n", st.Yellow("~"), st.Bold(sanitizeTerm(rr.Address)))
	for _, g := range groupByPattern(rr.Findings) {
		f := g.findings[0]
		title, why, fixSummary := findingTexts(f)
		fmt.Fprintf(w, "      %s %s %s\n", st.Cyan("•"), st.Bold(sanitizeTerm(strings.Join(g.attrs, ", "))), st.Dim("— "+title))
		if why != "" {
			fmt.Fprintln(w, st.Dim(wrapIndent(why, "        ")))
		}
		if fixSummary != "" {
			fmt.Fprintf(w, "        %s %s\n", st.Green("fix:"), strings.TrimPrefix(wrapIndent(fixSummary, "             "), "             "))
		}
	}
}

// patternGroup collects no-op findings of one resource that matched the same
// pattern, so companion attributes (e.g. ECS revision/arn) render once.
type patternGroup struct {
	attrs    []string
	findings []classify.AttrFinding
}

func groupByPattern(findings []classify.AttrFinding) []patternGroup {
	var out []patternGroup
	index := map[string]int{}
	for _, f := range findings {
		key := "unmatched"
		if f.Pattern != nil {
			key = f.Pattern.ID
		}
		i, ok := index[key]
		if !ok {
			i = len(out)
			index[key] = i
			out = append(out, patternGroup{})
		}
		out[i].attrs = append(out[i].attrs, f.Attribute)
		out[i].findings = append(out[i].findings, f)
	}
	return out
}

func renderRealResource(w io.Writer, rr classify.ResourceReport, st Style) {
	fmt.Fprintf(w, "\n  %s %s %s\n", st.actionSymbol(rr.Action), st.Bold(sanitizeTerm(rr.Address)), st.Dim("("+rr.Action+")"))
	if !rr.Analyzed {
		return // create/delete/replace: listed plainly, other tools own these
	}
	for _, f := range rr.Findings {
		attr := sanitizeTerm(f.Attribute)
		switch {
		case f.NoOp && rr.Class == classify.ClassLikelyNoise:
			fmt.Fprintf(w, "      %s %s\n", st.Bold(attr+":"), arrowValue(f, st))
			// resource-level confidence: a single high-confidence finding
			// can't speak for a resource the classifier only rated medium
			label := fmt.Sprintf("possible perma-diff noise (%s confidence): %s", rr.Confidence, findingTitle(f))
			fmt.Fprintf(w, "      %s %s\n", st.Magenta("◐"), st.Magenta(label))
		case f.NoOp:
			// noisy attribute inside an otherwise-real change
			fmt.Fprintf(w, "      %s\n", st.Dim(attr+": no-op ("+findingTitle(f)+")"))
		default:
			fmt.Fprintf(w, "      %s %s\n", st.Bold(attr+":"), arrowValue(f, st))
		}
		if f.Note != "" {
			fmt.Fprintln(w, st.Yellow(wrapIndent("note: "+f.Note, "        ")))
		}
	}
	if rr.NoOpCount > 0 && rr.Class == classify.ClassReal {
		fmt.Fprintln(w, st.Dim(fmt.Sprintf("      (%d of %d differing attributes are no-op noise; the rest are real)", rr.NoOpCount, rr.NoOpCount+rr.RealCount)))
	}
}

func arrowValue(f classify.AttrFinding, st Style) string {
	if f.Unknown {
		return fmt.Sprintf("%s → %s", compactValue(f.Before, f.Sensitive), st.Cyan("(known after apply)"))
	}
	return fmt.Sprintf("%s → %s", compactValue(f.Before, f.Sensitive), compactValue(f.After, f.Sensitive))
}

func findingTitle(f classify.AttrFinding) string {
	if f.Pattern != nil {
		return f.Pattern.Title
	}
	return "unexplained change"
}

func findingTexts(f classify.AttrFinding) (title, why, fix string) {
	title = findingTitle(f)
	if f.Pattern != nil {
		why = f.Pattern.Why
		fix = f.Pattern.Fix.Summary
	}
	return
}

func filter(rep *classify.Report, class classify.Class) []classify.ResourceReport {
	var out []classify.ResourceReport
	for _, rr := range rep.Resources {
		if rr.Class == class {
			out = append(out, rr)
		}
	}
	return out
}

func sortByAddress(rs []classify.ResourceReport) {
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Address < rs[j].Address })
}
