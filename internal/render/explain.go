package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/itsveems/permadiff/internal/classify"
)

// Explain writes the full canonicalisation reasoning for one resource:
// every differing attribute, every pattern tried, the canonical forms both
// sides reduced to, and the complete fix with HCL snippets.
func Explain(w io.Writer, rr *classify.ResourceReport, st Style) {
	fmt.Fprintf(w, "\n%s %s %s\n", st.actionSymbol(rr.Action), st.Bold(sanitizeTerm(rr.Address)), st.Dim("("+rr.Action+")"))

	if !rr.Analyzed {
		fmt.Fprintf(w, "\n%s\n\n", wrapIndent("This change is a "+rr.Action+", not an in-place update. permadiff only analyses updates for perma-diff noise; creates, deletes, and replaces are real by definition and are left to your normal review.", "  "))
		return
	}

	switch rr.Class {
	case classify.ClassNoise:
		fmt.Fprintf(w, "  %s\n", st.Green(fmt.Sprintf("verdict: perma-diff noise (%s confidence) — every differing attribute is a semantic no-op", rr.Confidence)))
	case classify.ClassLikelyNoise:
		fmt.Fprintf(w, "  %s\n", st.Magenta(fmt.Sprintf("verdict: likely perma-diff noise (%s confidence) — explained, but not certain enough to call noise", rr.Confidence)))
	default:
		fmt.Fprintf(w, "  %s\n", st.Yellow("verdict: real change — at least one attribute genuinely differs"))
	}

	for _, f := range rr.Findings {
		fmt.Fprintf(w, "\n  %s\n", st.Bold("attribute "+sanitizeTerm(f.Attribute)))
		if f.Sensitive {
			fmt.Fprintf(w, "    %s\n", st.Red("sensitive: values redacted below"))
		}
		if f.Unknown {
			fmt.Fprintf(w, "    after value: %s\n", st.Cyan("(known after apply)"))
		}

		if len(f.Attempts) == 0 {
			fmt.Fprintf(w, "    %s\n", st.Dim("no catalog pattern matches this (resource type, attribute) pair"))
		}
		for _, a := range f.Attempts {
			verdict := st.Yellow("could not prove equality")
			if a.Equal {
				verdict = st.Green("proved semantically equal")
			}
			fmt.Fprintf(w, "    pattern %s: %s\n", st.Cyan(a.PatternID), verdict)
			switch {
			case f.Sensitive:
				// Canonicalizer details may embed raw values; never show them
				// for sensitive attributes.
				fmt.Fprintln(w, st.Dim(wrapIndent("(reasoning detail redacted — sensitive attribute)", "      ")))
			case a.Detail != "":
				fmt.Fprintln(w, st.Dim(wrapIndent(a.Detail, "      ")))
			}
		}

		if !f.Sensitive && f.Result.BeforeCanon != "" {
			fmt.Fprintf(w, "    %s\n%s\n", st.Dim("canonicalised before:"), indentBlock(f.Result.BeforeCanon, "      "))
			fmt.Fprintf(w, "    %s\n%s\n", st.Dim("canonicalised after:"), indentBlock(f.Result.AfterCanon, "      "))
		}
		if f.Note != "" {
			fmt.Fprintln(w, st.Yellow(wrapIndent("note: "+f.Note, "    ")))
		}

		if f.Pattern != nil {
			p := f.Pattern
			fmt.Fprintf(w, "\n    %s\n", st.Bold("why this is a no-op"))
			fmt.Fprintln(w, wrapIndent(p.Why, "      "))
			if p.Fix.Summary != "" {
				fmt.Fprintf(w, "    %s\n", st.Bold(st.Green("recommended fix")))
				fmt.Fprintln(w, wrapIndent(p.Fix.Summary, "      "))
			}
			if p.Fix.HCLBefore != "" {
				fmt.Fprintf(w, "      %s\n%s\n", st.Dim("# before"), indentBlock(strings.TrimRight(p.Fix.HCLBefore, "\n"), "      "))
				fmt.Fprintf(w, "      %s\n%s\n", st.Dim("# after"), indentBlock(strings.TrimRight(p.Fix.HCLAfter, "\n"), "      "))
			}
			if p.Fix.Warning != "" {
				fmt.Fprintln(w, st.Red(wrapIndent("warning: "+p.Fix.Warning, "      ")))
			}
			if len(p.Docs) > 0 {
				fmt.Fprintf(w, "    %s\n", st.Dim("references:"))
				for _, d := range p.Docs {
					fmt.Fprintf(w, "      %s\n", st.Dim(d))
				}
			}
		}
	}
	fmt.Fprintln(w)
}
