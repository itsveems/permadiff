package render

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/itsveems/permadiff/internal/canon"
)

// Style applies ANSI colours when enabled; every method is a no-op pass-through
// otherwise, so output stays clean under pipes, NO_COLOR, and --no-color.
type Style struct{ Enabled bool }

func (s Style) wrap(code, str string) string {
	if !s.Enabled || str == "" {
		return str
	}
	return "\x1b[" + code + "m" + str + "\x1b[0m"
}

func (s Style) Bold(v string) string    { return s.wrap("1", v) }
func (s Style) Dim(v string) string     { return s.wrap("2", v) }
func (s Style) Red(v string) string     { return s.wrap("31", v) }
func (s Style) Green(v string) string   { return s.wrap("32", v) }
func (s Style) Yellow(v string) string  { return s.wrap("33", v) }
func (s Style) Cyan(v string) string    { return s.wrap("36", v) }
func (s Style) Magenta(v string) string { return s.wrap("35", v) }
func (s Style) BoldCyan(v string) string {
	return s.wrap("1;36", v)
}

// actionSymbol returns terraform's glyph for an action label, colourised.
func (s Style) actionSymbol(action string) string {
	switch {
	case action == "create":
		return s.Green("+")
	case action == "delete":
		return s.Red("-")
	case action == "update":
		return s.Yellow("~")
	case strings.HasPrefix(action, "replace"):
		return s.Red("±")
	default:
		return s.Yellow("~")
	}
}

const wrapWidth = 96

// wrapIndent word-wraps text to wrapWidth columns, prefixing every line with
// indent. Single newlines in the input are treated as spaces.
func wrapIndent(text, indent string) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	line := indent
	lineLen := len(indent)
	for i, w := range words {
		wl := utf8.RuneCountInString(w)
		if i > 0 && lineLen+1+wl > wrapWidth {
			b.WriteString(line)
			b.WriteByte('\n')
			line = indent + w
			lineLen = len(indent) + wl
			continue
		}
		if i > 0 {
			line += " "
			lineLen++
		}
		line += w
		lineLen += wl
	}
	b.WriteString(line)
	return b.String()
}

const redacted = "(sensitive value redacted)"

// compactValue renders an attribute value for one-line display, redacting
// sensitive values and truncating long ones.
func compactValue(v any, sensitive bool) string {
	if sensitive {
		return redacted
	}
	c := canon.Compact(v)
	const max = 60
	if utf8.RuneCountInString(c) > max {
		runes := []rune(c)
		return string(runes[:max-1]) + "…"
	}
	return c
}

// plural renders "1 change" / "3 changes" (simple s-pluralisation).
func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

// sanitizeTerm strips control characters (ANSI escape injection) from plan-
// supplied strings (addresses, attribute names) before terminal display.
func sanitizeTerm(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

// mdCode neutralises backticks so plan-supplied strings (addresses with
// for_each keys, attribute names) cannot break out of a markdown code span.
func mdCode(s string) string {
	return strings.ReplaceAll(sanitizeTerm(s), "`", "'")
}

// mdHTML escapes a plan-supplied string for a raw-HTML context (<summary>).
// Backticks are neutralised too: GitHub still processes inline markdown
// between raw HTML tags, so a backtick could open a code span mid-summary.
func mdHTML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "`", "'")
	return r.Replace(sanitizeTerm(s))
}

// indentBlock prefixes every line of block with indent.
func indentBlock(block, indent string) string {
	lines := strings.Split(strings.TrimRight(block, "\n"), "\n")
	for i, l := range lines {
		lines[i] = indent + l
	}
	return strings.Join(lines, "\n")
}
