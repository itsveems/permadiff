// Package catalog loads and validates the YAML perma-diff pattern catalog
// and answers "which pattern matches this (resource type, attribute)?".
package catalog

import (
	"fmt"
	"os"
	"path"

	"gopkg.in/yaml.v3"

	"github.com/itsveems/permadiff/internal/canon"
	"github.com/itsveems/permadiff/patterns"
)

// Confidence of a no-op finding. Only High findings are counted as noise in
// the summary; Medium findings are surfaced alongside real changes.
type Confidence string

const (
	High   Confidence = "high"
	Medium Confidence = "medium"
)

// Less reports whether c is weaker than o (medium < high).
func (c Confidence) Less(o Confidence) bool { return c == Medium && o == High }

// Kind of pattern.
const (
	KindCanonical = "canonical" // compare before/after through a canonicalizer
	KindComputed  = "computed"  // matches attributes flipping to (known after apply)
)

// Fix is the recommended remediation for a pattern.
type Fix struct {
	Summary   string `yaml:"summary"`
	HCLBefore string `yaml:"hcl_before"`
	HCLAfter  string `yaml:"hcl_after"`
	Warning   string `yaml:"warning"`
}

// Match selects which (resource type, attribute) pairs a pattern applies to.
// Entries are exact names or path.Match globs (*, ?). ExcludeAttributes wins
// over Attributes — used to carve byte-sensitive attributes (e.g. user_data)
// out of broad fallbacks.
type Match struct {
	ResourceTypes     []string `yaml:"resource_types"`
	Attributes        []string `yaml:"attributes"`
	ExcludeAttributes []string `yaml:"exclude_attributes"`
}

func (m Match) covers(resourceType, attribute string) bool {
	return matchAny(m.ResourceTypes, resourceType) &&
		matchAny(m.Attributes, attribute) &&
		!matchAny(m.ExcludeAttributes, attribute)
}

// Pattern is one catalog entry.
type Pattern struct {
	ID            string         `yaml:"id"`
	Title         string         `yaml:"title"`
	Kind          string         `yaml:"kind"` // "" means canonical
	Match         Match          `yaml:"match"`
	Canonicalizer string         `yaml:"canonicalizer"`
	Opts          map[string]any `yaml:"canonicalizer_opts"`
	Confidence    Confidence     `yaml:"confidence"`
	Why           string         `yaml:"why"`
	Fix           Fix            `yaml:"fix"`
	Docs          []string       `yaml:"docs"`
}

// IsComputed reports whether this is a computed-churn pattern.
func (p *Pattern) IsComputed() bool { return p.Kind == KindComputed }

// Catalog is an ordered pattern list; first match wins.
type Catalog struct {
	Version  int        `yaml:"version"`
	Patterns []*Pattern `yaml:"patterns"`
}

// LoadDefault parses the embedded catalog.
func LoadDefault() (*Catalog, error) {
	return Parse(patterns.Default, "embedded catalog")
}

// LoadWithExtra parses the embedded catalog plus an optional user-supplied
// YAML file whose patterns take precedence (they are matched first).
func LoadWithExtra(extraPath string) (*Catalog, error) {
	base, err := LoadDefault()
	if err != nil {
		return nil, err
	}
	if extraPath == "" {
		return base, nil
	}
	raw, err := os.ReadFile(extraPath)
	if err != nil {
		return nil, fmt.Errorf("reading extra catalog: %w", err)
	}
	extra, err := Parse(raw, extraPath)
	if err != nil {
		return nil, err
	}
	merged := &Catalog{Version: base.Version}
	merged.Patterns = append(merged.Patterns, extra.Patterns...)
	// An extra pattern reusing a built-in id OVERRIDES it: the shadowed
	// built-in is dropped entirely, so ids stay unique across the merged
	// catalog (renderers group findings by pattern id).
	override := map[string]bool{}
	for _, p := range extra.Patterns {
		override[p.ID] = true
	}
	for _, p := range base.Patterns {
		if !override[p.ID] {
			merged.Patterns = append(merged.Patterns, p)
		}
	}
	return merged, nil
}

// Parse decodes and validates catalog YAML. Every error names the offending
// pattern so contributors get actionable messages.
func Parse(raw []byte, source string) (*Catalog, error) {
	var c Catalog
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	seen := map[string]bool{}
	for i, p := range c.Patterns {
		where := fmt.Sprintf("%s: pattern %d (id %q)", source, i+1, p.ID)
		if p.ID == "" {
			return nil, fmt.Errorf("%s: missing id", where)
		}
		if seen[p.ID] {
			return nil, fmt.Errorf("%s: duplicate id", where)
		}
		seen[p.ID] = true
		if p.Kind == "" {
			p.Kind = KindCanonical
		}
		if p.Kind != KindCanonical && p.Kind != KindComputed {
			return nil, fmt.Errorf("%s: kind must be %q or %q", where, KindCanonical, KindComputed)
		}
		if p.Kind == KindCanonical {
			if _, err := canon.Lookup(p.Canonicalizer); err != nil {
				return nil, fmt.Errorf("%s: %w", where, err)
			}
		}
		if p.Confidence != High && p.Confidence != Medium {
			return nil, fmt.Errorf("%s: confidence must be \"high\" or \"medium\"", where)
		}
		if len(p.Match.ResourceTypes) == 0 || len(p.Match.Attributes) == 0 {
			return nil, fmt.Errorf("%s: match.resource_types and match.attributes are required", where)
		}
		for _, globs := range [][]string{p.Match.ResourceTypes, p.Match.Attributes, p.Match.ExcludeAttributes} {
			for _, g := range globs {
				// path.Match validates pattern syntax regardless of the name;
				// a malformed glob would otherwise be silently dead forever.
				if _, err := path.Match(g, ""); err != nil {
					return nil, fmt.Errorf("%s: invalid glob %q: %w", where, g, err)
				}
			}
		}
		if p.Why == "" {
			return nil, fmt.Errorf("%s: why is required — every finding must explain itself", where)
		}
	}
	return &c, nil
}

// FindCanonical returns the first canonical pattern matching the pair, or nil.
func (c *Catalog) FindCanonical(resourceType, attribute string) *Pattern {
	return c.find(resourceType, attribute, KindCanonical)
}

// FindCanonicalAll returns every canonical pattern matching the pair, in
// catalog order. The classifier tries each in turn: generic fallbacks overlap
// specific entries, and a pattern that fails to prove equality must not
// shadow a later one that can.
func (c *Catalog) FindCanonicalAll(resourceType, attribute string) []*Pattern {
	var out []*Pattern
	for _, p := range c.Patterns {
		if p.Kind != KindCanonical {
			continue
		}
		if p.Match.covers(resourceType, attribute) {
			out = append(out, p)
		}
	}
	return out
}

// FindComputed returns the first computed pattern matching the pair, or nil.
func (c *Catalog) FindComputed(resourceType, attribute string) *Pattern {
	return c.find(resourceType, attribute, KindComputed)
}

func (c *Catalog) find(resourceType, attribute, kind string) *Pattern {
	for _, p := range c.Patterns {
		if p.Kind != kind {
			continue
		}
		if p.Match.covers(resourceType, attribute) {
			return p
		}
	}
	return nil
}

func matchAny(globs []string, name string) bool {
	for _, g := range globs {
		if g == name {
			return true
		}
		if ok, err := path.Match(g, name); err == nil && ok {
			return true
		}
	}
	return false
}
