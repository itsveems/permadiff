// Package classify walks a parsed plan, diffs each update attribute by
// attribute, and uses the pattern catalog + canonicalizers to separate
// perma-diff noise from real changes.
//
// The cardinal rule, inherited from the canonicalizers and enforced again
// here: a change is noise only when EVERY differing attribute is proven a
// no-op. One unexplained attribute makes the whole resource a real change.
package classify

import (
	"sort"

	"github.com/itsveems/permadiff/internal/canon"
	"github.com/itsveems/permadiff/internal/catalog"
	"github.com/itsveems/permadiff/internal/plan"
)

// Class is the verdict for one resource change.
type Class string

const (
	// ClassNoise: every differing attribute is a high-confidence no-op.
	ClassNoise Class = "noise"
	// ClassLikelyNoise: every differing attribute is explained, but at least
	// one only with medium confidence. Surfaced WITH the real changes —
	// medium is not certain enough to call noise.
	ClassLikelyNoise Class = "likely-noise"
	// ClassReal: at least one attribute genuinely changes (or the action is
	// create/delete/replace, which are real by definition).
	ClassReal Class = "real"
)

// Attempt records one pattern tried against an attribute, for --explain.
type Attempt struct {
	PatternID string
	Equal     bool
	Detail    string
}

// AttrFinding is the verdict for one differing attribute.
type AttrFinding struct {
	Attribute  string
	Sensitive  bool // renderers must redact values
	Unknown    bool // flips to "(known after apply)"
	NoOp       bool
	Confidence catalog.Confidence // valid when NoOp
	Pattern    *catalog.Pattern   // matched pattern; nil for unexplained changes
	Result     canon.Result       // canonical forms + reasoning detail
	Note       string             // advisory (e.g. SG description ForceNew quirk)
	Attempts   []Attempt          // every pattern tried, in order
	Before     any
	After      any
}

// ResourceReport is the verdict for one resource change.
type ResourceReport struct {
	Address    string
	Type       string
	Action     string
	Analyzed   bool // true for in-place updates (the quadrant we analyse)
	Class      Class
	Confidence catalog.Confidence
	Findings   []AttrFinding
	NoOpCount  int
	RealCount  int
}

// Report is the full classification of a plan.
type Report struct {
	TerraformVersion string
	Resources        []ResourceReport
	Total            int // all real-world changes (everything but no-op/read)
	Noise            int // ClassNoise
	LikelyNoise      int // ClassLikelyNoise
	Real             int // ClassReal
}

// RealTotal is what the headline calls "real changes": everything we did not
// prove to be noise with high confidence.
func (r *Report) RealTotal() int { return r.Real + r.LikelyNoise }

// Find returns the report for one resource address, or nil.
func (r *Report) Find(address string) *ResourceReport {
	for i := range r.Resources {
		if r.Resources[i].Address == address {
			return &r.Resources[i]
		}
	}
	return nil
}

// Analyze classifies every resource change in the plan.
func Analyze(p *plan.Plan, cat *catalog.Catalog) *Report {
	rep := &Report{TerraformVersion: p.TerraformVersion}
	for _, rc := range p.ResourceChanges {
		if rc.Mode != "managed" {
			continue // data source reads are not changes
		}
		if rc.Change.IsNoOp() || rc.Change.IsRead() {
			continue
		}
		rr := ResourceReport{
			Address: rc.Address,
			Type:    rc.Type,
			Action:  rc.Change.ActionLabel(),
		}
		if rc.Change.IsUpdate() {
			rr.Analyzed = true
			analyzeUpdate(&rr, rc, cat)
		} else {
			rr.Class = ClassReal // create/destroy/replace: real by definition
		}
		rep.Resources = append(rep.Resources, rr)
	}
	sort.Slice(rep.Resources, func(i, j int) bool {
		return rep.Resources[i].Address < rep.Resources[j].Address
	})
	for _, rr := range rep.Resources {
		rep.Total++
		switch rr.Class {
		case ClassNoise:
			rep.Noise++
		case ClassLikelyNoise:
			rep.LikelyNoise++
		default:
			rep.Real++
		}
	}
	return rep
}

func analyzeUpdate(rr *ResourceReport, rc plan.ResourceChange, cat *catalog.Catalog) {
	ch := rc.Change
	for _, attr := range changedAttrs(ch) {
		f := AttrFinding{
			Attribute: attr,
			Unknown:   ch.UnknownTop(attr),
			Sensitive: ch.SensitiveTop(attr),
			Before:    ch.Before[attr],
			After:     ch.After[attr],
		}
		switch {
		case ch.WhollyUnknown(attr):
			// The entire attribute flips to (known after apply): there are no
			// values to compare, so only a computed-churn pattern can explain it.
			classifyUnknown(&f, rc.Type, cat)
		case f.Unknown:
			// Partially unknown: some leaves are unknown but others are known
			// and may have really changed. No pattern gets to wave this
			// through without a comparison — conservative: real.
			f.Result.Detail = "partially unknown after apply; the known portion cannot be proven a no-op — treated as a real change"
		default:
			classifyValue(&f, rc.Type, cat)
		}
		rr.Findings = append(rr.Findings, f)
	}

	if len(rr.Findings) == 0 {
		// An update with no top-level attribute differences we can see —
		// be honest and conservative: real, with nothing suppressed.
		rr.Class = ClassReal
		return
	}

	allNoOp, allComputed := true, true
	conf := catalog.High
	for i := range rr.Findings {
		f := &rr.Findings[i]
		if !f.NoOp {
			allNoOp = false
			rr.RealCount++
			continue
		}
		rr.NoOpCount++
		if f.Confidence.Less(conf) {
			conf = f.Confidence
		}
		if !f.Unknown {
			allComputed = false
		}
	}
	switch {
	case !allNoOp:
		rr.Class = ClassReal
	default:
		// When the ONLY findings are computed flips to (known after apply),
		// we never saw a comparable value — cap at medium no matter what the
		// catalog says, so a value-less plan can't be called certain noise.
		if allComputed {
			conf = catalog.Medium
		}
		rr.Confidence = conf
		if conf == catalog.High {
			rr.Class = ClassNoise
		} else {
			rr.Class = ClassLikelyNoise
		}
	}
}

// changedAttrs returns the sorted top-level attribute names that differ
// between before and after, or that flip to unknown.
func changedAttrs(ch plan.Change) []string {
	names := map[string]bool{}
	for k := range ch.Before {
		names[k] = true
	}
	for k := range ch.After {
		names[k] = true
	}
	for k := range ch.AfterUnknown {
		names[k] = true
	}
	var out []string
	for k := range names {
		if ch.UnknownTop(k) {
			out = append(out, k)
			continue
		}
		b, hasB := ch.Before[k]
		a, hasA := ch.After[k]
		if !hasB && !hasA {
			continue
		}
		if !canon.DeepEqual(b, a) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func classifyUnknown(f *AttrFinding, resourceType string, cat *catalog.Catalog) {
	p := cat.FindComputed(resourceType, f.Attribute)
	if p == nil {
		f.Result.Detail = "flips to (known after apply) and no computed-churn pattern covers it — treated as a real change"
		return
	}
	f.NoOp = true
	f.Pattern = p
	f.Confidence = p.Confidence
	f.Result.Detail = "flips to (known after apply); matched computed-churn pattern " + p.ID
	f.Attempts = append(f.Attempts, Attempt{PatternID: p.ID, Equal: true, Detail: f.Result.Detail})
}

func classifyValue(f *AttrFinding, resourceType string, cat *catalog.Catalog) {
	for _, p := range cat.FindCanonicalAll(resourceType, f.Attribute) {
		fn, err := canon.Lookup(p.Canonicalizer)
		if err != nil {
			continue // validated at load time; defensive
		}
		res := fn(f.Before, f.After, p.Opts)
		f.Attempts = append(f.Attempts, Attempt{PatternID: p.ID, Equal: res.Equal, Detail: res.Detail})
		if res.Note != "" && f.Note == "" {
			f.Note = res.Note
		}
		if res.Equal {
			f.NoOp = true
			f.Pattern = p
			f.Confidence = p.Confidence
			f.Result = res
			return
		}
		// Keep the most informative non-equal result for --explain.
		if f.Result.BeforeCanon == "" && res.BeforeCanon != "" {
			f.Result = res
		}
	}
	if f.Result.Detail == "" {
		f.Result.Detail = "no catalog pattern proved this equal — treated as a real change"
	}
}
