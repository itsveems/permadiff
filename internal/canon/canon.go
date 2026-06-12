// Package canon implements the canonicalisation strategies that decide
// whether a changed attribute is semantically identical before and after.
//
// Every strategy follows one rule above all others: when in doubt, NOT equal.
// A parse error, an unexpected type, an unrecognised shape — all of these
// mean "treat as a real change". False negatives (missed noise) are fine;
// false positives (real change labelled noise) are forbidden.
package canon

import (
	"fmt"
	"sort"
)

// Result is the outcome of canonicalising one attribute's before/after pair.
type Result struct {
	// Equal is true only when before and after are semantically identical
	// after canonicalisation, with no ambiguity.
	Equal bool
	// BeforeCanon / AfterCanon are human-readable canonical renderings,
	// shown by --explain.
	BeforeCanon string
	AfterCanon  string
	// Detail describes what the canonicalizer did / observed, e.g.
	// "sorted 3 Statement entries; normalised Action scalars to lists".
	Detail string
	// Note is an advisory attached even when Equal is false, e.g. the
	// security-group description ForceNew quirk.
	Note string
}

// Func is a canonicalisation strategy. It must never return Equal=true
// unless certain. opts come from the catalog entry (strategy-specific).
type Func func(before, after any, opts map[string]any) Result

var registry = map[string]Func{}

func register(name string, f Func) {
	registry[name] = f
}

// Lookup returns the named strategy or an error listing valid names.
func Lookup(name string) (Func, error) {
	f, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown canonicalizer %q (valid: %v)", name, Names())
	}
	return f, nil
}

// Names lists registered strategy names, for error messages and docs.
func Names() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// notEqual is the conservative default result.
func notEqual(detail string) Result {
	return Result{Equal: false, Detail: detail}
}
