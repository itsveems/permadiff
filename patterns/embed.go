// Package patterns embeds the default perma-diff pattern catalog so the
// binary is self-contained. The YAML lives here, at the repository top level,
// because it is the file community contributions edit.
package patterns

import _ "embed"

//go:embed catalog.yaml
var Default []byte
