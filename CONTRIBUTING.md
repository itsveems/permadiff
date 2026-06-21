# Contributing to permadiff

Thanks for helping. Most contributions are new perma-diff patterns, and they
usually need **no Go code** — just a catalogue entry plus two fixtures (the no-op
and its mandatory "real twin").

See the **Contributing a pattern** section of the
[README](README.md#contributing-a-pattern) for the step-by-step, and the design
rules — "prove it or it's real" and "when in doubt, not equal" — in the README's
**How it decides** section.

The one report always prioritised is a **real change shown as noise** (a false
positive): that is the single thing permadiff must never do. Open an issue with
the plan snippet and it will be treated as a bug, not a feature request.

By contributing you agree that your contributions are licensed under the project's
[MIT licence](LICENSE).
