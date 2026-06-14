# Changelog

All notable changes to permadiff are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/).

## [0.1.0] — Unreleased

Initial release.

### Added
- Plan analysis for `terraform show -json` output (file or stdin):
  update-in-place changes are compared attribute by attribute and classified
  as perma-diff noise or real changes. Nothing is suppressed.
- Conservative canonicalisation engine: AWS policy JSON (IAM/S3/KMS/SQS/SNS
  grammar), generic JSON formatting, set-semantic lists, security-group rule
  sets, scalar type coercion, Route 53 name normalisation, empty-collection
  equivalence, ECS container-definition normalisation.
- YAML pattern catalog (12 seed AWS pattern families, 17 entries) embedded in the binary,
  extensible at runtime via `--catalog`; every entry carries a plain-English
  explanation and a prioritised fix (HCL fix first, narrowly scoped
  `ignore_changes` only for irreducible churn, with warnings).
- Confidence levels: only high-confidence findings count as noise;
  medium-confidence findings (e.g. `tags_all` computed churn) stay with the
  real changes, annotated.
- Colourised terminal renderer and `--format=markdown` (GitHub PR-comment
  ready); sensitive values are always redacted.
- `--explain <address>`: full canonicalisation reasoning, every pattern tried,
  canonical before/after, and the complete fix with HCL snippets.
- Test suite with per-pattern fixture pairs: every no-op fixture has a
  look-alike real-change twin that must classify as real (false-positive
  guards).
- Conservative-safety hardening: exact-precision
  number comparison (`json.Number`, no float64 collapse of large integers);
  keyed last-wins ECS lists (environment/secrets/systemControls/ulimits) keep
  order when duplicate keys exist; the `"*"` ≡ `{"AWS":"*"}` Principal collapse
  is gated to `Effect: Allow` and never applied to `NotPrincipal` or any `Deny`
  statement (under Deny the two forms deny different principal sets, so the
  collapse would hide a real change — e.g. a `DenyInsecureTransport` that stops
  blocking anonymous access); trailing-JSON rejection; whole-object boolean sensitivity
  marks honoured; partially-unknown attributes never waved through by computed
  patterns; markdown/terminal output escaped against hostile addresses; the
  generic JSON pattern restricted to a curated allowlist so verbatim-bytes
  attributes (`user_data`, SSM parameter values) are never called noise.

### Known limitations
- AWS provider only; seed catalog of 12 pattern families; top-level attribute
  granularity. See README "Known limitations".
