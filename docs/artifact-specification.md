# Artifact specification recovery

`recover_artifact_specification` projects authenticated analysis Evidence into an
evidence-graded **specification** of an artifact: claims grouped by dimension,
each tagged with a provenance tier and linked to the Evidence that supports it,
with coverage and unknowns made explicit. It reuses Evidence that existing
analysis workflows already produced and runs no new analysis.

- MCP tool: `recover_artifact_specification`
- CLI command: `rea recover-artifact-specification`

## What it returns

An `ArtifactSpecification` carried as the `normalized_result` of a derived
Evidence record:

- `claims` — each has a `dimension` (`structure`, `interface`, `behavior`,
  `dependencies`), a `statement`, a `provenance` tier, `evidence_refs`, and an
  optional `contradiction`.
- `coverage` — per-dimension state (`covered` / `partial` / `not-covered`, with a
  reason), what was examined and not, explicit `unknowns`, and `limits`.
- `redaction` — whether caller-declared sensitive values were redacted.
- `reconstruction` — null unless the overlay was requested (see below).
- `diff` — null unless `compare_to` was supplied (see below).

## Provenance model

Provenance tiers reuse the Evidence confidence vocabulary plus `unknown`:

- `observed` / `derived` / `inferred` — the strongest confidence of the Evidence
  supporting the claim. A claim's tier is **never** stronger than its Evidence.
- `unknown` — reserved for claims with no supporting Evidence; a dimension with
  no Evidence is reported `not-covered`, not omitted.

The projection copies no Evidence payload values into claim text — only operation
and predicate identifiers — so transport credentials and marked sensitive values
cannot leak. Callers may additionally pass `sensitive_values` (literal strings)
to redact; secrecy is never inferred from names.

## Bounded output

`detail` defaults to `summary`, which caps the returned `claims` (see
`max_claims`) and marks `coverage.limits.truncated`. Request `detail: "full"` for
every claim. Coverage is always computed from the complete claim set.

## Reconstruction overlay (on demand)

Pass `reconstruction: true` to attach a read-only reconstruction-grade
assessment, projected from the existing obligation-ledger service: per-obligation
verdicts (`ready` / `partial` / `unknown`) and whether observed runtime Evidence
is still needed. Nothing is marked `ready` without observed proof. When behavioral
gaps remain, the overlay reports the capture workflow to run; it never launches
the target. Launching a capture under a grant is target-execution authority and is
gated pending a maintainer scope decision.

## Version diff

Pass `compare_to` (another version's `evidence_bundle` + `target_family`) to
include a `diff` of added, removed, and changed claims, keyed by `claim_id`, each
entry preserving provenance. The diff is computed on full projections of both
versions.

## Supported targets and phased coverage

The specification is produced by classifying each target family's existing
Evidence into dimensions. The MVP covers one representative per major evidence
shape:

1. **Static-format** (e.g. ELF/PE/WASM/APK-signature inspection) → structure.
2. **Decompiled-code** (e.g. .NET managed metadata, JavaScript application graph)
   → interface.
3. **Capture/protocol** (e.g. pcap/HAR) → behavior.

Remaining families are added in later phases; a family not yet covered returns an
explicit not-yet-supported result rather than a fabricated specification. The
dimension classifier is a documented seam: family-specific classifiers plug in as
coverage expands.

## Limitations

- Only the inline `evidence_bundle` source is supported today; retained-session
  and evidence-file sources, and launching analysis from a raw artifact, are
  follow-ups.
- Contradiction detection surfaces conflicting results recorded for the same
  operation; richer cross-source conflict analysis is future work.
