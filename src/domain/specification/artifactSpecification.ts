import { z } from "zod";

import { prefixedDigestSchema } from "../digests.js";

/**
 * Artifact Specification domain schemas.
 *
 * A Specification is a projection over Evidence already gathered by existing
 * analysis workflows: claims grouped by dimension, each tagged with a provenance
 * tier and linked to the Evidence that supports it. The schemas here own the
 * shape; {@link ../../application/ArtifactSpecificationRecovery} orchestrates how
 * Evidence is obtained, and `specificationProjection.ts` builds the claims.
 */

/** The facets a Specification can describe (spec FR-003). */
export const dimensionSchema = z.enum([
  "structure",
  "interface",
  "behavior",
  "dependencies",
]);
export type Dimension = z.infer<typeof dimensionSchema>;

/**
 * Support level of a claim. `observed | derived | inferred` reuse the Evidence
 * confidence vocabulary (`../evidence.ts`); `unknown` marks a claim with no
 * supporting Evidence. A claim's tier MUST NOT exceed the strongest supporting
 * Evidence confidence (enforced in the projection, spec FR-005).
 */
export const provenanceTierSchema = z.enum([
  "observed",
  "derived",
  "inferred",
  "unknown",
]);
export type ProvenanceTier = z.infer<typeof provenanceTierSchema>;

/** Rank used to pick a claim's tier from its supporting Evidence; higher wins. */
const PROVENANCE_RANK: Record<ProvenanceTier, number> = {
  observed: 3,
  derived: 2,
  inferred: 1,
  unknown: 0,
};

/** Order two tiers; returns the stronger (spec FR-005: never upgrade past Evidence). */
export const strongerProvenance = (
  left: ProvenanceTier,
  right: ProvenanceTier,
): ProvenanceTier =>
  (PROVENANCE_RANK[left] ?? 0) >= (PROVENANCE_RANK[right] ?? 0) ? left : right;

/** Link from a claim to the retained Evidence record (and optional location) that supports it. */
export const specEvidenceReferenceSchema = z.strictObject({
  evidence_id: prefixedDigestSchema("ev"),
  location: z.string().min(1).nullable(),
});
export type SpecEvidenceReference = z.infer<typeof specEvidenceReferenceSchema>;

/** A conflicting pair of supporting Evidence, retained rather than resolved (spec FR-008). */
export const specContradictionSchema = z.strictObject({
  refs: z.array(specEvidenceReferenceSchema).min(2),
  note: z.string().min(1),
});

/** One statement in the Specification. */
export const specClaimSchema = z
  .strictObject({
    claim_id: z.string().min(1),
    dimension: dimensionSchema,
    statement: z.string().min(1),
    provenance: provenanceTierSchema,
    evidence_refs: z.array(specEvidenceReferenceSchema),
    contradiction: specContradictionSchema.nullable(),
  })
  .superRefine((claim, context) => {
    // FR-004 / SC-001: every claim is traceable to Evidence unless it is an
    // explicit unknown.
    if (claim.provenance !== "unknown" && claim.evidence_refs.length === 0)
      context.addIssue({
        code: "custom",
        path: ["evidence_refs"],
        message:
          "A claim with a non-unknown provenance tier must reference at least one Evidence record",
      });
    if (claim.provenance === "unknown" && claim.evidence_refs.length > 0)
      context.addIssue({
        code: "custom",
        path: ["provenance"],
        message:
          "A claim that references Evidence cannot carry the unknown provenance tier",
      });
  });
export type SpecClaim = z.infer<typeof specClaimSchema>;

/**
 * Difference between two versions of a specification, keyed by `claim_id`
 * (FR-015). Each entry keeps the full claim, so provenance and Evidence
 * references survive the comparison. Defined here (beside `specClaimSchema`) so
 * the aggregate schema can embed it without a circular import.
 */
export const specificationDiffSchema = z.strictObject({
  added: z.array(specClaimSchema),
  removed: z.array(specClaimSchema),
  changed: z.array(
    z.strictObject({ before: specClaimSchema, after: specClaimSchema }),
  ),
});
export type SpecificationDiff = z.infer<typeof specificationDiffSchema>;

/** Per-dimension coverage state; not-covered/partial MUST carry a reason (FR-003, SC-008). */
export const dimensionCoverageSchema = z
  .strictObject({
    dimension: dimensionSchema,
    state: z.enum(["covered", "partial", "not-covered"]),
    reason: z.string().min(1).nullable(),
  })
  .superRefine((entry, context) => {
    if (entry.state !== "covered" && entry.reason === null)
      context.addIssue({
        code: "custom",
        path: ["reason"],
        message: "A partial or not-covered dimension must state a reason",
      });
  });
export type DimensionCoverage = z.infer<typeof dimensionCoverageSchema>;

/** What was examined, what was not, and the limits of the result (spec FR-007/016/017). */
export const coverageSummarySchema = z.strictObject({
  dimensions: z.array(dimensionCoverageSchema),
  examined: z.string().min(1),
  unexamined: z.string().min(1),
  limits: z.strictObject({
    truncated: z.boolean(),
    reason: z.string().min(1).nullable(),
  }),
  unknowns: z.array(z.string().min(1)),
  missing_authority: z
    .strictObject({
      scope: z.string().min(1),
      affected_claims: z.array(z.string().min(1)),
    })
    .nullable(),
});
export type CoverageSummary = z.infer<typeof coverageSummarySchema>;

/** The artifact under analysis; preserves the caller's reference and content digest (FR-011). */
export const artifactRefSchema = z.strictObject({
  reference: z.string().min(1),
  digest: z.string().min(1).nullable(),
});
export type ArtifactRef = z.infer<typeof artifactRefSchema>;

/** Record of credential/sensitive-value redaction applied to the Specification (FR-012). */
export const redactionRecordSchema = z.strictObject({
  applied: z.boolean(),
  markers: z.array(z.string().min(1)),
});

/** Reproducibility verdict for a behavior, projected from the reconstruction services. */
export const reconstructionVerdictSchema = z.enum([
  "ready",
  "partial",
  "unknown",
]);
export type ReconstructionVerdict = z.infer<typeof reconstructionVerdictSchema>;

/** Per-obligation reconstruction verdict (FR-014). */
export const reconstructionClaimVerdictSchema = z.strictObject({
  obligation_id: z.string().min(1),
  status: reconstructionVerdictSchema,
  reasons: z.array(z.string().min(1)),
});

/**
 * On-demand reconstruction-grade overlay (FR-014), projected read-only from the
 * existing obligation-ledger and coverage services. `capture_grant_required` is
 * set when closing open behavioral obligations would need observed runtime
 * Evidence; launching a capture to obtain it is gated (FR-018) and never done here.
 */
export const reconstructionAssessmentSchema = z.strictObject({
  status: reconstructionVerdictSchema,
  ledger_status: z.string().min(1),
  verdicts: z.array(reconstructionClaimVerdictSchema),
  reasons: z.array(z.string().min(1)),
  capture_grant_required: z.boolean(),
});
export type ReconstructionAssessment = z.infer<
  typeof reconstructionAssessmentSchema
>;

/**
 * The deliverable. `target_family` is null when the artifact's family is not yet
 * supported (FR-002); in that case `claims` is empty and `coverage` reports the
 * reason. `reconstruction` is null unless the on-demand overlay was requested
 * (FR-014).
 */
export const artifactSpecificationSchema = z.strictObject({
  schema: z.literal("ArtifactSpecification"),
  artifact: artifactRefSchema,
  target_family: z.string().min(1).nullable(),
  claims: z.array(specClaimSchema),
  coverage: coverageSummarySchema,
  redaction: redactionRecordSchema,
  reconstruction: reconstructionAssessmentSchema.nullable(),
  diff: specificationDiffSchema.nullable(),
});
export type ArtifactSpecification = z.infer<typeof artifactSpecificationSchema>;
