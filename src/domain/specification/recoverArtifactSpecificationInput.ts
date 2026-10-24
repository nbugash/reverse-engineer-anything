import { z } from "zod";

import { dimensionSchema } from "./artifactSpecification.js";

/**
 * Input for recovering an artifact specification.
 *
 * `evidence_bundle` is authenticated by the application service (mirroring the
 * reconstruction-ledger tool), so it is accepted as unknown here. `target_family`
 * is null when the caller's family is not yet supported (spec FR-002). Inline
 * Evidence is the supported source for this increment; retained-session and
 * evidence-file sources, and the on-demand reconstruction overlay, are added by
 * later tasks.
 */
export const recoverArtifactSpecificationInputSchema = z.strictObject({
  evidence_bundle: z.unknown(),
  target_family: z.string().min(1).nullable(),
  dimensions: z.array(dimensionSchema).min(1).optional(),
  artifact: z
    .strictObject({
      reference: z.string().min(1),
      digest: z.string().min(1).nullable(),
    })
    .optional(),
  /** Caller-declared literal sensitive values to redact (FR-012); never inferred from names. */
  sensitive_values: z.array(z.string().min(1)).optional(),
  /** "summary" (default) returns a bounded set of claims; "full" returns all (FR-019). */
  detail: z.enum(["summary", "full"]).optional(),
  /** Claim cap in summary detail. */
  max_claims: z.int().min(1).optional(),
  /** When true, attach the on-demand read-only reconstruction-grade overlay (FR-014). */
  reconstruction: z.boolean().optional(),
  /** Another version's Evidence to diff the recovered specification against (FR-015). */
  compare_to: z
    .strictObject({
      evidence_bundle: z.unknown(),
      target_family: z.string().min(1).nullable(),
    })
    .optional(),
});
export type RecoverArtifactSpecificationInput = z.infer<
  typeof recoverArtifactSpecificationInputSchema
>;
