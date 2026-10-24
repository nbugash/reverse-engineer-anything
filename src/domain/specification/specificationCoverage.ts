import {
  type Dimension,
  dimensionSchema,
  type DimensionCoverage,
  type SpecClaim,
} from "./artifactSpecification.js";

/** Every dimension the Specification schema knows about. */
export const ALL_DIMENSIONS: readonly Dimension[] = dimensionSchema.options;

/**
 * Derive per-dimension coverage from the projected claims.
 *
 * A dimension is `covered` when at least one claim rests on observed or derived
 * Evidence, `partial` when only inferred-tier claims support it, and
 * `not-covered` when no claim does. Partial and not-covered carry a reason
 * (spec FR-003, SC-008). `requested` bounds which dimensions are reported.
 */
export const computeDimensionCoverage = (
  claims: readonly SpecClaim[],
  requested: readonly Dimension[] = ALL_DIMENSIONS,
  notCoveredReason: (dimension: Dimension) => string = () =>
    "No Evidence supported this dimension for the examined artifact",
): DimensionCoverage[] =>
  requested.map((dimension) => {
    const forDimension = claims.filter(
      (claim) => claim.dimension === dimension,
    );
    if (forDimension.length === 0)
      return {
        dimension,
        state: "not-covered",
        reason: notCoveredReason(dimension),
      };
    const hasStrong = forDimension.some(
      (claim) =>
        claim.provenance === "observed" || claim.provenance === "derived",
    );
    return hasStrong
      ? { dimension, state: "covered", reason: null }
      : {
          dimension,
          state: "partial",
          reason: "Only inferred-tier Evidence supports this dimension",
        };
  });

/** Dimensions with no supporting claim, surfaced as explicit unknowns (spec FR-006). */
export const uncoveredDimensionUnknowns = (
  coverage: readonly DimensionCoverage[],
): string[] =>
  coverage
    .filter((entry) => entry.state === "not-covered")
    .map(
      (entry) => `No Evidence recovered for the ${entry.dimension} dimension`,
    );
