import type { Evidence, EvidenceLocation } from "../evidence.js";
import { redactExplicitText } from "../explicitSensitiveValues.js";

import {
  type ArtifactRef,
  type ArtifactSpecification,
  artifactSpecificationSchema,
  type Dimension,
  type ProvenanceTier,
  type SpecClaim,
  type SpecEvidenceReference,
  strongerProvenance,
} from "./artifactSpecification.js";
import {
  ALL_DIMENSIONS,
  computeDimensionCoverage,
  uncoveredDimensionUnknowns,
} from "./specificationCoverage.js";

/**
 * Pure projection from retained Evidence to an Artifact Specification.
 *
 * It reuses Evidence already gathered by existing analysis workflows — it never
 * re-parses raw source (spec FR-013). Every claim's provenance is the strongest
 * confidence of its supporting Evidence and is never upgraded past it (FR-005);
 * dimensions with no Evidence are reported, not omitted (FR-003/006). Conflicting
 * results for one operation are preserved as a contradiction rather than resolved
 * (FR-008). The projection copies no Evidence payload values into claim text — only
 * operation/predicate identifiers — so declared sensitive values cannot leak; any
 * caller-declared literals are additionally redacted from statements and locations
 * (FR-012). The result is deterministic for a given input (FR-015): claims and
 * references are sorted, independent of record order. By default a bounded summary
 * is returned with full detail available on request (FR-019).
 */

/** Default cap on claims returned in summary detail (FR-019 / SC-010). */
export const DEFAULT_SUMMARY_CLAIM_LIMIT = 50;

/** Assign a dimension to one Evidence record. Family adapters replace this (task T020). */
export type DimensionClassifier = (evidence: Evidence) => Dimension;

const DEPENDENCY_TERMS = [
  "dependenc",
  "package",
  "crate",
  "module-graph",
  "import-edge",
] as const;
const BEHAVIOR_TERMS = [
  "capture",
  "network",
  "http",
  "protocol",
  "packet",
  "runtime",
  "process",
  "scenario",
  "behavior",
  "trace",
  "pcap",
  "screenshot",
  "screen",
] as const;
const INTERFACE_TERMS = [
  "export",
  "import",
  "route",
  "api",
  "interface",
  "symbol",
  "method",
  "function",
  "signer",
  "entrypoint",
  "manifest",
] as const;

/**
 * Default, deliberately conservative classifier keyed on the Evidence
 * predicate/operation. It is a documented seam, not a semantic authority: a
 * caller passes a family-specific classifier when a target needs one. It covers
 * the three MVP evidence shapes — static-format (structure), decompiled-code
 * (interface), and capture/protocol/visual (behavior).
 */
export const classifyDimension: DimensionClassifier = (evidence) => {
  const key = `${evidence.predicate_type} ${evidence.operation}`.toLowerCase();
  const matches = (terms: readonly string[]): boolean =>
    terms.some((term) => key.includes(term));
  if (matches(DEPENDENCY_TERMS)) return "dependencies";
  if (matches(BEHAVIOR_TERMS)) return "behavior";
  if (matches(INTERFACE_TERMS)) return "interface";
  return "structure";
};

/** Render the first Evidence location to a short reference string, or null. */
const renderLocation = (
  location: EvidenceLocation | undefined,
): string | null => {
  switch (location?.kind) {
    case "artifact-path":
      return location.path;
    case "address-range":
      return `${location.start}-${location.end}`;
    case "file-offset":
      return `@${location.offset}`;
    case "file-offset-range":
      return `@${location.start}-${location.end}`;
    default:
      return null;
  }
};

interface ClaimGroup {
  dimension: Dimension;
  predicate: string;
  operation: string;
  provenance: ProvenanceTier;
  /** evidence_id -> rendered location */
  refs: Map<string, string | null>;
  /** distinct normalized_result digests observed for this operation */
  resultDigests: Set<string>;
}

/** Inputs for one projection run. */
export interface SpecificationProjectionInput {
  readonly artifact: ArtifactRef;
  /** Selected target family, or null when the family is not yet supported (FR-002). */
  readonly targetFamily: string | null;
  readonly records: readonly Evidence[];
  readonly dimensions?: readonly Dimension[];
  readonly classify?: DimensionClassifier;
  /** Caller-declared literal sensitive values to redact (FR-012); never inferred. */
  readonly sensitiveValues?: readonly string[];
  /** "summary" (default) bounds the returned claims; "full" returns all (FR-019). */
  readonly detail?: "summary" | "full";
  /** Claim cap in summary detail; defaults to DEFAULT_SUMMARY_CLAIM_LIMIT. */
  readonly maxClaims?: number;
}

const redact = (value: string, sensitive: readonly string[]): string =>
  sensitive.length === 0 ? value : redactExplicitText(value, [...sensitive]);

const redactLocation = (
  location: string | null,
  sensitive: readonly string[],
): string | null => {
  if (location === null || sensitive.length === 0) return location;
  const redacted = redactExplicitText(location, [...sensitive]);
  return redacted === "" ? null : redacted;
};

const notSupportedSpecification = (
  input: SpecificationProjectionInput,
  requested: readonly Dimension[],
): ArtifactSpecification => {
  const coverage = computeDimensionCoverage(
    [],
    requested,
    () => "Target family is not yet supported by specification recovery",
  );
  return artifactSpecificationSchema.parse({
    schema: "ArtifactSpecification",
    artifact: input.artifact,
    target_family: null,
    claims: [],
    coverage: {
      dimensions: coverage,
      examined: "No analysis Evidence; the target family is not yet supported",
      unexamined: "All dimensions",
      limits: { truncated: false, reason: null },
      unknowns: uncoveredDimensionUnknowns(coverage),
      missing_authority: null,
    },
    redaction: {
      applied: (input.sensitiveValues?.length ?? 0) > 0,
      markers: [],
    },
    reconstruction: null,
    diff: null,
  });
};

/** Project retained Evidence into a validated Artifact Specification. */
export const projectSpecification = (
  input: SpecificationProjectionInput,
): ArtifactSpecification => {
  const requested = input.dimensions ?? ALL_DIMENSIONS;
  if (input.targetFamily === null)
    return notSupportedSpecification(input, requested);

  const classify = input.classify ?? classifyDimension;
  const sensitive = input.sensitiveValues ?? [];
  const groups = new Map<string, ClaimGroup>();
  for (const evidence of input.records) {
    const dimension = classify(evidence);
    if (!requested.includes(dimension)) continue;
    const key = [dimension, evidence.predicate_type, evidence.operation].join(
      "::",
    );
    const tier: ProvenanceTier = evidence.confidence;
    const location = renderLocation(evidence.locations[0]);
    const resultDigest = JSON.stringify(evidence.normalized_result);
    const existing = groups.get(key);
    if (existing) {
      existing.provenance = strongerProvenance(existing.provenance, tier);
      if (!existing.refs.has(evidence.evidence_id))
        existing.refs.set(evidence.evidence_id, location);
      existing.resultDigests.add(resultDigest);
    } else {
      groups.set(key, {
        dimension,
        predicate: evidence.predicate_type,
        operation: evidence.operation,
        provenance: tier,
        refs: new Map([[evidence.evidence_id, location]]),
        resultDigests: new Set([resultDigest]),
      });
    }
  }

  const allClaims: SpecClaim[] = [...groups.entries()]
    .map(([key, group]) => {
      const refs: SpecEvidenceReference[] = [...group.refs.entries()]
        .map(([evidence_id, location]) => ({
          evidence_id,
          location: redactLocation(location, sensitive),
        }))
        .sort((left, right) =>
          left.evidence_id.localeCompare(right.evidence_id),
        );
      return {
        claim_id: key,
        dimension: group.dimension,
        statement: redact(`${group.operation} (${group.predicate})`, sensitive),
        provenance: group.provenance,
        evidence_refs: refs,
        // Multiple distinct results for one operation are a preserved contradiction (FR-008).
        contradiction:
          group.resultDigests.size > 1
            ? {
                refs,
                note: "Conflicting results recorded for the same operation; both retained.",
              }
            : null,
      };
    })
    .sort((left, right) => left.claim_id.localeCompare(right.claim_id));

  // Coverage is computed from the complete claim set, before any summary cap.
  const coverage = computeDimensionCoverage(allClaims, requested);
  const examinedDimensions = new Set(allClaims.map((claim) => claim.dimension));
  const notCovered = coverage
    .filter((entry) => entry.state === "not-covered")
    .map((entry) => entry.dimension);

  const detail = input.detail ?? "summary";
  const limit = input.maxClaims ?? DEFAULT_SUMMARY_CLAIM_LIMIT;
  const capped = detail === "summary" && allClaims.length > limit;
  const claims = capped ? allClaims.slice(0, limit) : allClaims;

  return artifactSpecificationSchema.parse({
    schema: "ArtifactSpecification",
    artifact: input.artifact,
    target_family: input.targetFamily,
    claims,
    coverage: {
      dimensions: coverage,
      examined: `${input.records.length} Evidence record(s) projected into ${allClaims.length} claim(s) across ${examinedDimensions.size} dimension(s)`,
      unexamined: notCovered.length > 0 ? notCovered.join(", ") : "None",
      limits: capped
        ? {
            truncated: true,
            reason: `Summary detail returns ${limit} of ${allClaims.length} claims; request full detail for the rest`,
          }
        : { truncated: false, reason: null },
      unknowns: uncoveredDimensionUnknowns(coverage),
      missing_authority: null,
    },
    redaction: {
      applied: sensitive.length > 0,
      markers:
        sensitive.length > 0
          ? [`${sensitive.length} caller-declared sensitive value(s) redacted`]
          : [],
    },
    reconstruction: null,
    diff: null,
  });
};
