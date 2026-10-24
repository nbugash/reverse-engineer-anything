import type {
  ArtifactSpecification,
  Dimension,
} from "./artifactSpecification.js";
import { ALL_DIMENSIONS } from "./specificationCoverage.js";

/**
 * Render a specification as human-readable Markdown, preserving each claim's
 * provenance tier and Evidence references (spec FR-010). This is a pure
 * presentation of the same facts; it adds no claim the projection did not make.
 */
export const renderSpecificationMarkdown = (
  specification: ArtifactSpecification,
): string => {
  const lines: string[] = [];
  const family = specification.target_family ?? "(not yet supported)";
  lines.push(`# Artifact specification: ${specification.artifact.reference}`);
  lines.push("");
  lines.push(`- Target family: ${family}`);
  lines.push(`- Claims: ${specification.claims.length}`);
  if (specification.coverage.limits.truncated)
    lines.push(
      `- Note: ${specification.coverage.limits.reason ?? "truncated"}`,
    );
  lines.push("");

  for (const dimension of ALL_DIMENSIONS) {
    const claims = specification.claims.filter(
      (claim) => claim.dimension === dimension,
    );
    const coverage = specification.coverage.dimensions.find(
      (entry) => entry.dimension === dimension,
    );
    lines.push(`## ${titleCase(dimension)} — ${coverage?.state ?? "unknown"}`);
    if (claims.length === 0) {
      lines.push(coverage?.reason ?? "No claims.");
      lines.push("");
      continue;
    }
    for (const claim of claims) {
      const refs = claim.evidence_refs
        .map((ref) =>
          ref.location === null
            ? ref.evidence_id
            : `${ref.evidence_id} @ ${ref.location}`,
        )
        .join(", ");
      const contradiction =
        claim.contradiction === null ? "" : " [CONTRADICTION]";
      lines.push(
        `- [${claim.provenance}] ${claim.statement}${contradiction} — ${refs}`,
      );
    }
    lines.push("");
  }

  if (specification.coverage.unknowns.length > 0) {
    lines.push("## Unknowns");
    for (const unknown of specification.coverage.unknowns)
      lines.push(`- ${unknown}`);
    lines.push("");
  }

  return lines.join("\n");
};

const titleCase = (dimension: Dimension): string =>
  dimension.charAt(0).toUpperCase() + dimension.slice(1);
