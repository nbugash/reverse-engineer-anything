import { describe, expect, it } from "vitest";

import { createEvidence, type Evidence } from "../evidence.js";
import type { JsonValue } from "../jsonValue.js";

import type { ArtifactRef } from "./artifactSpecification.js";
import { diffSpecifications } from "./specificationDiff.js";
import { projectSpecification } from "./specificationProjection.js";
import { renderSpecificationMarkdown } from "./specificationRender.js";

const provider = { id: "fixture", name: "Fixture", version: "1" } as const;
const artifact: ArtifactRef = { reference: "fixture-artifact", digest: null };

const evidence = (
  operation: string,
  predicateType: string,
  result: JsonValue = {},
): Evidence =>
  createEvidence(undefined, provider, {
    predicateType,
    operation,
    parameters: {},
    result,
    confidence: "observed",
  });

const project = (records: readonly Evidence[]) =>
  projectSpecification({
    artifact,
    targetFamily: "elf",
    records,
    detail: "full",
  });

describe("diffSpecifications (FR-015)", () => {
  it("reports added, removed, and changed claims by claim_id, preserving provenance", () => {
    const previous = project([
      evidence("inspect_sections", "rea.binary-layout", { v: 1 }),
      evidence("list_exports", "rea.exports"),
    ]);
    const current = project([
      evidence("inspect_sections", "rea.binary-layout", { v: 2 }),
      evidence("inspect_imports", "rea.imports"),
    ]);
    const diff = diffSpecifications(previous, current);

    expect(
      diff.added.some((claim) => claim.claim_id.includes("inspect_imports")),
    ).toBe(true);
    expect(
      diff.removed.some((claim) => claim.claim_id.includes("list_exports")),
    ).toBe(true);
    expect(
      diff.changed.some((entry) =>
        entry.after.claim_id.includes("inspect_sections"),
      ),
    ).toBe(true);
    // Provenance survives the comparison.
    for (const entry of diff.changed)
      expect(entry.after.provenance).toBe("observed");
  });

  it("is empty for identical specifications", () => {
    const records = [evidence("inspect_sections", "rea.binary-layout")];
    const diff = diffSpecifications(project(records), project(records));
    expect(diff).toEqual({ added: [], removed: [], changed: [] });
  });
});

describe("renderSpecificationMarkdown (FR-010)", () => {
  it("preserves provenance tiers and Evidence references", () => {
    const record = evidence("inspect_sections", "rea.binary-layout");
    const markdown = renderSpecificationMarkdown(project([record]));
    expect(markdown).toContain("# Artifact specification: fixture-artifact");
    expect(markdown).toContain("[observed]");
    expect(markdown).toContain(record.evidence_id);
  });
});

describe("specification determinism (FR-015)", () => {
  it("produces identical output and stable claim ids for identical input", () => {
    const records = [
      evidence("inspect_sections", "rea.binary-layout"),
      evidence("list_exports", "rea.exports"),
    ];
    const first = project(records);
    const second = project(records);
    expect(first).toEqual(second);
    expect(first.claims.map((claim) => claim.claim_id)).toEqual(
      second.claims.map((claim) => claim.claim_id),
    );
  });
});
