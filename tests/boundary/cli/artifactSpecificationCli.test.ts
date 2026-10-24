import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import { createEvidence } from "../../../src/domain/evidence.js";
import { createEvidenceBundle } from "../../../src/domain/evidenceBundle.js";
import { recoverArtifactSpecificationEvidence } from "../../../src/application/RecoverArtifactSpecificationService.js";

const execute = promisify(execFile);

const provider = { id: "fixture", name: "Fixture", version: "1" } as const;

const record = (
  operation: string,
  predicateType: string,
  confidence: "observed" | "derived" | "inferred",
) =>
  createEvidence(undefined, provider, {
    predicateType,
    operation,
    parameters: {},
    result: {},
    confidence,
  });

const runCli = async (input: unknown): Promise<unknown> => {
  const { stdout } = await execute(
    process.execPath,
    [
      "scripts/rea.mjs",
      "recover-artifact-specification",
      JSON.stringify(input),
      "--json",
    ],
    { cwd: process.cwd(), env: process.env, maxBuffer: 16 * 1_024 * 1_024 },
  );
  return JSON.parse(stdout);
};

describe("recover artifact specification CLI", () => {
  it("projects provenance-graded claims from an authenticated bundle", async () => {
    const bundle = createEvidenceBundle([
      record("inspect_sections", "rea.binary-layout", "observed"),
      record("list_exports", "rea.exports", "inferred"),
    ]);
    const input = { evidence_bundle: bundle, target_family: "elf-static" };

    const output = (await runCli(input)) as {
      normalized_result: {
        schema: string;
        target_family: string | null;
        claims: readonly {
          dimension: string;
          provenance: string;
          evidence_refs: readonly unknown[];
        }[];
        coverage: {
          dimensions: readonly { dimension: string; state: string }[];
        };
      };
    };
    const spec = output.normalized_result;

    expect(spec.schema).toBe("ArtifactSpecification");
    expect(spec.target_family).toBe("elf-static");
    expect(spec.claims).toHaveLength(2);
    // Every claim is traceable to Evidence and carries a provenance tier (SC-001).
    for (const claim of spec.claims) {
      expect(claim.provenance).toMatch(/^(observed|derived|inferred)$/u);
      expect(claim.evidence_refs.length).toBeGreaterThan(0);
    }
    expect(
      spec.coverage.dimensions.find((entry) => entry.dimension === "structure")
        ?.state,
    ).toBe("covered");
    expect(
      spec.coverage.dimensions.find((entry) => entry.dimension === "interface")
        ?.state,
    ).toBe("partial");

    // CLI output equals the direct service projection (CLI/MCP parity source, SC-005).
    const direct = recoverArtifactSpecificationEvidence(input);
    expect(direct.ok).toBe(true);
    if (direct.ok) expect(spec).toEqual(direct.value.normalized_result);
  }, 20_000);

  it("returns an explicit not-yet-supported specification for a null family", async () => {
    const input = {
      evidence_bundle: createEvidenceBundle([]),
      target_family: null,
    };
    const output = (await runCli(input)) as {
      normalized_result: {
        target_family: string | null;
        claims: readonly unknown[];
        coverage: { dimensions: readonly { state: string }[] };
      };
    };
    expect(output.normalized_result.target_family).toBeNull();
    expect(output.normalized_result.claims).toHaveLength(0);
    expect(
      output.normalized_result.coverage.dimensions.every(
        (entry) => entry.state === "not-covered",
      ),
    ).toBe(true);
  }, 20_000);

  it("diffs two versions via compare_to (FR-015)", async () => {
    const previous = createEvidenceBundle([
      record("inspect_sections", "rea.binary-layout", "observed"),
      record("list_exports", "rea.exports", "observed"),
    ]);
    const current = createEvidenceBundle([
      record("inspect_sections", "rea.binary-layout", "observed"),
      record("inspect_imports", "rea.imports", "observed"),
    ]);
    const output = (await runCli({
      evidence_bundle: current,
      target_family: "elf-static",
      compare_to: { evidence_bundle: previous, target_family: "elf-static" },
    })) as {
      normalized_result: {
        diff: {
          added: readonly { claim_id: string }[];
          removed: readonly { claim_id: string }[];
        } | null;
      };
    };
    const diff = output.normalized_result.diff;
    expect(diff).not.toBeNull();
    expect(
      diff?.added.some((claim) => claim.claim_id.includes("inspect_imports")),
    ).toBe(true);
    expect(
      diff?.removed.some((claim) => claim.claim_id.includes("list_exports")),
    ).toBe(true);
  }, 20_000);
});
