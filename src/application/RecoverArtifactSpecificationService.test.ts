import { describe, expect, it } from "vitest";

import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { createEvidence } from "../domain/evidence.js";
import { createEvidenceBundle } from "../domain/evidenceBundle.js";
import type { ArtifactSpecification } from "../domain/specification/index.js";
import { processEvidence } from "./ReconstructionObligationLedger.fixture.js";
import { recoverArtifactSpecificationEvidence } from "./RecoverArtifactSpecificationService.js";

const spec = (input: unknown): ArtifactSpecification => {
  const result = recoverArtifactSpecificationEvidence(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as ArtifactSpecification;
};

describe("recoverArtifactSpecificationEvidence reconstruction overlay", () => {
  it("omits the overlay unless requested", () => {
    const bundle = createEvidenceBundle([
      createEvidence(
        undefined,
        { id: "fixture", name: "Fixture", version: "1" },
        {
          predicateType: "rea.binary-layout",
          operation: "inspect_sections",
          parameters: {},
          result: {},
          confidence: "observed",
        },
      ),
    ]);
    expect(
      spec({ evidence_bundle: bundle, target_family: "elf" }).reconstruction,
    ).toBeNull();
  });

  it("attaches read-only verdicts and never marks ready without observed proof (FR-014)", () => {
    const bundle = createEvidenceBundle([processEvidence()]);
    const overlay = spec({
      evidence_bundle: bundle,
      target_family: "packaged",
      reconstruction: true,
    }).reconstruction;
    expect(overlay).not.toBeNull();
    expect(overlay?.verdicts.length).toBeGreaterThan(0);
    // No obligation closes to "ready" without observed reconstruction proof.
    expect(
      overlay?.verdicts.every((verdict) => verdict.status !== "ready"),
    ).toBe(true);
    // Open behavioral obligations need observed Evidence; a capture is reported, not launched (FR-018).
    expect(overlay?.capture_grant_required).toBe(true);
    expect(overlay?.reasons.length).toBeGreaterThan(0);
  });

  it("rejects a non-canonical Evidence bundle as an integrity mismatch (T011)", () => {
    const bundle = createEvidenceBundle([
      createEvidence(
        undefined,
        { id: "fixture", name: "Fixture", version: "1" },
        { operation: "observe", parameters: { a: "1" }, result: {} },
      ),
      createEvidence(
        undefined,
        { id: "fixture", name: "Fixture", version: "1" },
        { operation: "observe", parameters: { a: "2" }, result: {} },
      ),
    ]);
    const tampered = { ...bundle, records: [...bundle.records].reverse() };
    const result = recoverArtifactSpecificationEvidence({
      evidence_bundle: tampered,
      target_family: "elf",
    });
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(projectAnalysisError(result.error).code).toBe(
        "evidence_integrity_mismatch",
      );
  });

  // FR-018 / task T032: launching a capture under a grant is target-execution
  // authority, BLOCKED pending a maintainer scope decision. The seam is defined
  // (SpecificationCaptureProvider) but no launch path is integrated; this guard
  // stays skipped until that decision is granted.
  it.skip("launches a capture under an explicit grant (BLOCKED: maintainer scope decision required)", () => {
    expect.fail("Capture launch is gated and intentionally not implemented");
  });
});
