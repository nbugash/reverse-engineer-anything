import { describe, expect, it } from "vitest";

import { createEvidence, type Evidence } from "../evidence.js";
import type { JsonValue } from "../jsonValue.js";

import {
  artifactSpecificationSchema,
  type ArtifactRef,
} from "./artifactSpecification.js";
import { projectSpecification } from "./specificationProjection.js";

const provider = { id: "fixture", name: "Fixture", version: "1" } as const;
const artifact: ArtifactRef = { reference: "fixture-artifact", digest: null };

const evidence = (
  operation: string,
  predicateType: string,
  confidence: "observed" | "derived" | "inferred",
  result: JsonValue = {},
): Evidence =>
  createEvidence(undefined, provider, {
    predicateType,
    operation,
    parameters: {},
    result,
    confidence,
  });

describe("projectSpecification", () => {
  it("projects claims that carry provenance and Evidence references, and validates", () => {
    const spec = projectSpecification({
      artifact,
      targetFamily: "elf-static",
      records: [evidence("inspect_sections", "rea.binary-layout", "observed")],
    });
    expect(() => artifactSpecificationSchema.parse(spec)).not.toThrow();
    expect(spec.claims).toHaveLength(1);
    expect(spec.claims[0]?.provenance).toBe("observed");
    expect(spec.claims[0]?.evidence_refs).toHaveLength(1);
  });

  it("keeps the strongest provenance and merges references into one statement", () => {
    const spec = projectSpecification({
      artifact,
      targetFamily: "managed",
      records: [
        evidence("list_exports", "rea.exports", "inferred"),
        evidence("list_exports", "rea.exports", "observed"),
      ],
    });
    expect(spec.claims).toHaveLength(1);
    expect(spec.claims[0]?.provenance).toBe("observed");
    expect(spec.claims[0]?.evidence_refs).toHaveLength(2);
  });

  it("never upgrades an inferred-only claim and marks its dimension partial", () => {
    const spec = projectSpecification({
      artifact,
      targetFamily: "managed",
      records: [evidence("list_methods", "rea.methods", "inferred")],
    });
    expect(
      spec.claims.find((claim) => claim.dimension === "interface")?.provenance,
    ).toBe("inferred");
    expect(
      spec.coverage.dimensions.find((entry) => entry.dimension === "interface")
        ?.state,
    ).toBe("partial");
  });

  it("reports dimensions with no Evidence as not-covered unknowns", () => {
    const spec = projectSpecification({
      artifact,
      targetFamily: "elf-static",
      records: [evidence("inspect_sections", "rea.binary-layout", "observed")],
    });
    const deps = spec.coverage.dimensions.find(
      (entry) => entry.dimension === "dependencies",
    );
    expect(deps?.state).toBe("not-covered");
    expect(deps?.reason).toBeTruthy();
    expect(
      spec.coverage.unknowns.some((unknown) =>
        unknown.includes("dependencies"),
      ),
    ).toBe(true);
  });

  it("is deterministic and independent of record order", () => {
    const a = evidence("inspect_sections", "rea.binary-layout", "observed", {
      a: "1",
    });
    const b = evidence("list_exports", "rea.exports", "derived", { b: "2" });
    expect(
      projectSpecification({ artifact, targetFamily: "elf", records: [a, b] }),
    ).toEqual(
      projectSpecification({ artifact, targetFamily: "elf", records: [b, a] }),
    );
  });

  it("returns an explicit not-yet-supported specification for an unknown family", () => {
    const spec = projectSpecification({
      artifact,
      targetFamily: null,
      records: [],
    });
    expect(spec.target_family).toBeNull();
    expect(spec.claims).toHaveLength(0);
    expect(
      spec.coverage.dimensions.every((entry) => entry.state === "not-covered"),
    ).toBe(true);
  });

  it("classifies capture/runtime Evidence as behavior", () => {
    const spec = projectSpecification({
      artifact,
      targetFamily: "pcap",
      records: [evidence("inspect_pcap_capture", "rea.pcap", "observed")],
    });
    expect(spec.claims[0]?.dimension).toBe("behavior");
  });
});

describe("projectSpecification quality", () => {
  it("classifies the three MVP evidence shapes into their dimensions (T020)", () => {
    const spec = projectSpecification({
      artifact,
      targetFamily: "mixed",
      records: [
        evidence("inspect_sections", "rea.binary-layout", "observed"),
        evidence("inspect_managed_method", "rea.managed-method", "derived"),
        evidence("inspect_pcap_capture", "rea.pcap", "observed"),
        evidence("list_dependencies", "rea.dependencies", "derived"),
      ],
    });
    const byDimension = new Map(
      spec.claims.map((claim) => [claim.dimension, claim]),
    );
    expect(byDimension.get("structure")).toBeDefined();
    expect(byDimension.get("interface")).toBeDefined();
    expect(byDimension.get("behavior")).toBeDefined();
    expect(byDimension.get("dependencies")).toBeDefined();
  });

  it("never labels an inferred-only corpus as observed (provenance audit, SC-002)", () => {
    const spec = projectSpecification({
      artifact,
      targetFamily: "elf",
      records: [
        evidence("inspect_sections", "rea.binary-layout", "inferred"),
        evidence("list_exports", "rea.exports", "inferred"),
        evidence("inspect_pcap_capture", "rea.pcap", "inferred"),
      ],
    });
    expect(spec.claims.every((claim) => claim.provenance === "inferred")).toBe(
      true,
    );
  });

  it("never projects Evidence payload values into claim text (SC-009)", () => {
    const spec = projectSpecification({
      artifact,
      targetFamily: "elf",
      records: [
        evidence("inspect_sections", "rea.binary-layout", "observed", {
          token: "S3KRET-VALUE",
        }),
      ],
    });
    const serialized = JSON.stringify(spec.claims);
    expect(serialized).not.toContain("S3KRET-VALUE");
  });

  it("redacts caller-declared sensitive values from locations (FR-012)", () => {
    const record = createEvidence(undefined, provider, {
      predicateType: "rea.binary-layout",
      operation: "inspect_sections",
      parameters: {},
      result: {},
      confidence: "observed",
      locations: [{ kind: "artifact-path", path: "/opt/S3KRET/app" }],
    });
    const spec = projectSpecification({
      artifact,
      targetFamily: "elf",
      records: [record],
      sensitiveValues: ["S3KRET"],
    });
    expect(spec.redaction.applied).toBe(true);
    const location = spec.claims[0]?.evidence_refs[0]?.location ?? "";
    expect(location).not.toContain("S3KRET");
  });

  it("cites visual/screenshot Evidence as a behavior claim (FR-020)", () => {
    const spec = projectSpecification({
      artifact,
      targetFamily: "web",
      records: [
        evidence("capture_web_screenshot", "rea.web-screenshot", "observed"),
      ],
    });
    const claim = spec.claims.find((entry) => entry.dimension === "behavior");
    expect(claim).toBeDefined();
    expect(claim?.evidence_refs.length).toBeGreaterThan(0);
  });

  it("preserves conflicting results for one operation as a contradiction (FR-008)", () => {
    const spec = projectSpecification({
      artifact,
      targetFamily: "elf",
      records: [
        evidence("inspect_header", "rea.layout", "observed", {
          endianness: "little",
        }),
        evidence("inspect_header", "rea.layout", "observed", {
          endianness: "big",
        }),
      ],
    });
    expect(spec.claims).toHaveLength(1);
    expect(spec.claims[0]?.contradiction).not.toBeNull();
    expect(spec.claims[0]?.evidence_refs).toHaveLength(2);
  });

  it("bounds summary detail and offers full detail (FR-019/SC-010)", () => {
    const records = ["inspect_a", "inspect_b", "inspect_c"].map((operation) =>
      evidence(operation, "rea.binary-layout", "observed"),
    );
    const summary = projectSpecification({
      artifact,
      targetFamily: "elf",
      records,
      maxClaims: 2,
    });
    expect(summary.claims).toHaveLength(2);
    expect(summary.coverage.limits.truncated).toBe(true);
    const full = projectSpecification({
      artifact,
      targetFamily: "elf",
      records,
      detail: "full",
    });
    expect(full.claims).toHaveLength(3);
    expect(full.coverage.limits.truncated).toBe(false);
  });
});
