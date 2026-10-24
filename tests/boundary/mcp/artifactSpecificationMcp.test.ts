import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { describe, expect, it } from "vitest";

import { createEvidence } from "../../../src/domain/evidence.js";
import { createEvidenceBundle } from "../../../src/domain/evidenceBundle.js";
import { ok as resultOk } from "../../../src/domain/result.js";
import { createServer } from "../../../src/server/createServer.js";
import { recoverArtifactSpecificationEvidence } from "../../../src/application/RecoverArtifactSpecificationService.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { observed } from "../../fixtures/analysisExecution.js";
import { processEvidence } from "../../../src/application/ReconstructionObligationLedger.fixture.js";

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

type SpecRequest = (args: {
  evidence_bundle: unknown;
  target_family: string | null;
  reconstruction?: boolean;
}) => ReturnType<Client["callTool"]>;

const withSpecClient = async (
  run: (request: SpecRequest) => Promise<void>,
): Promise<void> => {
  const session = createTestBinarySession(() => ({
    execute: () => Promise.resolve(observed(null)),
    close: () => Promise.resolve(resultOk(null)),
  }));
  const server = createServer({ kind: "session", session });
  const client = new Client({ name: "artifact-spec-test", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    await run((args) =>
      client.callTool({
        name: "recover_artifact_specification",
        arguments: args,
      }),
    );
  } finally {
    await client.close();
    await server.close();
    await session.close();
  }
};

describe("recover artifact specification MCP", () => {
  it("projects provenance-graded claims and matches the direct service (parity)", async () => {
    const bundle = createEvidenceBundle([
      record("inspect_sections", "rea.binary-layout", "observed"),
      record("list_exports", "rea.exports", "inferred"),
    ]);
    const input = { evidence_bundle: bundle, target_family: "elf-static" };
    await withSpecClient(async (request) => {
      const result = await request(input);
      expect(result.isError).not.toBe(true);
      const envelope = result.structuredContent as {
        normalized_result: {
          schema: string;
          target_family: string | null;
          claims: readonly {
            provenance: string;
            evidence_refs: readonly unknown[];
          }[];
        };
      };
      const spec = envelope.normalized_result;
      expect(spec.schema).toBe("ArtifactSpecification");
      expect(spec.target_family).toBe("elf-static");
      expect(spec.claims).toHaveLength(2);
      for (const claim of spec.claims) {
        expect(claim.provenance).toMatch(/^(observed|derived|inferred)$/u);
        expect(claim.evidence_refs.length).toBeGreaterThan(0);
      }
      // MCP output equals the direct service projection → CLI/MCP parity (SC-005).
      const direct = recoverArtifactSpecificationEvidence(input);
      expect(direct.ok).toBe(true);
      if (direct.ok) expect(spec).toEqual(direct.value.normalized_result);
    });
  });

  it("returns an explicit not-yet-supported specification for a null family", async () => {
    await withSpecClient(async (request) => {
      const result = await request({
        evidence_bundle: createEvidenceBundle([]),
        target_family: null,
      });
      expect(result.isError).not.toBe(true);
      const envelope = result.structuredContent as {
        normalized_result: {
          target_family: string | null;
          claims: readonly unknown[];
          coverage: { dimensions: readonly { state: string }[] };
        };
      };
      expect(envelope.normalized_result.target_family).toBeNull();
      expect(envelope.normalized_result.claims).toHaveLength(0);
      expect(
        envelope.normalized_result.coverage.dimensions.every(
          (entry) => entry.state === "not-covered",
        ),
      ).toBe(true);
    });
  });

  it("attaches the read-only reconstruction overlay when requested (FR-014)", async () => {
    const bundle = createEvidenceBundle([processEvidence()]);
    await withSpecClient(async (request) => {
      const result = await request({
        evidence_bundle: bundle,
        target_family: "packaged",
        reconstruction: true,
      });
      expect(result.isError).not.toBe(true);
      const envelope = result.structuredContent as {
        normalized_result: {
          reconstruction: {
            status: string;
            verdicts: readonly { status: string }[];
            capture_grant_required: boolean;
          } | null;
        };
      };
      const overlay = envelope.normalized_result.reconstruction;
      expect(overlay).not.toBeNull();
      expect(
        overlay?.verdicts.every((verdict) => verdict.status !== "ready"),
      ).toBe(true);
      expect(overlay?.capture_grant_required).toBe(true);
    });
  });
});
