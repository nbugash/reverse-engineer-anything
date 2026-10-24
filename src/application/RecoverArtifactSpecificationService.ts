import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { createEvidence, type Evidence } from "../domain/evidence.js";
import { readEvidenceBundle } from "../domain/evidenceBundle.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { REA_WORKFLOW_PROVIDER } from "../domain/investigationProviders.js";
import { err, ok, type Result } from "../domain/result.js";
import { reconstructionObligationLedgerSchema } from "../domain/reconstructionObligationLedgerSchemas.js";
import {
  type ArtifactSpecification,
  type ReconstructionAssessment,
  type ReconstructionVerdict,
  diffSpecifications,
  projectSpecification,
  recoverArtifactSpecificationInputSchema,
} from "../domain/specification/index.js";
import { buildReconstructionObligationLedgerEvidence } from "./ReconstructionObligationLedgerService.js";

const OPERATION = "recover_artifact_specification";

/**
 * Recover an evidence-graded artifact specification from an authenticated
 * Evidence bundle. This reuses Evidence already gathered by existing analysis
 * workflows and runs no new analysis (spec FR-013): it authenticates the bundle,
 * then projects its records into a Specification. The result is wrapped as a
 * derived Evidence record whose normalized_result is the Specification.
 */
export const recoverArtifactSpecificationEvidence = (
  input: unknown,
): Result<Evidence, AnalysisError> => {
  const frame = recoverArtifactSpecificationInputSchema.safeParse(input);
  if (!frame.success)
    return err(
      analysisInputErrorFromIssues(OPERATION, frame.error.issues, input, {
        cause: frame.error,
      }),
    );
  const bundle = readEvidenceBundle(frame.data.evidence_bundle);
  if (!bundle.ok) return bundle;
  const specification = projectSpecification({
    artifact: frame.data.artifact ?? { reference: "artifact", digest: null },
    targetFamily: frame.data.target_family,
    records: bundle.value.records,
    ...(frame.data.dimensions ? { dimensions: frame.data.dimensions } : {}),
    ...(frame.data.sensitive_values
      ? { sensitiveValues: frame.data.sensitive_values }
      : {}),
    ...(frame.data.detail ? { detail: frame.data.detail } : {}),
    ...(frame.data.max_claims !== undefined
      ? { maxClaims: frame.data.max_claims }
      : {}),
  });
  const withOverlay: ArtifactSpecification = frame.data.reconstruction
    ? {
        ...specification,
        reconstruction: buildReconstructionAssessment(
          frame.data.evidence_bundle,
        ),
      }
    : specification;

  if (frame.data.compare_to === undefined)
    return ok(createSpecificationEvidence(withOverlay));

  const previousBundle = readEvidenceBundle(
    frame.data.compare_to.evidence_bundle,
  );
  if (!previousBundle.ok) return previousBundle;
  const dimensions = frame.data.dimensions
    ? { dimensions: frame.data.dimensions }
    : {};
  // Diff on full projections of both versions so a summary cap cannot hide changes.
  const previousFull = projectSpecification({
    artifact: frame.data.artifact ?? { reference: "artifact", digest: null },
    targetFamily: frame.data.compare_to.target_family,
    records: previousBundle.value.records,
    detail: "full",
    ...dimensions,
  });
  const currentFull = projectSpecification({
    artifact: frame.data.artifact ?? { reference: "artifact", digest: null },
    targetFamily: frame.data.target_family,
    records: bundle.value.records,
    detail: "full",
    ...dimensions,
  });
  return ok(
    createSpecificationEvidence({
      ...withOverlay,
      diff: diffSpecifications(previousFull, currentFull),
    }),
  );
};

/** Map the obligation-ledger status to a reconstruction verdict (read-only). */
const ledgerVerdict = (status: string): ReconstructionVerdict =>
  status === "ready" ? "ready" : status === "open" ? "partial" : "unknown";

/** Map one obligation's status to a reconstruction verdict (FR-014; no upgrade). */
const obligationVerdict = (status: string): ReconstructionVerdict =>
  status === "verified"
    ? "ready"
    : status === "implemented" || status === "characterized"
      ? "partial"
      : "unknown";

/**
 * Build the on-demand reconstruction overlay by reading the existing obligation
 * ledger over the same bundle. It only reads verdicts — it never re-derives
 * closure (FR-014) and never launches a capture (FR-018).
 */
const buildReconstructionAssessment = (
  evidenceBundle: unknown,
): ReconstructionAssessment => {
  const ledgerEvidence = buildReconstructionObligationLedgerEvidence({
    evidence_bundle: evidenceBundle,
    reviewed_obligations: [],
    manifest: { bindings: [], contradictions: [] },
  });
  if (!ledgerEvidence.ok)
    return {
      status: "unknown",
      ledger_status: "unavailable",
      verdicts: [],
      reasons: [
        "Reconstruction overlay unavailable: the Evidence bundle could not be evaluated.",
      ],
      capture_grant_required: false,
    };
  const ledger = reconstructionObligationLedgerSchema.parse(
    ledgerEvidence.value.normalized_result,
  );
  const verdicts = ledger.obligations.map((obligation) => ({
    obligation_id: obligation.obligation_id,
    status: obligationVerdict(obligation.status),
    reasons: obligation.required_next_evidence,
  }));
  const captureGrantRequired = verdicts.some(
    (verdict) => verdict.status !== "ready",
  );
  return {
    status: ledgerVerdict(ledger.status),
    ledger_status: ledger.status,
    verdicts,
    capture_grant_required: captureGrantRequired,
    reasons: captureGrantRequired
      ? [
          "Open or unverified obligations need observed runtime Evidence. Run a process or scenario capture workflow and re-run with that Evidence; launching a capture is gated by a maintainer scope decision and is not performed here.",
        ]
      : [],
  };
};

/**
 * Capture-provider seam (FR-018) — interface only. Launching the target to gather
 * new runtime Evidence is target-execution authority and is BLOCKED pending a
 * maintainer scope decision (CONTRIBUTING). No implementation is wired here, and
 * the read-only overlay above launches nothing.
 */
export interface CaptureGrant {
  readonly scope: string;
}
export interface SpecificationCaptureProvider {
  readonly launchAndCapture: (grant: CaptureGrant) => never;
}

/** Wrap a projected Specification as a derived Evidence record. */
const createSpecificationEvidence = (
  specification: ArtifactSpecification,
): Evidence =>
  createEvidence(undefined, REA_WORKFLOW_PROVIDER, {
    predicateType: "rea.artifact-specification",
    operation: OPERATION,
    parameters: {
      target_family: specification.target_family,
      claim_count: specification.claims.length,
    },
    result: specification,
    rawResult: null,
    confidence: "derived",
    authority: "analyst-inference",
    environment: null,
    limitations: [],
    evidenceLinks: [],
  });
