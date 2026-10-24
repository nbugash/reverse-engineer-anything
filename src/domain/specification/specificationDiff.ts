import type {
  ArtifactSpecification,
  SpecClaim,
  SpecificationDiff,
} from "./artifactSpecification.js";

const byId = (claims: readonly SpecClaim[]): Map<string, SpecClaim> =>
  new Map(claims.map((claim) => [claim.claim_id, claim]));

const sameClaim = (left: SpecClaim, right: SpecClaim): boolean =>
  JSON.stringify(left) === JSON.stringify(right);

/**
 * Compare two specifications and report added, removed, and changed claims.
 * Output is deterministic: every list is sorted by `claim_id`.
 */
export const diffSpecifications = (
  previous: ArtifactSpecification,
  current: ArtifactSpecification,
): SpecificationDiff => {
  const before = byId(previous.claims);
  const after = byId(current.claims);
  const byClaimId = (left: { claim_id: string }, right: { claim_id: string }) =>
    left.claim_id.localeCompare(right.claim_id);

  const added = current.claims
    .filter((claim) => !before.has(claim.claim_id))
    .sort(byClaimId);
  const removed = previous.claims
    .filter((claim) => !after.has(claim.claim_id))
    .sort(byClaimId);
  const changed = current.claims
    .filter((claim) => {
      const prior = before.get(claim.claim_id);
      return prior !== undefined && !sameClaim(prior, claim);
    })
    .map((claim) => ({ before: before.get(claim.claim_id)!, after: claim }))
    .sort((left, right) => byClaimId(left.after, right.after));

  return { added, removed, changed };
};
