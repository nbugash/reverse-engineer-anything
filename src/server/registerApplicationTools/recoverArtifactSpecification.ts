import type { EvidenceMcpServer } from "../EvidenceMcpServer.js";
import { runAdmittedToolOperation } from "../admittedToolOperation.js";

import { recoverArtifactSpecificationEvidence } from "../../application/RecoverArtifactSpecificationService.js";
import { toolContract } from "../../contracts/toolContracts.js";
import { logToolExecution } from "../toolLogging.js";
import { applicationToolRegistrationOptions } from "../toolRegistrationOptions.js";
import type { ApplicationToolRegistration } from "./types.js";

const contract = toolContract("recover_artifact_specification");

/** Register the read-only artifact specification recovery projection. */
export const registerRecoverArtifactSpecificationTool = (
  server: EvidenceMcpServer,
  options: ApplicationToolRegistration,
): void => {
  server.registerTool(
    contract.name,
    applicationToolRegistrationOptions(contract),
    async (input, context) =>
      runAdmittedToolOperation(
        server,
        options.withAdmittedAnalysis,
        contract.name,
        context.mcpReq.signal,
        async () => {
          const result = await logToolExecution(
            options.logger,
            contract.name,
            () => Promise.resolve(recoverArtifactSpecificationEvidence(input)),
          );
          return server.delivery.toCallToolResult(result, contract);
        },
      ),
  );
};
