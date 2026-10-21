/**
 * Held calls name the agent that asked, through the real composition root.
 *
 * CAPABILITY UNDER TEST: when a wrapped harness's MCP server holds a call for
 * the operator, the approval request carries the hub agent id of that harness
 * (`agent:<SANCTUARY_AGENT_ID>`), so the operator's card can say which agent is
 * asking. The value is server-set from the wrap-time environment, the same
 * source the router uses for its caller identity; it is never taken from the
 * tool's arguments.
 *
 * WIRED-CONSUMER RIG (AGENTS.md assurance rule 4): the server is booted through
 * `createSanctuaryServer`, the entrypoint `index.ts` exports, and the call goes
 * through the real `tools/call` handler, router and `ApprovalGate`. The callback
 * approval channel (the documented embedding-host channel) captures the exact
 * request the gate hands its channel and denies it, so no export runs.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { createSanctuaryServer } from "../../src/index.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateDefaultPolicyYaml } from "../../src/principal-policy/loader.js";
import type {
  ApprovalRequest,
  ApprovalResponse,
} from "../../src/principal-policy/types.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

const AGENT_ID_ENV = "SANCTUARY_AGENT_ID";
const WRAPPED_AGENT_ID = "claude-code:fortress-fedcba9876543210";
// Must match the `agent:` form of requestingAgentId in server/src/principal-policy/gate.ts.
const EXPECTED_REQUESTER = `agent:${WRAPPED_AGENT_ID}`;
// Owner read/write only, like every principal-policy file the server writes.
const POLICY_FILE_MODE = 0o600;
// Owner-only fortress directory, matching the server's own creation mode.
const FORTRESS_DIR_MODE = 0o700;

let fortressHome: Awaited<ReturnType<typeof createTempHome>>;
let originalAgentId: string | undefined;
let cleanups: Array<() => Promise<void>>;

beforeEach(async () => {
  originalAgentId = process.env[AGENT_ID_ENV];
  cleanups = [];
  fortressHome = await createTempHome("sanctuary-gate-requesting-agent");
  await mkdir(fortressHome.defaultFortressPath, {
    recursive: true,
    mode: FORTRESS_DIR_MODE,
  });
  const callbackPolicyYaml = generateDefaultPolicyYaml().replace(
    /approval_channel:\n  type: \w+/,
    "approval_channel:\n  type: callback",
  );
  await writeFile(
    join(fortressHome.defaultFortressPath, "principal-policy.yaml"),
    callbackPolicyYaml,
    { mode: POLICY_FILE_MODE },
  );
});

afterEach(async () => {
  try {
    for (const cleanup of cleanups) await cleanup();
  } finally {
    if (originalAgentId === undefined) delete process.env[AGENT_ID_ENV];
    else process.env[AGENT_ID_ENV] = originalAgentId;
    await fortressHome.cleanup();
  }
});

async function heldStateExportRequest(): Promise<ApprovalRequest> {
  const captured: ApprovalRequest[] = [];
  const deny = async (request: ApprovalRequest): Promise<ApprovalResponse> => {
    captured.push(request);
    return {
      decision: "deny",
      decided_at: new Date().toISOString(),
      decided_by: "human",
    };
  };
  const booted = await createSanctuaryServer({
    storage: new MemoryStorage(),
    passphrase: TEST_PASSPHRASE,
    approvalCallback: deny,
  });
  cleanups.push(() => booted.cleanup());
  const handler = (
    booted.server as unknown as { _requestHandlers: Map<string, Function> }
  )._requestHandlers.get("tools/call");
  if (!handler) throw new Error("tools/call handler not registered");
  await handler(
    { method: "tools/call" as const, params: { name: "state_export", arguments: {} } },
    {},
  );
  expect(captured).toHaveLength(1);
  return captured[0]!;
}

describe("held calls carry the requesting agent through the real boot path", () => {
  it("stamps the wrapped agent's hub id from SANCTUARY_AGENT_ID", async () => {
    process.env[AGENT_ID_ENV] = WRAPPED_AGENT_ID;
    const request = await heldStateExportRequest();
    expect(request.operation).toBe("state_export");
    expect(request.tier).toBe(1);
    expect(request.requesting_agent_id).toBe(EXPECTED_REQUESTER);
    // The attribution is a typed field, not a context key a caller could also write.
    expect(request.context).not.toHaveProperty("agent_id");
  });

  // fail-before-exempt: pins the unattributed case, which is also absent on the base; its witness is a planted change
  // that stamps a placeholder requester when SANCTUARY_AGENT_ID is unset, which turns it red.
  it("leaves a hold unattributed when the process serves no wrapped agent", async () => {
    delete process.env[AGENT_ID_ENV];
    const request = await heldStateExportRequest();
    expect(request.requesting_agent_id).toBeUndefined();
  });
});
