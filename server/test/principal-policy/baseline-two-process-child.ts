/**
 * Child fixture for baseline-two-process.test.ts: boots a real server on the fortress named by the
 * environment, remembers one key in its own session, reports ready on stdout, then exits cleanly
 * (running cleanup, which saves a whole snapshot) when the parent writes "exit" on stdin.
 */
import { createSanctuaryServer } from "../../src/index.js";
import type { ApprovalResponse } from "../../src/principal-policy/types.js";

async function main(): Promise<void> {
  let approvals = 0;
  // Non-interactive: every approval request is denied and counted.
  const deny = async (): Promise<ApprovalResponse> => {
    approvals++;
    return { decision: "deny", decided_at: new Date().toISOString(), decided_by: "human" };
  };
  const booted = await createSanctuaryServer({ approvalCallback: deny });
  const handler = (booted.server as unknown as {
    _requestHandlers: Map<string, (request: unknown, extra: unknown) => Promise<{ content: Array<{ text: string }> }>>;
  })._requestHandlers.get("tools/call");
  if (!handler) throw new Error("tools/call handler not registered");
  const result = await handler({ method: "tools/call", params: { name: "sanctuary_remember", arguments: { key: "cup", value: process.argv[2] ?? "" } } }, {});
  const body = JSON.parse(result.content[0]!.text) as Record<string, unknown>;
  process.stdout.write(`${JSON.stringify({ ready: true, saved: body.key === "cup", approvals })}\n`);
  let input = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) {
    input += chunk;
    if (input.includes("exit\n")) break;
  }
  await booted.cleanup();
  process.exit(0);
}

main().catch((error: unknown) => {
  process.stderr.write(`child failed: ${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exit(1);
});
