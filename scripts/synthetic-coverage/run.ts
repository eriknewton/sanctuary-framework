import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import "./fixtures/substrate-trust/attestation-envelope.js";
import "./fixtures/substrate-trust/audit-chain-checkpoint.js";
import "./fixtures/substrate-trust/certificate-to-key.js";
import "./fixtures/substrate-trust/custody-key-isolation.js";
import "./fixtures/substrate-trust/identity-signing.js";
import "./fixtures/castle-wall/boundary-admission.js";
import "./fixtures/castle-wall/custody-key-gate.js";
import "./fixtures/castle-wall/deny-by-default.js";
import "./fixtures/castle-wall/identity-signing-tool-registry-guard.js";
import "./fixtures/castle-wall/sentinel-registration.js";
import "./fixtures/audit-and-envelope/audit-chain-verifier.js";
import "./fixtures/audit-and-envelope/state-envelope-migration.js";
import "./fixtures/outbound-trust/context-gate-source-of-truth.js";
import "./fixtures/outbound-trust/query-anonymity.js";
import "./fixtures/proxy/proxy-env-isolation.js";
import "./fixtures/proxy/proxy-sse-ssrf.js";
import "./fixtures/proxy/proxy-tool-discovery.js";
import "./fixtures/state-trust/config-profile-fail-closed.js";
import "./fixtures/state-trust/critical-audit-durability.js";
import "./fixtures/state-trust/exit-bundle.js";
import { buildReport, renderMarkdownSummary } from "./report.js";

function findRepoRoot(start = process.cwd()): string {
  let current = resolve(start);
  while (true) {
    if (existsSync(resolve(current, "ASSURANCE_MATRIX.md"))) {
      return current;
    }
    const parent = dirname(current);
    if (parent === current) {
      throw new Error(`Unable to locate repository root from ${start}`);
    }
    current = parent;
  }
}

async function main(): Promise<void> {
  const platform = process.platform === "darwin" ? "macos" : "linux";
  const sha = process.env.GITHUB_SHA ?? "local";
  const report = await buildReport({ platform, sha });
  const outDir = resolve(findRepoRoot(), "scripts/synthetic-coverage/.out");
  mkdirSync(outDir, { recursive: true });
  writeFileSync(resolve(outDir, "report.json"), JSON.stringify(report, null, 2));
  writeFileSync(resolve(outDir, "report.md"), renderMarkdownSummary(report));
  console.log(renderMarkdownSummary(report));
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
