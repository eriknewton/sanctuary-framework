import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  produceGateArtifact,
  renderGateArtifactMarkdown,
  type CoverageReport,
  type ParityReport,
} from "./rollup.js";

const linuxPath = process.argv[2];
const macosPath = process.argv[3];
const parityPath = process.argv[4];

if (!linuxPath || !macosPath || !parityPath) {
  console.error("Usage: rollup-cli <linux-report.json> <macos-report.json> <parity-report.json>");
  process.exit(1);
}

const linux: CoverageReport = JSON.parse(readFileSync(linuxPath, "utf8"));
const macos: CoverageReport = JSON.parse(readFileSync(macosPath, "utf8"));
const parity: ParityReport = JSON.parse(readFileSync(parityPath, "utf8"));
const artifact = produceGateArtifact(linux, macos, parity);
const outDir = resolve(process.cwd(), "scripts/synthetic-coverage/.out");
const markdown = renderGateArtifactMarkdown(artifact);

mkdirSync(outDir, { recursive: true });
writeFileSync(resolve(outDir, "gate-a-artifact.json"), JSON.stringify(artifact, null, 2));
writeFileSync(resolve(outDir, "gate-a-artifact.md"), markdown);
console.log(markdown);

if (artifact.gate_state !== "gate_a_green") {
  process.exit(2);
}
