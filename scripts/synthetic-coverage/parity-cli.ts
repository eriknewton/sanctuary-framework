import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { compareReports, renderParityMarkdown, type CoverageReport } from "./parity.js";

const linuxPath = process.argv[2];
const macosPath = process.argv[3];

if (!linuxPath || !macosPath) {
  console.error("Usage: parity-cli <linux-report.json> <macos-report.json>");
  process.exit(1);
}

const linux: CoverageReport = JSON.parse(readFileSync(linuxPath, "utf8"));
const macos: CoverageReport = JSON.parse(readFileSync(macosPath, "utf8"));
const report = compareReports(linux, macos);
const outDir = resolve(process.cwd(), "scripts/synthetic-coverage/.out");
const markdown = renderParityMarkdown(report);

mkdirSync(outDir, { recursive: true });
writeFileSync(resolve(outDir, "parity.json"), JSON.stringify(report, null, 2));
writeFileSync(resolve(outDir, "parity.md"), markdown);
console.log(markdown);

if (report.parity_state !== "clean") {
  process.exit(2);
}
