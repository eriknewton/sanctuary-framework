#!/usr/bin/env node
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const repoRoot = new URL("..", import.meta.url).pathname;
let workflowsDir = join(repoRoot, ".github", "workflows");
if (process.argv.length > 2) {
  if (process.argv.length !== 4 || process.argv[2] !== "--workflows-dir") {
    console.error("Usage: check-release-action-pins.mjs [--workflows-dir <directory>]");
    process.exit(2);
  }
  workflowsDir = process.argv[3];
}
const SHA_PIN = /^[0-9a-f]{40}$/;
const WRITE_PERMISSION = /^(?:\s*permissions:\s*write-all|\s+[A-Za-z][A-Za-z0-9-]*:\s*write)\s*(?:#.*)?$/m;

function isReleaseSensitive(source) {
  const releaseTriggered = /^\s{2}release:\s*$/m.test(source);
  const tagTriggered = /^\s+tags:\s*(?:\[|$)/m.test(source);
  const pullRequestTargetTriggered = /^\s{2}pull_request_target:\s*/m.test(source);
  const explicitlyPrivileged = WRITE_PERMISSION.test(source);
  // A workflow with no top-level permissions declaration inherits the
  // repository default, which operators can configure as read-write. Treat
  // the absence itself as sensitive, regardless of trigger type.
  // Deliberately no leading `\s*`: only a column-zero workflow declaration
  // overrides repository defaults. Job-level permissions do not.
  const inheritsRepositoryDefaults = !/^permissions:/m.test(source);
  return releaseTriggered || tagTriggered || pullRequestTargetTriggered || explicitlyPrivileged || inheritsRepositoryDefaults;
}

const failures = [];
const scanned = [];
function checkExternalUses(name, source) {
  for (const [index, line] of source.split(/\r?\n/).entries()) {
    const match = /^\s*-?\s*uses:\s*([^\s#]+)(?:\s+#.*)?$/.exec(line);
    if (!match || match[1].startsWith("./")) continue;
    const at = match[1].lastIndexOf("@");
    const ref = at >= 0 ? match[1].slice(at + 1) : "";
    if (!SHA_PIN.test(ref)) failures.push(`${name}:${index + 1} ${match[1]}`);
  }
}

for (const name of readdirSync(workflowsDir).filter((entry) => /\.ya?ml$/.test(entry)).sort()) {
  const source = readFileSync(join(workflowsDir, name), "utf8");
  if (!isReleaseSensitive(source)) continue;
  scanned.push(name);
  checkExternalUses(name, source);
}

// A local composite executes inside the caller's authority. Scan every
// repository composite beside .github/workflows so an external dependency
// cannot hide one hop behind `uses: ./.github/actions/...`.
const actionsDir = join(workflowsDir, "..", "actions");
if (existsSync(actionsDir)) {
  const pending = [actionsDir];
  while (pending.length > 0) {
    const dir = pending.pop();
    for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) pending.push(path);
      else if (/^action\.ya?ml$/.test(entry.name)) {
        const label = path.slice(actionsDir.length + 1);
        checkExternalUses(`actions/${label}`, readFileSync(path, "utf8"));
      }
    }
  }
}

if (scanned.length === 0) failures.push("no release-sensitive workflows were discovered (anti-vacuity)");
if (failures.length > 0) {
  console.error("Release action pin check failed. External actions on release-sensitive or privileged workflows must use immutable 40-character commit SHAs:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Release action pin check passed (${scanned.length} workflows plus repository composites: ${scanned.join(", ")}).`);
