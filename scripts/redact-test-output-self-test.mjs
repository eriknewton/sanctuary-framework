#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const redactor = join(scriptDir, "redact-test-output.mjs");

const forbidden = [
  "RECOVERY_VALUE_SHOULD_NOT_SURVIVE",
  "AUTH_VALUE_SHOULD_NOT_SURVIVE",
  "PASSPHRASE_VALUE_SHOULD_NOT_SURVIVE",
  "BEARER_VALUE_SHOULD_NOT_SURVIVE",
  "RECOVERY_PATH_SHOULD_NOT_SURVIVE",
  "KEYRING_ID_SHOULD_NOT_SURVIVE",
  "ENV_VALUE_SHOULD_NOT_SURVIVE",
];

const input = [
  "Test Files  1132 passed (1132)",
  "Tests  16389 passed | 4 skipped (16393)",
  "Recovery key:",
  "  RECOVERY_VALUE_SHOULD_NOT_SURVIVE",
  "Auth token: AUTH_VALUE_SHOULD_NOT_SURVIVE",
  'fixture={"passphrase":"PASSPHRASE_VALUE_SHOULD_NOT_SURVIVE"}',
  "Authorization: Bearer BEARER_VALUE_SHOULD_NOT_SURVIVE",
  "Recovery material staged locally for the operator at:",
  "  RECOVERY_PATH_SHOULD_NOT_SURVIVE",
  "Also escrowed in the OS keyring (service sanctuary-recovery-KEYRING_ID_SHOULD_NOT_SURVIVE)",
  "https://127.0.0.1/?token=AUTH_VALUE_SHOULD_NOT_SURVIVE",
  "SANCTUARY_RECOVERY_KEY=ENV_VALUE_SHOULD_NOT_SURVIVE",
  "Transform failed with 1 error",
  "",
].join("\n");

const result = spawnSync(process.execPath, [redactor], {
  encoding: "utf8",
  input,
});

if (result.status !== 0) {
  process.stderr.write(result.stderr || `redactor exited ${result.status}\n`);
  process.exit(1);
}

for (const value of forbidden) {
  if (result.stdout.includes(value)) {
    throw new Error(`redactor leaked planted sentinel: ${value}`);
  }
}

for (const preserved of [
  "Test Files  1132 passed (1132)",
  "Tests  16389 passed | 4 skipped (16393)",
  "Transform failed with 1 error",
]) {
  if (!result.stdout.includes(preserved)) {
    throw new Error(`redactor changed gate-significant output: ${preserved}`);
  }
}

const redactionCount = result.stdout.match(/\[REDACTED\]/g)?.length ?? 0;
if (redactionCount !== 8) {
  throw new Error(`expected 8 redactions, observed ${redactionCount}`);
}

// A diagnostic arriving where a multiline value was expected must not become
// an apparently clean gate transcript. Refuse without echoing candidate bytes.
// Exercise the actual consumers' entire classifier sets, not a hand-maintained
// subset. A changed declaration format must fail this extraction for review.
const consumerMarkers = [
  [join(scriptDir, "../.githooks/pre-commit"), /TRANSFORM_ERROR_PATTERNS='\(([^']+)\)'/],
  [join(scriptDir, "../.github/workflows/test-baseline-guard.yml"), /PATTERNS='\(([^']+)\)'/],
].flatMap(([path, pattern]) => {
  const match = readFileSync(path, "utf8").match(pattern);
  if (!match) throw new Error("gate classifier extraction needs review");
  return match[1].split("|");
});
const diagnostics = [
  ...new Set(consumerMarkers),
  "Test Files 1132 passed (1132)",
  "Tests 16315 passed (16315)",
];
const labels = [
  "Recovery key:",
  "Auth token:",
  "Recovery material staged locally for the operator at:",
  "An off-host plaintext copy was written to:",
  "Sanctuary init: recovery key written to:",
];
const sentinel = "COLLISION_VALUE_MUST_NOT_BE_EMITTED";
for (const first of labels) {
  for (const second of labels) {
    const consecutive = spawnSync(process.execPath, [redactor], {
      encoding: "utf8",
      input: `${first}\n${second}\n${sentinel}\n`,
    });
    if (consecutive.status !== 0 || consecutive.stdout.includes(sentinel) ||
        consecutive.stderr.includes(sentinel)) {
      throw new Error("consecutive labels exposed the following value");
    }
  }
}
for (const diagnostic of diagnostics) {
  for (const label of labels) {
    const collision = spawnSync(process.execPath, [redactor], {
      encoding: "utf8",
      input: `${label}\n\n${diagnostic} ${sentinel}\n${sentinel}_DELAYED\nTests 16315 passed (16315)\n`,
    });
    if (collision.status !== 1 ||
        collision.stdout.includes(sentinel) || collision.stderr.includes(sentinel)) {
      throw new Error("multiline diagnostic collision did not fail closed safely");
    }
  }
  const inline = spawnSync(process.execPath, [redactor], {
    encoding: "utf8",
    input: `fixture={"passphrase":"${diagnostic} ${sentinel}"}\n`,
  });
  if (inline.status !== 1 || inline.stdout.includes(sentinel) || inline.stderr.includes(sentinel)) {
    throw new Error("inline diagnostic collision did not fail closed safely");
  }
}

process.stdout.write("redact-test-output self-test: PASS\n");
