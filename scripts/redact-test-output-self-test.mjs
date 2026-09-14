#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

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

process.stdout.write("redact-test-output self-test: PASS\n");
