#!/usr/bin/env node

// Streams test output to stdout while removing values that must never reach a
// commit hook buffer or a public CI log. The test process still sees and tests
// its real fixture values; only the diagnostic copy is redacted.

import { createInterface } from "node:readline";

const nextLineLabels = [
  /^\s*Recovery key:\s*$/i,
  /^\s*Auth token:\s*$/i,
  /^\s*Recovery material staged locally for the operator at:\s*$/i,
  /^\s*An off-host plaintext copy was written to:\s*$/i,
  /^\s*Sanctuary init: recovery key written to:\s*$/i,
];

const labelledValue =
  /((?:"|'|&quot;)?(?:recovery(?:[ _-]?key)?|passphrase|auth(?:entication)?[ _-]?token|bearer[ _-]?token|SANCTUARY_(?:PASSPHRASE|RECOVERY_KEY|DASHBOARD_AUTH_TOKEN))(?:"|'|&quot;)?\s*(?::|=)\s*)("[^"]*"|'[^']*'|[^\s,}\]]+)/gi;

const cliSecret =
  /((?:--(?:auth-token|passphrase|recovery-key)|Authorization:\s*Bearer)\s+)([^\s]+)/gi;

const queryToken = /([?&](?:token|auth_token|bearer_token)=)[^&#\s]+/gi;
const keyringService = /(service\s+sanctuary-recovery-)[^)\s]+/gi;

// Output can interleave a diagnostic with a secret value. Never silently hide
// a gate diagnostic during redaction: suppress the bytes but fail the pipeline.
// These broad words cover the transform/collection classifier and count headers
// in both .githooks/pre-commit and .github/workflows/test-baseline-guard.yml.
const gateDiagnostic = /\b(?:transform|failed|cannot|tests|test files)\b/i;

let redactNextNonEmpty = false;

function redactLine(line) {
  if (nextLineLabels.some((pattern) => pattern.test(line))) {
    redactNextNonEmpty = true;
    return line;
  }

  if (redactNextNonEmpty && line.trim() !== "") {
    redactNextNonEmpty = false;
    return `${line.match(/^\s*/)?.[0] ?? ""}[REDACTED]`;
  }

  return line
    .replace(labelledValue, "$1[REDACTED]")
    .replace(cliSecret, "$1[REDACTED]")
    .replace(queryToken, "$1[REDACTED]")
    .replace(keyringService, "$1[REDACTED]");
}

process.stdout.on("error", (error) => {
  if (error.code === "EPIPE") process.exit(0);
  throw error;
});

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
let refused = false;
for await (const line of lines) {
  // Drain without forwarding after ambiguity: a delayed value may follow it.
  if (refused) continue;
  const redacted = redactLine(line);
  if (redacted !== line && gateDiagnostic.test(line)) {
    refused = true;
    process.exitCode = 1;
    process.stderr.write("redactor: ambiguous diagnostic; refusing gate output\n");
    continue;
  }
  process.stdout.write(`${redacted}\n`);
}
