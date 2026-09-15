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

let redactNextNonEmpty = false;

function redactLine(line) {
  if (redactNextNonEmpty && line.trim() !== "") {
    redactNextNonEmpty = false;
    return `${line.match(/^\s*/)?.[0] ?? ""}[REDACTED]`;
  }

  if (nextLineLabels.some((pattern) => pattern.test(line))) {
    redactNextNonEmpty = true;
    return line;
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
for await (const line of lines) {
  process.stdout.write(`${redactLine(line)}\n`);
}
