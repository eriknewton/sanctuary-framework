#!/usr/bin/env node
/**
 * Sanctuary Quickstart CLI entry point.
 *
 * Generates an Ed25519 identity and saves it locally. Publishing a profile
 * to Verascore happens only when the operator asks for it: `--publish`, or
 * a yes at the interactive prompt. See `cli.ts` for the decision order.
 *
 * Usage:
 *   npx @sanctuary-framework/quickstart
 *   npx @sanctuary-framework/quickstart --name="My Agent" --publish
 *   npx @sanctuary-framework/quickstart --name="My Agent" --no-publish
 */

import os from "node:os";

import { run } from "./cli.js";

const RED = "\x1b[31m";
const RESET = "\x1b[0m";

run({
  argv: process.argv.slice(2),
  env: process.env,
  input: process.stdin,
  output: process.stdout,
  // The prompt is only offered when a person can see it and answer it.
  interactive: Boolean(process.stdin.isTTY && process.stdout.isTTY),
  homeDir: os.homedir(),
}).then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    process.stderr.write(`${RED}Fatal:${RESET} ${(err as Error).message}\n`);
    process.exitCode = 1;
  },
);
