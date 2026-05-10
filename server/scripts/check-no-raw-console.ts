#!/usr/bin/env node
/**
 * Sanctuary server console-discipline gate, entry point.
 *
 * Run via:
 *   npx vite-node server/scripts/check-no-raw-console.ts
 *   npx vite-node server/scripts/check-no-raw-console.ts --quiet
 *   npx vite-node server/scripts/check-no-raw-console.ts --root <path>
 *
 * Library + tests live in `check-no-raw-console.lib.ts`. This file is the
 * thin runner so importing the library from the self-test does not
 * inadvertently trigger a scan or a process.exit.
 */

import { resolve } from "node:path";
import { runMain } from "./check-no-raw-console.lib.js";

const defaultRoot = resolve(__dirname, "..", "..");
process.exit(runMain(process.argv.slice(2), defaultRoot));
