#!/usr/bin/env node

import { runSafeModeDaemon } from "./castle-wall.js";

const argv = process.argv.slice(2);
if (
  argv[0] !== "castle-wall" ||
  argv[1] !== "daemon" ||
  !argv.slice(2).includes("--safe-mode") ||
  !argv.slice(2).includes("--launchd")
) {
  process.stderr.write(
    "This executable is restricted to Castle Wall launchd safe mode.\n",
  );
  process.exitCode = 2;
} else {
  process.exitCode = await runSafeModeDaemon(argv.slice(2));
}
