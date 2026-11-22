/** Operator control of the next server start's default session binding. */
import { stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import type { Writable } from "node:stream";
import { updateFortressConfig } from "../config.js";
import { resolveStoragePath } from "../paths.js";
import { consumeFlagValue, FORTRESS_FLAG_USAGE_EXIT_CODE, shellQuoteSingleArg } from "./argv.js";

/** The operator command wrap and init print whenever they leave default binding off; it names runSessionBindingCommand's enable. */
export function sessionBindingEnableHint(fortressPath: string): string {
  return `  To enable default session binding, run sanctuary session-binding enable --fortress ${shellQuoteSingleArg(fortressPath)}`;
}

const HELP = `Usage: sanctuary session-binding <enable|disable|status> [--fortress <path>] [--yes]

A flag written to a different fortress path reads as off; status prints the absolute path it read.
A server that was already running when you disabled the flag stays bound until it exits; restart it.
A sanctuary.json.lock left by a killed command makes the next start wait and then refuse; remove it only when no Sanctuary process is running.
`;

/** Change only the operator-owned binding key, or report it without writing. */
export async function runSessionBindingCommand(options: {
  argv: string[];
  env?: NodeJS.ProcessEnv;
  out?: Writable;
  err?: Writable;
}): Promise<number> {
  const out = options.out ?? process.stdout;
  const err = options.err ?? process.stderr;
  const parsed = consumeFlagValue(options.argv, "--fortress");
  if (parsed.error) {
    err.write(`${parsed.error}\n`);
    return FORTRESS_FLAG_USAGE_EXIT_CODE;
  }
  if (parsed.argv.includes("--help") || parsed.argv.includes("-h")) {
    out.write(HELP);
    return 0;
  }
  const [command, ...flags] = parsed.argv;
  if (!["enable", "disable", "status"].includes(command ?? "") || flags.some(flag => flag !== "--yes")) {
    err.write(HELP);
    return FORTRESS_FLAG_USAGE_EXIT_CODE;
  }
  const fortress = resolve(parsed.value ?? resolveStoragePath(options.env ?? process.env));
  const path = join(fortress, "sanctuary.json");

  try {
    if (!(await stat(fortress)).isDirectory()) throw new Error("Fortress path is not a directory");
  } catch (error) {
    out.write(`Config: ${path}\n`);
    err.write(`Fortress directory must exist: ${error instanceof Error ? error.message : String(error)}\n`);
    return FORTRESS_FLAG_USAGE_EXIT_CODE;
  }
  try {
    if (command === "status") {
      const { sessionBindingStatus } = await import("./doctor.js");
      const report = await sessionBindingStatus(fortress, options.env ?? process.env);
      out.write(`${report.message}\n${report.hint}\n`);
      return report.status === "FAIL" ? 1 : 0;
    }
    out.write(`Config: ${path}\n`);
    const enabled = command === "enable";
    out.write(`Write session_binding: ${JSON.stringify({ sole_identity: enabled })}\n`);
    if (!flags.includes("--yes")) {
      if (!process.stdin.isTTY) {
        err.write("Without a terminal, enable and disable require --yes.\n");
        return FORTRESS_FLAG_USAGE_EXIT_CODE;
      }
      const terminal = createInterface({ input: process.stdin, output: out });
      try {
        if (!/^y(es)?$/i.test((await terminal.question("Continue? [y/N] ")).trim())) {
          return FORTRESS_FLAG_USAGE_EXIT_CODE;
        }
      } finally {
        terminal.close();
      }
    }
    // The session_binding owner key must match updateFortressConfig in config.ts.
    await updateFortressConfig(path, "session_binding", () => ({ session_binding: { sole_identity: enabled } }));
    out.write("A running server is unaffected until restart.\n");
    return 0;
  } catch (error) {
    err.write(`Session binding: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}
