/**
 * Shared execFile-to-promise runner for the egress-gate module's command
 * shims (`pfctl` in `pf-anchor.ts`, `lsof` in `peer-identity.ts`). One
 * implementation so the fail-closed exit-code semantics cannot drift
 * between the two.
 *
 * Never a shell (argv only; no interpolation surface). A spawn failure,
 * timeout, or signal RESOLVES with a synthetic non-zero exit (127) so every
 * caller stays on its fail-closed path instead of having to catch.
 */

import { execFile } from "node:child_process";

/** Result of one executed command. */
export interface ExecCommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** The runner shape both pf-anchor and peer-identity consume. */
export interface ExecCommandRunner {
  run(command: string, args: readonly string[]): Promise<ExecCommandResult>;
}

/** Build a promise-shaped execFile runner with a hard timeout. */
export function createExecFileRunner(timeoutMs: number): ExecCommandRunner {
  return {
    run(command: string, args: readonly string[]): Promise<ExecCommandResult> {
      return new Promise((resolve) => {
        execFile(
          command,
          [...args],
          { timeout: timeoutMs, encoding: "utf8" },
          (error, stdout, stderr) => {
            if (error && typeof (error as NodeJS.ErrnoException).code !== "number") {
              // Spawn failure / timeout / signal: synthesize a non-zero exit.
              resolve({ code: 127, stdout: stdout ?? "", stderr: `${stderr ?? ""}${error.message}` });
              return;
            }
            const code = error ? ((error as NodeJS.ErrnoException).code as unknown as number) : 0;
            resolve({ code: typeof code === "number" ? code : 127, stdout, stderr });
          },
        );
      });
    },
  };
}
