import { createInterface } from "node:readline";

/**
 * Bound on `--passphrase-stdin` reads so a pipe that is opened and never
 * written does not hang the command forever. Callers render the empty result
 * according to their command's credential policy.
 */
export const PASSPHRASE_STDIN_READ_DEADLINE_MS = 30_000;

/**
 * Read the first line from stdin as a fortress passphrase. `readline` strips
 * exactly the line terminator it consumed, so the returned value is the
 * operator's line content, never the trailing newline from a pipe.
 */
export async function readPassphraseFromStdin(
  stdin: NodeJS.ReadableStream,
): Promise<string> {
  return new Promise((resolvePassphrase) => {
    const rl = createInterface({ input: stdin });
    let settled = false;
    const finish = (value: string): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      try {
        rl.close();
      } catch {
        // Already closed; the value is what matters.
      }
      resolvePassphrase(value);
    };
    const deadline = setTimeout(() => finish(""), PASSPHRASE_STDIN_READ_DEADLINE_MS);
    rl.once("line", (line) => finish(line));
    rl.once("close", () => finish(""));
    rl.once("error", () => finish(""));
  });
}
