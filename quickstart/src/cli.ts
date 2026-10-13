/**
 * Sanctuary Quickstart CLI logic.
 *
 * Generates an Ed25519 identity, saves it locally, and publishes a profile
 * to Verascore only when the operator says so. Kept separate from the bin
 * entry (`index.ts`) so tests can drive `run` with their own streams.
 *
 * Publish decision, in order:
 *   1. `--no-publish`: never publish.
 *   2. `--publish`: publish without asking (scripted use).
 *   3. interactive terminal (stdin and stdout are both TTYs) and no `--yes`:
 *      show the exact request and destination, then ask; the default is No.
 *   4. anything else (no TTY, or `--yes`): do not publish, and say how.
 * The local identity is written before this decision on every path.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import readline from "node:readline";

import { generateIdentity, type QuickstartIdentity } from "./identity.js";
import {
  buildPublishRequest,
  sendPublishRequest,
  type PublishRequest,
} from "./publish.js";

const DEFAULT_VERASCORE_URL = "https://verascore.ai";
const DEFAULT_AGENT_NAME = "Sovereign Agent";

/** Process exit code for a command-line usage error (BSD sysexits convention for bad flags). */
const EXIT_USAGE = 2;

// ANSI color codes (no dependencies).
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";
const CYAN = "\x1b[36m";
const YELLOW = "\x1b[33m";
const RED = "\x1b[31m";

export const HELP_TEXT = `Usage: sanctuary-quickstart [--name="Agent Name"] [--publish | --no-publish] [--yes]

Creates a local Ed25519 identity at ~/.sanctuary/quickstart-identity.json.
Publishing a signed profile to Verascore is optional and off unless you
choose it.

Options:
  --name="Agent Name"  Name for the agent profile (default: "${DEFAULT_AGENT_NAME}").
  --publish            Publish to Verascore without asking. For scripts.
  --no-publish         Never publish. Only the local identity is created.
  --yes, -y            Accept every default without prompting. The publish
                       default is No, so --yes alone does not publish.
  --help, -h           Show this help.

In an interactive terminal with neither --publish nor --no-publish, quickstart
shows exactly what it would send and to which URL, then asks before sending.
Without a terminal it does not publish unless --publish is given.

Environment:
  VERASCORE_URL        Verascore base URL (default: ${DEFAULT_VERASCORE_URL}).
`;

export type PublishFlag = "publish" | "no-publish" | undefined;

export interface ParsedArgs {
  name?: string;
  yes: boolean;
  publish: PublishFlag;
  help: boolean;
  error?: string;
}

export function parseArgs(argv: readonly string[]): ParsedArgs {
  const parsed: ParsedArgs = { yes: false, publish: undefined, help: false };
  let sawPublish = false;
  let sawNoPublish = false;
  for (const arg of argv) {
    if (arg === "--yes" || arg === "-y") {
      parsed.yes = true;
    } else if (arg.startsWith("--name=")) {
      parsed.name = arg.slice("--name=".length);
    } else if (arg === "--publish") {
      sawPublish = true;
    } else if (arg === "--no-publish") {
      sawNoPublish = true;
    } else if (arg === "--help" || arg === "-h") {
      parsed.help = true;
    }
  }
  if (sawPublish && sawNoPublish) {
    parsed.error = "--publish and --no-publish cannot be used together.";
  } else if (sawPublish) {
    parsed.publish = "publish";
  } else if (sawNoPublish) {
    parsed.publish = "no-publish";
  }
  return parsed;
}

/** What happens to the publish step, before any network call. */
export type PublishDecision = "publish" | "skip" | "ask" | "skip-noninteractive";

/**
 * The single place the publish decision is made. Nothing reaches Verascore
 * unless this returns "publish", or returns "ask" and the operator answers
 * yes: data leaves the machine only with explicit operator intent.
 */
export function decidePublish(
  flag: PublishFlag,
  interactive: boolean,
  yes: boolean,
): PublishDecision {
  if (flag === "no-publish") return "skip";
  if (flag === "publish") return "publish";
  if (interactive && !yes) return "ask";
  return "skip-noninteractive";
}

/** Only an explicit yes publishes; Enter, EOF and anything else mean No. */
export function isYes(answer: string): boolean {
  return /^(y|yes)$/i.test(answer.trim());
}

export interface RunOptions {
  /** Arguments after the node binary and script path. */
  argv: readonly string[];
  env: Record<string, string | undefined>;
  input: NodeJS.ReadableStream;
  output: NodeJS.WritableStream;
  /** True when stdin and stdout are both terminals. */
  interactive: boolean;
  /** Directory that holds `.sanctuary/`; the operator's home in production. */
  homeDir: string;
}

function printBanner(out: NodeJS.WritableStream): void {
  const banner = `
${BOLD}${CYAN}   ____                  _
  / ___|  __ _ _ __   ___| |_ _   _  __ _ _ __ _   _
  \\___ \\ / _\` | '_ \\ / __| __| | | |/ _\` | '__| | | |
   ___) | (_| | | | | (__| |_| |_| | (_| | |  | |_| |
  |____/ \\__,_|_| |_|\\___|\\__|\\__,_|\\__,_|_|   \\__, |
                                               |___/ ${RESET}
${DIM}  Zero-friction agent onboarding${RESET}
`;
  out.write(banner + "\n");
}

function greenBox(url: string): string {
  const line = `  Profile: ${url}  `;
  const border = "─".repeat(line.length);
  return [
    `${GREEN}┌${border}┐${RESET}`,
    `${GREEN}│${RESET}${BOLD}${line}${RESET}${GREEN}│${RESET}`,
    `${GREEN}└${border}┘${RESET}`,
  ].join("\n");
}

/**
 * One question at a time over a single readline interface. A closed input
 * (EOF, Ctrl-D) answers with the empty string, which every caller treats as
 * the default.
 */
function makeAsker(opts: RunOptions): {
  ask: (question: string) => Promise<string>;
  close: () => void;
} {
  let rl: readline.Interface | null = null;
  let closed = false;
  const get = (): readline.Interface => {
    if (!rl) {
      rl = readline.createInterface({
        input: opts.input,
        output: opts.output,
        terminal: false,
      });
      rl.on("close", () => {
        closed = true;
      });
    }
    return rl;
  };
  return {
    ask: (question) =>
      new Promise((resolve) => {
        if (closed) {
          resolve("");
          return;
        }
        const iface = get();
        const onClose = (): void => resolve("");
        iface.once("close", onClose);
        iface.question(question, (answer) => {
          iface.off("close", onClose);
          resolve(answer);
        });
      }),
    close: () => {
      if (rl) rl.close();
    },
  };
}

async function saveIdentity(
  identity: QuickstartIdentity,
  homeDir: string,
): Promise<string> {
  const identityDir = path.join(homeDir, ".sanctuary");
  const identityPath = path.join(identityDir, "quickstart-identity.json");
  await fs.mkdir(identityDir, { recursive: true, mode: 0o700 });
  const json = JSON.stringify(identity, null, 2);
  await fs.writeFile(identityPath, json, { mode: 0o600 });
  // Enforce permissions even if file already existed.
  try {
    await fs.chmod(identityPath, 0o600);
  } catch {
    // best-effort
  }
  return identityPath;
}

/**
 * The disclosure shown before the question: the destination and the exact
 * request body. The body is printed from the same object that is sent, so
 * the operator approves what actually leaves the machine.
 */
export function describeRequest(request: PublishRequest): string {
  return (
    `${BOLD}Publishing is optional.${RESET} If you say yes, quickstart sends one HTTP POST.\n` +
    `  To:       ${request.endpoint}\n` +
    `  Profile:  ${request.profileUrl} (public once published)\n` +
    `  Body (sent as compact JSON; nothing else is sent and the private key stays local):\n` +
    `${JSON.stringify(request.body, null, 2)}\n`
  );
}

function printPublishHint(out: NodeJS.WritableStream, savedPath: string): void {
  out.write(
    `${DIM}  Not published. Nothing was sent to Verascore.${RESET}\n` +
      `${DIM}  To publish, run quickstart again with --publish. A new run creates a new${RESET}\n` +
      `${DIM}  identity and replaces ${savedPath}.${RESET}\n\n`,
  );
}

/** Run the quickstart. Resolves to the process exit code. */
export async function run(opts: RunOptions): Promise<number> {
  const out = opts.output;
  const args = parseArgs(opts.argv);

  if (args.help) {
    out.write(HELP_TEXT);
    return 0;
  }
  if (args.error) {
    out.write(`${RED}✗${RESET} ${args.error}\n\n${HELP_TEXT}`);
    return EXIT_USAGE;
  }

  const verascoreUrl = opts.env.VERASCORE_URL || DEFAULT_VERASCORE_URL;
  const decision = decidePublish(args.publish, opts.interactive, args.yes);
  const asker = makeAsker(opts);

  try {
    printBanner(out);

    let agentName: string;
    if (args.name) {
      agentName = args.name;
      out.write(`${DIM}Agent name:${RESET} ${agentName}\n\n`);
    } else if (args.yes || !opts.interactive) {
      agentName = DEFAULT_AGENT_NAME;
      out.write(`${DIM}Agent name:${RESET} ${agentName} (default)\n\n`);
    } else {
      agentName =
        (await asker.ask(`${BOLD}Agent name:${RESET} `)).trim() ||
        DEFAULT_AGENT_NAME;
      out.write("\n");
    }

    // 1. Generate identity. 2. Save locally. Both happen on every path.
    const identity = generateIdentity();
    let savedPath = "";
    try {
      savedPath = await saveIdentity(identity, opts.homeDir);
      out.write(`${GREEN}✓${RESET} Identity created ${DIM}(${savedPath})${RESET}\n`);
      out.write(`${DIM}  DID: ${identity.did}${RESET}\n\n`);
    } catch (err) {
      out.write(`${RED}✗${RESET} Failed to save identity: ${(err as Error).message}\n`);
      return 1;
    }

    // 3. Decide whether to publish. Only "publish", or "ask" answered yes,
    // reaches the network.
    const request = buildPublishRequest(identity, agentName, verascoreUrl);
    let publish = decision === "publish";
    if (decision === "ask") {
      out.write(describeRequest(request) + "\n");
      publish = isYes(await asker.ask(`${BOLD}Publish this profile to Verascore? [y/N]${RESET} `));
      out.write("\n");
    }
    if (!publish) {
      printPublishHint(out, savedPath);
      return 0;
    }

    out.write(`${DIM}  Publishing to ${request.endpoint}...${RESET}\n`);
    try {
      const result = await sendPublishRequest(request);
      if (result.ok) {
        out.write(`${GREEN}✓${RESET} Profile published\n\n`);
        out.write(greenBox(result.profileUrl) + "\n\n");
        out.write(
          `${BOLD}Next steps:${RESET}\n` +
            `  ${DIM}•${RESET} Claim this identity at: ${CYAN}${result.profileUrl}${RESET}\n` +
            `  ${DIM}•${RESET} Install full Sanctuary:  ${CYAN}npm install -g @sanctuary-framework/mcp-server${RESET}\n` +
            `  ${DIM}•${RESET} Identity saved at:       ${DIM}${savedPath}${RESET}\n\n`,
        );
      } else {
        out.write(
          `${YELLOW}!${RESET} Publish returned status ${result.status}. Identity saved locally.\n`,
        );
        out.write(
          `${DIM}  You can publish later with the full Sanctuary server.${RESET}\n` +
            `${DIM}  Identity: ${savedPath}${RESET}\n` +
            `${DIM}  DID:      ${identity.did}${RESET}\n\n`,
        );
      }
    } catch (err) {
      out.write(`${YELLOW}!${RESET} Could not reach Verascore: ${(err as Error).message}\n`);
      out.write(
        `${DIM}  Identity saved locally. You can publish later.${RESET}\n` +
          `${DIM}  Identity: ${savedPath}${RESET}\n` +
          `${DIM}  DID:      ${identity.did}${RESET}\n\n`,
      );
    }
    return 0;
  } finally {
    asker.close();
  }
}
