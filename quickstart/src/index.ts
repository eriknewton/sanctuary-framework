#!/usr/bin/env node
/**
 * Sanctuary Quickstart CLI
 *
 * Zero-friction agent onboarding. Generates an Ed25519 identity,
 * saves it locally, publishes a sovereign agent profile to Verascore,
 * and prints the live profile URL.
 *
 * Usage:
 *   npx @sanctuary-framework/quickstart
 *   npx @sanctuary-framework/quickstart --name="My Agent" --yes
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";
import readline from "node:readline";

import { generateIdentity, type QuickstartIdentity } from "./identity.js";
import { publishProfile } from "./publish.js";

const VERASCORE_URL = process.env.VERASCORE_URL || "https://verascore.ai";
const IDENTITY_DIR = path.join(os.homedir(), ".sanctuary");
const IDENTITY_PATH = path.join(IDENTITY_DIR, "quickstart-identity.json");

// ANSI color codes (no dependencies).
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";
const CYAN = "\x1b[36m";
const YELLOW = "\x1b[33m";
const RED = "\x1b[31m";

function printBanner(): void {
  const banner = `
${BOLD}${CYAN}   ____                  _
  / ___|  __ _ _ __   ___| |_ _   _  __ _ _ __ _   _
  \\___ \\ / _\` | '_ \\ / __| __| | | |/ _\` | '__| | | |
   ___) | (_| | | | | (__| |_| |_| | (_| | |  | |_| |
  |____/ \\__,_|_| |_|\\___|\\__|\\__,_|\\__,_|_|   \\__, |
                                               |___/ ${RESET}
${DIM}  Zero-friction agent onboarding${RESET}
`;
  process.stdout.write(banner + "\n");
}

function parseArgs(argv: string[]): { name?: string; yes: boolean } {
  let name: string | undefined;
  let yes = false;
  for (const arg of argv.slice(2)) {
    if (arg === "--yes" || arg === "-y") {
      yes = true;
    } else if (arg.startsWith("--name=")) {
      name = arg.slice("--name=".length);
    } else if (arg === "--help" || arg === "-h") {
      process.stdout.write(
        "Usage: sanctuary-quickstart [--name=\"Agent Name\"] [--yes]\n",
      );
      process.exit(0);
    }
  }
  return { name, yes };
}

async function promptName(): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolve) => {
    rl.question(`${BOLD}Agent name:${RESET} `, (answer) => {
      rl.close();
      resolve(answer.trim() || "Sovereign Agent");
    });
  });
}

async function saveIdentity(identity: QuickstartIdentity): Promise<string> {
  await fs.mkdir(IDENTITY_DIR, { recursive: true, mode: 0o700 });
  const json = JSON.stringify(identity, null, 2);
  await fs.writeFile(IDENTITY_PATH, json, { mode: 0o600 });
  // Enforce permissions even if file already existed.
  try {
    await fs.chmod(IDENTITY_PATH, 0o600);
  } catch {
    // best-effort
  }
  return IDENTITY_PATH;
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

async function main(): Promise<void> {
  const { name: nameArg, yes } = parseArgs(process.argv);

  printBanner();

  let agentName: string;
  if (nameArg) {
    agentName = nameArg;
    process.stdout.write(`${DIM}Agent name:${RESET} ${agentName}\n\n`);
  } else if (yes) {
    agentName = "Sovereign Agent";
    process.stdout.write(`${DIM}Agent name:${RESET} ${agentName} (default)\n\n`);
  } else {
    agentName = await promptName();
    process.stdout.write("\n");
  }

  // 1. Generate identity.
  const identity = generateIdentity();

  // 2. Save locally.
  let savedPath = "";
  try {
    savedPath = await saveIdentity(identity);
    process.stdout.write(
      `${GREEN}✓${RESET} Identity created ${DIM}(${savedPath})${RESET}\n`,
    );
    process.stdout.write(`${DIM}  DID: ${identity.did}${RESET}\n`);
  } catch (err) {
    process.stdout.write(
      `${RED}✗${RESET} Failed to save identity: ${(err as Error).message}\n`,
    );
    process.exit(1);
  }

  // 3. Publish to Verascore.
  process.stdout.write(`${DIM}  Publishing to ${VERASCORE_URL}...${RESET}\n`);
  try {
    const result = await publishProfile(identity, agentName, VERASCORE_URL);
    if (result.ok) {
      process.stdout.write(`${GREEN}✓${RESET} Profile published\n\n`);
      process.stdout.write(greenBox(result.profileUrl) + "\n\n");
      process.stdout.write(
        `${BOLD}Next steps:${RESET}\n` +
          `  ${DIM}•${RESET} Claim this identity at: ${CYAN}${result.profileUrl}${RESET}\n` +
          `  ${DIM}•${RESET} Install full Sanctuary:  ${CYAN}npm install -g @sanctuary-framework/mcp-server${RESET}\n` +
          `  ${DIM}•${RESET} Identity saved at:       ${DIM}${savedPath}${RESET}\n\n`,
      );
    } else {
      process.stdout.write(
        `${YELLOW}!${RESET} Publish returned status ${result.status}. Identity saved locally.\n`,
      );
      process.stdout.write(
        `${DIM}  You can publish later with the full Sanctuary server.${RESET}\n` +
          `${DIM}  Identity: ${savedPath}${RESET}\n` +
          `${DIM}  DID:      ${identity.did}${RESET}\n\n`,
      );
    }
  } catch (err) {
    process.stdout.write(
      `${YELLOW}!${RESET} Could not reach Verascore: ${(err as Error).message}\n`,
    );
    process.stdout.write(
      `${DIM}  Identity saved locally. You can publish later.${RESET}\n` +
        `${DIM}  Identity: ${savedPath}${RESET}\n` +
        `${DIM}  DID:      ${identity.did}${RESET}\n\n`,
    );
  }
}

main().catch((err) => {
  process.stderr.write(`${RED}Fatal:${RESET} ${(err as Error).message}\n`);
  process.exit(1);
});
