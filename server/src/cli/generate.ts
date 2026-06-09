/**
 * sanctuary generate
 *
 * Pure deployment-template generator. Does not read or write Sanctuary state.
 */

import { execPath } from "node:process";
import { userInfo } from "node:os";
import { resolve } from "node:path";
import { Writable } from "node:stream";
import { fileURLToPath } from "node:url";

export interface GenerateCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  currentUser?: string;
  binaryPath?: string;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

export async function runGenerateCommand(
  args: GenerateCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const [sub, ...rest] = args.argv;

  if (!sub || sub === "--help" || sub === "-h") {
    printUsage(sub ? out : err);
    return sub ? 0 : 2;
  }
  if (sub !== "systemd") {
    write(err, `Unknown generate command: ${sub}\n`);
    printUsage(err);
    return 2;
  }
  if (rest.includes("--help") || rest.includes("-h")) {
    printSystemdUsage(out);
    return 0;
  }

  const user = flagValue(rest, "--user") ?? args.currentUser ?? userInfo().username;
  const stateDir = flagValue(rest, "--state-dir") ?? "~/.sanctuary";
  const binary = flagValue(rest, "--binary") ?? args.binaryPath ?? resolveBinaryPath();
  const platform = args.platform ?? process.platform;

  write(out, renderSystemdUnit({ user, stateDir, binary, platform }));
  return 0;
}

function printUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary generate <command> [options]

Commands:
  systemd   Emit a Linux systemd service unit for the Sanctuary daemon.
`,
  );
}

function printSystemdUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary generate systemd [--user <name>] [--state-dir <path>] [--binary <path>]

Options:
  --user <name>       Service user. Defaults to the current user.
  --state-dir <path>  Sanctuary state directory. Defaults to ~/.sanctuary.
  --binary <path>     Sanctuary CLI entrypoint. Defaults to this CLI path.
`,
  );
}

export function renderSystemdUnit(opts: {
  user: string;
  stateDir: string;
  binary: string;
  platform?: NodeJS.Platform;
}): string {
  const note =
    opts.platform === "darwin"
      ? "# Note: this host is macOS. This unit is for Linux systemd hosts; macOS launchd is out of scope.\n"
      : "";
  return `# Sanctuary systemd unit
# Install:
#   sudo install -m 0644 sanctuary.service /etc/systemd/system/sanctuary.service
#   sudo systemctl daemon-reload
#   sudo systemctl enable --now sanctuary.service
${note}[Unit]
Description=Sanctuary MCP Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${opts.user}
Environment=SANCTUARY_STORAGE_PATH=${opts.stateDir}
ExecStart=${shellQuote(opts.binary)} dashboard --no-confirm
Restart=on-failure
RestartSec=5
WorkingDirectory=/

[Install]
WantedBy=multi-user.target
`;
}

function resolveBinaryPath(): string {
  const cliPath = fileURLToPath(import.meta.url);
  if (cliPath.endsWith("/dist/cli/generate.js")) {
    return resolve(cliPath, "../../cli.js");
  }
  return execPath;
}

function shellQuote(value: string): string {
  if (/^[A-Za-z0-9_@%+=:,./~-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function flagValue(argv: string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index !== -1) return argv[index + 1];
  const prefixed = argv.find((arg) => arg.startsWith(`${name}=`));
  return prefixed?.slice(name.length + 1);
}
