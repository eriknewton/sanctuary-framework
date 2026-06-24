/**
 * sanctuary deploy
 *
 * Pure provider-neutral deploy plan renderer. It does not read or write
 * Sanctuary state and it never emits custody, enrollment, or recovery material.
 */

import { execPath } from "node:process";
import { resolve } from "node:path";
import { Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { OPERATOR_CLOUD_DISCLOSURE } from "../mesh/node-posture.js";

export interface DeployCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  binaryPath?: string;
}

export interface OperatorCloudPlanOpts {
  provider: string;
  label: string;
  region: string;
  serviceUser: string;
  stateDir: string;
  installDir: string;
  binary: string;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

export async function runDeployCommand(args: DeployCommandArgs): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const [target, action, ...rest] = args.argv;

  if (!target || target === "--help" || target === "-h") {
    printUsage(target ? out : err);
    return target ? 0 : 2;
  }
  if (target !== "operator-cloud") {
    write(err, `Unknown deploy target: ${target}\n`);
    printUsage(err);
    return 2;
  }
  if (!action || action === "--help" || action === "-h") {
    printOperatorCloudUsage(action ? out : err);
    return action ? 0 : 2;
  }
  if (action !== "plan") {
    write(err, `Unknown operator-cloud deploy command: ${action}\n`);
    printOperatorCloudUsage(err);
    return 2;
  }
  if (rest.includes("--help") || rest.includes("-h")) {
    printOperatorCloudPlanUsage(out);
    return 0;
  }

  const opts: OperatorCloudPlanOpts = {
    provider: flagValue(rest, "--provider") ?? "generic-ssh",
    label: flagValue(rest, "--label") ?? "operator-cloud-1",
    region: flagValue(rest, "--region") ?? "unspecified",
    serviceUser: flagValue(rest, "--user") ?? "sanctuary",
    stateDir: flagValue(rest, "--state-dir") ?? "/var/lib/sanctuary",
    installDir: flagValue(rest, "--install-dir") ?? "/opt/sanctuary",
    binary: flagValue(rest, "--binary") ?? args.binaryPath ?? resolveBinaryPath(),
  };

  write(out, renderOperatorCloudPlan(opts));
  return 0;
}

function printUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary deploy <target> <command> [options]

Targets:
  operator-cloud   Emit a provider-neutral operator-cloud deployment plan.
`,
  );
}

function printOperatorCloudUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary deploy operator-cloud <command> [options]

Commands:
  plan   Emit disclosure, cloud-init, and systemd skeletons with path/config fields only.
`,
  );
}

function printOperatorCloudPlanUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary deploy operator-cloud plan [options]

Options:
  --provider <name>      Provider label for the plan. Defaults to generic-ssh.
  --label <name>         Node label. Defaults to operator-cloud-1.
  --region <name>        Region label. Defaults to unspecified.
  --user <name>          Service user. Defaults to sanctuary.
  --state-dir <path>     Sanctuary state directory. Defaults to /var/lib/sanctuary.
  --install-dir <path>   Install directory. Defaults to /opt/sanctuary.
  --binary <path>        Sanctuary CLI entrypoint. Defaults to this CLI path.
`,
  );
}

export function renderOperatorCloudPlan(opts: OperatorCloudPlanOpts): string {
  const unit = renderOperatorCloudSystemdUnit(opts);
  return `# Sanctuary operator-cloud deployment plan
schema_version: operator-cloud-deploy-plan-v1
node_mode: operator_cloud
provider: ${opts.provider}
label: ${opts.label}
region: ${opts.region}
trust_boundary: provider in trust boundary, not TEE
tee_attested: false
drill_status: unproven
disclosure: ${OPERATOR_CLOUD_DISCLOSURE}

paths:
  install_dir: ${opts.installDir}
  state_dir: ${opts.stateDir}
  service_user: ${opts.serviceUser}
  binary: ${opts.binary}

cloud_init:
  users:
    - name: ${opts.serviceUser}
      system: true
      shell: /usr/sbin/nologin
  write_files:
    - path: /etc/systemd/system/sanctuary.service
      owner: root:root
      permissions: "0644"
      content: |
${indent(unit, 8)}
  runcmd:
    - mkdir -p ${opts.installDir}
    - mkdir -p ${opts.stateDir}
    - chown ${opts.serviceUser}:${opts.serviceUser} ${opts.stateDir}
    - systemctl daemon-reload
    - systemctl enable --now sanctuary.service

systemd_unit: |
${indent(unit, 2)}`;
}

export function renderOperatorCloudSystemdUnit(opts: OperatorCloudPlanOpts): string {
  return `[Unit]
Description=Sanctuary Operator Cloud Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${opts.serviceUser}
Environment=SANCTUARY_STORAGE_PATH=${opts.stateDir}
WorkingDirectory=${opts.installDir}
ExecStart=${shellQuote(opts.binary)} dashboard --host 0.0.0.0 --no-confirm
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`;
}

function resolveBinaryPath(): string {
  const cliPath = fileURLToPath(import.meta.url);
  if (cliPath.endsWith("/dist/cli/deploy.js")) {
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

function indent(text: string, spaces: number): string {
  const prefix = " ".repeat(spaces);
  return text
    .split("\n")
    .map((line) => (line.length === 0 ? line : prefix + line))
    .join("\n");
}
