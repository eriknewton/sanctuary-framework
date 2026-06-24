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

export interface OperatorCloudDeliveryOpts {
  host: string;
  user: string;
  bundlePath: string;
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
  if (action === "delivery") {
    if (rest.includes("--help") || rest.includes("-h")) {
      printOperatorCloudDeliveryUsage(out);
      return 0;
    }
    const deliveryOpts: OperatorCloudDeliveryOpts = {
      host: flagValue(rest, "--host") ?? "<operator-approved-host>",
      user: flagValue(rest, "--user") ?? "sanctuary",
      bundlePath: flagValue(rest, "--bundle-path") ?? "/run/sanctuary/provision-bundle.json",
    };
    write(out, renderOperatorCloudDeliveryPlan(deliveryOpts));
    return 0;
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
  plan       Emit disclosure, cloud-init, and systemd skeletons with path/config fields only.
  delivery   Emit a secret-free post-boot bundle-delivery skeleton (SSH/pull). No secrets.
`,
  );
}

function printOperatorCloudDeliveryUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary deploy operator-cloud delivery [options]

Emit a secret-free plan for delivering the scoped provision bundle to a booted
operator-cloud VM over an operator-approved SSH/pull channel. NEVER place the
bundle in cloud-init/user-data. This command emits NO secret material.

Options:
  --host <host>          Operator-approved delivery host. Display only.
  --user <name>          SSH user. Defaults to sanctuary.
  --bundle-path <path>   Where the bundle lands on the VM. Defaults to /run/sanctuary/provision-bundle.json.
`,
  );
}

/**
 * Render a SECRET-FREE post-boot delivery skeleton. The scoped provision bundle
 * is delivered AFTER the VM boots, over an operator-approved SSH/pull channel,
 * and NEVER through cloud-init/user-data. This renderer emits no secret bytes:
 * the bundle + its one-time delivery key are produced and approved separately
 * by the local `operator-cloud provision` flow and copied by the operator.
 */
export function renderOperatorCloudDeliveryPlan(opts: OperatorCloudDeliveryOpts): string {
  return `# Sanctuary operator-cloud bundle delivery plan (post-boot, secret-free)
schema_version: operator-cloud-delivery-plan-v1
delivery_channel: ssh-pull
cloud_init_embedding: forbidden
disclosure: ${OPERATOR_CLOUD_DISCLOSURE}

# Step 1 (on the VM, after boot): mint a one-time prepare id + delivery pubkey.
#   ${shellQuote(opts.bundlePath)} is written 0600 and consumed once.
# Step 2 (on the operator's local machine): run the approved provision flow,
#   which prebuilds + digests the bundle and shows the Tier-1 approval prompt.
# Step 3 (after approval): copy the encrypted bundle to the VM over SSH.
steps:
  - run_on: vm
    description: prepare one-time delivery material (no secrets leave the VM)
  - run_on: operator-local
    description: approve provision (Tier 1) and encrypt the bundle to the prepare material
  - run_on: operator-local
    description: scp -p the encrypted bundle to ${opts.user}@${opts.host}:${opts.bundlePath}
  - run_on: vm
    description: sanctuary federation join --provision-bundle ${opts.bundlePath} (consumed once, then deleted)

# The bundle and its delivery key NEVER appear in cloud-init, user-data, serial
# console, shell history, or provider metadata. Delete the bundle on the VM after
# join completes.
`;
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
