# Ubuntu cold-install operator guide

The explicit `install` variant packages the daemon, `sanctuary-linux`, the
`protected-agent-v1` launcher, the finite `network-agent-standin`, and the three
required systemd units for Ubuntu 24.04 amd64 with systemd 255. Installation is
inert. Provisioning and activation are separate operator actions.

Linux remains drill-gated under the [Assurance Matrix](../../../ASSURANCE_MATRIX.md).
An active unit or `KernelRuntimeReady` is not `Enforcing`. This path witnesses
the shipped stand-in; a third-party workload needs its own captured evidence.
No reboot or general Linux enforcement assurance follows from package tests.

## Artifact and prerequisites

Obtain the exact package artifact (the published pre-release is
[Castle Wall Linux 0.1.0-1](https://github.com/eriknewton/sanctuary-framework/releases/tag/castle-wall-linux-0.1.0-1),
asset `sanctuary-castle-wall_0.1.0-1_amd64.deb`, source commit `bbd6c7d7`) and
its independently authenticated source SHA, SHA-256, required-check inventory,
workstation signer artifact, `endpoints.json` and `rules.json`. Require all checks at that source head to have succeeded;
a missing, skipped or cancelled required job is not success. The adjacent
checksum detects corruption but does not authenticate delivery.

Use a fresh Ubuntu host with real PID 1 systemd, unified cgroup v2, working
IPv4/IPv6 routes and nftables/NFQUEUE. The package declares runtime dependencies;
no compiler, checkout or Node runtime is required on the target. The owner uses
the separate `sanctuary-linux-policy-sign` workstation executable. Existing
accounts, configuration, mounts, unit overrides or product state cause refusal.
There is no upgrade, account adoption or internal-package conversion path.

The example identity is U=60123, reserved service number B=60124,
F=0123456789abcdef, signed system uid ceiling 1000. Confirm these identities
are unused before choosing them. B remains absent from NSS in this no-broker
profile. Do not create a broker account. Provision creates the `sanctuary`
group and exact locked, nologin U account/group without a persistent home.
Failure mode: NSS timeout or incomplete output is uncertainty, not absence.

## Install, provision and start

1. As the ordinary operator, verify the delivered bytes:

   ```bash
   printf '%s  install.deb\n' "$INSTALL_SHA256" | sha256sum -c -
   ```

   Verify the workstation artifact and input hashes in the same way. Stop on
   any mismatch or unavailable required-check evidence.

2. Record OS/kernel/systemd versions, machine and boot IDs, package/account/nft
   inventory, routes and independent network controls, then install:

   ```bash
   sudo apt-get install ./install.deb
   /usr/local/libexec/sanctuary/network-agent-standin --control --endpoints endpoints.json
   ```

   Verify wall and mount remain inactive, no agent runs and no account or policy
   was created. The control sends exactly one immediate attempt to each of six
   endpoints and exits with bounded JSON testimony. Independent receiver records
   must establish reachability; exit zero alone does not. Failure mode: auto-start
   or an unreachable family invalidates the installation observation.

3. Stage the literal command and bounded endpoints:

   ```bash
   sudo sanctuary-linux provision --agent-uid 60123 --service-uid 60124 --fortress-id 0123456789abcdef --stage-file endpoints.json -- /usr/local/libexec/sanctuary/network-agent-standin --endpoints /etc/sanctuary/agent/endpoints.json
   ```

   For another workload, substitute a root-installed ELF and literal arguments
   after `--`. Shell scripts, PATH lookup and shell interpolation are unsupported.
   Configured must still be absent. Failure mode: interrupted provisioning must
   not authorize a launch; only the identical request can resume its transaction.

4. On the separately authorized owner workstation, with descriptor 3 supplied
   by existing owner custody, sign the explicit generation `N`:

   ```bash
   sanctuary-linux-policy-sign --fortress-id 0123456789abcdef --agent-uid 60123 --system-uid-ceiling 1000 --generation "$N" --rules rules.json --key-fd 3 --output policy.bundle.json
   ```

   Transfer only the public bundle and independently verified public-key SHA-256
   fingerprint. Failure mode: absent signing authority stops this step; do not
   generate a replacement owner key or transfer private bytes to the target.

5. Admit the signed policy and inspect status:

   ```bash
   sudo sanctuary-linux policy-install --bundle policy.bundle.json --expected-key-sha256 "$POLICY_KEY_SHA256"
   sudo sanctuary-linux status --json
   ```

   Policy must explicitly bind uid U and fortress F. IP/CIDR rules may narrow
   ports and TCP/UDP; hostname, template and time-window rules are unsupported.
   Failure mode: wrong origin, pin, identity, rule or generation refuses before
   Configured. Completed equality and rollback refuse; daemon restart alone may
   reclaim the exact previously committed signed generation. No service starts.

6. Start the workload, then enable the next boot:

   ```bash
   sudo sanctuary-linux start
   sudo sanctuary-linux enable
   /usr/local/libexec/sanctuary/network-agent-standin --control --endpoints endpoints.json
   sudo sanctuary-linux status --json
   U=60123
   systemctl show "sanctuary-agent@${U}.service" --property=InvocationID,ActiveState,SubState,Result,MainPID,ExecMainStartTimestampMonotonic,ActiveEnterTimestampMonotonic,ExecMainStatus,NRestarts,ControlGroup,FragmentPath,DropInPaths
   sudo nft -a list table inet sanctuary-castle
   sudo sanctuary-linux evidence --output evidence/boot-0
   ```

   `start` waits for stable PID/start ticks and the configured second executable,
   after wall READY and both prechecks. The stand-in waits 60 seconds, sends
   exactly 18 attempts shared by parent/child/grandchild, then idles. Each attempt
   has a three-second deadline, no application retry and a capped response.
   Complete controls in the quiet window. Collect evidence after all attempts;
   an early capture reports incomplete and requires a new output directory.
   Join nonce receipts, live uid rule/handle/mark, WAL and workload testimony for
   allow/deny observations. Failure mode: a queued job, trampoline exec, connection
   errno or zero receipts without a complete receiver window is not proof.

A separately reviewed acceptance run performs five subsequent reboots and a
same-boot wall-restart observation on each boot. Keep the same signed generation
through those observations. Do not rerun provision or policy-install. An explicit
wall restart propagates a new agent activation behind the new READY; count its
18 attempts and do not issue an extra agent start. Unchanged boot ID, repaired
initial launch or missed controls cannot count as reboot success. This guide
and cold-install CI do not themselves establish reboot survival.

## Stop, evidence and recovery

`enable` starts nothing. `disable` removes only agent boot intent and leaves
running workloads and wall enablement unchanged. `Restart=no` forbids automatic
agent retries; it does not suppress the bound restart after an operator wall
restart. Do not reset failed state to disguise a failed observation.

```bash
sudo sanctuary-linux stop
sudo systemctl stop sanctuary-castle-wall.service
sudo sanctuary-linux evidence --output evidence/final
sudo /usr/local/libexec/sanctuary/castle-wall-daemon --disarm
sudo systemctl disable sanctuary-castle-wall.service
```

Stop disables the agent first and proves its whole cgroup empty, including a
SIGTERM-resistant descendant. Confirm no other uid-U workload survives before
disarm. Stop retains the kernel floor and wall enablement. Failure mode: stop is
not disarm, and a process launched outside the product cgroup is not covered by
its stop proof. Final evidence can report incomplete after the workload exits;
retain the completed running capture and the explicit missingness. Disarm uses
authenticated ownership and does not reset policy high-water. If it refuses,
preserve state and follow the [deployment recovery guide](../../../server/docs/castle-wall-linux-deploy.md).

Provisioned package removal and upgrades are unsupported: `apt-get remove` and
`dpkg --purge` refuse retained configuration/state, even after stop/disarm. Do not
delete keys, policy or tables to force successful removal. Successful remove and
purge apply only to an inert, never-provisioned installation. Disposable proof
host retirement is a separate authorized lifecycle.

## Bounds and fixed outputs

The mandatory host-visible tmpfs at `/var/lib/sanctuary-agent-workspace` is
64 MiB and 4096 inodes with noexec/nosuid/nodev. The underlying root directory
is not U-writable. Agent memory is 512 MiB, tasks 64, core dumps zero, and streams
are null. Workspace is ephemeral and non-secret. Hidden temporary paths and
persistent agent homes are not writable alternatives.

Provision writes root-owned `/etc/sanctuary/castle-wall.env`, command/endpoints
under `/etc/sanctuary/agent/`, and the fixed policy directory
`/var/lib/sanctuary/0123456789abcdef/policy/egress/`. Policy-install writes the
raw public `pinned.key`, manifest and exact signed rules, then publishes
`configured-v1.json` last. The daemon creates private audit/ownership material;
none is an installer input or evidence export. The shipped schema is
`/usr/share/doc/sanctuary-castle-wall/schemas/contract.rs`.

Audit capacity is finite. The 100 MiB WAL reserves up to 64 KiB for control
recovery. This no-broker profile promises no unlimited runtime: exhaustion
fails closed. Evidence copies a verified bounded public WAL prefix and never
ACKs, truncates or exports seeds. Packet and row budgets must be substantiated
for each acceptance schedule; the 256-byte application response limit is not
itself a transport packet bound.

## Building the two variants

Build on Ubuntu from a clean committed tree with Rust 1.95.0 and locked Cargo:

```bash
bash castle-wall-daemon/packaging/ubuntu/build-deb.sh --variant install --revision 1 --output /tmp/sanctuary-install
bash castle-wall-daemon/packaging/ubuntu/build-deb.sh --variant internal --revision 1 --output /tmp/sanctuary-internal
bash castle-wall-daemon/packaging/ubuntu/assert-structure.sh --artifact-dir /tmp/sanctuary-internal
```

`internal` remains the default, `install_ready=false`, structural and
unprovisioned-only. Its independent archive/lifecycle guard does not accept the
install variant. The install builder requires all four real binaries and the
canonical mount; a stub or absent consumer refuses. Both hooks are bounded,
read-only admission guards: they do not provision, start, stop, reload, disarm or
clean host state. Source identity and runtime library closure bind the final
payload; metadata is not an independent CI attestation.

Use separate dpkg invocations to remove a conflicting internal package and to
install this variant. The guard observes the committed status database; within
a multi-package transaction, that snapshot can still name the removed package
until dpkg checkpoints its journal. The symptom is a conservative conflict
refusal; finish the original transaction and retry the cold install separately.

A refused remove or purge can change dpkg selection while keeping the package installed. The CLI still permits `stop`, `disable`, and evidence capture. Before activation, recover selection with `printf 'sanctuary-castle-wall install\n' | sudo dpkg --set-selections`; otherwise start/enable refuse. Provisioned package removal remains unsupported. The CLI requires an authenticated audit login session (`/proc/self/loginuid` must not be `4294967295`); `SUDO_UID` cannot replace it.

The workstation signer tries fixed interpreter paths in order: `/usr/local/bin/node` then `/opt/homebrew/bin/node` on macOS, and `/usr/bin/node` then `/usr/local/bin/node` on Linux. Every directory and link on the path, and the interpreter itself, must be owned by root and not writable by group, others, or the invoking user (on macOS, no write ACL either). A Homebrew install owned by your user account is refused; the official Node.js installer package gives a root-owned `/usr/local/bin/node`. Install the trusted interpreter at one of these paths before passing a signing descriptor. The symptom of an untrusted interpreter is a silent exit 1 before any key is read. It never resolves an interpreter or path helper through PATH.
