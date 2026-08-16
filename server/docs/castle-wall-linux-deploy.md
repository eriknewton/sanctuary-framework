# Castle Wall Linux - operator deploy guide

This guide is currently a source-validation reference, not a production
activation runbook. Castle Wall Linux Phase 1 ships no enforcement (Assurance Matrix
`not_implemented`): the nftables,
cgroup v2, and NFQUEUE modules are integration-tested, but the shipped daemon
does not install the table, bind NFQUEUE, create cgroup scopes, or call the
deny-by-default evaluator. The shipped systemd unit is also `Type=notify`
without daemon readiness signaling. Open defect: **IC-02, IC-03, IC-04**
.

The Linux implementation source is intended to use nftables for packet-routing
decisions, cgroup v2 for per-agent process scope, and NFQUEUE for inline
verdicts from the privileged daemon. The shipped daemon does not assemble that
loop yet. Open defect: **IC-02, IC-04**
. It does not load a
custom kernel module.
It does not use eBPF for Phase 1 enforcement. eBPF remains an
observability substrate for Sentinel work, not the Layer 1 allow or deny
path.

## Phase 1 scope

What Phase 1 source currently implements and tests:

- Linux kernel-binding modules for nftables, cgroup v2, and NFQUEUE. They are
  tested, but not called by the shipped daemon boot path. Open defect:
  **IC-02, IC-04**.
- Per-agent egress scope helpers. The shipped daemon does not create the
  transient units from `daemon::boot` yet.
- Dedicated firewall namespace helpers. The shipped daemon does not install
  `inet sanctuary-castle` from its boot path yet.
- NFQUEUE fail-open disabled. Packets routed to queue `0` require an
  explicit daemon verdict. Prompt-required, deny, and evaluator errors
  map to drop.
- Signed allowlist manifest loading with a TOFU-pinned fortress public
  key.
- Tamper-evident daemon WAL with chained SHA-256 entries, mode `0600`,
  fsync for critical events, and drain into Sanctuary main over IPC.
- systemd service hardening with a root daemon, `CAP_NET_ADMIN`, and
  constrained writable paths.

What is NOT in Phase 1:

- A custom kernel module.
- eBPF enforcement.
- Rootless container enforcement. The daemon refuses non-systemd PID 1
  environments.
- A host-wide firewall replacement. Castle Wall scopes enforcement to
  wrapped-agent cgroups and keeps the base output chain policy at
  `accept` for unrelated host traffic.

## Prerequisites

- **Linux with systemd as PID 1.** The daemon creates systemd transient
  `.service` units to anchor per-agent cgroups.
- **Unified cgroup v2 mounted at `/sys/fs/cgroup`.**
- **nftables.** The source module shells out to `nft` and installs the
  `inet sanctuary-castle` table when called by tests; the shipped daemon boot
  path does not call it. Open defect: **IC-02**
 .
- **NFQUEUE libraries.** Development builds need
  `libnetfilter-queue-dev` and `libnfnetlink-dev`.
- **Rust 1.74 or newer** when building the daemon from source.
- **Root install path.** The shipped systemd unit runs the daemon as
  `root:sanctuary` with `CAP_NET_ADMIN`.

Ubuntu or Debian package baseline:

```bash
sudo apt-get update
sudo apt-get install -y nftables libnetfilter-queue-dev libnfnetlink-dev
```

## Architecture at a glance

This diagram is the intended Phase 1 composition once **IC-02, IC-03, IC-04**
are fixed. Today the
source modules and integration tests cover these pieces, but the shipped daemon
boot path does not wire the kernel-enforcement loop.

```
Sanctuary main process                     Linux Castle Wall daemon
  +--------------------+                     +----------------------+
  | CastleWallRuntime  |                     | castle-wall-daemon   |
  |                    |  JSON-RPC over UDS  |                      |
  | IpcClient          | <-----------------> | IpcServer            |
  | AuditConsumer      |                     | ManifestStore        |
  | ApprovalStub       |                     | WalWriter            |
  +--------------------+                     | Policy evaluator     |
                                             | NFQUEUE verdict loop |
                                             +----------------------+
                                                       ^
                                                       |
  /run/sanctuary/<fortress-id>/filter.sock             |
                                                       |
Linux kernel                                           |
  +----------------------------------------------------+
  | nftables: inet sanctuary-castle                    |
  | cgroup v2 socket match: system.slice/sanctuary-*   |
  | NFQUEUE queue 0, fail-open disabled                |
  +----------------------------------------------------+
```

Canonical paths for fortress `<fortress-id>`:

- IPC socket: `/run/sanctuary/<fortress-id>/filter.sock`
- State directory: `/var/lib/sanctuary/<fortress-id>`
- Policy directory: `/var/lib/sanctuary/<fortress-id>/policy/egress`
- Pinned key:
  `/var/lib/sanctuary/<fortress-id>/policy/egress/pinned.key`
- Daemon WAL: `/var/lib/sanctuary/<fortress-id>/filter-events.wal`
- systemd unit: `/etc/systemd/system/sanctuary-castle-wall.service`
- Daemon binary:
  `/usr/local/libexec/sanctuary/castle-wall-daemon`

## Build the daemon

From the repo root:

```bash
cd castle-wall-daemon
cargo build --release
```

Install the release binary at the path expected by the systemd unit:

```bash
sudo install -d -m 0755 /usr/local/libexec/sanctuary
sudo install -m 0755 target/release/castle-wall-daemon \
  /usr/local/libexec/sanctuary/castle-wall-daemon
```

Smoke-test the binary before enabling the service:

```bash
/usr/local/libexec/sanctuary/castle-wall-daemon --help
```

## Install the systemd unit

Create the service group, runtime directory, state directory, policy
directory, pinned key, and initial signed manifest. Replace
`<fortress-id>` with the fortress identifier used by Sanctuary main.

```bash
sudo groupadd --system sanctuary || true
sudo install -d -m 0750 -o root -g sanctuary /run/sanctuary/<fortress-id>
sudo install -d -m 0750 -o root -g sanctuary \
  /var/lib/sanctuary/<fortress-id>/policy/egress
sudo install -m 0644 castle-wall-daemon/systemd/sanctuary-castle-wall.service \
  /etc/systemd/system/sanctuary-castle-wall.service
```

Install or generate these two files before starting the daemon:

```bash
sudo install -m 0640 -o root -g sanctuary pinned.key \
  /var/lib/sanctuary/<fortress-id>/policy/egress/pinned.key
sudo install -m 0640 -o root -g sanctuary manifest.json \
  /var/lib/sanctuary/<fortress-id>/policy/egress/manifest.json
```

Set the fortress id for systemd with a drop-in:

```bash
sudo systemctl edit sanctuary-castle-wall.service
```

Add:

```ini
[Service]
Environment=SANCTUARY_FORTRESS_ID=<fortress-id>
```

Then start the daemon:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sanctuary-castle-wall.service
```

## Kernel-binding posture

Castle Wall Linux Phase 1 is a netfilter path, not a kernel extension
and not an eBPF program.

- `nftables.rs` installs the dedicated `inet sanctuary-castle` table and
  a base `output` chain with `policy accept`.
- Each wrapped agent gets a `sanctuary-agent-<agent-id>.service`
  transient systemd unit. The daemon resolves its cgroup v2 path through
  `systemctl show --property=ControlGroup`.
- The base output chain jumps into the agent chain only when the socket
  belongs to that agent's cgroup v2 path.
- Static allow and deny rules are emitted as nftables expressions.
- Prompt and unmatched traffic routes to `queue num 0`.
- The NFQUEUE binding explicitly sets fail-open to `false`.
- The daemon maps `allow` to `NF_ACCEPT`. `deny`, `prompt_required`, and
  evaluator failure map to `NF_DROP`.

The daemon is privileged because nftables and NFQUEUE require
`CAP_NET_ADMIN`. The systemd unit keeps the capability set to
`CAP_NET_ADMIN`, uses `NoNewPrivileges=true`, protects most of the
filesystem with `ProtectSystem=strict`, and permits writes only under
`/run/sanctuary` and `/var/lib/sanctuary`.

`ProtectControlGroups=false` is intentional. The daemon must create and
manage cgroup v2 scopes for wrapped agents through systemd.

## Audit log location

The daemon writes its local WAL at:

```text
/var/lib/sanctuary/<fortress-id>/filter-events.wal
```

The WAL is newline-delimited JSON with a chained SHA-256 sequence. Phase
1 stores this daemon-side WAL as plaintext with mode `0600`. Sanctuary
main drains the WAL over the authenticated IPC channel and signs entries
into the normal Layer 1 audit log.

Default daemon retention:

- WAL TTL: 24 hours
- WAL size cap: 100 MB

The daemon also keeps an in-memory ring buffer for events waiting on
Sanctuary main. Critical events are preserved ahead of metric-class
events under buffer pressure.

## Operator verification commands

Check the service:

```bash
systemctl status sanctuary-castle-wall.service
journalctl -u sanctuary-castle-wall.service -n 100 --no-pager
```

Expected startup line:

```text
castle-wall-daemon: starting for fortress <fortress-id> (socket /run/sanctuary/<fortress-id>/filter.sock, policy /var/lib/sanctuary/<fortress-id>/policy/egress, wal /var/lib/sanctuary/<fortress-id>/filter-events.wal)
```

Verify the IPC socket:

```bash
sudo stat -c '%a %U %G %n' /run/sanctuary/<fortress-id>/filter.sock
```

Expected mode and ownership:

```text
660 root sanctuary /run/sanctuary/<fortress-id>/filter.sock
```

For source-validation builds that explicitly call the kernel-binding modules,
verify the Castle Wall nftables namespace:

```bash
sudo nft list table inet sanctuary-castle
```

Expected in that source-validation path. This is not expected from the shipped
daemon boot path until **IC-02, IC-04** are fixed
:

- Table family is `inet`.
- Table name is `sanctuary-castle`.
- Base chain is `output`.
- Wrapped agents have `agent_<id>` chains.
- Agent jump rules include `socket cgroupv2 level <N> "<path>"`.
- Unmatched scoped traffic routes to `queue num 0`.

Verify agent cgroup placement:

```bash
systemctl status sanctuary-agent-<agent-id>.service
systemctl show sanctuary-agent-<agent-id>.service --property=ControlGroup --value
```

Expected control group shape:

```text
/system.slice/sanctuary-agent-<agent-id>.service
```

Verify the WAL exists and is restricted:

```bash
sudo stat -c '%a %U %G %n' /var/lib/sanctuary/<fortress-id>/filter-events.wal
sudo tail -n 5 /var/lib/sanctuary/<fortress-id>/filter-events.wal
```

Expected after the enforcement loop is wired. Today the shipped daemon writes
`daemon_started`, but egress decisions are not produced by a live NFQUEUE loop.
Open defect: **IC-02, IC-04**
:

- Mode `600`.
- Owner `root`.
- Entries include `daemon_started` after service boot.
- Egress decisions appear as `egress_approved` or `egress_blocked`.

Run the source integration suite on a Linux host when validating a new
operator image:

```bash
cd castle-wall-daemon
sudo -E env "PATH=$PATH" cargo test --all-targets -- --test-threads=1
```

These tests install real nftables tables, bind NFQUEUE, and create real
cgroup v2 scopes. Run them only on a disposable host or a host where
temporary Castle Wall test rules are acceptable.

## SELinux and AppArmor notes

Castle Wall needs permission to:

- Execute `/usr/local/libexec/sanctuary/castle-wall-daemon`.
- Execute `nft`, `systemd-run`, and `systemctl`.
- Open netlink and NFQUEUE sockets.
- Bind the Unix socket under `/run/sanctuary/<fortress-id>`.
- Read policy files under
  `/var/lib/sanctuary/<fortress-id>/policy/egress`.
- Write `/var/lib/sanctuary/<fortress-id>/filter-events.wal`.

On SELinux systems, check denials with:

```bash
sudo ausearch -m avc -ts recent
```

If SELinux blocks the daemon, create a local policy module that grants
the paths and netlink operations above. Keep the grant scoped to the
Castle Wall binary and Sanctuary state directories.

On AppArmor systems, check denials with:

```bash
sudo journalctl -k --grep=apparmor --no-pager
```

If AppArmor blocks the daemon, add a profile or local override for the
same file paths, command executions, and network families. Do not disable
the host's broader security module globally unless this is an emergency
recovery window.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Service exits with `nftables and systemd` guidance | `nft` is missing, systemd is not PID 1, or cgroup v2 is unavailable | install nftables, boot with systemd, and confirm `/sys/fs/cgroup` is cgroup v2 |
| Service exits with pinned key failure | `pinned.key` is missing, unreadable, or not the expected raw public key | install the fortress pinned key at `/var/lib/sanctuary/<fortress-id>/policy/egress/pinned.key` with `0640 root:sanctuary` |
| Service exits with socket bind failure | stale non-socket path, wrong `/run/sanctuary` permissions, or another daemon is running | check `systemctl status`, remove only confirmed stale socket files, and fix `/run/sanctuary/<fortress-id>` ownership |
| `nft list table inet sanctuary-castle` fails | expected for the current shipped daemon boot path; otherwise the daemon did not install the table or lacks `CAP_NET_ADMIN` | track **IC-02** for the shipped path; in source-validation runs, verify the systemd unit uses `CapabilityBoundingSet=CAP_NET_ADMIN` and `AmbientCapabilities=CAP_NET_ADMIN` |
| Agent traffic bypasses Castle Wall | agent process is not in the expected `sanctuary-agent-<id>.service` cgroup | verify `ControlGroup`, rewrap the agent, and reload the agent ruleset |
| nft rejects a cgroup rule | cgroup level or relative path does not match the real systemd placement | compare `systemctl show ... ControlGroup` with the `socket cgroupv2 level <N> "<path>"` rule |
| Existing ufw or firewalld is active | expected coexistence posture | keep Castle Wall in `inet sanctuary-castle`; do not merge it into ufw or firewalld tables |
| WAL grows without truncation | Sanctuary main is not draining or ACKing daemon WAL entries | check the IPC socket, Sanctuary main runtime logs, and `audit.drain` handling |
| SELinux or AppArmor denial appears | host policy blocks daemon file, netlink, or NFQUEUE access | add a scoped local policy for the Castle Wall binary and state paths |

## Rollback

Stop the service:

```bash
sudo systemctl disable --now sanctuary-castle-wall.service
```

Remove Castle Wall nftables rules:

```bash
sudo nft delete table inet sanctuary-castle
```

Stop any leftover per-agent transient units:

```bash
systemctl list-units 'sanctuary-agent-*.service'
sudo systemctl stop 'sanctuary-agent-<agent-id>.service'
```

Leave the state directory in place if you need audit continuity:

```text
/var/lib/sanctuary/<fortress-id>
```

Remove the state directory only after exporting or preserving the WAL and
policy artifacts required for your audit record.

To reinstall, restore the daemon binary, service unit, pinned key, and
signed manifest, then run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sanctuary-castle-wall.service
```

## Castle-walking acknowledgement

Castle Wall Linux Phase 1 is not the production Castle Wall enforcement
baseline yet. The intended kernel-level decision path is nftables plus cgroup
v2 plus NFQUEUE, backed by the privileged Rust daemon's policy evaluator and
WAL, but the shipped daemon boot path does not install or enter that path.
Open defect: **IC-02, IC-03, IC-04**
.

Cooperative MCP is the sovereignty surface for compliant agents. It is not a
substitute for the Linux enforcement path. The Linux kernel-routing claim
becomes true only after **IC-02, IC-03, IC-04** are fixed
.
