# Castle Wall Linux - operator deploy guide

During the one-release signing-key-ID migration, readers accept either the
canonical 16-character SHA-256 fingerprint or the exact legacy
`castle-wall:<base64url(public-key)>` label for the pinned key. Publishers emit
only the canonical fingerprint; legacy emission is deprecated. The daemon also
reserves one eighth of the WAL cap (at most 64 KiB) for boot/loss/control
evidence. Ordinary evidence fails closed at the lower ceiling, leaving bounded
space to bring up authenticated IPC and drain the WAL without deleting any
unacknowledged row.

This is a deployment and drill guide for the Linux L2 enforcement candidate.
The source now assembles nftables, cgroup v2, NFQUEUE, signed policy reload,
authenticated IPC, durable audit, restart ownership recovery, and systemd
readiness. It remains **drill-gated**: do not publish a Linux enforcement claim
until the captured Gate A run passes on the reference Ubuntu server. A green
unit or source test alone is not that evidence.

The implementation does not load a custom kernel module and does not use eBPF
for the Layer 1 allow/deny path. All rule decisions execute in one ordered Rust
evaluator behind an NFQUEUE rule with fail-open disabled. Hostname,
hostname-pattern, template-id, and time-window rules are refused at admission
until authenticated DNS/SNI correlation and template attestation exist; this
release candidate enforces IP/CIDR destinations with optional port/protocol
narrowing.

## Phase 1 scope

What Phase 1 source currently implements and tests:

- Linux kernel binding for nftables, cgroup v2, and NFQUEUE, called by the
  daemon runtime and agent lifecycle.
- Per-agent egress scopes and atomic marker-bound chain/body/jump mutation.
- A dedicated `inet sanctuary-castle` namespace whose authenticated inventory
  is reclaimed across restart and removed only by explicit disarm.
- NFQUEUE fail-open disabled. Packets routed to queue `0` require an
  explicit daemon verdict. Prompt-required, deny, and evaluator errors
  map to drop.
- Signed allowlist manifest loading with a TOFU-pinned fortress public
  key, configured-fortress binding, and a durable monotonic generation
  high-water record.
- Tamper-evident daemon WAL with chained SHA-256 entries, mode `0600`,
  fsync for critical events, and drain into Sanctuary main over IPC.
- systemd service hardening with a root daemon, `CAP_NET_ADMIN`, and
  constrained writable paths.

### Assurance profiles

The server and desktop compositions share enforcement code but not the same
availability claim.

- **Server profile:** the root daemon is pre-provisioned by an administrator;
  Sanctuary main runs as a dedicated non-root service/broker principal named by
  `SANCTUARY_TRUSTED_SERVICE_UID`. Unit, environment, policy, keys, WAL, and
  state directories are root-owned. The user-facing CLI asks that broker to
  operate the already-installed service; runtime code never writes `/etc` or
  rewrites/restarts the unit. Only this profile is eligible for the stronger
  pre-auth isolation claim, and only after the drill verifies the installed
  principal and filesystem ownership.
- **Desktop/Omarchy composition:** Sanctuary may share the interactive user's
  UID. Short handshake deadlines, frame caps, rate limits, and bounded active
  connections still fail closed, but another process under the same UID can
  consume the connection budget. This residual same-UID availability risk is
  explicit; desktop composition never inherits the server assurance claim.

Server-profile dynamic policy changes cross the authenticated IPC session as a
single bounded `policy_bundle_publish_request`: signed manifest bytes plus the
complete referenced rule-file set, never a caller path. The daemon stages the
bundle under its root-owned generation store, verifies signature, fortress,
digests, exact membership, rule semantics, and monotonic generation, writes a
durable authorization record, then atomically switches a fsynced active-pointer
file and updates the in-memory evaluator. The reply is `ok:true` only after the
switch, high-water persistence, and durable success audit. A crash before the
pointer leaves the old generation active; after the pointer, restart loads the
complete new generation. Replayed, partial, oversized, wrong-fortress, or
wrong-key bundles are refused and never switch the pointer. Each authenticated
publication is bounded by the framed-byte/rule caps and the serialized mutation
deadline; immutable generation retention is capped at 1,024 entries. Reaching
the retention cap refuses before staging any bytes. This B+C tranche does not
ship online generation pruning: stop publication and preserve the complete
generation tree for investigation. Reclamation requires a separately reviewed,
crash-safe procedure that preserves the active and immediately previous
generation; do not delete generation directories ad hoc merely to clear the cap.

Sanctuary main applies the exported `linux-ip-cidr-v1` compatibility preflight
before signing or sending a bundle. It reports every incompatible rule and
performs no signer or storage call on refusal. The general curated catalog is
currently hostname-based and is not a Linux policy source. A usable Linux rule
must instead carry at least one literal `match.ip` or `match.cidr`, for example:

```json
{
  "id": "linux-anthropic-egress-v1",
  "schema_version": 1,
  "created_at": "2026-09-03T00:00:00Z",
  "match": { "ip": ["203.0.113.10"], "port": [443], "protocol": "tcp" },
  "scope": { "agent_ids": ["agent-a"] },
  "disposition": "allow"
}
```

The address above is documentation-only. Operators must supply and review the
actual service addresses; Sanctuary does not silently resolve a hostname into
an IP allowlist because that would create an unauthenticated policy binding.

The persistent audit-producer private seed remains at
`/var/lib/sanctuary/<fortress-id>/policy/egress/audit-producer.key`. On each boot
the root daemon republishes only its 32-byte public half at
`/run/sanctuary/<fortress-id>/audit-producer.pub`, inside the root-created
`root:sanctuary` runtime directory the dedicated broker can traverse. This split
keeps signing custody outside the broker while making verification possible;
placing a mode-0644 public file below the state directory's mode-0700 ancestor
would not actually make it readable.

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
- **nftables.** The daemon resolves `nft` only from fixed absolute paths. It
  installs `inet sanctuary-castle` under the host ownership lock; a missing or
  incompatible binary is a refuse-to-start condition, not a silent downgrade.
- **`jq`.** The manual last-resort recovery procedure below parses `nft -j`
  output with `/usr/bin/jq`. Failure mode if it is absent: the script's absence
  verification exits nonzero AFTER the delete, so an operator sees a hard failure
  rather than a silently unverified teardown, but the table is already gone.
  Install it before starting that procedure, not during it.
- **NFQUEUE libraries.** Development builds need
  `libnetfilter-queue-dev` and `libnfnetlink-dev`.
- **Rust 1.75 or newer** when building the daemon from source.
- **Root install path.** The shipped systemd unit runs the daemon as
  `root:sanctuary` with `CAP_NET_ADMIN`.

Ubuntu or Debian package baseline:

```bash
sudo apt-get update
sudo apt-get install -y nftables jq libnetfilter-queue-dev libnfnetlink-dev
```

## Architecture at a glance

This is the candidate composition exercised by the automated suite and the
required hardware drill:

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
cargo build --locked --release
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

For the server assurance profile, provision a dedicated non-login broker
principal and record its numeric UID for the environment file:

```bash
sudo groupadd --system sanctuary || true
sudo useradd --system --gid sanctuary --no-create-home \
  --home-dir /nonexistent --shell /usr/sbin/nologin sanctuary-broker
id -u sanctuary-broker
```

If the account already exists, verify its group membership and `nologin` shell
instead of recreating it. Do not run a desktop session or unrelated service as
this UID. The hardware drill must capture this identity check; placing an
ordinary interactive user in the group is the weaker desktop profile.

```bash
sudo install -d -m 0750 -o root -g sanctuary /run/sanctuary/<fortress-id>
sudo install -d -m 0700 -o root -g root \
  /var/lib/sanctuary/<fortress-id>/policy/egress
sudo install -d -m 0700 -o root -g root \
  /var/lib/sanctuary/<fortress-id>/policy/egress/rules
sudo install -m 0644 castle-wall-daemon/systemd/sanctuary-castle-wall.service \
  /etc/systemd/system/sanctuary-castle-wall.service
```

Install or generate these two files before starting the daemon:

```bash
sudo install -m 0600 -o root -g root pinned.key \
  /var/lib/sanctuary/<fortress-id>/policy/egress/pinned.key
sudo install -m 0600 -o root -g root manifest.json \
  /var/lib/sanctuary/<fortress-id>/policy/egress/manifest.json
```

Create the unit's required root-owned environment file:

```bash
sudo install -d -m 0755 -o root -g root /etc/sanctuary
sudo install -m 0600 -o root -g root /dev/null /etc/sanctuary/castle-wall.env
sudoedit /etc/sanctuary/castle-wall.env
```

Add:

```text
SANCTUARY_FORTRESS_ID=<fortress-id>
SANCTUARY_TRUSTED_SERVICE_UID=<numeric-uid-of-sanctuary-broker>
```

Then start the daemon:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sanctuary-castle-wall.service
```

### Last-resort recovery when ownership proof cannot be verified

`castle-wall-daemon --disarm` deliberately refuses a live table when the
authenticated journal/key is missing or corrupt, its recorded source no longer
matches the installed daemon, or the live handles/marker/shape have drifted.
Restore the matching binary plus journal/key from trusted backup and retry
`--disarm` whenever possible. If restoration is impossible, a root operator
must independently attribute `inet sanctuary-castle` to Sanctuary; a foreign
table must be removed by its owner. On the supported Ubuntu 24.04 layout, use
this evidence-preserving transaction. The daemon and recovery both serialize
on `/var/lib/sanctuary/castle-wall.nft.lock` (never the removed RuntimeDirectory).

```bash
sudo /bin/bash <<'SANCTUARY_RECOVERY'
set -euo pipefail
umask 077
readonly unit='sanctuary-castle-wall.service'
readonly state_dir='/var/lib/sanctuary'
readonly lock_path="$state_dir/castle-wall.nft.lock"

/usr/bin/systemctl stop "$unit"
active_state="$(/usr/bin/systemctl show --property=ActiveState --value "$unit")"
[[ "$active_state" == 'inactive' ]] || {
  echo "refusing recovery: unit state is $active_state" >&2
  exit 1
}

# Recreate only the persistent root-owned StateDirectory, then hold this one fd
# across evidence, deletion, absence verification, and journal retirement.
/usr/bin/install -d -o root -g root -m 0700 "$state_dir"
[[ ! -L "$lock_path" ]] || {
  echo 'refusing recovery: persistent lock path is a symlink' >&2
  exit 1
}
exec 9<>"$lock_path"
/usr/bin/flock --exclusive --nonblock 9 || {
  echo 'refusing recovery: host ownership lock is held' >&2
  exit 1
}
fd_identity="$(/usr/bin/stat -Lc '%d:%i:%u:%F' /proc/self/fd/9)"
path_identity="$(/usr/bin/stat -Lc '%d:%i:%u:%F' "$lock_path")"
[[ "$fd_identity" == "$path_identity" &&
   "$fd_identity" == *':0:regular file' ]] || {
  echo 'refusing recovery: lock is not the root-owned opened inode' >&2
  exit 1
}
/bin/chmod 0600 /proc/self/fd/9

recovery_dir="$(/usr/bin/mktemp -d "$state_dir/manual-recovery.XXXXXXXX")"
/bin/chmod 0700 "$recovery_dir"
/usr/sbin/nft -a -j list table inet sanctuary-castle \
  >"$recovery_dir/nft-table-before.json"
[[ ! -e "$state_dir/nft-ownership.json" ]] || \
  /bin/cp -p -- "$state_dir/nft-ownership.json" "$recovery_dir/"
[[ ! -e "$state_dir/nft-journal-auth.key" ]] || \
  /bin/cp -p -- "$state_dir/nft-journal-auth.key" "$recovery_dir/"

# HUMAN AUTHORIZATION BOUNDARY: continue only after attributing the captured
# table to Sanctuary. This name-qualified delete is intentionally not automated.
/usr/sbin/nft delete table inet sanctuary-castle
/usr/sbin/nft -j list tables >"$recovery_dir/nft-tables-after.json"
/usr/bin/jq -e . "$recovery_dir/nft-tables-after.json" >/dev/null
if /usr/bin/jq -e \
  '.nftables[]?.table | select(.family == "inet" and .name == "sanctuary-castle")' \
  "$recovery_dir/nft-tables-after.json" >/dev/null; then
  echo 'refusing recovery: table still exists' >&2
  exit 1
fi

[[ ! -e "$state_dir/nft-ownership.json" ]] || \
  /bin/mv -- "$state_dir/nft-ownership.json" \
  "$recovery_dir/nft-ownership.retired.json"
[[ ! -e "$state_dir/nft-journal-auth.key" ]] || \
  /bin/mv -- "$state_dir/nft-journal-auth.key" \
  "$recovery_dir/nft-journal-auth.retired.key"

exec 9>&-
/usr/bin/systemctl start "$unit"
SANCTUARY_RECOVERY
```

Do not retire the journal/key until deletion succeeded and absence was verified
while fd 9 still holds the persistent host lock. Keep captured evidence
root-only. On other supported distributions use the package's root-owned
absolute `nft` path; never substitute a PATH-resolved binary.

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

- In-memory audit-ring TTL: 24 hours
- WAL on-disk size cap: 100 MB (strict)

The cap applies to the actual NDJSON file, not just the in-memory ring. An
append that would exceed it fails before changing the file, sequence, or hash
chain. The daemon never deletes unacknowledged critical evidence to make room:
new enforcement attempts fail closed and control-plane mutations refuse until
Sanctuary main drains and authenticatedly ACKs older records. An already
oversized WAL refuses daemon startup without truncation.
The 24-hour TTL applies only to the lossy in-memory delivery cache; it never
expires unacknowledged durable WAL evidence.

The daemon also keeps an in-memory ring buffer for events waiting on
Sanctuary main. Critical events are preserved ahead of metric-class
events under buffer pressure.

### Version skew and the confirmed audit ACK

The daemon installs as a system binary while Sanctuary main ships via npm, so
the two can be at different versions on a real host. They negotiate a protocol
version and a capability set during the IPC handshake; neither side infers a
capability from the other's version number, and an unadvertised capability is
treated as absent.

The capability that changes what Sanctuary may claim is
`audit_drain_ack_response`: the daemon's explicit confirmation that it applied a
WAL truncation. Per the 2026-09-02 owner ruling a
CONFIRMED ACK is mandatory before Sanctuary reports drain health, arms a full
activation, or claims complete enforcement.

What an operator sees against a daemon too old to advertise it:

- The wall KEEPS OPERATING. The consumer sends the ACK one-way, the daemon still
  truncates, and the WAL does not grow toward its cap. A partial upgrade is not
  an outage.
- The activation reports `unconfirmed_audit_ack`, `drainHealthy()` reads false,
  and `sanctuary_health` shows Castle Wall `degraded` with an evidence string
  naming `audit_drain_ack_response`.
- A durable `castle_wall_audit_ack_unconfirmed` entry is written to the Layer 1
  audit log at activation.

Failure mode this prevents, and what it looks like from the outside: without the
ruling the wall reports fully healthy while the consumer is advancing its drain
cursor on unproven truncations, so a daemon silently REFUSING to truncate is
indistinguishable from one applying every ACK. The remedy is to upgrade the
daemon binary; nothing in the consumer can recover the proof after the fact.

Provision `/etc/sanctuary/castle-wall.env` as root-owned mode `0600` with both
`SANCTUARY_FORTRESS_ID` and `SANCTUARY_TRUSTED_SERVICE_UID`. The latter is the
numeric kernel UID of the Sanctuary main service principal that possesses the
pinned IPC handshake key. The daemon intentionally does not infer trusted
capacity from the pinned-key file owner; missing or invalid configuration is a
refuse-to-start error.

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

Verify the Castle Wall nftables namespace after the daemon reports ready:

```bash
sudo nft list table inet sanctuary-castle
```

Expected:

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

Expected after a wrapped agent attempts egress:

- Mode `600`.
- Owner `root`.
- Entries include `daemon_started` after service boot.
- Egress decisions appear as `egress_approved` or `egress_blocked`.

Run the source integration suite on a Linux host when validating a new
operator image:

```bash
cd castle-wall-daemon
sudo -E env "PATH=$PATH" cargo test --locked --all-targets --features test-isolation \
  -- --test-threads=1
```

These tests install real nftables tables, bind NFQUEUE, and create real
cgroup v2 scopes.

`--features test-isolation` is required, and getting it wrong fails in two
opposite ways that look nothing alike. Omit it and every kernel-touching suite is
silently skipped: cargo exits 0, the run looks green, and it validated nothing
about the boot path, and there is no error message to notice. The feature is also
what redirects those suites onto a per-process `sanctuary-castle-test-<pid>`
table and a temporary lock/journal root, and compiles in the guard that refuses
any `nft` call against the production `sanctuary-castle` table from a test build.
With the feature present the suites do not touch this host's live enforcement
state; without it they would have. Prefer a disposable host regardless.

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
| `nft list table inet sanctuary-castle` fails | daemon did not acquire the table, exited after a health loss, or lacks `CAP_NET_ADMIN` | inspect the unit journal and verify the systemd capability set; do not create/adopt the table manually |
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

Disarm only through the authenticated ownership path:

```bash
sudo /usr/local/libexec/sanctuary/castle-wall-daemon --disarm
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

Castle Wall Linux L2 is not a published production assurance baseline yet. The
kernel decision path is implemented, but remains `not_verified` until the
servers-first captured drill proves install, reboot/restart recovery, real
wrapped-agent allow/deny ordering, queue-pressure fail-closed behavior, DNS
bypass resistance, audit drain durability, and disarm on the reference host.

Cooperative MCP is the sovereignty surface for compliant agents. It is not a
substitute for the Linux enforcement path. The Linux kernel-routing claim
becomes publishable only after that drill passes and its evidence is reviewed.
