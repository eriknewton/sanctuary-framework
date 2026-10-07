#!/usr/bin/env bash
set -euo pipefail

pkg="${1:?usage: ci-arch-lifecycle.sh <pkg.tar.zst> [--noextract-witness]}"
mode="${2:-default}"
pkg="$(realpath "$pkg")"
work="$(mktemp -d)"
evidence="${EVIDENCE_DIR:-$work/evidence}"
mkdir -p "$evidence"
cli=/usr/bin/sanctuary-linux
fortress=0123456789abcdef
agent_uid=60123
service_uid=60124
wall_unit=sanctuary-castle-wall.service
agent_unit=sanctuary-agent@60123.service
mount_unit='var-lib-sanctuary\x2dagent\x2dworkspace.mount'
inputs_dir="${SANCTUARY_ARCH_INPUTS:-/inputs}"
inputs_dir="${inputs_dir%/}"

assert_systemd() {
  [[ "$(cat /proc/1/comm)" == systemd ]]
  systemctl is-system-running --wait >/dev/null || [[ "$(systemctl is-system-running)" =~ ^(running|degraded)$ ]]
}

# Failure diagnostics: a red run must leave the units' own account of why in the evidence; without it a failure
# such as "helper deadline exceeded" at start says only that the wall never reported ready (CI run 37636956109).
diagnose_on_failure() {
  local rc=$?
  if [[ "$rc" != 0 ]]; then
    local d="$evidence/failure-diagnostics"
    mkdir -p "$d"
    printf '%s\n' "$rc" >"$d/exit-code"
    systemctl status --no-pager --full "$wall_unit" "sanctuary-agent@${agent_uid}.service" >"$d/systemctl-status.txt" 2>&1 || true
    journalctl --no-pager -o short-precise -u "$wall_unit" -n 400 >"$d/journal-wall.txt" 2>&1 || true
    journalctl --no-pager -o short-precise -u "sanctuary-agent@${agent_uid}.service" -n 400 >"$d/journal-agent.txt" 2>&1 || true
    journalctl --no-pager -o short-precise -b -p warning -n 400 >"$d/journal-warnings.txt" 2>&1 || true
    systemctl list-jobs --no-pager >"$d/list-jobs.txt" 2>&1 || true
    systemctl --failed --no-pager >"$d/failed-units.txt" 2>&1 || true
    nft -j list ruleset >"$d/nft-ruleset.json" 2>&1 || true
    grep -E '^nfnetlink|^nf_' /proc/modules >"$d/modules.txt" 2>&1 || true
    record "failure diagnostics saved (exit $rc)"
  fi
  return "$rc"
}
trap diagnose_on_failure EXIT

record() {
  printf '%s\n' "$*" | tee -a "$evidence/lifecycle.log"
}

capture() {
  local label="$1"
  shift
  set +e
  "$@" >"$evidence/$label.out" 2>"$evidence/$label.err"
  local rc=$?
  set -e
  printf '%s\n' "$rc" >"$evidence/$label.rc"
  cat "$evidence/$label.out" "$evidence/$label.err" >"$evidence/$label.combined"
  return "$rc"
}

cli_capture() {
  local label="$1"
  shift
  # HOME is deliberately absent: operator identity must come from loginuid and root custody, not a user environment.
  capture "$label" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "$cli" "$@"
}

expect_cli_ok() {
  local label="$1"
  shift
  cli_capture "$label" "$@"
  record "cli ok: $label"
}

expect_cli_refused() {
  local label="$1"
  local phrase="$2"
  shift 2
  if cli_capture "$label" "$@"; then
    echo "$label unexpectedly succeeded" >&2
    exit 1
  fi
  grep -F "$phrase" "$evidence/$label.combined" >/dev/null
  record "cli refused: $label -> $phrase"
}

expect_cli_status_missing() {
  local label="$1"
  shift
  expect_cli_ok "$label" status --json
  python3 - "$evidence/$label.out" "$@" <<'PY'
import json
import sys

status = json.loads(open(sys.argv[1]).read())
required = set(sys.argv[2:])
missing = set(status.get("missing_evidence", []))
if not required.issubset(missing):
    raise SystemExit(f"missing_evidence {sorted(missing)} lacks {sorted(required)}")
PY
}

expect_cli_evidence_incomplete() {
  local label="$1"
  shift
  if cli_capture "$label" evidence --output "$evidence/$label"; then
    echo "$label unexpectedly completed evidence" >&2
    exit 1
  fi
  python3 - "$evidence/$label.out" "$@" <<'PY'
import json
import sys

result = json.loads(open(sys.argv[1]).read())
required = set(sys.argv[2:])
missing = set(result.get("missing", []))
status_missing = set(result.get("status", {}).get("missing_evidence", []))
if result.get("complete") is not False:
    raise SystemExit("evidence did not report complete:false")
if not required.issubset(missing | status_missing):
    raise SystemExit(f"missing evidence {sorted(missing | status_missing)} lacks {sorted(required)}")
PY
}

save_raw_captures() {
  local phase="$1"
  systemctl show "$wall_unit" --no-pager >"$evidence/systemctl-show-wall-$phase"
  systemctl show "$agent_unit" --no-pager >"$evidence/systemctl-show-agent-$phase" || true
  systemctl show "$mount_unit" --no-pager >"$evidence/systemctl-show-mount-$phase" || true
  systemctl list-jobs --no-pager >"$evidence/systemctl-list-jobs-$phase" || true
  pacman -Q sanctuary-castle-wall >"$evidence/pacman-Q-$phase" 2>"$evidence/pacman-Q-$phase.err" || true
  pacman -Qo /usr/bin/sanctuary-linux >"$evidence/pacman-Qo-cli-$phase" 2>"$evidence/pacman-Qo-cli-$phase.err" || true
  pacman -Qkk sanctuary-castle-wall >"$evidence/pacman-Qkk-$phase" 2>"$evidence/pacman-Qkk-$phase.err" || true
  cp /etc/login.defs "$evidence/login.defs"
  cp /etc/nsswitch.conf "$evidence/nsswitch.conf"
  nft -j -a list table inet sanctuary-castle >"$evidence/nft-table-$phase.json" 2>"$evidence/nft-table-$phase.err" || true
  nft -j -a list ruleset >"$evidence/nft-ruleset-$phase.json" 2>"$evidence/nft-ruleset-$phase.err" || true
}

write_expectation_files() {
  for path in "$evidence"/login.defs "$evidence"/pacman-Q-* "$evidence"/pacman-Qo-cli-* "$evidence"/systemctl-show-*; do
    [[ -f "$path" ]] || continue
    printf 'accept\n' >"$path.expect"
  done
}

write_vacuous_witnesses() {
  local cgroup_file="$1"
  python3 - "$evidence/vacuous-witnesses.json" "$cgroup_file" "${SANCTUARY_ARCH_CGROUPNS:-unknown}" <<'PY'
import json
import sys

cgroup_file = sys.argv[2]
data = {
    "reboot": "not witnessed in the PID 1 container",
    "kernel": "runner kernel, not linux-omarchy 7.2.5",
    "systemd": "container corpus, not the Omarchy 261.2 corpus",
    "reimage": "not performed; intended retirement remains reimage",
    "loginuid": "harness wrote /proc/self/loginuid before CLI execution",
    "network_online": "container adaptation: systemd-networkd-wait-online masked so network-online.target is reached; the drill host's real wait-online is the witness",
    "cgroupns": sys.argv[3],
    "descendants_check": "read cgroup.events" if cgroup_file else "vacuous: cgroup.events was not read",
}
open(sys.argv[1], "w").write(json.dumps(data, sort_keys=True, indent=2) + "\n")
PY
}

assert_status_json() {
  local label="$1"
  local pins="$2"
  python3 - "$evidence/$label.out" "$pins" "$agent_uid" "$service_uid" <<'PY'
import json
import sys

status = json.loads(open(sys.argv[1]).read())
pins = json.load(open(sys.argv[2]))
agent = int(sys.argv[3])
service = int(sys.argv[4])
if status["package_manager"] != "pacman":
    raise SystemExit("package_manager mismatch")
if status["agent_uid"] != agent or status["service_uid"] != service:
    raise SystemExit("uid mismatch")
if status["package_pins"] != pins:
    raise SystemExit("package_pins mismatch")
ranges = status.get("system_id_ranges")
if not ranges or not (ranges["sys_gid_min"] <= status["sanctuary_gid"] <= ranges["sys_gid_max"]):
    raise SystemExit("system_id_ranges did not admit sanctuary_gid")
PY
}

assert_configured_status() {
  local label="$1"
  python3 - "$evidence/$label.out" <<'PY'
import json
import sys

status = json.loads(open(sys.argv[1]).read())
if status.get("configured_valid") is not True:
    raise SystemExit("configured_valid was not true")
PY
}

assert_enabled_status() {
  local label="$1"
  python3 - "$evidence/$label.out" <<'PY'
import json
import sys

status = json.loads(open(sys.argv[1]).read())
if status.get("effective_units_valid") is not True:
    raise SystemExit("effective_units_valid was not true")
for unit in ("agent", "wall"):
    if status.get(unit, {}).get("UnitFileState") != "enabled":
        raise SystemExit(f"{unit} was not enabled")
PY
}

assert_started_status() {
  local label="$1"
  python3 - "$evidence/$label.out" <<'PY'
import json
import sys

status = json.loads(open(sys.argv[1]).read())
if "binding_observation" not in status or status["binding_observation"] is None:
    raise SystemExit("binding_observation missing")
if not status.get("workload"):
    raise SystemExit("stable workload identity missing")
PY
}

run_sentinels_and_wait_observation() {
  python3 - "$inputs_dir/endpoints.json" "$evidence/sentinel-receipts.json" <<'PY'
import json
import selectors
import socket
import sys
import threading
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

endpoints = json.load(open(sys.argv[1]))["endpoints"]
receipts_path = sys.argv[2]
key = Ed25519PrivateKey.from_private_bytes(bytes([22]) * 32)
selector = selectors.DefaultSelector()
stop = threading.Event()
receipts = []
errors = []

for family, ip in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
    for kind, port in [(socket.SOCK_STREAM, 41001), (socket.SOCK_DGRAM, 41002), (socket.SOCK_STREAM, 41003)]:
        s = socket.socket(family, kind)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.bind((ip, port))
        if kind == socket.SOCK_STREAM:
            s.listen(8)
        selector.register(s, selectors.EVENT_READ, (kind, port))

def loop():
    try:
        while not stop.is_set():
            for selected, _ in selector.select(0.1):
                sock = selected.fileobj
                kind, port = selected.data
                if kind == socket.SOCK_DGRAM:
                    data, peer = sock.recvfrom(257)
                else:
                    conn, peer = sock.accept()
                    with conn:
                        conn.settimeout(3)
                        data = b""
                        while len(data) < 32:
                            part = conn.recv(32 - len(data))
                            if not part:
                                break
                            data += part
                        if port == 41003 and len(data) == 32:
                            conn.sendall(data + key.sign(data))
                receipts.append({"port": port, "nonce_hex": data.hex(), "peer": str(peer)})
    except Exception as exc:
        errors.append(str(exc))

thread = threading.Thread(target=loop)
thread.start()
deadline = time.monotonic() + 120
observation = "/var/lib/sanctuary-agent-workspace/observations.json"
try:
    while time.monotonic() < deadline:
        if errors:
            raise SystemExit(errors[0])
        try:
            record = json.load(open(observation))
            if record.get("attempt_count", 0) >= sum(endpoint["attempts"] for endpoint in endpoints):
                break
        except FileNotFoundError:
            pass
        time.sleep(0.2)
    else:
        raise SystemExit("stand-in observation did not complete")
finally:
    stop.set()
    thread.join(timeout=4)
    for item in list(selector.get_map().values()):
        item.fileobj.close()
    selector.close()
    open(receipts_path, "w").write(json.dumps({"receipts": receipts, "errors": errors}, sort_keys=True, indent=2) + "\n")
if errors:
    raise SystemExit(errors[0])
PY
}

rewrite_identity_field() {
  local path="$1"
  local field="$2"
  local value="$3"
  python3 - "$path" "$field" "$value" <<'PY'
import json
import sys

path, field, value = sys.argv[1:]
data = json.load(open(path))
if value == "false":
    data[field] = False
else:
    data[field] = value
open(path, "w").write(json.dumps(data, sort_keys=True, indent=2) + "\n")
PY
}

set_guard_identity_to_current_file() {
  local identity="$1"
  local guard="$2"
  local digest
  digest="$(sha256sum "$identity" | cut -d' ' -f1)"
  python3 - "$guard" "$digest" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
digest = sys.argv[2]
lines = path.read_text().splitlines(keepends=True)
lines[1] = f"IDENTITY_SHA256 = '{digest}'\n"
path.write_text("".join(lines))
PY
}

run_unpinned_witness() {
  # Built for the host triple (no --target), so cargo writes release/ directly under the target directory.
  local unpinned="$work/unpinned-target/release/sanctuary-linux-arch"
  if [[ ! -x "$unpinned" ]]; then
    record 'building unpinned sanctuary-linux-arch for C0 witness'
    pacman -S --noconfirm --needed rustup git >/dev/null
    runuser -u build -- rustup toolchain install 1.95.0 --profile minimal >/dev/null
    # The target directory does not exist yet on a first build; create it owned by the build user (run 8 failed on
    # a chown of the missing path).
    install -d -o build -g build -m 0755 "$work/unpinned-target"
    runuser -u build -- bash -lc "cd /workspace/castle-wall-daemon && PATH=\"\$HOME/.cargo/bin:\$PATH\" CARGO_TARGET_DIR='$work/unpinned-target' cargo +1.95.0 build --locked --release --features arch-install --bin sanctuary-linux-arch >/dev/null"
  fi
  local saved="$work/sanctuary-linux.pinned"
  cp -p "$cli" "$saved"
  cp "$unpinned" "$cli"
  chmod 0755 "$cli"
  expect_cli_refused negative-unpinned-root 'Arch CLI built without package pins' status --json
  if runuser -u build -- env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "$cli" status --json >"$evidence/negative-unpinned-nonroot.out" 2>"$evidence/negative-unpinned-nonroot.err"; then
    echo "negative-unpinned-nonroot unexpectedly succeeded" >&2
    exit 1
  fi
  cat "$evidence/negative-unpinned-nonroot.out" "$evidence/negative-unpinned-nonroot.err" >"$evidence/negative-unpinned-nonroot.combined"
  grep -F 'Arch CLI built without package pins' "$evidence/negative-unpinned-nonroot.combined" >/dev/null
  cp -p "$saved" "$cli"
}

run_arch_cli_lifecycle() {
  record 'state_INERT: pinned CLI installed inert'
  if cli_capture state-inert-status status --json; then
    echo "inert status unexpectedly succeeded" >&2
    exit 1
  fi
  grep -F 'not provisioned' "$evidence/state-inert-status.combined" >/dev/null
  if grep -F 'Arch CLI built without package pins' "$evidence/state-inert-status.combined" >/dev/null; then
    echo "inert status hit unpinned refusal" >&2
    exit 1
  fi

  local operator_uid
  operator_uid="$(stat -c %u "$inputs_dir/endpoints.json")"
  if ! getent passwd "$operator_uid" >/dev/null; then
    useradd --uid "$operator_uid" --no-create-home --system lifecycle-operator
  fi
  # CI has no PAM login ceremony. The harness establishes the audit session so the CLI reads kernel loginuid, not an environment claim.
  printf '%s' "$operator_uid" >/proc/self/loginuid
  [[ "$(cat /proc/self/loginuid)" == "$operator_uid" ]]
  python3 - "$evidence/operator-session.json" "$operator_uid" <<'PY'
import json
import sys
open(sys.argv[1], "w").write(json.dumps({
    "uid": int(sys.argv[2]),
    "loginuid": int(sys.argv[2]),
    "setup": "explicit disposable Arch CI audit session; normal operator uses PAM",
}, sort_keys=True, indent=2) + "\n")
PY

  python3 - "$identity_path" "$evidence/arch-pins.json" <<'PY'
import json
import sys
identity = json.load(open(sys.argv[1]))
open(sys.argv[2], "w").write(json.dumps(identity["cli_pins"], sort_keys=True, indent=2) + "\n")
PY

  # Container adaptation, recorded in vacuous-witnesses.json: the agent unit orders after network-online.target, and
  # in this container systemd-networkd manages no link, so systemd-networkd-wait-online never completes and the agent's
  # start job queues past the CLI's helper deadline (CI run 37638516101: wall READY, agent job waiting on wait-online).
  systemctl mask --now systemd-networkd-wait-online.service >"$evidence/mask-wait-online.out" 2>&1
  record 'container adaptation: systemd-networkd-wait-online masked (network-online.target reached without a managed link)'
  record 'state_PROVISIONED: provision account and command identity'
  expect_cli_ok state-provisioned provision --agent-uid "$agent_uid" --service-uid "$service_uid" --fortress-id "$fortress" --stage-file "$inputs_dir/endpoints.json" -- /usr/local/libexec/sanctuary/network-agent-standin --endpoints /etc/sanctuary/agent/endpoints.json
  getent passwd "$agent_uid" >"$evidence/getent-passwd-agent"
  # The service uid is RESERVED, never created: account::verify requires it absent from passwd (reserve_service), so
  # the witness is getent's "not found" exit 2. A present row, or any other exit, fails the run.
  service_rc=0
  getent passwd "$service_uid" >"$evidence/getent-passwd-service" || service_rc=$?
  printf '%s\n' "$service_rc" >"$evidence/getent-passwd-service.rc"
  [[ "$service_rc" == 2 && ! -s "$evidence/getent-passwd-service" ]] || { record "service uid $service_uid is not reserved (getent rc $service_rc)"; exit 1; }
  getent group sanctuary >"$evidence/getent-group-sanctuary"
  expect_cli_ok state-provisioned-status status --json
  assert_status_json state-provisioned-status "$evidence/arch-pins.json"

  record 'state_POLICY: signed policy installed'
  expect_cli_ok state-policy policy-install --bundle "$inputs_dir/policy.bundle.json" --expected-key-sha256 "$(cat "$inputs_dir/policy-key-sha256")"
  expect_cli_ok state-policy-status status --json
  assert_configured_status state-policy-status

  record 'state_ENABLED: units enabled, observed, then disabled for explicit start witness'
  expect_cli_ok state-enabled enable
  expect_cli_ok state-enabled-status status --json
  assert_enabled_status state-enabled-status
  expect_cli_ok state-enabled-disable disable

  record 'state_STARTED: wall ready, agent second exec and binding observation'
  expect_cli_ok state-started start
  run_sentinels_and_wait_observation
  expect_cli_ok state-started-status status --json
  assert_started_status state-started-status
  expect_cli_ok state-started-evidence evidence --output "$evidence/cli"
  python3 - "$evidence/state-started-evidence.out" <<'PY'
import json
import sys
if json.loads(open(sys.argv[1]).read()).get("complete") is not True:
    raise SystemExit("evidence was not complete")
PY
  save_raw_captures running
  cgroup_path="$(python3 - "$evidence/systemctl-show-agent-running" <<'PY'
import sys
for line in open(sys.argv[1]):
    if line.startswith("ControlGroup="):
        print(line.split("=", 1)[1].strip())
PY
)"
  cgroup_file=
  if [[ -n "$cgroup_path" && -f "/sys/fs/cgroup$cgroup_path/cgroup.events" ]]; then
    cgroup_file="/sys/fs/cgroup$cgroup_path/cgroup.events"
  fi
  expect_cli_ok state-started-stop stop
  write_vacuous_witnesses "$cgroup_file"

  record 'state_NEGATIVES: isolated refusal witnesses'
  # The payload byte goes on a payload the digest loop covers that is NOT executing: `stop` stops the agent and
  # leaves the wall running by design, so appending to the daemon binary fails with ETXTBSY (CI run 37639891427).
  local daemon=/usr/local/libexec/sanctuary/network-agent-standin
  cp -p "$daemon" "$work/daemon.backup"
  printf x >>"$daemon"
  expect_cli_refused negative-payload 'installed payload digest mismatch' provision --agent-uid "$agent_uid" --service-uid "$service_uid" --fortress-id "$fortress" --stage-file "$inputs_dir/endpoints.json" -- /usr/local/libexec/sanctuary/network-agent-standin --endpoints /etc/sanctuary/agent/endpoints.json
  cp -p "$work/daemon.backup" "$daemon"

  cp -p "$identity_path" "$work/identity-edited.backup"
  rewrite_identity_field "$identity_path" rustc_version edited-by-lifecycle
  expect_cli_refused negative-identity 'guard identity header mismatch' provision --agent-uid "$agent_uid" --service-uid "$service_uid" --fortress-id "$fortress" --stage-file "$inputs_dir/endpoints.json" -- /usr/local/libexec/sanctuary/network-agent-standin --endpoints /etc/sanctuary/agent/endpoints.json
  cp -p "$work/identity-edited.backup" "$identity_path"

  cp -p "$guard_path" "$work/guard-body.backup"
  printf '\n# lifecycle negative\n' >>"$guard_path"
  expect_cli_refused negative-guard-body 'guard static payload mismatch' provision --agent-uid "$agent_uid" --service-uid "$service_uid" --fortress-id "$fortress" --stage-file "$inputs_dir/endpoints.json" -- /usr/local/libexec/sanctuary/network-agent-standin --endpoints /etc/sanctuary/agent/endpoints.json
  cp -p "$work/guard-body.backup" "$guard_path"

  cp -a /var/lib/pacman "$work/pacman-copy"
  rm -rf "$work/pacman-copy/local/sanctuary-castle-wall-"*
  cp /etc/pacman.conf "$work/pacman.conf.backup"
  printf '\nDBPath = %s\n' "$work/pacman-copy" >>/etc/pacman.conf
  if pacman -Q sanctuary-castle-wall >"$evidence/negative-dbpath-bare-pacman.out" 2>"$evidence/negative-dbpath-bare-pacman.err"; then
    echo "DBPath redirect did not make bare pacman disagree" >&2
    exit 1
  fi
  expect_cli_ok negative-dbpath-cli-status status --json
  cp "$work/pacman.conf.backup" /etc/pacman.conf
  record 'negative dbpath-redirect isolated check: fixed --dbpath /var/lib/pacman'

  version_swap_extra=$'  install -D -m 0755 /usr/bin/sanctuary-linux "$pkgdir/usr/bin/sanctuary-linux"'
  scratch_pkg sanctuary-castle-wall 0.1.1 "$work/version-swap.pkg.tar.zst" "$version_swap_extra"
  mask_hook 00-sanctuary-castle-wall-upgrade-guard.hook
  expect_ok version-swap-install pacman -U --noconfirm "$work/version-swap.pkg.tar.zst"
  expect_cli_refused negative-version-swap 'pinned package database entry absent' provision --agent-uid "$agent_uid" --service-uid "$service_uid" --fortress-id "$fortress" --stage-file "$inputs_dir/endpoints.json" -- /usr/local/libexec/sanctuary/network-agent-standin --endpoints /etc/sanctuary/agent/endpoints.json
  expect_ok version-swap-restore pacman -U --noconfirm "$pkg"
  unmask_hooks

  touch /var/lib/pacman/db.lck
  expect_cli_refused negative-db-lock 'pacman transaction holds the database lock' provision --agent-uid "$agent_uid" --service-uid "$service_uid" --fortress-id "$fortress" --stage-file "$inputs_dir/endpoints.json" -- /usr/local/libexec/sanctuary/network-agent-standin --endpoints /etc/sanctuary/agent/endpoints.json
  rm -f /var/lib/pacman/db.lck

  cp -p "$identity_path" "$work/install-ready.identity"
  cp -p "$guard_path" "$work/install-ready.guard"
  rewrite_identity_field "$identity_path" install_ready false
  set_guard_identity_to_current_file "$identity_path" "$guard_path"
  expect_cli_refused negative-install-ready 'install build identity mismatch' provision --agent-uid "$agent_uid" --service-uid "$service_uid" --fortress-id "$fortress" --stage-file "$inputs_dir/endpoints.json" -- /usr/local/libexec/sanctuary/network-agent-standin --endpoints /etc/sanctuary/agent/endpoints.json
  cp -p "$work/install-ready.identity" "$identity_path"
  cp -p "$work/install-ready.guard" "$guard_path"

  run_unpinned_witness

  record 'state_RETIRED: provisioned removal refused, masked removal, copied CLI refuses after removal'
  # The negatives restore with cp -p, so the only integrity finding allowed here is the mounted workspace directory's
  # mode (brief 3.2); any other -Qkk warning means the harness left the package altered (CI run 37649666312).
  pacman -Qkk sanctuary-castle-wall >"$evidence/pre-retire-qkk.out" 2>"$evidence/pre-retire-qkk.err" || true
  if grep -v -F '/var/lib/sanctuary-agent-workspace (Permissions mismatch)' "$evidence/pre-retire-qkk.err" | grep -q 'warning:'; then
    record 'harness left the package altered before retire (see pre-retire-qkk.err)'
    exit 1
  fi
  # With the workspace mounted, the remove guard's integrity probe refuses before its footprint check; without the
  # mount it refuses on the provisioned footprint. Expect the one the measured state predicts and record which.
  local retire_refusal="$provisioned_refusal"
  if grep -q -F '(Permissions mismatch)' "$evidence/pre-retire-qkk.err"; then
    retire_refusal='probe failed or incomplete'
  fi
  record "retire removal expects: $retire_refusal"
  expect_refused retire-remove-provisioned "$retire_refusal" pacman -R --noconfirm sanctuary-castle-wall
  expect_refused retire-remove-dd-provisioned "$retire_refusal" pacman -Rdd --noconfirm sanctuary-castle-wall
  install -d -m 0755 "$evidence/copied-cli"
  cp "$cli" "$evidence/copied-cli/sanctuary-linux"
  chmod 0755 "$evidence/copied-cli/sanctuary-linux"
  mask_hook 00-sanctuary-castle-wall-remove-guard.hook
  expect_ok retire-remove-provisioned-masked pacman -Rdd --noconfirm sanctuary-castle-wall
  unmask_hooks
  cli="$evidence/copied-cli/sanctuary-linux"
  expect_cli_refused retire-provision-not-installed 'pinned package database entry absent' provision --agent-uid "$agent_uid" --service-uid "$service_uid" --fortress-id "$fortress" --stage-file "$inputs_dir/endpoints.json" -- /usr/local/libexec/sanctuary/network-agent-standin --endpoints /etc/sanctuary/agent/endpoints.json
  expect_cli_refused retire-policy-not-installed 'pinned package database entry absent' policy-install --bundle "$inputs_dir/policy.bundle.json" --expected-key-sha256 "$(cat "$inputs_dir/policy-key-sha256")"
  expect_cli_refused retire-disable-not-installed 'pinned package database entry absent' disable
  expect_cli_refused retire-stop-not-installed 'pinned package database entry absent' stop
  expect_cli_refused retire-start-config-missing 'No such file or directory' start
  expect_cli_refused retire-enable-config-missing 'No such file or directory' enable
  expect_cli_status_missing retire-status-missing 'verified package and effective units' 'validated configuration' 'build identity'
  expect_cli_evidence_incomplete retire-evidence-missing 'verified package and effective units' 'validated configuration' 'build identity'
  save_raw_captures retired
  write_expectation_files
  record 'state_RETIRED complete'
}

scratch_pkg() {
  local name="$1" version="$2" out="$3" extra="${4:-}"
  local root="$work/$name-$version"
  mkdir -p "$root"
  cat >"$root/PKGBUILD" <<PKG
pkgname=$name
pkgver=$version
pkgrel=1
pkgdesc='scratch package for Castle Wall lifecycle CI'
arch=('any')
license=('LicenseRef-Scratch')
# A scratch package that carries the CLI ELF would otherwise get a split -debug package and a stripped binary.
options=('!debug' '!strip')
source=()
sha256sums=()
package() {
  install -d "\$pkgdir/usr/share/$name"
  printf '%s\n' "$name $version" >"\$pkgdir/usr/share/$name/payload.txt"
$extra
}
PKG
  chown -R build:build "$root"
  # -f: the same name and version can be built twice with different contents (the upgrade witness builds a plain
  # 0.1.1, the version-swap negative a 0.1.1 that carries the CLI); without it makepkg exits 13 on the second build.
  runuser -u build -- bash -lc "cd '$root' && makepkg -f --noconfirm --nodeps >/dev/null"
  # Exactly one artifact, named for this package and version; a second match (a -debug split) is a harness failure.
  local built=("$root/$name-$version"-*.pkg.tar.zst)
  [[ ${#built[@]} == 1 && -f "${built[0]}" ]] || { echo "scratch build for $name $version produced ${#built[@]} packages" >&2; return 1; }
  cp "${built[0]}" "$out"
}

mask_hook() {
  local hook="$1"
  install -d -m 0755 /etc/pacman.d/hooks
  printf '[Trigger]\nOperation = Install\nType = Package\nTarget = __never_matches__\n\n[Action]\nDescription = Mask Castle Wall test hook\nWhen = PreTransaction\nExec = /usr/bin/true\n' >"/etc/pacman.d/hooks/$hook"
}

unmask_hooks() {
  rm -f /etc/pacman.d/hooks/00-sanctuary-castle-wall-upgrade-guard.hook
  rm -f /etc/pacman.d/hooks/00-sanctuary-castle-wall-remove-guard.hook
}

expect_refused() {
  local label="$1"
  shift
  local phrase="${1:?expect_refused requires a guard phrase}"
  shift
  if "$@" >"$evidence/$label.out" 2>"$evidence/$label.err"; then
    echo "$label unexpectedly succeeded" >&2
    exit 1
  fi
  cat "$evidence/$label.out" "$evidence/$label.err" >"$evidence/$label.combined"
  grep -F 'Castle Wall package guard refused:' "$evidence/$label.combined" >/dev/null
  grep -F "$phrase" "$evidence/$label.combined" >/dev/null
  record "refused: $label"
}

expect_ok() {
  local label="$1"
  shift
  "$@" >"$evidence/$label.out" 2>"$evidence/$label.err"
  record "admitted: $label"
}

assert_inert() {
  pacman -Qkk sanctuary-castle-wall
  # Capture, never pipe: under `set -o pipefail` a disabled unit makes
  # `systemctl is-enabled` exit 1 and an inactive one makes `is-active` exit 3,
  # so `systemctl ... | grep` aborted this script on a correct fresh install
  # with no message (CI run 37404360159). The comparison below is the assertion.
  [[ "$(systemctl is-enabled sanctuary-castle-wall.service 2>/dev/null || true)" == disabled ]]
  [[ "$(systemctl is-active sanctuary-castle-wall.service 2>/dev/null || true)" == inactive ]]
  [[ ! -e /etc/sanctuary || -z "$(find /etc/sanctuary -mindepth 1 -maxdepth 1 -print -quit)" ]]
}

assert_systemd
id build >/dev/null 2>&1 || useradd -m build
# mktemp creates a root-owned 0700 parent; makepkg as build needs access to its scratch PKGBUILD tree.
chown build:build "$work"
pacman -Syu --noconfirm --needed base-devel zstd systemd nftables iproute2 util-linux shadow python libnetfilter_queue >/dev/null

identity_path=/usr/lib/sanctuary-castle-wall/build-identity
identity_rel=${identity_path#/}
identity_dir_rel=${identity_rel%/*}
guard_path=/usr/share/libalpm/scripts/sanctuary-castle-wall-guard

if [[ "$mode" == --noextract-witness ]]; then
  record 'NoExtract witness keeps the image pacman.conf rules; base failure was captured in run 37365438647 attempt 2'
  pacman-conf NoExtract | grep -Fx 'usr/share/doc/*' >/dev/null
  expect_ok noextract-head-install pacman -U --noconfirm "$pkg"
  pacman -Qkk sanctuary-castle-wall >"$evidence/noextract-head-qkk.out"
  if pacman -Ql sanctuary-castle-wall | grep -F '/usr/share/doc' >"$evidence/noextract-head-doc-paths.out"; then
    echo "NoExtract head package listed usr/share/doc payload paths" >&2
    exit 1
  fi
  installed_sha="$(sha256sum "$identity_path" | cut -d' ' -f1)"
  guard_sha="$(awk -F"'" 'NR == 2 && $1 == "IDENTITY_SHA256 = " {print $2}' "$guard_path")"
  [[ "$installed_sha" == "$guard_sha" ]]
  expect_ok noextract-inert-remove pacman -R --noconfirm sanctuary-castle-wall
  expect_ok noextract-reinstall pacman -U --noconfirm "$pkg"
  install -d -m 0755 /etc/sanctuary
  printf provisioned >/etc/sanctuary/provisioned
  provisioned_refusal='runtime/config entry present under /etc/sanctuary'
  expect_refused noextract-remove-provisioned "$provisioned_refusal" pacman -R --noconfirm sanctuary-castle-wall
  expect_refused noextract-remove-dd-provisioned "$provisioned_refusal" pacman -Rdd --noconfirm sanctuary-castle-wall
  mask_hook 00-sanctuary-castle-wall-remove-guard.hook
  expect_ok noextract-remove-provisioned-masked pacman -R --noconfirm sanctuary-castle-wall
  unmask_hooks
  rm -f /etc/sanctuary/provisioned

  # pacman check_file_exists skips a NoExtract-matched missing file, so a rule
  # naming only the identity leaves -Qkk clean; withholding the directory leaves
  # pacman's mtree directory entry reported.
  sed -i "/^\[options\]/a NoExtract = $identity_dir_rel/*" /etc/pacman.conf
  pacman-conf NoExtract | grep -Fx "$identity_dir_rel/*" >/dev/null
  expect_ok noextract-missing-identity-install pacman -U --noconfirm "$pkg"
  [[ ! -e "$identity_path" ]]
  if pacman -Qkk sanctuary-castle-wall >"$evidence/noextract-missing-qkk.out" 2>"$evidence/noextract-missing-qkk.err"; then
    echo "missing identity install unexpectedly passed pacman -Qkk" >&2
    exit 1
  fi
  cat "$evidence/noextract-missing-qkk.out" "$evidence/noextract-missing-qkk.err" >"$evidence/noextract-missing-qkk.combined"
  grep -F "$identity_dir_rel" "$evidence/noextract-missing-qkk.combined" >/dev/null
  identity_absent='build identity absent'
  expect_refused noextract-missing-inert-remove "$identity_absent" pacman -R --noconfirm sanctuary-castle-wall
  install -d -m 0755 /etc/sanctuary
  printf provisioned >/etc/sanctuary/provisioned
  expect_refused noextract-missing-provisioned-remove "$identity_absent" pacman -R --noconfirm sanctuary-castle-wall
  expect_refused noextract-missing-provisioned-remove-dd "$identity_absent" pacman -Rdd --noconfirm sanctuary-castle-wall
  record 'NoExtract identity-present and missing-identity witnesses passed'
  exit 0
fi

if [[ "$mode" != default ]]; then
  echo "unsupported lifecycle mode: $mode" >&2
  exit 1
fi

# The official archlinux container image ships NoExtract rules (usr/share/doc/*,
# locales, help) that stock Arch and Omarchy do not have. The build identity the
# P1 guard bound to lived under usr/share/doc, so under those rules a fresh
# install never received it and `pacman -Qkk` reported an altered file before
# any hook ran (seen 2026-10-05: "/usr/share/doc (No such file or directory),
# 1 altered file"). P2b has a separate NoExtract witness that keeps the rule.
# The proof target is a default pacman.conf, so strip the image's rules and refuse
# to continue if any NoExtract remains; a silent skip here would test a host that
# does not exist. Failure mode: the first-install witness fails on `-Qkk` with no
# refusal text, which reads like a package defect rather than a container artifact.
sed -i '/^[[:space:]]*NoExtract/d' /etc/pacman.conf
if compgen -G '/etc/pacman.d/*.conf' >/dev/null; then sed -i '/^[[:space:]]*NoExtract/d' /etc/pacman.d/*.conf; fi
if [[ -n "$(pacman-conf NoExtract)" ]]; then
  echo "container pacman.conf still carries NoExtract rules; the lifecycle witness needs default extraction" >&2
  exit 1
fi
record 'container pacman.conf has no NoExtract rules (default extraction, as on stock Arch and Omarchy)'

record 'first install is not refused'
expect_ok first-install pacman -U --noconfirm "$pkg"
assert_inert

scratch_pkg sanctuary-castle-wall 0.1.1 "$work/upgrade.pkg.tar.zst"
scratch_pkg sanctuary-castle-wall 0.0.9 "$work/downgrade.pkg.tar.zst"
scratch_pkg unrelated-hold-witness 1.0.0 "$work/unrelated.pkg.tar.zst"
sbin_conflict_extra=$'  install -d "$pkgdir/usr/sbin"\n  printf conflict >"$pkgdir/usr/sbin/sanctuary-linux"'
scratch_pkg sbin-conflict 1.0.0 "$work/sbin.pkg.tar.zst" "$sbin_conflict_extra"

# Must match UPGRADE_REFUSAL in sanctuary-castle-wall-guard.py.
upgrade_refusal='in-place Castle Wall upgrade, reinstall and downgrade are unsupported; retire this host and cold-install a new package'
# Must match PROVISIONED_FOOTPRINT_REFUSAL in sanctuary-castle-wall-guard.py.
provisioned_refusal='runtime/config entry present under /etc/sanctuary'

expect_refused upgrade "$upgrade_refusal" pacman -U --noconfirm "$work/upgrade.pkg.tar.zst"
mask_hook 00-sanctuary-castle-wall-upgrade-guard.hook
expect_ok upgrade-masked pacman -U --noconfirm "$work/upgrade.pkg.tar.zst"
unmask_hooks
mask_hook 00-sanctuary-castle-wall-upgrade-guard.hook
expect_ok restore-original-after-upgrade pacman -U --noconfirm "$pkg"
unmask_hooks

expect_refused reinstall "$upgrade_refusal" pacman -U --noconfirm "$pkg"
mask_hook 00-sanctuary-castle-wall-upgrade-guard.hook
expect_ok reinstall-masked pacman -U --noconfirm "$pkg"
unmask_hooks

expect_refused downgrade "$upgrade_refusal" pacman -U --noconfirm "$work/downgrade.pkg.tar.zst"
mask_hook 00-sanctuary-castle-wall-upgrade-guard.hook
expect_ok downgrade-masked pacman -U --noconfirm "$work/downgrade.pkg.tar.zst"
expect_ok restore-original-after-downgrade pacman -U --noconfirm "$pkg"
unmask_hooks

expect_refused foreign-alone "$upgrade_refusal" pacman -U --noconfirm "$work/upgrade.pkg.tar.zst"
expect_refused foreign-batched "$upgrade_refusal" pacman -U --noconfirm "$work/upgrade.pkg.tar.zst" "$work/unrelated.pkg.tar.zst"
# The claim is "held back with it": the AbortOnFail refusal must have aborted the
# whole transaction, so the unrelated package in the same batch stays uninstalled.
if pacman -Q unrelated-hold-witness >/dev/null 2>&1; then
  echo "foreign-batched refusal did not hold back the unrelated package" >&2
  exit 1
fi
record 'held back: unrelated package in the refused batch stayed uninstalled'
mask_hook 00-sanctuary-castle-wall-upgrade-guard.hook
expect_ok foreign-batched-masked pacman -U --noconfirm "$work/upgrade.pkg.tar.zst" "$work/unrelated.pkg.tar.zst"
expect_ok restore-original-after-foreign pacman -U --noconfirm "$pkg"
unmask_hooks

install -d -m 0755 /etc/sanctuary
printf provisioned >/etc/sanctuary/provisioned
expect_refused remove-provisioned "$provisioned_refusal" pacman -R --noconfirm sanctuary-castle-wall
expect_refused remove-dd-provisioned "$provisioned_refusal" pacman -Rdd --noconfirm sanctuary-castle-wall
mask_hook 00-sanctuary-castle-wall-remove-guard.hook
expect_ok remove-provisioned-masked pacman -R --noconfirm sanctuary-castle-wall
unmask_hooks
expect_ok reinstall-after-remove-masked pacman -U --noconfirm "$pkg"
mask_hook 00-sanctuary-castle-wall-remove-guard.hook
expect_ok remove-dd-provisioned-masked pacman -Rdd --noconfirm sanctuary-castle-wall
unmask_hooks
rm -f /etc/sanctuary/provisioned

expect_ok reinstall-after-remove pacman -U --noconfirm "$pkg"
expect_ok inert-remove pacman -R --noconfirm sanctuary-castle-wall
expect_ok reinstall-for-cli-lifecycle pacman -U --noconfirm "$pkg"
run_arch_cli_lifecycle
expect_ok reinstall-for-sbin-conflict pacman -U --noconfirm "$pkg"

if pacman -U --noconfirm "$work/sbin.pkg.tar.zst" >"$evidence/sbin-conflict.out" 2>"$evidence/sbin-conflict.err"; then
  echo "usr/sbin conflict witness unexpectedly installed" >&2
  exit 1
fi
grep -E 'conflicting files|exists in filesystem' "$evidence/sbin-conflict.err" >/dev/null
record 'usr/sbin conflict refused by pacman'
