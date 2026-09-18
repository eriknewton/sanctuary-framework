#!/usr/bin/env bash
# Fresh GitHub-hosted Ubuntu 24.04 VM only. Runs real dpkg/systemd/nft probes.
# Each deliberately failed scenario receives its own VM job; no force removal
# or cleanup is used to turn a damaged state back into a passing baseline.
set -euo pipefail

die() { echo "lifecycle CI refused: $*" >&2; exit 1; }

# Diagnostic preflight only: inspect executable links, not truncated comm or
# incidental command-line text. An inaccessible live PID is unknown and fails;
# a PID that vanishes during the scan is not evidence of a running daemon.
direct_daemon_proc_absent() {
  local proc_root="$1"
  python3 - "$proc_root" <<'PY'
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
try:
    entries = list(root.iterdir())
except OSError as exc:
    raise SystemExit(f"process inventory unavailable: {exc}")
for pid in entries:
    if not pid.name.isdecimal():
        continue
    try:
        pid_info = os.stat(pid, follow_symlinks=False)
    except FileNotFoundError:
        continue  # PID vanished during enumeration.
    except OSError as exc:
        raise SystemExit(f"cannot inspect PID {pid.name}: {exc}")
    if not stat.S_ISDIR(pid_info.st_mode):
        raise SystemExit(f"numeric process entry {pid.name} is not a directory")
    try:
        executable = os.readlink(pid / "exe")
    except FileNotFoundError:
        try:
            os.stat(pid, follow_symlinks=False)
        except FileNotFoundError:
            continue  # PID vanished before its executable could be read.
        except OSError as exc:
            raise SystemExit(f"cannot inspect live PID {pid.name}: {exc}")
        try:
            command_line = (pid / "cmdline").read_bytes()
        except FileNotFoundError:
            try:
                os.stat(pid, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise SystemExit(f"cannot inspect live PID {pid.name}: {exc}")
            raise SystemExit(f"live PID {pid.name} has unreadable executable and cmdline")
        except OSError as exc:
            raise SystemExit(f"cannot classify live PID {pid.name}: {exc}")
        if command_line:
            raise SystemExit(f"live PID {pid.name} has no readable executable")
        continue  # Zombie or kernel thread has no executable or command line.
    except OSError as exc:
        raise SystemExit(f"cannot read executable for PID {pid.name}: {exc}")
    executable = executable.removesuffix(" (deleted)")
    if Path(executable).name == "castle-wall-daemon":
        raise SystemExit(f"direct daemon executable exists at PID {pid.name}")
PY
}

if [[ "${1:-}" == --test-process-scan ]]; then
  [[ $# == 2 ]] || die "usage: ci-lifecycle.sh --test-process-scan <synthetic-proc-root>"
  direct_daemon_proc_absent "$2"
  exit 0
fi

scenario="${1:-}"
artifacts="${2:-}"
evidence="${3:-}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ -n "$scenario" && -d "$artifacts" && -n "$evidence" ]] || die "usage: ci-lifecycle.sh <scenario> <artifact-root> <evidence-dir>"
[[ "$(id -u)" == 0 ]] || die "must run as root on the disposable CI VM"
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted && "${RUNNER_OS:-}" == Linux ]] \
  || die "requires a positively identified fresh GitHub-hosted Linux runner"
[[ "$(uname -m)" == x86_64 && "$(dpkg --print-architecture)" == amd64 ]] || die "Ubuntu amd64 required"
[[ "$(</proc/1/comm)" == systemd ]] || die "real systemd PID 1 required"
systemctl --version >/dev/null || die "systemctl unavailable"
systemctl show --property=Version --no-pager >/dev/null || die "real systemd manager unavailable"
command -v nft >/dev/null || die "nft probe unavailable"
command -v python3 >/dev/null || die "Python 3 probe unavailable"
[[ ! -e "$evidence" ]] || die "evidence output already exists"
mkdir -m 0755 -- "$evidence"

mapfile -t v1_matches < <(find "$artifacts/revision-1" -maxdepth 1 -name '*.deb' -type f -print)
mapfile -t v2_matches < <(find "$artifacts/revision-2" -maxdepth 1 -name '*.deb' -type f -print)
[[ ${#v1_matches[@]} == 1 && ${#v2_matches[@]} == 1 ]] || die "expected one deb per revision"
v1="${v1_matches[0]}"
v2="${v2_matches[0]}"
package=sanctuary-castle-wall-internal
unit=sanctuary-castle-wall.service
daemon=/usr/local/libexec/sanctuary/castle-wall-daemon
unit_file=/etc/systemd/system/sanctuary-castle-wall.service
v1_version="$(dpkg-deb -f "$v1" Version)"
v2_version="$(dpkg-deb -f "$v2" Version)"
dpkg --compare-versions "$v1_version" lt "$v2_version" || die "package revisions not increasing"
v1_daemon_sha="$(dpkg-deb --fsys-tarfile "$v1" | tar -xOf - ./usr/local/libexec/sanctuary/castle-wall-daemon | sha256sum | cut -d' ' -f1)"
v1_unit_sha="$(dpkg-deb --fsys-tarfile "$v1" | tar -xOf - ./etc/systemd/system/sanctuary-castle-wall.service | sha256sum | cut -d' ' -f1)"
{
  echo "scenario=$scenario"
  echo "source_commit=${GITHUB_SHA:-unknown}"
  echo "v1_version=$v1_version"
  echo "v2_version=$v2_version"
  echo "runner_environment=$RUNNER_ENVIRONMENT"
  cat /etc/os-release
  dpkg --version | head -n 1
  systemctl --version | head -n 1
  nft --version
  sha256sum "$v1" "$v2"
} > "$evidence/preflight-metadata.txt"

status() {
  python3 - "$package" <<'PY'
from pathlib import Path
import sys
text = Path('/var/lib/dpkg/status').read_text()
found = []
for stanza in text.split('\n\n'):
    fields = {}
    for line in stanza.splitlines():
        if ': ' in line and not line.startswith((' ', '\t')):
            key, value = line.split(': ', 1)
            if key in fields:
                raise SystemExit('duplicate status field')
            fields[key] = value
    if fields.get('Package') == sys.argv[1]:
        found.append(fields)
if len(found) > 1:
    raise SystemExit('duplicate package status stanza')
fields = found[0] if found else {}
print(fields.get('Status', 'ABSENT'))
print(fields.get('Version', 'NO_VERSION'))
PY
}

nft_check() {
  nft -j list tables | python3 -c 'import json,sys; data=json.load(sys.stdin); assert isinstance(data.get("nftables"),list); assert not any(x.get("table",{}).get("family")=="inet" and x.get("table",{}).get("name")=="sanctuary-castle" for x in data["nftables"])'
}

snapshot() {
  local out="$evidence/$1"
  mkdir -m 0755 -- "$out"
  status > "$out/dpkg-status.txt"
  systemctl show "$unit" --all --no-pager \
    --property=Id,Names,Following,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,Job,NeedDaemonReload \
    > "$out/systemctl-show.txt" 2> "$out/systemctl-stderr.txt" || true
  nft -j list tables > "$out/nft-tables.json"
  if [[ -f "$daemon" ]]; then sha256sum "$daemon" > "$out/daemon.sha256"; fi
  if [[ -f "$unit_file" ]]; then sha256sum "$unit_file" > "$out/unit.sha256"; fi
  find /etc/sanctuary /var/lib/sanctuary /run/sanctuary -maxdepth 2 -print \
    > "$out/bounded-paths.txt" 2> "$out/find-stderr.txt" || true
}

assert_absent() {
  [[ ! -e "$daemon" && ! -L "$daemon" && ! -e "$unit_file" && ! -L "$unit_file" \
     && ! -e /usr/share/doc/sanctuary-castle-wall-internal/build-identity \
     && ! -L /usr/share/doc/sanctuary-castle-wall-internal/build-identity ]] \
    || die "package payload already exists"
  [[ ! -e /etc/sanctuary/castle-wall.env && ! -L /etc/sanctuary/castle-wall.env ]] \
    || die "Castle Wall environment exists"
  for root in /var/lib/sanctuary /run/sanctuary; do
    [[ ! -L "$root" ]] || die "runtime root is a symlink: $root"
    [[ ! -e "$root" || -z "$(find "$root" -mindepth 1 -maxdepth 1 -print -quit)" ]] \
      || die "Castle Wall runtime root is not empty: $root"
  done
  [[ "$(status | head -n1)" == ABSENT || "$(status | head -n1)" == *" ok not-installed" ]] \
    || die "package already installed or residual"
  direct_daemon_proc_absent /proc || die "direct daemon process exists or inventory is unknown"
  nft_check || die "Castle Wall nft table or bad inventory exists"
  [[ ! -e "$unit_file" ]] || die "unit file exists"
  systemctl show "$unit" --property=FragmentPath --value --no-pager | grep -Fx '' >/dev/null \
    || die "effective unit fragment exists"
}

assert_installed_v1() {
  [[ "$(status | head -n1)" == 'install ok installed' ]] || die "v1 no longer in exact installed state"
  [[ "$(status | tail -n1)" == "$v1_version" ]] || die "v1 Version changed"
  [[ -f "$daemon" && -f "$unit_file" ]] || die "old recovery payload lost"
  [[ "$(sha256sum "$daemon" | cut -d' ' -f1)" == "$v1_daemon_sha" ]] || die "old daemon bytes changed"
  [[ "$(sha256sum "$unit_file" | cut -d' ' -f1)" == "$v1_unit_sha" ]] || die "old unit bytes changed"
  cmp -s "$unit_file" "$(dirname "${BASH_SOURCE[0]}")/../../systemd/sanctuary-castle-wall.service" \
    || die "installed unit differs from source"
  nft_check || die "Castle Wall nft table appeared"
}

# Diagnostic wrappers are confined to isolated CI scenarios. They record real
# dpkg callback ordering and then execute the unchanged hook body. The accepted
# artifacts and production hook template never write a phase trace.
trace_python_hook() {
  local path="$1" label="$2" log="$evidence/phase-calls.txt"
  python3 - "$path" "$label" "$log" <<'PY'
from pathlib import Path
import sys
path, label, log = sys.argv[1:]
source = Path(path).read_text()
header = '#!/usr/bin/python3\n'
if not source.startswith(header):
    raise SystemExit('unexpected hook header in diagnostic trace fixture')
trace = (
    'import sys\n'
    f'with open({log!r}, "a", encoding="utf-8") as trace_file:\n'
    f'    trace_file.write({label!r} + " " + " ".join(sys.argv[1:]) + "\\n")\n'
)
Path(path).write_text(header + trace + source[len(header):])
PY
}

assert_phase_calls() {
  local expected="$1"
  [[ -f "$evidence/phase-calls.txt" ]] || die "dpkg phase trace absent"
  diff -u <(printf '%s\n' "$expected") "$evidence/phase-calls.txt" \
    || die "unexpected dpkg maintainer-script callback order"
}

assert_inert() {
  [[ "$(systemctl show "$unit" --property=ActiveState --value)" == inactive ]] \
    || die "unit became active"
  [[ "$(systemctl show "$unit" --property=UnitFileState --value)" == disabled ]] \
    || die "unit became enabled or changed state"
  nft_check || die "Castle Wall nft table appeared"
  [[ ! -e /etc/sanctuary/castle-wall.env ]] || die "environment unexpectedly created"
  for root in /var/lib/sanctuary /run/sanctuary; do
    [[ ! -e "$root" || -z "$(find "$root" -mindepth 1 -maxdepth 1 -print -quit)" ]] \
      || die "runtime state unexpectedly created"
  done
}

attempt_refusal() {
  local label="$1" deb="$2" expected="$3"
  if dpkg --install "$deb" > "$evidence/$label.stdout" 2> "$evidence/$label.stderr"; then
    die "$label unexpectedly succeeded"
  fi
  if [[ "$expected" == callback:abort-upgrade ]]; then
    if [[ ! -f "$evidence/old-preinst-calls.txt" ]] \
       || ! grep -Eq '^abort-upgrade( |$)' "$evidence/old-preinst-calls.txt"; then
      die "$label did not invoke the expected old preinst abort-upgrade callback"
    fi
  else
    grep -F "Castle Wall package guard refused: $expected" "$evidence/$label.stderr" >/dev/null \
      || die "$label failed without the expected guard refusal: $expected"
  fi
  snapshot "$label"
}

snapshot preflight
assert_absent
python3 - "$script_dir/lifecycle-guard.py" <<'PY'
import runpy, sys
guard = runpy.run_path(sys.argv[1], init_globals={
    'ROLE': 'preinst', 'PACKAGE_VERSION': 'preflight',
    'DAEMON_SHA256': '0' * 64, 'UNIT_SHA256': '0' * 64,
})
guard['inspect'](False, 'install')
PY
case "$scenario" in
  happy)
    dpkg --install "$v1" > "$evidence/install-v1.stdout" 2> "$evidence/install-v1.stderr"
    snapshot installed-v1
    assert_installed_v1
    assert_inert
    # Recopy the exact A119 bytes into the already package-owned leaf after
    # querying the real manager. Record whether its cache actually reports
    # staleness; an inactive unit may have been garbage-collected meanwhile.
    unit_before="$(sha256sum "$unit_file" | cut -d' ' -f1)"
    install -m 0644 "$script_dir/../../systemd/sanctuary-castle-wall.service" "$unit_file"
    [[ "$(sha256sum "$unit_file" | cut -d' ' -f1)" == "$unit_before" ]] \
      || die "stale-manager fixture changed unit bytes"
    snapshot inert-stale-before-upgrade
    upgrade_snapshot="$evidence/inert-stale-before-upgrade/systemctl-show.txt"
    [[ "$(grep -c '^NeedDaemonReload=' "$upgrade_snapshot")" == 1 ]] \
      || die "upgrade manager observation incomplete"
    upgrade_reload="$(sed -n 's/^NeedDaemonReload=//p' "$upgrade_snapshot")"
    [[ "$upgrade_reload" == yes || "$upgrade_reload" == no ]] \
      || die "real manager did not expose an exact daemon-reload state"
    printf 'upgrade_need_daemon_reload=%s\n' "$upgrade_reload" > "$evidence/stale-manager-coverage.txt"
    [[ "$upgrade_reload" == yes ]] \
      || printf 'stale_upgrade_unexercised=manager_did_not_report_yes\n' >> "$evidence/stale-manager-coverage.txt"
    dpkg --install "$v2" > "$evidence/upgrade-v2.stdout" 2> "$evidence/upgrade-v2.stderr"
    snapshot upgraded-v2
    [[ "$(status | tail -n1)" == "$v2_version" ]] || die "upgrade Version mismatch"
    assert_inert
    dpkg --remove "$package" > "$evidence/remove.stdout" 2> "$evidence/remove.stderr"
    snapshot removed
    post_remove_snapshot=removed
    [[ ! -e "$daemon" && ! -e "$unit_file" ]] || die "guarded remove retained payload"
    if [[ "$(status | head -n1)" == 'deinstall ok config-files' ]]; then
      dpkg --purge "$package" > "$evidence/purge.stdout" 2> "$evidence/purge.stderr"
      snapshot purged
      post_remove_snapshot=purged
    fi
    [[ "$(status | head -n1)" == *' ok not-installed' || "$(status | head -n1)" == ABSENT ]] \
      || die "remove/purge left unadmitted state"
    manager_snapshot="$evidence/$post_remove_snapshot/systemctl-show.txt"
    for property in LoadState FragmentPath UnitFileState NeedDaemonReload; do
      [[ "$(grep -c "^$property=" "$manager_snapshot")" == 1 ]] \
        || die "post-removal manager observation missing or duplicate: $property"
    done
    manager_load="$(sed -n 's/^LoadState=//p' "$manager_snapshot")"
    manager_fragment="$(sed -n 's/^FragmentPath=//p' "$manager_snapshot")"
    manager_unit_file="$(sed -n 's/^UnitFileState=//p' "$manager_snapshot")"
    manager_reload="$(sed -n 's/^NeedDaemonReload=//p' "$manager_snapshot")"
    [[ -n "$manager_load" && ( "$manager_reload" == yes || "$manager_reload" == no ) ]] \
      || die "post-removal manager observation incomplete"
    if [[ "$manager_load" == not-found && -z "$manager_fragment" \
       && ( -z "$manager_unit_file" || "$manager_unit_file" == not-found ) \
       && "$manager_reload" == no ]]; then
      printf 'stale_reinstall_veto_unexercised=manager_already_fresh\n' >> "$evidence/stale-manager-coverage.txt"
    else
      attempt_refusal stale-manager-reinstall-veto "$v1" 'fresh unit is still effective or stale'
      [[ ! -e "$daemon" && ! -e "$unit_file" ]] \
        || die "stale-manager refusal unpacked package bytes"
      printf 'stale_reinstall_veto_observed=yes\n' >> "$evidence/stale-manager-coverage.txt"
    fi
    # This is the explicit operator step, never a maintainer-script action.
    systemctl daemon-reload
    snapshot operator-reloaded
    dpkg --install "$v1" > "$evidence/reinstall.stdout" 2> "$evidence/reinstall.stderr"
    snapshot reinstalled
    assert_installed_v1
    assert_inert
    cat "$evidence/stale-manager-coverage.txt"
    ;;
  old-veto)
    dpkg --install "$v1" > "$evidence/install-v1.stdout" 2> "$evidence/install-v1.stderr"
    assert_installed_v1
    trace_python_hook "/var/lib/dpkg/info/$package.prerm" old-prerm
    fixture="$evidence/old-veto-traced-incoming"
    dpkg-deb --raw-extract "$v2" "$fixture"
    trace_python_hook "$fixture/DEBIAN/preinst" new-preinst
    trace_python_hook "$fixture/DEBIAN/prerm" new-prerm
    dpkg-deb --root-owner-group --build "$fixture" "$evidence/old-veto-traced-incoming.deb" >/dev/null
    [[ ! -e /var/lib/sanctuary && ! -L /var/lib/sanctuary ]] \
      || die "collision fixture root already exists; refusing to alter it"
    install -d -m 0700 /var/lib/sanctuary
    printf 'dummy collision\n' > /var/lib/sanctuary/collision
    chmod 0600 /var/lib/sanctuary/collision
    snapshot collision
    attempt_refusal old-prerm-veto "$evidence/old-veto-traced-incoming.deb" 'runtime/config entry present under /var/lib/sanctuary'
    assert_phase_calls "$(printf 'old-prerm upgrade %s\nnew-prerm failed-upgrade %s %s' "$v2_version" "$v1_version" "$v2_version")"
    grep -F 'Castle Wall package guard refused: runtime/config entry present under /var/lib/sanctuary' \
      "$evidence/old-prerm-veto.stderr" >/dev/null || die "old prerm guard refusal not observed"
    grep -F 'Castle Wall package guard refused: failed-upgrade veto' \
      "$evidence/old-prerm-veto.stderr" >/dev/null || die "incoming failed-upgrade veto not observed"
    [[ "$(status | head -n1)" == 'install ok installed' ]] || die "old-prerm veto lost exact installed state"
    assert_installed_v1
    rm -- /var/lib/sanctuary/collision
    rmdir -- /var/lib/sanctuary
    dpkg --install "$v2" > "$evidence/old-veto-corrected-retry.stdout" 2> "$evidence/old-veto-corrected-retry.stderr"
    snapshot old-veto-corrected-retry
    [[ "$(status | head -n1)" == 'install ok installed' && "$(status | tail -n1)" == "$v2_version" ]] \
      || die "ordinary retry after old-prerm veto did not install v2"
    assert_inert
    ;;
  new-veto)
    dpkg --install "$v1" > "$evidence/install-v1.stdout" 2> "$evidence/install-v1.stderr"
    assert_installed_v1
    trace_python_hook "/var/lib/dpkg/info/$package.prerm" old-prerm
    fixture="$evidence/new-preinst-diagnostic"
    dpkg-deb --raw-extract "$v2" "$fixture"
    trace_python_hook "$fixture/DEBIAN/preinst" new-preinst
    trace_python_hook "$fixture/DEBIAN/prerm" new-prerm
    python3 - "$fixture/DEBIAN/preinst" "$v2_version" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]); old=f'PACKAGE_VERSION = "{sys.argv[2]}"'; text=p.read_text()
if text.count(old)!=1: raise SystemExit('cannot locate bound preinst version')
p.write_text(text.replace(old, 'PACKAGE_VERSION = "diagnostic-version-mismatch"'))
PY
    dpkg-deb --root-owner-group --build "$fixture" "$evidence/new-preinst-diagnostic.deb" >/dev/null
    attempt_refusal new-preinst-veto "$evidence/new-preinst-diagnostic.deb" 'incoming package version argument mismatch'
    assert_phase_calls "$(printf 'old-prerm upgrade %s\nnew-preinst upgrade %s %s' "$v2_version" "$v1_version" "$v2_version")"
    grep -F 'Castle Wall package guard refused: incoming package version argument mismatch' \
      "$evidence/new-preinst-veto.stderr" >/dev/null || die "new preinst guard refusal not observed"
    [[ "$(status | head -n1)" == 'install ok installed' ]] || die "new-preinst veto lost exact installed state"
    assert_installed_v1
    dpkg --install "$v2" > "$evidence/new-preinst-corrected-retry.stdout" 2> "$evidence/new-preinst-corrected-retry.stderr"
    snapshot new-preinst-corrected-retry
    [[ "$(status | head -n1)" == 'install ok installed' && "$(status | tail -n1)" == "$v2_version" ]] \
      || die "ordinary retry after new-preinst veto did not install v2"
    assert_inert
    ;;
  unpack-fault)
    dpkg --install "$v1" > "$evidence/install-v1.stdout" 2> "$evidence/install-v1.stderr"
    assert_installed_v1
    # Diagnostic old-script wrapper records the real dpkg callback and then
    # delegates to the unchanged guarded Python preinst. It is confined to
    # this terminal fresh-VM fault case, not shipped in either accepted deb.
    old_preinst="/var/lib/dpkg/info/$package.preinst"
    cp -- "$old_preinst" "$evidence/original-old-preinst"
    python3 - "$old_preinst" "$evidence/original-old-preinst" "$evidence/old-preinst-calls.txt" <<'PY'
from pathlib import Path
import shlex,sys
target, original, log = map(Path, sys.argv[1:])
target.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> ' + shlex.quote(str(log)) + '\nexec /usr/bin/python3 ' + shlex.quote(str(original)) + ' "$@"\n')
target.chmod(0o755)
PY
    fixture="$evidence/unpack-fault-diagnostic"
    dpkg-deb --raw-extract "$v2" "$fixture"
    doc="$fixture/usr/share/doc/sanctuary-castle-wall-internal"
    printf 'fault injection only\n' > "$doc/unpack-fault"
    mkdir -m 0755 /usr/share/doc/sanctuary-castle-wall-internal/unpack-fault
    dpkg-deb --root-owner-group --build "$fixture" "$evidence/unpack-fault-diagnostic.deb" >/dev/null
    attempt_refusal post-unpack-fault "$evidence/unpack-fault-diagnostic.deb" callback:abort-upgrade
    grep -Eq '^abort-upgrade( |$)' "$evidence/old-preinst-calls.txt" \
      || die "old preinst abort-upgrade callback not observed after unpack fault"
    ;;
  legacy)
    fixture="$evidence/legacy-unbound-diagnostic"
    dpkg-deb --raw-extract "$v1" "$fixture"
    python3 - "$fixture/DEBIAN/control" "$fixture/usr/share/doc/sanctuary-castle-wall-internal/build-identity" <<'PY'
from pathlib import Path
import re,sys
control=Path(sys.argv[1]); text=control.read_text(); text,n=re.subn(r'^Version: .+$','Version: 0.0.0-1',text,count=1,flags=re.M)
if n!=1: raise SystemExit('cannot rewrite legacy Version')
control.write_text(text)
identity=Path(sys.argv[2]); identity.write_text('artifact_kind=internal-structural-deb\ninstall_ready=false\n')
PY
    rm -- "$fixture/DEBIAN/preinst" "$fixture/DEBIAN/prerm"
    dpkg-deb --root-owner-group --build "$fixture" "$evidence/legacy-unbound-diagnostic.deb" >/dev/null
    dpkg --install "$evidence/legacy-unbound-diagnostic.deb" > "$evidence/install-legacy.stdout" 2> "$evidence/install-legacy.stderr"
    snapshot legacy-installed
    attempt_refusal legacy-upgrade-veto "$v1" 'unbound build identity'
    [[ "$(status | tail -n1)" == '0.0.0-1' ]] || die "legacy payload was replaced"
    ;;
  dangling)
    mkdir -p /etc/systemd/system/multi-user.target.wants
    ln -s /etc/systemd/system/sanctuary-castle-wall.service \
      /etc/systemd/system/multi-user.target.wants/sanctuary-castle-wall.service
    snapshot dangling-link
    attempt_refusal dangling-link-veto "$v1" 'systemd alias or enablement symlink'
    [[ ! -e "$daemon" ]] || die "payload appeared after refusal"
    ;;
  local-dangling)
    [[ ! -e /usr/local/lib/systemd/system/codex-package-fixture.wants \
       && ! -L /usr/local/lib/systemd/system/codex-package-fixture.wants ]] \
      || die "local search-root fixture path already exists"
    install -d -m 0755 /usr/local/lib/systemd/system/codex-package-fixture.wants
    ln -s /etc/systemd/system/sanctuary-castle-wall.service \
      /usr/local/lib/systemd/system/codex-package-fixture.wants/sanctuary-castle-wall.service
    snapshot local-search-root-dangling
    attempt_refusal local-search-root-veto "$v1" 'systemd alias or enablement symlink'
    [[ "$(status | head -n1)" == 'install ok not-installed' && ! -e "$daemon" ]] \
      || die "out-of-old-roots dangling link refusal unpacked package bytes"
    ;;
  writable-wants)
    [[ ! -e /etc/systemd/system/codex-package-fixture.wants \
       && ! -L /etc/systemd/system/codex-package-fixture.wants ]] \
      || die "writable-wants fixture path already exists"
    install -d -m 0777 /etc/systemd/system/codex-package-fixture.wants
    snapshot unsafe-empty-wants
    attempt_refusal unsafe-enable-directory-veto "$v1" 'unsafe systemd directory'
    grep -F 'unsafe systemd directory' "$evidence/unsafe-enable-directory-veto.stderr" >/dev/null \
      || die "empty writable enablement directory was not the refusal cause"
    [[ "$(status | head -n1)" == 'install ok not-installed' && ! -e "$daemon" ]] \
      || die "unsafe-directory refusal unpacked package bytes"
    ;;
  env-collision)
    [[ ! -e /etc/sanctuary && ! -L /etc/sanctuary ]] \
      || die "environment fixture root already exists"
    install -d -m 0755 /etc/sanctuary
    printf 'dummy collision\n' > /etc/sanctuary/castle-wall.env
    chmod 0600 /etc/sanctuary/castle-wall.env
    snapshot env-collision
    attempt_refusal env-veto "$v1" 'Castle Wall environment present'
    [[ ! -e "$daemon" ]] || die "payload appeared after refusal"
    ;;
  fresh-retry)
    [[ ! -e /etc/sanctuary && ! -L /etc/sanctuary ]] \
      || die "environment fixture root already exists"
    install -d -m 0755 /etc/sanctuary
    printf 'dummy collision\n' > /etc/sanctuary/castle-wall.env
    chmod 0600 /etc/sanctuary/castle-wall.env
    attempt_refusal fresh-preinst-veto "$v1" 'Castle Wall environment present'
    grep -F 'Castle Wall environment present' "$evidence/fresh-preinst-veto.stderr" >/dev/null \
      || die "fresh refusal did not come from the guard's preinst"
    [[ "$(status | head -n1)" == 'install ok not-installed' && "$(status | tail -n1)" == NO_VERSION ]] \
      || die "fresh refusal left an unadmitted dpkg status"
    [[ ! -e "$daemon" && ! -e "$unit_file" ]] || die "fresh refusal unpacked payload"
    [[ ! -e "/var/lib/dpkg/info/$package.prerm" && ! -e "/var/lib/dpkg/info/$package.postrm" ]] \
      || die "fresh refusal installed unexpected package callbacks"
    rm -- /etc/sanctuary/castle-wall.env
    rmdir -- /etc/sanctuary
    dpkg --install "$v1" > "$evidence/fresh-corrected-retry.stdout" 2> "$evidence/fresh-corrected-retry.stderr"
    snapshot fresh-corrected-retry
    assert_installed_v1
    assert_inert
    ;;
  fresh-purge)
    [[ ! -e /etc/sanctuary && ! -L /etc/sanctuary ]] \
      || die "environment fixture root already exists"
    install -d -m 0755 /etc/sanctuary
    printf 'dummy collision\n' > /etc/sanctuary/castle-wall.env
    chmod 0600 /etc/sanctuary/castle-wall.env
    attempt_refusal fresh-preinst-veto "$v1" 'Castle Wall environment present'
    grep -F 'Castle Wall environment present' "$evidence/fresh-preinst-veto.stderr" >/dev/null \
      || die "fresh refusal did not come from the guard's preinst"
    [[ "$(status | head -n1)" == 'install ok not-installed' && "$(status | tail -n1)" == NO_VERSION ]] \
      || die "fresh refusal left an unadmitted dpkg status"
    [[ ! -e "$daemon" && ! -e "$unit_file" ]] || die "fresh refusal unpacked payload"
    [[ ! -e "/var/lib/dpkg/info/$package.prerm" && ! -e "/var/lib/dpkg/info/$package.postrm" ]] \
      || die "fresh refusal installed unexpected package callbacks"
    dpkg --purge "$package" > "$evidence/fresh-purge.stdout" 2> "$evidence/fresh-purge.stderr"
    snapshot fresh-purged
    [[ "$(status | head -n1)" == 'purge ok not-installed' && "$(status | tail -n1)" == NO_VERSION ]] \
      || die "ordinary purge after fresh refusal left an unadmitted status"
    [[ ! -e "$daemon" && ! -e "$unit_file" ]] || die "ordinary purge installed package payload"
    [[ ! -e "/var/lib/dpkg/info/$package.prerm" && ! -e "/var/lib/dpkg/info/$package.postrm" ]] \
      || die "ordinary purge retained unexpected callbacks"
    ;;
  *) die "unknown isolated scenario: $scenario" ;;
esac
echo "fresh real-manager lifecycle scenario passed: $scenario"
