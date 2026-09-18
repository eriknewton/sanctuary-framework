#!/usr/bin/env bash
# Assert only the internal package's metadata and bytes. This never installs a
# package or invokes systemctl, nft, or the daemon.
set -euo pipefail

usage() {
  echo "usage: $0 --artifact-dir <directory>" >&2
  exit 64
}

validate_checksum_record() {
  local record_path="$1"
  local artifact_name="$2"
  # The checksum is a portable, one-artifact sidecar. Reject every extra,
  # malformed, absolute, or differently named record instead of accepting a
  # valid line among host-dependent entries.
  awk -v artifact="$artifact_name" '
    NF != 2 { invalid = 1; next }
    length($1) != 64 || $1 !~ /^[0-9a-f]+$/ { invalid = 1; next }
    $2 != artifact { invalid = 1; next }
    { records += 1 }
    END { exit(!invalid && records == 1 ? 0 : 1) }
  ' "$record_path"
}

artifact_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact-dir)
      [[ $# -ge 2 ]] || usage
      artifact_dir="$2"
      shift 2
      ;;
    --check-checksum-record)
      [[ $# -eq 3 ]] || usage
      validate_checksum_record "$2" "$3" || {
        echo "checksum must be exactly one canonical sibling-deb record" >&2
        exit 1
      }
      exit 0
      ;;
    *) usage ;;
  esac
done
[[ -n "$artifact_dir" && -d "$artifact_dir" ]] || usage

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
crate_dir="$(cd -- "$script_dir/../.." && pwd -P)"
repo_root="$(cd -- "$crate_dir/.." && pwd -P)"
unit_source="$crate_dir/systemd/sanctuary-castle-wall.service"
[[ -f "$repo_root/AGENTS.md" && -f "$crate_dir/Cargo.toml" && -f "$unit_source" ]] \
  || { echo "package script is not under the Castle Wall daemon subtree" >&2; exit 1; }

for command in cmp dpkg-deb grep sha256sum tar; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing command: $command" >&2; exit 1; }
done

shopt -s nullglob
artifacts=("$artifact_dir"/*.deb)
manifests=("$artifact_dir"/*.manifest.txt)
checksums=("$artifact_dir"/*.deb.sha256)
[[ ${#artifacts[@]} -eq 1 && ${#manifests[@]} -eq 1 && ${#checksums[@]} -eq 1 ]] \
  || { echo "expected exactly one deb, manifest, and checksum" >&2; exit 1; }
deb_path="${artifacts[0]}"
manifest_path="${manifests[0]}"
checksum_path="${checksums[0]}"

(
  cd -- "$artifact_dir"
  sha256sum -c "$(basename -- "$checksum_path")"
) >/dev/null
# Require a self-contained checksum sidecar: one basename-only record for this
# one deb. A moved CI artifact must not retain workspace paths or extra entries.
validate_checksum_record "$checksum_path" "$(basename -- "$deb_path")" || {
  echo "checksum must be exactly one canonical sibling-deb record" >&2
  exit 1
}
[[ "$(dpkg-deb -f "$deb_path" Package)" == "sanctuary-castle-wall-internal" ]]
[[ "$(dpkg-deb -f "$deb_path" Architecture)" == "amd64" ]]
depends="$(dpkg-deb -f "$deb_path" Depends)"
[[ -n "$depends" ]]
if grep -Eq '(^|[ ,])-dev(:amd64)?($|[ ,])' <<<"$depends"; then
  echo "runtime Depends must be derived from runtime ownership, never -dev packages" >&2
  exit 1
fi
grep -Fx 'artifact_kind=internal-structural-deb' "$manifest_path"
grep -Fx 'install_ready=false' "$manifest_path"
grep -Fqx 'artifact_kind=internal-structural-deb' <(
  dpkg-deb --fsys-tarfile "$deb_path" | tar -xOf - \
    ./usr/share/doc/sanctuary-castle-wall-internal/build-identity
)
grep -Fqx 'install_ready=false' <(
  dpkg-deb --fsys-tarfile "$deb_path" | tar -xOf - \
    ./usr/share/doc/sanctuary-castle-wall-internal/build-identity
)
dpkg-deb --fsys-tarfile "$deb_path" | tar -xOf - \
  ./etc/systemd/system/sanctuary-castle-wall.service | cmp - "$unit_source"

# No control scripts means package installation cannot enable, start, stop,
# disarm, or delete a Castle Wall runtime.
if dpkg-deb --ctrl-tarfile "$deb_path" | tar -tf - | grep -Eq '(^|/)(postinst|prerm|postrm|preinst)$'; then
  echo "internal structural package must not contain maintainer lifecycle scripts" >&2
  exit 1
fi

echo "internal package structure is valid; no install or service action was run"
