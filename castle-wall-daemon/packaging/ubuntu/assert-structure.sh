#!/usr/bin/env bash
# Assert only the internal package's metadata and bytes. This never installs a
# package or invokes systemctl, nft, or the daemon.
set -euo pipefail

usage() {
  echo "usage: $0 --artifact-dir <directory> | --check-depends <field>" >&2
  exit 64
}

validate_runtime_depends() {
  local depends="$1" part name
  local -a parts=()
  [[ -n "$depends" ]] || { echo "runtime Depends is empty" >&2; return 1; }
  [[ "$depends" != ,* && "$depends" != *, && "$depends" != *,,* ]] \
    || { echo "runtime Depends has an empty package token" >&2; return 1; }
  IFS=',' read -r -a parts <<< "$depends"
  for part in "${parts[@]}"; do
    name="${part#"${part%%[![:space:]]*}"}"
    name="${name%"${name##*[![:space:]]}"}"
    [[ "$name" =~ ^[a-z0-9][a-z0-9+.-]*(:amd64)?$ ]] \
      || { echo "runtime Depends must contain plain package names only" >&2; return 1; }
    name="${name%:amd64}"
    [[ "$name" != *-dev && "$name" != systemd && "$name" != nftables ]] \
      || { echo "runtime Depends contains probe or -dev package" >&2; return 1; }
  done
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
    --check-depends)
      [[ $# -eq 2 ]] || usage
      validate_runtime_depends "$2"
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

for command in cmp dpkg-deb grep python3 sha256sum tar; do
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
validate_runtime_depends "$depends"
[[ "$(dpkg-deb -f "$deb_path" Pre-Depends)" == "systemd, nftables, python3" ]] || {
  echo "guard probe Pre-Depends metadata mismatch" >&2
  exit 1
}
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

python3 "$script_dir/assert-source-constants.py"
python3 "$script_dir/assert-archive.py" "$deb_path"

echo "internal guarded package structure is valid; no install or service action was run"
