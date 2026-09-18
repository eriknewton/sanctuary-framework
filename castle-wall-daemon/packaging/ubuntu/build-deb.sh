#!/usr/bin/env bash
# Build an INTERNAL unprovisioned-guarded Debian artifact for Castle Wall.
#
# This builder never installs or starts the package. The generated maintainer
# scripts refuse unsafe lifecycle operations; they do not provision or disarm.
set -euo pipefail
umask 022

usage() {
  echo "usage: $0 --revision <positive-decimal> --output <empty-artifact-directory> | --check-package-version <Cargo.toml>" >&2
  exit 64
}

die() {
  echo "linux package build: $*" >&2
  exit 1
}

read_package_version() {
  python3 - "$1" <<'PY'
import pathlib
import sys
import tomllib

with pathlib.Path(sys.argv[1]).open("rb") as source:
    document = tomllib.load(source)
package = document.get("package")
version = package.get("version") if isinstance(package, dict) else None
if not isinstance(version, str) or not version:
    raise SystemExit("Cargo [package].version is missing or invalid")
print(version)
PY
}

if [[ "${1:-}" == --check-package-version ]]; then
  [[ $# -eq 2 ]] || usage
  read_package_version "$2"
  exit 0
fi

output_dir=""
revision=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --revision)
      [[ $# -ge 2 ]] || usage
      revision="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || usage
      output_dir="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done
[[ -n "$output_dir" && -n "$revision" ]] || usage
[[ "$revision" =~ ^[1-9][0-9]*$ ]] || die "revision must be a positive decimal without leading zeroes"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
crate_dir="$(cd -- "$script_dir/../.." && pwd -P)"
repo_root="$(cd -- "$crate_dir/.." && pwd -P)"
unit_source="$crate_dir/systemd/sanctuary-castle-wall.service"

for command in cargo dpkg dpkg-deb dpkg-query git ldd python3 readlink rustc sha256sum tar; do
  command -v "$command" >/dev/null 2>&1 || die "required command missing: $command"
done
[[ "$(uname -s)" == "Linux" ]] || die "Ubuntu/Linux build host required"
[[ "$(dpkg --print-architecture)" == "amd64" ]] || die "only Ubuntu amd64 is in scope"
[[ -f "$crate_dir/Cargo.lock" && -f "$crate_dir/Cargo.toml" && -f "$unit_source" ]] || die "required source input missing"
# A package without a single source revision cannot be reviewed or reproduced.
[[ -z "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)" ]] \
  || die "refusing dirty or untracked source inputs"
source_commit="$(git -C "$repo_root" rev-parse HEAD)"
source_version="$(read_package_version "$crate_dir/Cargo.toml")" \
  || die "could not read daemon [package].version from Cargo.toml"
[[ -n "$source_version" ]] || die "could not read daemon version from Cargo.toml"
[[ "$source_version" =~ ^[0-9][0-9A-Za-z.+~-]*$ ]] || die "daemon source version is not safe for Debian package metadata"
package_version="${source_version}-${revision}"
dpkg --validate-version "$package_version" >/dev/null 2>&1 || die "invalid Debian package version"
[[ -d "$output_dir" || ! -e "$output_dir" ]] || die "output path is not a directory"
mkdir -p -- "$output_dir"
[[ -z "$(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] || die "output directory must be empty"

build_root="$(mktemp -d "${TMPDIR:-/tmp}/sanctuary-linux-package.XXXXXX")"
trap 'rm -rf -- "$build_root"' EXIT
target_dir="$build_root/target"
stage_dir="$build_root/stage"

# Deliberately no --features: test-isolation is a test-only seam and must never
# enter this production-default binary.
cargo build --manifest-path "$crate_dir/Cargo.toml" --locked --release \
  --bin castle-wall-daemon --target-dir "$target_dir"
binary="$target_dir/release/castle-wall-daemon"
[[ -x "$binary" ]] || die "locked release build did not produce castle-wall-daemon"

declare -A dependency_set=()
add_debian_owner() {
  local filesystem_path="$1" canonical_path
  local owner_lines owner
  # On usr-merged Ubuntu, ldd can report a /lib alias while dpkg records the
  # owner at /usr/lib. Resolve every real runtime input first; an unresolved
  # path still fails closed rather than being omitted from Depends.
  canonical_path="$(readlink -f -- "$filesystem_path")" \
    || die "could not canonicalize required runtime path: $filesystem_path"
  [[ -e "$canonical_path" ]] || die "required runtime path does not exist: $filesystem_path"
  # Parse every exact-path owner. A diversion notice or any ambiguous output
  # is a refusal; silently taking the first line can understate Depends.
  owner_lines="$(python3 - "$canonical_path" <<'PY'
import re
import subprocess
import sys

path = sys.argv[1]
result = subprocess.run(["dpkg-query", "-S", "--", path],
                        capture_output=True, text=True, check=False, timeout=15,
                        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
if result.returncode or result.stderr or not result.stdout or len(result.stdout) > 1_000_000:
    raise SystemExit("dpkg owner inventory failed")
name = r"[a-z0-9][a-z0-9+.-]*(?::amd64)?"
pattern = re.compile(rf"({name}(?:, {name})*): {re.escape(path)}")
owners = set()
for line in result.stdout.splitlines():
    match = pattern.fullmatch(line)
    if match is None:
        raise SystemExit(f"unrecognized owner/diversion line: {line}")
    owners.update(match.group(1).split(", "))
if not owners:
    raise SystemExit("no exact Debian owners")
print("\n".join(sorted(owners)))
PY
  )" || die "no unambiguous Debian owner for runtime path: $canonical_path (from $filesystem_path)"
  while IFS= read -r owner; do
    [[ -n "$owner" ]] && dependency_set["$owner"]=1
  done <<< "$owner_lines"
}

# Derive libraries from the finished ELF and map each installed path back to the
# Ubuntu package database. Do not substitute the CI's -dev build dependencies.
while IFS= read -r library; do
  [[ -n "$library" ]] && add_debian_owner "$library"
done < <(ldd "$binary" | awk '$1 ~ /^\// { print $1; next } $3 ~ /^\// { print $3 }' | sort -u)

# The guard invokes these before unpack, so map their executable owners and
# move them from ordinary ELF Depends to Pre-Depends.
systemctl_path=/usr/bin/systemctl
[[ -x "$systemctl_path" ]] || die "systemctl was not found on the Ubuntu build host"
add_debian_owner "$systemctl_path"
[[ -n "${dependency_set[systemd]:-}" || -n "${dependency_set[systemd:amd64]:-}" ]] \
  || die "systemctl was not mapped to a Debian systemd package"
found_nft=false
for executable in /usr/sbin/nft /usr/bin/nft; do
  if [[ -x "$executable" ]]; then
    add_debian_owner "$executable"
    found_nft=true
    break
  fi
done
[[ "$found_nft" == true ]] || die "nft executable was not found on the Ubuntu build host"
[[ -n "${dependency_set[nftables]:-}" || -n "${dependency_set[nftables:amd64]:-}" ]] \
  || die "nft was not mapped to the nftables package"
[[ -x /usr/bin/python3 ]] || die "Python 3 probe executable was not found"
dpkg-query -W -f='${Status}' python3 | grep -Fx 'install ok installed' >/dev/null \
  || die "Python 3 package is not installed on build host"
unset 'dependency_set[systemd]' 'dependency_set[systemd:amd64]'
unset 'dependency_set[nftables]' 'dependency_set[nftables:amd64]'
[[ ${#dependency_set[@]} -gt 0 ]] || die "runtime dependency derivation produced no packages"
mapfile -t runtime_dependencies < <(printf '%s\n' "${!dependency_set[@]}" | LC_ALL=C sort)
runtime_depends="$(IFS=', '; echo "${runtime_dependencies[*]}")"
pre_depends="systemd, nftables, python3"

install -d -m 0755 \
  "$stage_dir/DEBIAN" \
  "$stage_dir/usr/local/libexec/sanctuary" \
  "$stage_dir/etc/systemd/system" \
  "$stage_dir/usr/share/doc/sanctuary-castle-wall-internal"
install -m 0755 "$binary" "$stage_dir/usr/local/libexec/sanctuary/castle-wall-daemon"
# The A119-owned unit is an input, never a packaging-maintained copy.
install -m 0644 "$unit_source" "$stage_dir/etc/systemd/system/sanctuary-castle-wall.service"

cat > "$stage_dir/DEBIAN/control" <<EOF
Package: sanctuary-castle-wall-internal
Version: $package_version
Section: admin
Priority: optional
Architecture: amd64
Pre-Depends: $pre_depends
Depends: $runtime_depends
Maintainer: Erik Newton <eriknewton@gmail.com>
Description: INTERNAL structural Castle Wall daemon package artifact
 This internal artifact validates package structure and provenance only.
 It is not install-ready and must not be used to claim Linux enforcement.
EOF

binary_sha256="$(sha256sum "$binary" | awk '{print $1}')"
unit_sha256="$(sha256sum "$unit_source" | awk '{print $1}')"
lock_sha256="$(sha256sum "$crate_dir/Cargo.lock" | awk '{print $1}')"
for role in preinst prerm; do
  script="$stage_dir/DEBIAN/$role"
  {
    printf '%s\n' '#!/usr/bin/python3'
    printf 'ROLE = "%s"\n' "$role"
    printf 'PACKAGE_VERSION = "%s"\n' "$package_version"
    printf 'DAEMON_SHA256 = "%s"\n' "$binary_sha256"
    printf 'UNIT_SHA256 = "%s"\n' "$unit_sha256"
    cat "$script_dir/lifecycle-guard.py"
  } > "$script"
  chmod 0755 "$script"
done
cat > "$stage_dir/usr/share/doc/sanctuary-castle-wall-internal/build-identity" <<EOF
artifact_kind=internal-structural-deb
install_ready=false
package=sanctuary-castle-wall-internal
package_version=$package_version
source_commit=$source_commit
cargo_lock_sha256=$lock_sha256
rustc_version=$(rustc --version)
daemon_sha256=$binary_sha256
unit_source=castle-wall-daemon/systemd/sanctuary-castle-wall.service
unit_sha256=$unit_sha256
runtime_depends=$runtime_depends
pre_depends=$pre_depends
EOF

artifact_base="sanctuary-castle-wall-internal_${package_version}_amd64"
deb_path="$output_dir/$artifact_base.deb"
manifest_path="$output_dir/$artifact_base.manifest.txt"
checksum_path="$output_dir/$artifact_base.deb.sha256"
dpkg-deb --root-owner-group --build "$stage_dir" "$deb_path" >/dev/null
# The checksum travels beside the artifact, so it names only the artifact's
# basename and remains verifiable after the output directory is moved.
(
  cd -- "$output_dir"
  sha256sum "$(basename -- "$deb_path")" > "$(basename -- "$checksum_path")"
  sha256sum -c "$(basename -- "$checksum_path")"
) >/dev/null
{
  echo "artifact_kind=internal-structural-deb"
  echo "install_ready=false"
  echo "artifact_file=$(basename -- "$deb_path")"
  echo "artifact_sha256=$(sha256sum "$deb_path" | awk '{print $1}')"
  echo "source_commit=$source_commit"
  echo "cargo_lock_sha256=$lock_sha256"
  echo "daemon_sha256=$binary_sha256"
  echo "unit_sha256=$unit_sha256"
  echo "runtime_depends=$runtime_depends"
  echo "pre_depends=$pre_depends"
  echo "package_metadata:"
  dpkg-deb -f "$deb_path"
  echo "package_contents:"
  dpkg-deb -c "$deb_path"
} > "$manifest_path"

echo "internal structural artifact: $deb_path"
echo "manifest: $manifest_path"
echo "checksum: $checksum_path"
