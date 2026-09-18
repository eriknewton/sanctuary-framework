#!/usr/bin/env bash
# Build an INTERNAL structural Debian artifact for the Castle Wall daemon.
#
# This script intentionally has no service lifecycle behavior. The artifact is
# neither install-ready nor evidence that Linux enforcement is proven: its only
# purpose is to make the package layout, binary provenance, and Ubuntu runtime
# dependency derivation reviewable before the A119 disarm/removal contract lands.
set -euo pipefail

usage() {
  echo "usage: $0 --output <empty-artifact-directory>" >&2
  exit 64
}

die() {
  echo "linux package build: $*" >&2
  exit 1
}

output_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      [[ $# -ge 2 ]] || usage
      output_dir="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done
[[ -n "$output_dir" ]] || usage

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
crate_dir="$(cd -- "$script_dir/../.." && pwd -P)"
repo_root="$(cd -- "$crate_dir/.." && pwd -P)"
unit_source="$crate_dir/systemd/sanctuary-castle-wall.service"

for command in cargo dpkg dpkg-deb dpkg-query git ldd rustc sha256sum tar; do
  command -v "$command" >/dev/null 2>&1 || die "required command missing: $command"
done
[[ "$(uname -s)" == "Linux" ]] || die "Ubuntu/Linux build host required"
[[ "$(dpkg --print-architecture)" == "amd64" ]] || die "only Ubuntu amd64 is in scope"
[[ -f "$crate_dir/Cargo.lock" && -f "$crate_dir/Cargo.toml" && -f "$unit_source" ]] || die "required source input missing"
[[ -d "$output_dir" || ! -e "$output_dir" ]] || die "output path is not a directory"
mkdir -p -- "$output_dir"
[[ -z "$(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] || die "output directory must be empty"

# A package without a single source revision cannot be reviewed or reproduced.
git -C "$repo_root" diff --quiet || die "refusing a dirty worktree"
git -C "$repo_root" diff --cached --quiet || die "refusing staged changes"
source_commit="$(git -C "$repo_root" rev-parse HEAD)"
source_short_commit="$(git -C "$repo_root" rev-parse --short=12 HEAD)"
source_version="$(sed -nE 's/^version = "([^"]+)"$/\1/p' "$crate_dir/Cargo.toml" | head -n 1)"
[[ -n "$source_version" ]] || die "could not read daemon version from Cargo.toml"
package_version="${source_version}+git${source_short_commit}"

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
  local filesystem_path="$1"
  local owner_line owner
  owner_line="$(dpkg-query -S -- "$filesystem_path" 2>/dev/null | head -n 1)" \
    || die "no Debian package owns required runtime path: $filesystem_path"
  [[ -n "$owner_line" ]] || die "no Debian package owns required runtime path: $filesystem_path"
  # dpkg-query's separator is ': '; retaining a possible ':amd64' suffix makes
  # the generated dependency unambiguous on the Ubuntu architecture we build.
  owner="${owner_line%%: *}"
  while IFS= read -r owner; do
    owner="${owner#"${owner%%[![:space:]]*}"}"
    owner="${owner%"${owner##*[![:space:]]}"}"
    [[ -n "$owner" ]] && dependency_set["$owner"]=1
  done < <(printf '%s\n' "$owner" | tr ',' '\n')
}

# Derive libraries from the finished ELF and map each installed path back to the
# Ubuntu package database. Do not substitute the CI's -dev build dependencies.
while IFS= read -r library; do
  [[ -n "$library" ]] && add_debian_owner "$library"
done < <(ldd "$binary" | awk '$1 ~ /^\// { print $1; next } $3 ~ /^\// { print $3 }' | sort -u)

# The daemon executes systemd and nftables tooling at runtime. Map their actual
# host paths through dpkg-query too, rather than hard-coding package names.
systemctl_path=/usr/bin/systemctl
[[ -x "$systemctl_path" ]] || die "systemctl was not found on the Ubuntu build host"
add_debian_owner "$(readlink -f -- "$systemctl_path")"
[[ -n "${dependency_set[systemd]:-}" || -n "${dependency_set[systemd:amd64]:-}" ]] \
  || die "systemctl was not mapped to a Debian systemd package"
found_nft=false
for executable in /usr/sbin/nft /usr/bin/nft; do
  if [[ -x "$executable" ]]; then
    add_debian_owner "$(readlink -f -- "$executable")"
    found_nft=true
    break
  fi
done
[[ "$found_nft" == true ]] || die "nft executable was not found on the Ubuntu build host"
[[ ${#dependency_set[@]} -gt 0 ]] || die "runtime dependency derivation produced no packages"
mapfile -t runtime_dependencies < <(printf '%s\n' "${!dependency_set[@]}" | LC_ALL=C sort)
runtime_depends="$(IFS=', '; echo "${runtime_dependencies[*]}")"

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
Depends: $runtime_depends
Maintainer: Erik Newton <eriknewton@gmail.com>
Description: INTERNAL structural Castle Wall daemon package artifact
 This internal artifact validates package structure and provenance only.
 It is not install-ready and must not be used to claim Linux enforcement.
EOF

binary_sha256="$(sha256sum "$binary" | awk '{print $1}')"
unit_sha256="$(sha256sum "$unit_source" | awk '{print $1}')"
lock_sha256="$(sha256sum "$crate_dir/Cargo.lock" | awk '{print $1}')"
cat > "$stage_dir/usr/share/doc/sanctuary-castle-wall-internal/build-identity" <<EOF
artifact_kind=internal-structural-deb
install_ready=false
source_commit=$source_commit
cargo_lock_sha256=$lock_sha256
rustc_version=$(rustc --version)
daemon_sha256=$binary_sha256
unit_source=castle-wall-daemon/systemd/sanctuary-castle-wall.service
unit_sha256=$unit_sha256
runtime_depends=$runtime_depends
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
  echo "package_metadata:"
  dpkg-deb -f "$deb_path"
  echo "package_contents:"
  dpkg-deb -c "$deb_path"
} > "$manifest_path"

echo "internal structural artifact: $deb_path"
echo "manifest: $manifest_path"
echo "checksum: $checksum_path"
