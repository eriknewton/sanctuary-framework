#!/usr/bin/env bash
# Build the sanctuary-jail shim as a STATIC Linux binary for both supported
# guest architectures. This is the delivery vehicle for the B2 static-binary
# jail path: the macOS launcher bind-mounts the aarch64 binary into guest
# images that lack python3 (SanctuaryGuestJail static-binary delivery).
#
# Static linkage is load-bearing: the binary must run on ANY guest image,
# including ones with no libc at all. The script FAILS if either output is
# not statically linked.
#
# Requirements (Linux host / CI runner):
#   rustup targets: x86_64-unknown-linux-musl, aarch64-unknown-linux-musl
#   packages:       musl-tools, gcc-aarch64-linux-gnu, file
# On macOS only `cargo check --target <musl target>` is possible (no musl
# cross-linker); use CI for the real artifacts.
set -euo pipefail

cd "$(dirname "$0")/.."

TARGETS=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)

for target in "${TARGETS[@]}"; do
  echo "==> building sanctuary-jail for ${target}"
  cargo build --locked --release --bin sanctuary-jail --target "${target}"

  bin="target/${target}/release/sanctuary-jail"
  [ -f "${bin}" ] || { echo "FAIL: ${bin} not produced" >&2; exit 1; }

  desc="$(file -b "${bin}")"
  echo "    ${desc}"

  # Fail closed on linkage: a dynamically linked shim would silently fail to
  # exec inside libc-less guests.
  if printf '%s' "${desc}" | grep -q "dynamically linked"; then
    echo "FAIL: ${bin} is dynamically linked; static linkage is required" >&2
    exit 1
  fi
  if ! printf '%s' "${desc}" | grep -Eq "statically linked|static-pie linked"; then
    echo "FAIL: could not confirm static linkage for ${bin}" >&2
    exit 1
  fi
done

echo "OK: static sanctuary-jail built for ${TARGETS[*]}"
