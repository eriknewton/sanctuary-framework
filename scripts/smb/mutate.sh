#!/usr/bin/env bash
# Each plant runs alone in a disposable copy and must fail its exact named witness.
# Failure mode: a compile/collection error is a broken patch, never a killed plant.
set -euo pipefail
slice="${1:?usage: mutate.sh SLICE}"
[[ "$slice" =~ ^[a-z0-9-]+$ ]] || exit 2
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
mutation_scratch="$(mktemp -d "${TMPDIR:-/tmp}/smb-mutation.XXXXXX")"
cleanup() {
  case "$mutation_scratch" in "${TMPDIR:-/tmp}"/smb-mutation.*) find "$mutation_scratch" -delete ;; *) exit 2 ;; esac
}
trap cleanup EXIT
python3 "$repo_root/scripts/smb/mutation_runner.py" "$repo_root" "$mutation_scratch" "$slice"
