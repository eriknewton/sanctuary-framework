#!/usr/bin/env bash
# Generate a padded digest list from an external newline-delimited extract.
# Public salt permits testing guesses; it does not conceal known candidate ids.
set -euo pipefail
export LC_ALL=C
fail() { printf '%s\n' 'ERROR embargo generator cannot run' >&3; exit 2; }
exec 3>&2 2>/dev/null
trap fail ERR
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# Parsing and the hash recipe must match embargo-digest-lib.sh, shared with check-embargo.sh.
source "$script_dir/embargo-digest-lib.sh"
[[ $# -ge 1 ]] || fail
input=$1
shift
salt_file="$script_dir/embargo-salt.txt"
out=''
while [[ $# -gt 0 ]]; do
  [[ $# -ge 2 ]] || fail
  case "$1" in
    --salt) salt_file=$2 ;;
    --out) out=$2 ;;
    *) fail ;;
  esac
  shift 2
done
[[ -f "$input" && ! -L "$input" ]] || fail
input_dir=$(cd -- "$(dirname -- "$input")" && pwd -P)
# A tracked extract belongs outside the public tree, regardless of invocation directory.
if git -C "$input_dir" ls-files --error-unmatch -- "$(basename -- "$input")" >/dev/null 2>&1; then
  fail
fi
repo_top=$(git -C "$script_dir" rev-parse --show-toplevel) || fail
repo_top=$(cd -- "$repo_top" && pwd -P) || fail
input_real="$input_dir/$(basename -- "$input")"
# Physical paths at a component boundary keep even untracked extracts external.
[[ "$input_real" != "$repo_top"/* ]] || fail
salt=$(cat -- "$salt_file") || fail
[[ "$salt" =~ ^[0-9a-f]{64}$ ]] || fail # 32 random bytes encoded as two hex digits each.
tmp=$(mktemp -d "${TMPDIR:-/tmp}/embargo-generate.XXXXXX")
cleanup() {
  local file
  for file in "$tmp/rows" "$tmp/sorted" "$tmp/output"; do
    [[ ! -f "$file" ]] || unlink "$file"
  done
  rmdir -- "$tmp"
}
trap cleanup EXIT
: > "$tmp/rows"
while IFS= read -r entry || [[ -n "$entry" ]]; do
  [[ "$entry" =~ ^[[:space:]]*(#.*)?$ ]] && continue
  normalized=$(embargo_normalize_id "$entry") || fail
  embargo_is_id_shaped "$normalized" || fail
  if [[ "$normalized" == DEFECT.* ]]; then
    bare=${normalized#DEFECT.}
  else
    bare=$normalized
  fi
  # Bare aliases must match the tokenizer grammar in embargo-digest-lib.sh.
  if embargo_is_id_shaped "$bare"; then
    embargo_digest "$salt" "$bare" >> "$tmp/rows" || fail
  fi
  embargo_digest "$salt" "DEFECT.$bare" >> "$tmp/rows" || fail
done < "$input"
sort -u "$tmp/rows" > "$tmp/sorted"
count=$(wc -l < "$tmp/sorted")
# Sixteen rows per bucket conceal the exact count, including an empty extract.
bucket=16
target=$(( ((count + bucket - 1) / bucket) * bucket ))
[[ $target -ge $bucket ]] || target=$bucket
while [[ $count -lt $target ]]; do
  # Random 32-byte preimages make accidental citation matches negligible.
  preimage=$(openssl rand -hex 32) || fail
  [[ "$preimage" =~ ^[0-9a-f]{64}$ ]] || fail # 32 random bytes in hex.
  embargo_digest "$salt" "$preimage" >> "$tmp/sorted" || fail
  sort -u "$tmp/sorted" > "$tmp/rows"
  cp "$tmp/rows" "$tmp/sorted"
  count=$(wc -l < "$tmp/sorted")
done
{
  printf '%s\n' '# Salted digests for listed-id membership checks.'
  printf '# Digest lines: %s\n' "$target"
  cat "$tmp/sorted"
} > "$tmp/output"
if [[ -n "$out" ]]; then
  mv "$tmp/output" "$out" || fail
else
  cat "$tmp/output"
fi
