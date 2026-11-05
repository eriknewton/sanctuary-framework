#!/usr/bin/env bash
# Generate a padded digest list from an external newline-delimited extract.
# Public salt permits testing guesses; it does not conceal known candidate ids.
set -euo pipefail
export LC_ALL=C
fail() { printf '%s\n' 'ERROR embargo generator cannot run' >&3; exit 2; }
exec 3>&2 2>/dev/null
trap fail ERR
script_dir=$(dirname -- "${BASH_SOURCE[0]}") || fail
script_dir=$(cd -- "$script_dir" && pwd) || fail
# Parsing and the hash recipe must match embargo-digest-lib.sh, shared with check-embargo.sh.
source "$script_dir/embargo-digest-lib.sh" || fail
# Readiness is required even when no token needs hashing.
embargo_hash_ready || fail
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
input_dir=$(dirname -- "$input") || fail
input_dir=$(cd -- "$input_dir" && pwd -P) || fail
input_name=$(basename -- "$input") || fail
# A tracked extract belongs outside the public tree, regardless of invocation directory.
if git -C "$input_dir" ls-files --error-unmatch -- "$input_name" >/dev/null 2>&1; then
  fail
fi
repo_top=$(git -C "$script_dir" rev-parse --show-toplevel) || fail
repo_top=$(cd -- "$repo_top" && pwd -P) || fail
input_real="$input_dir/$input_name"
# Physical paths at a component boundary keep even untracked extracts external.
[[ "$input_real" != "$repo_top"/* ]] || fail
tmp=$(mktemp -d "${TMPDIR:-/tmp}/embargo-generate.XXXXXX") || fail
cleanup() {
  local pending=$? file cleanup_failed=0
  # Must match scratch ownership in check-embargo.sh and embargo-digest-lib.sh.
  for file in "$tmp"/*; do
    [[ ! -f "$file" ]] || unlink "$file" || cleanup_failed=1
  done
  rmdir -- "$tmp" || cleanup_failed=1
  # Successful cleanup preserves generation status; incomplete cleanup cannot report success.
  [[ $cleanup_failed -eq 0 ]] || fail
  exit "$pending"
}
trap cleanup EXIT
# The checked copy establishes complete acquisition before parsing begins.
src=$input; dst="$tmp/extract"
cat -- "$src" > "$dst" || fail
src=$salt_file; dst="$tmp/salt"
cat -- "$src" > "$dst" || fail
# Shell strings cannot carry NUL; the bytes are checked before the string exists.
LC_ALL=C tr -d '\000' < "$tmp/salt" | cmp -s - "$tmp/salt" || fail
salt_bytes=$(wc -c < "$tmp/salt") || fail
[[ $salt_bytes -eq 65 ]] || fail # 64 lowercase hex bytes plus exactly one LF.
salt=$(cat -- "$tmp/salt") || fail
[[ "$salt" =~ ^[0-9a-f]{64}$ ]] || fail # 32 random bytes encoded as two hex digits each.
# Newline-delimited extracts reject NUL rather than changing entry boundaries.
LC_ALL=C tr -d '\000' < "$tmp/extract" | cmp -s - "$tmp/extract" || fail
embargo_normalize_stream < "$tmp/extract" > "$tmp/normalized" || fail
: > "$tmp/rows"
while IFS= read -r entry || [[ -n "$entry" ]]; do
  [[ "$entry" =~ ^[[:space:]]*(#.*)?$ ]] && continue
  normalized=$entry
  embargo_trim_id || fail
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
done < "$tmp/normalized"
sort -u "$tmp/rows" > "$tmp/sorted" || fail
count=$(wc -l < "$tmp/sorted") || fail
# Sixteen rows per bucket conceal the exact count, including an empty extract.
bucket=16
target=$(( ((count + bucket - 1) / bucket) * bucket ))
[[ $target -ge $bucket ]] || target=$bucket
while [[ $count -lt $target ]]; do
  # Random 32-byte preimages make accidental citation matches negligible.
  preimage=$(openssl rand -hex 32) || fail
  [[ "$preimage" =~ ^[0-9a-f]{64}$ ]] || fail # 32 random bytes in hex.
  embargo_digest "$salt" "$preimage" >> "$tmp/sorted" || fail
  sort -u "$tmp/sorted" > "$tmp/rows" || fail
  cp "$tmp/rows" "$tmp/sorted" || fail
  count=$(wc -l < "$tmp/sorted") || fail
done
{
  printf '%s\n' '# Salted digests for listed-id membership checks.'
  printf '# Digest lines: %s\n' "$target"
  cat "$tmp/sorted" || fail
} > "$tmp/output"
if [[ -n "$out" ]]; then
  mv "$tmp/output" "$out" || fail
else
  cat "$tmp/output" || fail
fi
