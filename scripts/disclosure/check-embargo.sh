#!/usr/bin/env bash
# Refuse a range or text body that cites a listed id, without printing citations.
# A required PR check gates merging. A push run is a detector after publication,
# and requires operator review; it cannot refuse a push already accepted.
# Bound: ids spelled with spaces, split across lines, or described in words are
# not recognized. Public salt allows membership testing of guessed ids.
# Exit codes: 0 clean, 1 match, 2 cannot run.
set -euo pipefail
export LC_ALL=C
fail() { printf '%s\n' 'ERROR embargo scanner cannot run' >&3; exit 2; }
exec 3>&2 2>/dev/null
trap fail ERR
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# Parsing and the hash recipe must match embargo-digest-lib.sh, shared with generate-embargo-digests.sh.
source "$script_dir/embargo-digest-lib.sh"
base=''; head=''; repo=.; format=text
text_files=(); text_labels=(); text_count=0
while [[ $# -gt 0 ]]; do
  [[ $# -ge 2 ]] || fail
  case "$1" in
    --base) base=$2 ;;
    --head) head=$2 ;;
    --repo) repo=$2 ;;
    --format) format=$2 ;;
    --text)
      [[ "$2" == *=* ]] || fail
      label=${2%%=*}
      # Only fixed surface names reach logs; arbitrary caller labels remain private.
      case "$label" in pr-body|pr-title) ;; *) label=text ;; esac
      text_labels+=("$label"); text_files+=("${2#*=}"); text_count=$((text_count + 1)) ;;
    *) fail ;;
  esac
  shift 2
done
[[ "$format" == text || "$format" == tsv ]] || fail
[[ "$base" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ && "$head" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || fail
git -C "$repo" cat-file -e "$head^{commit}" || fail
zero=0
if [[ "$base" =~ ^0+$ ]]; then zero=1; else git -C "$repo" cat-file -e "$base^{commit}" || fail; fi
tmp=$(mktemp -d "${TMPDIR:-/tmp}/embargo-scan.XXXXXX")
cleanup() {
  local file
  for file in "$tmp/union" "$tmp/list" "$tmp/raw-diff" "$tmp/added" "$tmp/messages" "$tmp/line" "$tmp/tokens"; do
    [[ ! -f "$file" ]] || unlink "$file"
  done
  rmdir -- "$tmp"
}
trap cleanup EXIT
salt_path=scripts/disclosure/embargo-salt.txt
list_path=scripts/disclosure/embargoed-id-digests.txt
salt=$(git -C "$repo" show "$head:$salt_path" || { [[ $zero -eq 0 ]] && git -C "$repo" show "$base:$salt_path"; }) || fail
[[ "$salt" =~ ^[0-9a-f]{64}$ ]] || fail # 32 bytes in hex.
# Lists from two salts cannot be compared using one recipe; rotation needs regenerated evidence.
if [[ $zero -eq 0 ]] && base_salt=$(git -C "$repo" show "$base:$salt_path"); then
  [[ "$base_salt" == "$salt" ]] || fail
fi
: > "$tmp/union"
found=0
for tree in "$base" "$head"; do
  [[ "$tree" =~ ^0+$ ]] && continue
  if git -C "$repo" cat-file -e "$tree:$list_path"; then
    git -C "$repo" show "$tree:$list_path" > "$tmp/list" || fail
    found=1
    while IFS= read -r row || [[ -n "$row" ]]; do
      [[ "$row" == \#* || -z "$row" ]] && continue
      [[ "$row" =~ ^[0-9a-f]{64}$ ]] || fail # SHA-256 is 32 bytes, two hex digits each.
      printf '%s\n' "$row" >> "$tmp/union"
    done < "$tmp/list"
  fi
done
# Missing both lists provides no membership evidence, so cannot count as clean.
[[ $found -eq 1 ]] || fail
sort -u "$tmp/union" > "$tmp/list"
printf '%s\n' 'INFO required PR check gates merging; push scan is a detector after publication.' >&3
if [[ $zero -eq 1 ]]; then
  printf '%s\n' 'INFO zero base: scanning only the head commit and head tree list.' >&3
  git -C "$repo" log -1 --format=%H%n%B "$head" > "$tmp/messages"
  git -C "$repo" diff-tree --root --no-commit-id --no-ext-diff --no-textconv --unified=0 -r -p "$head" > "$tmp/raw-diff"
else
  git -C "$repo" log --format=%H%n%B "$base..$head" > "$tmp/messages"
  ancestor=$(git -C "$repo" merge-base "$base" "$head") || fail
  git -C "$repo" diff --no-ext-diff --no-textconv --unified=0 "$ancestor" "$head" -- > "$tmp/raw-diff"
fi
# Hunk state distinguishes added content beginning with ++ from +++ path headers.
awk '/^diff --git / { hunk=0 } /^@@ / { hunk=1; next } hunk && /^\+/ { print substr($0,2) }' "$tmp/raw-diff" > "$tmp/added"
result=0
scan() {
  local surface=$1 file=$2 line number=0 token digest
  [[ -f "$file" && -r "$file" ]] || fail
  while IFS= read -r line || [[ -n "$line" ]]; do
    number=$((number + 1))
    printf '%s\n' "$line" > "$tmp/line"
    embargo_tokens "$tmp/line" > "$tmp/tokens"
    while IFS= read -r token; do
      digest=$(embargo_digest "$salt" "$token")
      if grep -Fqx -- "$digest" "$tmp/list"; then
        # Fixed surfaces and a 12-hex digest prefix identify evidence without echoing input.
        if [[ "$format" == tsv ]]; then
          printf 'FAIL\tEMB-01\t%s\tline\t%s\tdigest\t%.12s\n' "$surface" "$number" "$digest"
        else
          printf 'FAIL EMB-01 %s line %s digest %.12s\n' "$surface" "$number" "$digest"
        fi
        result=1
      fi
    done < "$tmp/tokens"
  done < "$file"
}
scan commit-message "$tmp/messages"
i=0
while [[ $i -lt $text_count ]]; do
  scan "${text_labels[$i]}" "${text_files[$i]}"
  i=$((i + 1))
done
scan added-line "$tmp/added"
exit "$result"
