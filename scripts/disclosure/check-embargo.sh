#!/usr/bin/env bash
# Refuse a range or text body that cites a listed id, without printing citations.
# A required PR check gates merging. A push run is a detector after publication,
# and requires operator review; it cannot refuse a push already accepted.
# Unscanned: branch names, tags and tag messages, release notes and GitHub release
# bodies, binary text git cannot split into lines even with --text, ids spelled
# with spaces, split across lines or described in words, and bare short slugs
# without their defect. prefix. Public salt allows membership testing of guesses.
# Content absent from the net added lines, including text added and then removed
# within the range or removed and restored unchanged, is outside the added-line
# surface; commit messages are still scanned.
# Added (A) and renamed (R) destination paths are scanned; copies appear as A
# without copy detection. Type changes (T) introduce no new name and are not
# scanned; a rewrite too large to be a rename appears as A and is scanned.
# A PR editing scripts/disclosure/ or .github/workflows/embargo-guard.yml runs its
# own copy of the guard. Such a PR merges only after the coordinator's two-family review.
# CLI zero-base mode scans only the head commit; merge-head diffs may be empty.
# Exit codes: 0 clean, 1 match, 2 cannot run.
set -euo pipefail
# Token splitting must never expand input as filesystem patterns.
set -f
export LC_ALL=C
fail() { printf '%s\n' 'ERROR embargo scanner cannot run' >&3; exit 2; }
exec 3>&2 2>/dev/null
trap fail ERR
script_dir=$(dirname -- "${BASH_SOURCE[0]}") || fail
script_dir=$(cd -- "$script_dir" && pwd) || fail
# Parsing and the hash recipe must match embargo-digest-lib.sh, shared with generate-embargo-digests.sh.
source "$script_dir/embargo-digest-lib.sh" || fail
# Readiness is required even when no token needs hashing.
embargo_hash_ready || fail
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
tmp=$(mktemp -d "${TMPDIR:-/tmp}/embargo-scan.XXXXXX") || fail
cleanup() {
  local pending=$? file cleanup_failed=0
  # Must match scratch ownership in embargo-digest-lib.sh and generate-embargo-digests.sh.
  # Globbing is enabled only for owned scratch, never for input token splitting.
  set +f
  for file in "$tmp"/*; do
    [[ ! -f "$file" ]] || unlink "$file" || cleanup_failed=1
  done
  rmdir -- "$tmp" || cleanup_failed=1
  # Successful cleanup preserves the scan result; incomplete cleanup cannot report readiness.
  [[ $cleanup_failed -eq 0 ]] || fail
  exit "$pending"
}
trap cleanup EXIT
salt_path=scripts/disclosure/embargo-salt.txt
list_path=scripts/disclosure/embargoed-id-digests.txt
base_salt=''; head_salt=''; base_present=0
: > "$tmp/pairs"
# Both endpoint pairs participate, so removing a head digest cannot suppress a
# recognized same-range citation protected by the base pair; a lift that cites
# nothing is allowed by design. Digests across different salts are incomparable.
for side in base head; do
  tree=$base
  [[ "$side" != head ]] || tree=$head
  [[ ! "$tree" =~ ^0+$ ]] || continue
  # Only absence from a successfully read inventory permits the pre-guard shape.
  git -C "$repo" ls-tree -r -z "$tree" -- "$salt_path" "$list_path" > "$tmp/inventory" || fail
  has_salt=0; has_list=0
  while IFS= read -r -d '' entry; do
    metadata=${entry%%$'\t'*}; path=${entry#*$'\t'}
    [[ "$metadata" == *' blob '* ]] || fail
    case "$path" in
      "$salt_path") has_salt=1 ;;
      "$list_path") has_list=1 ;;
      *) fail ;;
    esac
  done < "$tmp/inventory"
  if [[ "$side" == base && $has_salt -eq 0 && $has_list -eq 0 ]]; then
    printf '%s\n' 'INFO base tree carries no list; head list only.' >&3
    continue
  fi
  [[ $has_list -eq 1 ]] || fail
  if [[ $has_salt -eq 1 ]]; then
    git -C "$repo" show "$tree:$salt_path" > "$tmp/salt" || fail
    # Shell strings cannot carry NUL; the bytes are checked before the string exists.
    LC_ALL=C tr -d '\000' < "$tmp/salt" | cmp -s - "$tmp/salt" || fail
    salt_bytes=$(wc -c < "$tmp/salt") || fail
    [[ $salt_bytes -eq 65 ]] || fail # 64 lowercase hex bytes plus exactly one LF.
    salt=$(cat -- "$tmp/salt") || fail
    [[ "$salt" =~ ^[0-9a-f]{64}$ ]] || fail # 32 bytes in hex.
  else
    [[ "$side" == head && -n "$base_salt" ]] || fail
    salt=$base_salt
  fi
  if [[ "$side" == base ]]; then base_salt=$salt; base_present=1; else head_salt=$salt; fi
  git -C "$repo" show "$tree:$list_path" > "$tmp/list" || fail
  # Evidence bytes are validated without content normalization before row parsing.
  LC_ALL=C tr -d '\000' < "$tmp/list" | cmp -s - "$tmp/list" || fail
  while IFS= read -r row || [[ -n "$row" ]]; do
    [[ "$row" == \#* || -z "$row" ]] && continue
    [[ "$row" =~ ^[0-9a-f]{64}$ ]] || fail # SHA-256 is 32 bytes in hex.
    printf '%s\t%s\n' "$salt" "$row" >> "$tmp/pairs"
  done < "$tmp/list"
done
[[ -n "$head_salt" ]] || fail
printf '%s\n' "$head_salt" > "$tmp/salts.raw"
[[ $base_present -eq 0 ]] || printf '%s\n' "$base_salt" >> "$tmp/salts.raw"
sort -u "$tmp/salts.raw" > "$tmp/salts" || fail
printf '%s\n' 'INFO required PR check gates merging; push scan is a detector after publication.' >&3
if [[ $zero -eq 1 ]]; then
  printf '%s\n' 'INFO zero base: scanning only the head commit and head tree list.' >&3
  git -C "$repo" log -1 --format=%H%n%B "$head" > "$tmp/messages" || fail
  git -C "$repo" diff-tree --root --no-commit-id --no-ext-diff --no-textconv --text --unified=0 -r -p "$head" > "$tmp/raw-diff" || fail
  git -C "$repo" diff-tree --root --no-commit-id -r -M --name-only --diff-filter=AR -z "$head" -- > "$tmp/paths" || fail
else
  git -C "$repo" log --format=%H%n%B "$base..$head" > "$tmp/messages" || fail
  ancestor=$(git -C "$repo" merge-base "$base" "$head") || fail
  git -C "$repo" diff --no-ext-diff --no-textconv --text --unified=0 "$ancestor" "$head" -- > "$tmp/raw-diff" || fail
  git -C "$repo" diff -M --name-only --diff-filter=AR -z "$ancestor" "$head" -- > "$tmp/paths" || fail
fi
# NUL is outside the identifier alphabet; mapping it to a space preserves token
# boundaries and original line records on both userlands. Path delimiters stay NUL.
content_bytes() {
  LC_ALL=C tr '\000' ' ' < "$1" > "$2" || return 2
}
content_bytes "$tmp/raw-diff" "$tmp/diff-content" || fail
# Hunk state distinguishes added content beginning with ++ from +++ path headers.
awk '/^diff --git / { hunk=0 } /^@@ / { hunk=1; next } hunk && /^\+/ { print substr($0,2) }' "$tmp/diff-content" > "$tmp/added" || fail
# Occurrences retain surface order, while the global set bounds work before hashing.
: > "$tmp/occurrences"
scan() {
  local surface=$1 file=$2 line number
  content_bytes "$file" "$tmp/content" || fail
  embargo_normalize_stream < "$tmp/content" > "$tmp/normalized" || fail
  # Number original records once; normalization preserves LF and embedded token boundaries.
  awk '{ print NR "\t" $0 }' "$tmp/normalized" > "$tmp/numbered" || fail
  while IFS= read -r line || [[ -n "$line" ]]; do
    number=${line%%$'\t'*}; line=${line#*$'\t'}
    embargo_tokens "$line" "$surface" "$number" >> "$tmp/occurrences" || fail
  done < "$tmp/numbered"
}
scan commit-message "$tmp/messages"
i=0
while [[ $i -lt $text_count ]]; do
  src=${text_files[$i]}; dst="$tmp/text"
  # The checked copy establishes complete acquisition before parsing begins.
  cat -- "$src" > "$dst" || fail
  scan "${text_labels[$i]}" "$dst"
  i=$((i + 1))
done
scan added-line "$tmp/added"
embargo_normalize_stream < "$tmp/paths" > "$tmp/normalized-paths" || fail
number=0
# NUL records preserve one index per path, including names containing newlines.
while IFS= read -r -d '' path; do
  number=$((number + 1))
  embargo_tokens "$path" added-path "$number" >> "$tmp/occurrences" || fail
done < "$tmp/normalized-paths"
cut -f1 "$tmp/occurrences" > "$tmp/token-column" || fail
sort -u "$tmp/token-column" > "$tmp/unique" || fail
count=$(wc -l < "$tmp/unique") || fail
# 50000 tokens times at most two salts is 100000 hash processes, about 300 s at
# 3 ms each, plus hash output processing and bulk tokenizer/sort/join stages.
# Each surface uses a fixed number of bulk stages; record parsing uses builtins.
# The combined budget remains inside the 30 minute job bound.
# This work bound must match timeout-minutes in .github/workflows/embargo-guard.yml.
EMBARGO_MAX_UNIQUE_TOKENS=50000
if [[ $count -gt $EMBARGO_MAX_UNIQUE_TOKENS ]]; then
  printf '%s\n' 'ERROR embargo scanner cannot run: token bound exceeded' >&3
  exit 2
fi
: > "$tmp/matches"
while IFS= read -r salt; do
  awk -F '\t' -v salt="$salt" '$1 == salt {print $2}' "$tmp/pairs" > "$tmp/members" || fail
  while IFS= read -r token; do
    digest=$(embargo_digest "$salt" "$token") || fail
    if grep -Fqx -- "$digest" "$tmp/members"; then
      printf '%s\t%s\n' "$token" "$digest" >> "$tmp/matches"
    else
      status=$?
      [[ $status -eq 1 ]] || fail # grep 1 means no member; other failures provide no evidence.
    fi
  done < "$tmp/unique"
done < "$tmp/salts"
# Portable awk joins membership to original occurrence order without printing input.
# A 12-hex prefix identifies evidence while keeping reports compact.
awk -F '\t' -v format="$format" '
  FILENAME == ARGV[1] {if (!($1 in hit)) hit[$1]=$2; next}
  $1 in hit {
    key=$1 FS $2 FS $3
    if (seen[key]++) next
    sep=(format == "tsv" ? "\t" : " ")
    printf "FAIL%sEMB-01%s%s%sline%s%s%sdigest%s%.12s\n", sep,sep,$2,sep,sep,$3,sep,sep,hit[$1]
  }
' "$tmp/matches" "$tmp/occurrences" > "$tmp/report" || fail
cat "$tmp/report" || fail
[[ ! -s "$tmp/report" ]] || exit 1
exit 0
