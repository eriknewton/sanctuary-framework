#!/usr/bin/env bash
# Shared parsing and hashing for listed-id membership checks.
# Whole tokens are tested first; prefixed tokens also lose trailing dot suffixes,
# and other dotted tokens contribute each id-shaped segment conservatively.
# Bare short slugs stay outside the grammar: hashing every short word would make
# the work bound the limiting factor on large diffs. Prefixed slugs use the shared regex.
# Every non-decoy generator digest has a tokenizer spelling; random hex decoys do not.
export LC_ALL=C

# Must match the bulk stage in check-embargo.sh and generate-embargo-digests.sh.
embargo_normalize_stream() {
  tr 'a-z_' 'A-Z-' || return 2
}

# The caller supplies normalized in its local scope; no subprocess runs per record.
embargo_trim_id() {
  while [[ "$normalized" == [._-]* ]]; do normalized=${normalized#?}; done
  while [[ "$normalized" == *[._-] ]]; do normalized=${normalized%?}; done
  return 0
}

embargo_is_id_shaped() {
  local value="$1"
  # Handle lengths 4..64 cover the supported citation vocabulary.
  [[ "$value" =~ ^DEFECT\.[A-Z0-9]+([.-][A-Z0-9]+)*$ ]] ||
    { [[ ${#value} -ge 4 && ${#value} -le 64 && "$value" =~ [A-Z] ]] &&
      [[ "$value" =~ ^[A-Z0-9]+(-[A-Z0-9]+)+$ ]]; }
}

# Readiness must match the unconditional calls in check-embargo.sh and generate-embargo-digests.sh.
embargo_hash_ready() {
  command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1
}

embargo_digest() (
  set -o pipefail
  local digest
  # Public salt separates repositories; normalization must precede hashing so spellings agree.
  # This must match the recipe asserted in server/test/structure/embargo-guard.test.ts.
  if command -v sha256sum >/dev/null 2>&1; then
    digest=$(printf '%s\n%s' "$1" "$2" | sha256sum | awk '{print $1}') || return 2
  else
    digest=$(printf '%s\n%s' "$1" "$2" | shasum -a 256 | awk '{print $1}') || return 2
  fi
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 2 # SHA-256 has 32 bytes in hex.
  printf '%s\n' "$digest"
)

# The scanner owns all staged files and cleanup; this helper uses only builtins.
# Must match check-embargo.sh: normalized records, globbing disabled, fixed surface and index.
embargo_tokens() {
  local line=$1 surface=$2 number=$3 normalized segment rest
  local IFS=$' \t\n'
  # Default-IFS splitting follows bulk normalization, preserving the shared alias grammar.
  for normalized in ${line//[^A-Za-z0-9._-]/ }; do
    embargo_trim_id || return 2
    if embargo_is_id_shaped "$normalized"; then
      printf '%s\t%s\t%s\n' "$normalized" "$surface" "$number" || return 2
    fi
    if [[ "$normalized" == DEFECT.* ]]; then
      while [[ "${normalized#DEFECT.}" == *.* ]]; do
        normalized=${normalized%.*}
        if embargo_is_id_shaped "$normalized"; then
          printf '%s\t%s\t%s\n' "$normalized" "$surface" "$number" || return 2
        fi
      done
    elif [[ "$normalized" == *.* ]]; then
      rest=$normalized
      while [[ -n "$rest" ]]; do
        segment=${rest%%.*}
        if embargo_is_id_shaped "$segment"; then
          printf '%s\t%s\t%s\n' "$segment" "$surface" "$number" || return 2
        fi
        [[ "$rest" == *.* ]] || break
        rest=${rest#*.}
      done
    fi
  done
  return 0
}
