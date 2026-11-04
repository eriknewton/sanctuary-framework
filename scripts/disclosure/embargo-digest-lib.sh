#!/usr/bin/env bash
# Shared parsing and hashing for listed-id membership checks.
# Whole tokens are tested first; prefixed tokens also lose trailing dot suffixes,
# and other dotted tokens contribute each id-shaped segment conservatively.
# Bare short slugs stay outside the grammar: hashing every short word would make
# the work bound the limiting factor on large diffs. Prefixed slugs use the shared regex.
# Every non-decoy generator digest has a tokenizer spelling; random hex decoys do not.
export LC_ALL=C

# The scalar and token-stream callers share the same normalization pipeline.
embargo_normalize_stream() {
  sed -E 's/^[._-]+//; s/[._-]+$//' | tr 'a-z_' 'A-Z-'
}

embargo_normalize_id() {
  printf '%s' "$1" | embargo_normalize_stream
}

embargo_is_id_shaped() {
  local value="$1"
  # Handle lengths 4..64 cover the supported citation vocabulary.
  [[ "$value" =~ ^DEFECT\.[A-Z0-9]+([.-][A-Z0-9]+)*$ ]] ||
    { [[ ${#value} -ge 4 && ${#value} -le 64 && "$value" =~ [A-Z] ]] &&
      [[ "$value" =~ ^[A-Z0-9]+(-[A-Z0-9]+)+$ ]]; }
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

# The caller owns scratch.raw, scratch.normalized and scratch.ready and cleans them.
# This contract must match cleanup in scripts/disclosure/check-embargo.sh.
embargo_tokens() {
  local normalized segment rest scratch=$2
  # Stage every producer before publishing tokens, so partial output is never evidence.
  tr -cs 'A-Za-z0-9._-' '\n' < "$1" > "$scratch.raw" || return 2
  embargo_normalize_stream < "$scratch.raw" > "$scratch.normalized" || return 2
  : > "$scratch.ready" || return 2
  while IFS= read -r normalized || [[ -n "$normalized" ]]; do
    # Strip boundaries per token after the shared bulk normalization.
    while [[ "$normalized" == [._-]* ]]; do normalized=${normalized#?}; done
    while [[ "$normalized" == *[._-] ]]; do normalized=${normalized%?}; done
    if embargo_is_id_shaped "$normalized"; then
      printf '%s\n' "$normalized" >> "$scratch.ready" || return 2
    fi
    if [[ "$normalized" == DEFECT.* ]]; then
      while [[ "${normalized#DEFECT.}" == *.* ]]; do
        normalized=${normalized%.*}
        if embargo_is_id_shaped "$normalized"; then
          printf '%s\n' "$normalized" >> "$scratch.ready" || return 2
        fi
      done
    elif [[ "$normalized" == *.* ]]; then
      rest=$normalized
      while [[ -n "$rest" ]]; do
        segment=${rest%%.*}
        if embargo_is_id_shaped "$segment"; then
          printf '%s\n' "$segment" >> "$scratch.ready" || return 2
        fi
        [[ "$rest" == *.* ]] || break
        rest=${rest#*.}
      done
    fi
  done < "$scratch.normalized"
  cat "$scratch.ready" || return 2
}
