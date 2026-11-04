#!/usr/bin/env bash
# Shared parsing and hashing for listed-id membership checks.
export LC_ALL=C

embargo_normalize_id() {
  printf '%s' "$1" | sed -E 's/^[._-]+//; s/[._-]+$//' | tr 'a-z_' 'A-Z-'
}

embargo_is_id_shaped() {
  local value="$1"
  # Handle lengths 4..64 cover the supported citation vocabulary.
  [[ "$value" =~ ^DEFECT\.[A-Z0-9]+([.-][A-Z0-9]+)*$ ]] ||
    { [[ ${#value} -ge 4 && ${#value} -le 64 && "$value" =~ [A-Z] ]] &&
      [[ "$value" =~ ^[A-Z0-9]+(-[A-Z0-9]+)+$ ]]; }
}

embargo_digest() {
  # Public salt separates repositories; normalization must precede hashing so spellings agree.
  # This must match the recipe asserted in server/test/structure/embargo-guard.test.ts.
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s\n%s' "$1" "$2" | sha256sum | awk '{print $1}'
  else
    printf '%s\n%s' "$1" "$2" | shasum -a 256 | awk '{print $1}'
  fi
}

embargo_tokens() {
  local token normalized
  # Maximal ASCII runs keep punctuation boundaries independent of host locale.
  while IFS= read -r token || [[ -n "$token" ]]; do
    normalized=$(embargo_normalize_id "$token") || return 2
    if embargo_is_id_shaped "$normalized"; then
      printf '%s\n' "$normalized"
    fi
  done < <(tr -cs 'A-Za-z0-9._-' '\n' < "$1")
}
