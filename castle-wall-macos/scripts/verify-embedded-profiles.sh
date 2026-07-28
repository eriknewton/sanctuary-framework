#!/usr/bin/env bash
#
# verify-embedded-profiles.sh - fail-closed launchability assertions for a
# signed Sanctuary-CastleWall.app bundle.
#
# Why this exists: the v1.7.0 and v1.7.1 release assets were signed and
# notarized but could not launch on any Mac. The binaries claim restricted
# entitlements (com.apple.developer.system-extension.install and the
# networkextension content-filter provider), and macOS AMFI refuses to spawn
# a restricted-entitlement binary whose bundle carries no
# Contents/embedded.provisionprofile ("Launchd job spawn failed", RBS error 5).
# Signing succeeds, notarization succeeds, spctl accepts - nothing in that
# chain checks for the profile. These assertions do, so this class can never
# ship silently again.
#
# Asserts, in order, each with a message naming exactly what is missing:
#   1. Contents/embedded.provisionprofile exists in the outer app.
#   2. Contents/embedded.provisionprofile exists in the nested
#      .systemextension bundle (the working local build carries both; the
#      broken CI builds carried neither).
#   3. For each (bundle, profile) pair, every restricted entitlement the
#      signed binary claims is covered by the profile's entitlement grant
#      (parsed with `security cms -D` + plistlib; arrays compare as subset).
#   4. codesign --verify --deep --strict passes on the outer app.
#
# Usage: verify-embedded-profiles.sh <path-to-Sanctuary-CastleWall.app>
#
# Exit codes: 0 all assertions hold; 1 an assertion failed (message on stderr).
#
set -euo pipefail

APP="${1:-}"
if [ -z "${APP}" ] || [ ! -d "${APP}" ]; then
    echo "[verify-profiles] ERROR: usage: $(basename "$0") <path-to-.app> (got: '${APP:-<empty>}')" >&2
    exit 1
fi

SYSEXT="${APP}/Contents/Library/SystemExtensions/ai.sanctuaryprotocol.macos.castle-wall.systemextension"
HOST_PROFILE="${APP}/Contents/embedded.provisionprofile"
EXT_PROFILE="${SYSEXT}/Contents/embedded.provisionprofile"

fail() {
    echo "[verify-profiles] ASSERTION FAILED: $*" >&2
    exit 1
}

# --- 1 + 2: profile presence, one message per missing placement. ---
if [ ! -f "${HOST_PROFILE}" ]; then
    fail "outer app is missing Contents/embedded.provisionprofile (${HOST_PROFILE}). AMFI will refuse to spawn the host binary; this is the exact v1.7.0/v1.7.1 defect."
fi
if [ ! -d "${SYSEXT}" ]; then
    fail "nested system extension bundle missing at ${SYSEXT}"
fi
if [ ! -f "${EXT_PROFILE}" ]; then
    fail "nested .systemextension is missing Contents/embedded.provisionprofile (${EXT_PROFILE}). The extension claims the content-filter provider entitlement and needs its own profile (the working local build embeds one)."
fi
echo "[verify-profiles] presence OK: both embedded.provisionprofile placements exist"

# --- 3: entitlement coverage, per (bundle, profile) pair. ---
# Claimed entitlements come from the signed code (codesign -d --entitlements),
# the grant comes from the CMS-wrapped profile plist (security cms -D). A
# claimed key in the restricted com.apple.developer.* namespace that the
# profile does not cover is precisely the AMFI-kill condition. Keys outside
# that namespace (e.g. com.apple.security.*) are not profile-constrained and
# are ignored.
check_coverage() {
    local bundle="$1"
    local profile="$2"
    local label="$3"
    local claimed_plist profile_plist

    claimed_plist="$(mktemp)"
    profile_plist="$(mktemp)"
    trap 'rm -f "${claimed_plist}" "${profile_plist}"' RETURN

    if ! codesign -d --entitlements - --xml "${bundle}" > "${claimed_plist}" 2>/dev/null; then
        fail "${label}: could not read signed entitlements from ${bundle} (is it signed?)"
    fi
    if ! security cms -D -i "${profile}" > "${profile_plist}" 2>/dev/null; then
        fail "${label}: could not decode provisioning profile ${profile} (security cms -D failed; file may be corrupt)"
    fi

    python3 - "${claimed_plist}" "${profile_plist}" "${label}" <<'PYEOF'
import plistlib, sys

claimed_path, profile_path, label = sys.argv[1], sys.argv[2], sys.argv[3]
with open(claimed_path, "rb") as f:
    data = f.read()
if not data.strip():
    # A signed binary with no entitlements claims nothing; nothing to cover.
    print(f"[verify-profiles] {label}: binary claims no entitlements; coverage trivially holds")
    sys.exit(0)
claimed = plistlib.loads(data)
profile = plistlib.loads(open(profile_path, "rb").read())
grant = profile.get("Entitlements")
if not isinstance(grant, dict):
    print(f"[verify-profiles] ASSERTION FAILED: {label}: profile has no Entitlements dict", file=sys.stderr)
    sys.exit(1)

RESTRICTED_PREFIX = "com.apple.developer."
failures = []
for key, want in claimed.items():
    if not key.startswith(RESTRICTED_PREFIX):
        continue  # not profile-constrained
    if key not in grant:
        failures.append(f"claimed restricted entitlement '{key}' is absent from the profile grant")
        continue
    have = grant[key]
    if isinstance(want, list):
        if not isinstance(have, list):
            failures.append(f"'{key}': claimed a list but profile grants {type(have).__name__}")
        else:
            missing = [v for v in want if v not in have]
            if missing:
                failures.append(f"'{key}': profile grant is missing claimed value(s): {missing}")
    elif want != have:
        failures.append(f"'{key}': claimed {want!r} but profile grants {have!r}")

if failures:
    for msg in failures:
        print(f"[verify-profiles] ASSERTION FAILED: {label}: {msg}", file=sys.stderr)
    sys.exit(1)

covered = [k for k in claimed if k.startswith(RESTRICTED_PREFIX)]
print(f"[verify-profiles] {label}: profile covers all {len(covered)} claimed restricted entitlement(s): {covered}")
PYEOF
}

check_coverage "${APP}" "${HOST_PROFILE}" "host app"
check_coverage "${SYSEXT}" "${EXT_PROFILE}" "system extension"

# --- 4: whole-bundle signature integrity (profiles are sealed resources; a
# profile copied in AFTER codesign would fail exactly here). ---
if ! codesign --verify --deep --strict "${APP}"; then
    fail "codesign --verify --deep --strict failed for ${APP}. If the profiles were added after signing, the seal is broken; profiles must be copied in BEFORE codesign runs."
fi
echo "[verify-profiles] codesign --verify --deep --strict OK"

echo "[verify-profiles] ALL ASSERTIONS PASSED for ${APP}"
