#!/usr/bin/env bash
#
# stage-cli-runtime.sh - assemble the sealed Sanctuary CLI runtime that the
# signed Castle Wall app carries at Contents/Resources/cli-runtime.
#
# This is the ONE copy step for the sealed runtime. build-wrapped.sh calls it
# for the real app bundle; the structure and smoke tests under
# server/test/structure/ call it into a temp directory. Both paths therefore
# ship (and test) byte-identical layouts.
#
# Layout produced under <dest>:
#   dist/             the complete built server/dist tree minus build-only
#                     artifacts (see EXCLUDES below)
#   package.json      the server package manifest (module resolution root)
#   node_modules/     the production dependency closure (unless --dist-only)
#
# Usage:
#   stage-cli-runtime.sh <dest cli-runtime dir> [--dist-only]
#
# Environment (same names build-wrapped.sh honors):
#   SANCTUARY_CLI_RUNTIME_DIR     built dist tree   (default: <repo>/server/dist)
#   SANCTUARY_CLI_NODE_MODULES    dependency closure (default: <repo>/server/node_modules)
#   SANCTUARY_CLI_PACKAGE_JSON    package manifest  (default: <repo>/server/package.json)
#
# --dist-only is a TEST-HARNESS mode: it skips node_modules so a test can stage
# the dist tree quickly and supply dependencies its own way. build-wrapped.sh
# never passes it; a release runtime without node_modules cannot start.
#
# Failure mode to recognize from the outside: a runtime that is missing a dist
# sibling still boots an EXISTING fortress cleanly and fails only on the first
# fortress creation (`sanctuary protect` / `sanctuary init`), because that is
# the path that forks dist/directory-capability-worker.js. The presence gate at
# the end of this script exists so that failure happens at build time instead.

set -euo pipefail

PKG_DIR="$(cd "$(dirname "$0")"/.. && pwd)"
REPO_DIR="$(cd "${PKG_DIR}/.." && pwd)"

CLI_RUNTIME_SRC="${SANCTUARY_CLI_RUNTIME_DIR:-${REPO_DIR}/server/dist}"
CLI_RUNTIME_NODE_MODULES="${SANCTUARY_CLI_NODE_MODULES:-${REPO_DIR}/server/node_modules}"
CLI_RUNTIME_PACKAGE_JSON="${SANCTUARY_CLI_PACKAGE_JSON:-${REPO_DIR}/server/package.json}"
# Must match the list in server/scripts/sealed-cli-runtime-entries.mjs; that
# file is the presence gate this script runs after copying.
CLI_RUNTIME_ENTRIES="${REPO_DIR}/server/scripts/sealed-cli-runtime-entries.mjs"

log() {
    echo "[stage-cli-runtime] $*"
}

fail() {
    echo "[stage-cli-runtime] ERROR: $*" >&2
    exit 1
}

CLI_RUNTIME_DEST=""
DIST_ONLY=0
for arg in "$@"; do
    case "${arg}" in
        --dist-only) DIST_ONLY=1 ;;
        --*) fail "unknown option: ${arg}" ;;
        *)
            [ -z "${CLI_RUNTIME_DEST}" ] || fail "exactly one destination directory is expected"
            CLI_RUNTIME_DEST="${arg}"
            ;;
    esac
done
[ -n "${CLI_RUNTIME_DEST}" ] || fail "usage: stage-cli-runtime.sh <dest cli-runtime dir> [--dist-only]"

command -v rsync >/dev/null 2>&1 || fail "required command not found on PATH: rsync"
command -v node >/dev/null 2>&1 || fail "required command not found on PATH: node"

# The sealed CLI is `dist/cli.js`; the checks below name the inputs a build must
# have produced before the runtime can be staged at all.
[ -f "${CLI_RUNTIME_SRC}/cli.js" ] || fail "built CLI runtime not found at ${CLI_RUNTIME_SRC}/cli.js (run npm run build in server/)"
[ -f "${CLI_RUNTIME_PACKAGE_JSON}" ] || fail "package manifest not found at ${CLI_RUNTIME_PACKAGE_JSON}"
[ -f "${CLI_RUNTIME_ENTRIES}" ] || fail "sealed-runtime entry list not found at ${CLI_RUNTIME_ENTRIES}"
if [ "${DIST_ONLY}" = "0" ]; then
    [ -d "${CLI_RUNTIME_NODE_MODULES}" ] || fail "dependency closure not found at ${CLI_RUNTIME_NODE_MODULES}"
fi

# INVARIANT: the sealed runtime ships the WHOLE built dist tree, never a
# hand-typed file list. dist/cli.js reaches its siblings by path at run time
# (fork of dist/directory-capability-worker.js on fortress creation,
# dist/templates, dist/reference-plugin, dist/intelligence/catalog-v3, and any
# asset a future build step adds), so a list here would drift the first time an
# entry is added to server/tsup.config.ts or a copy-*.mjs script. Copying the
# tree makes completeness a property of the build, and the gate below makes an
# incomplete tree a build failure.
#
# EXCLUDES are build-only artifacts that no code path loads from the sealed
# runtime, kept out for size (they roughly quintuple the dist payload):
#   *.map           source maps (debug only)
#   *.d.ts, *.d.cts, *.d.mts   type declarations (compile-time only)
#   *.cjs           the CommonJS dual of each entry; the launcher runs the ESM
#                   `cli.js`, which never requires a `.cjs` sibling
#   /boot-runtime/  the Castle Wall boot daemon, sealed separately by
#                   build-wrapped.sh at Contents/Resources/boot-runtime
# server/test/structure/sealed-cli-runtime-contents.test.ts parses this exact
# exclude list and fails if any pattern would drop a required entry.
mkdir -p "${CLI_RUNTIME_DEST}/dist"
rsync -a \
    --exclude='*.map' \
    --exclude='*.d.ts' \
    --exclude='*.d.cts' \
    --exclude='*.d.mts' \
    --exclude='*.cjs' \
    --exclude='/boot-runtime/' \
    "${CLI_RUNTIME_SRC}/" "${CLI_RUNTIME_DEST}/dist/"
cp "${CLI_RUNTIME_PACKAGE_JSON}" "${CLI_RUNTIME_DEST}/package.json"

if [ "${DIST_ONLY}" = "0" ]; then
    # `.bin` holds symlinks into packages; the sealed runtime is exec'd by
    # absolute path and must not contain symbolic links (checked below).
    mkdir -p "${CLI_RUNTIME_DEST}/node_modules"
    rsync -a --exclude='.bin' "${CLI_RUNTIME_NODE_MODULES}/" "${CLI_RUNTIME_DEST}/node_modules/"
else
    log "--dist-only: node_modules not staged (test-harness mode)"
fi

if find "${CLI_RUNTIME_DEST}" -type l -print -quit | grep -q .; then
    fail "CLI runtime must not contain symbolic links"
fi

# Presence gate: every entry the CLI reaches at run time must be in the staged
# tree. This turns "cli.js alone" into a build failure rather than a first-run
# failure on an installed Mac.
node "${CLI_RUNTIME_ENTRIES}" --assert "${CLI_RUNTIME_DEST}/dist" \
    || fail "staged CLI runtime is incomplete under ${CLI_RUNTIME_DEST}/dist"

log "staged sealed CLI runtime at ${CLI_RUNTIME_DEST} ($(find "${CLI_RUNTIME_DEST}/dist" -type f | wc -l | tr -d ' ') dist files)"
