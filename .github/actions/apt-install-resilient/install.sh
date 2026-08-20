#!/usr/bin/env bash
# apt-get update + install for the packages given as arguments, bounded and
# retried via scripts/ci/retry-with-timeout.sh, with apt's own
# non-interactive and network-timeout options set so a dead mirror errors
# out instead of blocking.
#
# Usage: install.sh <package> [<package> ...]
#
# Failure mode: see scripts/ci/retry-with-timeout.sh's header. In short, a
# fast red with exit 124 means every attempt timed out (stalled mirror);
# a fast red with the same non-124 code on every attempt means apt itself
# is refusing (bad package name, unsatisfiable dependency) and rerunning
# will not help.
set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
RETRY="$REPO_ROOT/scripts/ci/retry-with-timeout.sh"

if [ "$#" -eq 0 ]; then
  echo "apt-install-resilient: no packages given" >&2
  exit 64
fi

# DEBIAN_FRONTEND=noninteractive: refuses any interactive debconf prompt
# instead of blocking on stdin forever -- a config-file prompt from a
# package with maintainer scripts would otherwise hang indefinitely with
# no timeout to catch it, since it isn't a network stall the retry
# wrapper's `timeout` would even attribute correctly.
export DEBIAN_FRONTEND=noninteractive

# Acquire::Retries=3: apt's own low-level retry for a single dropped
# connection *within* one attempt (complements, not replaces, the
# attempt-level retry below). Acquire::http(s)::Timeout=15: apt gives up
# on a stalled TCP connect/read after 15s instead of the OS default
# (which can run to minutes), so a half-open connection to a dead mirror
# surfaces as an apt error quickly rather than hanging until our outer
# 180s attempt timeout has to catch it the hard way.
APT_OPTS=(
  -o Acquire::Retries=3
  -o Acquire::http::Timeout=15
  -o Acquire::https::Timeout=15
)

# update and install are retried as two separate calls (not chained with
# `&&` inside one retried block) so a failure names which phase failed --
# required by the "must be visible in the log" contract. Worst-case total
# for this script is therefore roughly double one retry-with-timeout.sh
# call: ~2 * 9.3min =~ 18.6 minutes if BOTH phases exhaust every retry,
# still a small fixed ceiling next to the hours-long hangs this replaces.
# See .github/actions/apt-install-resilient/action.yml for the
# step-level timeout-minutes backstop sized against this.
"$RETRY" "apt-get update" -- \
  sudo -E apt-get "${APT_OPTS[@]}" update -qq

"$RETRY" "apt-get install" -- \
  sudo -E apt-get "${APT_OPTS[@]}" install -y -qq "$@"
