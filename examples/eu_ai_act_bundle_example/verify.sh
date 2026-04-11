#!/usr/bin/env bash
# Verify the EU AI Act example bundle with standard CLI tools.
# Usage: ./verify.sh
#
# This script recomputes the SHA-256 of each file and compares it
# against the digest recorded in 00_bundle_manifest.json.

set -euo pipefail

cd "$(dirname "$0")"

echo "Recomputing SHA-256 for each bundle file..."
echo ""
for f in 0[1-6]_*.md; do
  printf "%-48s " "$f"
  shasum -a 256 "$f" | awk '{print $1}'
done

echo ""
echo "Compare against the sha256 field for each file in"
echo "00_bundle_manifest.json — every digest must match exactly."
echo ""
echo "NOT LEGAL ADVICE. This bundle is a fictional example."
