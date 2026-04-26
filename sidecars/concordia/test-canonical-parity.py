#!/usr/bin/env python3
"""Helper for cross-language canonical-JSON parity test.

Reads a JSON-encoded array of fixtures from stdin. For each fixture,
runs Concordia's canonical_json (the same function used to produce
signing input bytes for every Concordia message) and writes a JSON
array of hex-encoded byte strings to stdout.

The TypeScript test owns the fixture set and the assertions; this
script is the Python half of the parity check.
"""

import json
import sys
from concordia.signing import canonical_json


def main() -> None:
    raw = sys.stdin.read()
    fixtures = json.loads(raw)
    if not isinstance(fixtures, list):
        sys.stderr.write("expected JSON array of fixtures on stdin\n")
        sys.exit(2)

    results = []
    for f in fixtures:
        try:
            out_bytes = canonical_json(f)
            results.append({"hex": out_bytes.hex(), "error": None})
        except Exception as e:
            results.append({"hex": None, "error": f"{type(e).__name__}: {e}"})

    sys.stdout.write(json.dumps(results))


if __name__ == "__main__":
    main()
