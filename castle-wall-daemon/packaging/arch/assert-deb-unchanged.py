#!/usr/bin/env python3
"""Compare base/head install .debs while allowing source_commit-derived fields."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path


def extract(deb: Path, out: Path) -> None:
    subprocess.run(["dpkg-deb", "-x", str(deb), str(out / "fs")], check=True)
    subprocess.run(["dpkg-deb", "-e", str(deb), str(out / "control")], check=True)


def load_identity(root: Path) -> dict:
    return json.loads((root / "fs/usr/share/doc/sanctuary-castle-wall/build-identity").read_text())


def relevant_identity(identity: dict) -> dict:
    trimmed = dict(identity)
    trimmed.pop("source_commit", None)
    return trimmed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("base_deb", type=Path)
    parser.add_argument("head_deb", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        base, head = root / "base", root / "head"
        extract(args.base_deb, base)
        extract(args.head_deb, head)
        base_identity, head_identity = load_identity(base), load_identity(head)
        for field in ("payload_sha256", "guard_sha256"):
            if base_identity.get(field) != head_identity.get(field):
                raise SystemExit(f"{field} changed")
        if (base / "control/control").read_bytes() != (head / "control/control").read_bytes():
            raise SystemExit("control file changed")
        if relevant_identity(base_identity) != relevant_identity(head_identity):
            raise SystemExit("unexpected build identity field changed")


if __name__ == "__main__":
    main()
