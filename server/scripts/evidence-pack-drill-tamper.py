#!/usr/bin/env python3
"""Create plain-file synthetic drill copies and record exact byte changes."""
import argparse
import hashlib
import json
import os
from pathlib import Path

REPORT = "01_evidence_pack.md"
PDF = "evidence-pack.pdf"
MANIFEST = "00_pack_manifest.json"
AUDIT = "audit-chain.jsonl"
REPORT_OFFSET = 2
PDF_OFFSET = 8
PREFIX_ENTRIES = 2


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    source, output = Path(args.source), Path(args.output)
    if source.is_symlink() or not source.is_dir():
        raise ValueError("plain source directory required")
    files = {}
    for path in source.iterdir():
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError("plain files required")
        files[path.name] = path.read_bytes()
    # Exclusive creation preserves earlier observations and never deletes a delivery.
    output.mkdir(mode=0o700)
    records = []
    for label, name in [("byte-edit", REPORT), ("pdf-edit", PDF), ("manifest-whitespace", MANIFEST), ("removed-file", REPORT), ("shortened-file", AUDIT)]:
        target = output / label
        target.mkdir(mode=0o700)
        original = files[name]
        changed = original
        if label in ("byte-edit", "pdf-edit"):
            changed = bytearray(original)
            changed[REPORT_OFFSET if label == "byte-edit" else PDF_OFFSET] ^= 1
            changed = bytes(changed)
        elif label == "manifest-whitespace":
            changed += b"\n"
        elif label == "removed-file":
            changed = None
        else:
            lines = [(line, json.loads(line)) for line in original.splitlines(keepends=True)]
            entries = [row for _, row in lines if row["type"] == "entry"]
            last_sequence = entries[PREFIX_ENTRIES - 1]["seq"]
            # The production export lists entries before checkpoints, so select the genuine prefix checkpoint explicitly.
            kept = [line for line, row in lines if
                    (row["type"] == "entry" and row["seq"] <= last_sequence) or
                    (row["type"] == "checkpoint" and row["checkpoint_sequence"] <= last_sequence)]
            if not any(row["type"] == "checkpoint" and row["checkpoint_sequence"] == last_sequence for _, row in lines):
                raise ValueError("fixture prefix requires its genuine checkpoint")
            changed = b"".join(kept)
            if changed == original:
                raise ValueError("fixture must be advanced before shortening")
        for filename, data in files.items():
            data = changed if filename == name else data
            if data is not None:
                fd = os.open(target / filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
        records.append({"case": label, "file": name, "before_size": len(original), "before_sha256": digest(original), "after_size": None if changed is None else len(changed), "after_sha256": None if changed is None else digest(changed)})
    (output / "mutations.json").write_text(json.dumps(records, indent=2) + "\n")


if __name__ == "__main__":
    main()
