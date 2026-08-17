/**
 * SCAN-NUL-01 — every TypeScript source file under `server/src` must be TEXT to
 * line-based tooling.
 *
 * Capability pinned: `grep`, `awk`, `sed`, and every audit or sweep built on
 * them read the whole tree. A single raw NUL byte anywhere in a file makes
 * those tools classify that ENTIRE file as binary and skip it silently, with no
 * error and no diagnostic, so a scan reports "no matches" for a file it never
 * opened. Control bytes belong in source as escape sequences, which produce the
 * identical runtime value while keeping the file readable.
 *
 * SCOPE BOUND of this pin (the scope is part of the claim): it checks `.ts`
 * files under `server/src` for the C0 control bytes that trip binary detection,
 * excluding tab, newline, and carriage return, which are ordinary text. It does
 * not police other trees, non-`.ts` files, or DEL/C1 bytes, and it says nothing
 * about a file's runtime behavior.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC_ROOT = join(
  fileURLToPath(import.meta.url),
  "..",
  "..",
  "..",
  "src"
);

/**
 * The C0 control bytes that make line-based tooling treat a file as binary.
 * Tab (0x09), line feed (0x0a) and carriage return (0x0d) are excluded because
 * they are ordinary text; every other byte below 0x20 is not.
 */
const TEXT_CONTROL_BYTES = new Set([0x09, 0x0a, 0x0d]);
const FIRST_PRINTABLE_BYTE = 0x20;

function typescriptSources(dir: string, found: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      typescriptSources(full, found);
    } else if (entry.endsWith(".ts")) {
      found.push(full);
    }
  }
  return found;
}

describe("server/src is readable by line-based tooling", () => {
  const files = typescriptSources(SRC_ROOT);

  // Anti-vacuity: a walk that resolved nothing would report zero offenders and
  // pass while checking nothing, which is the absent-reads-as-passing shape.
  it("walks a non-empty set of TypeScript sources", () => {
    expect(files.length).toBeGreaterThan(100);
  });

  it("contains no raw C0 control byte outside tab, newline, and carriage return", () => {
    const offenders: string[] = [];
    for (const file of files) {
      const bytes = readFileSync(file);
      for (let i = 0; i < bytes.length; i += 1) {
        const byte = bytes[i]!;
        if (byte < FIRST_PRINTABLE_BYTE && !TEXT_CONTROL_BYTES.has(byte)) {
          const line = bytes.subarray(0, i).toString("utf8").split("\n").length;
          offenders.push(
            `${file.slice(SRC_ROOT.length + 1)}:${line} byte 0x${byte.toString(16).padStart(2, "0")}`
          );
          break;
        }
      }
    }
    expect(
      offenders,
      "write the control byte as an escape sequence; the runtime value is identical and the file stays readable to grep"
    ).toEqual([]);
  });
});
