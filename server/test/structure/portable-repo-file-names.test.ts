/**
 * Every tracked path in the repository must be a name every operating system
 * can check out. Anthropic's plugin directory validates the whole repository
 * that hosts plugin/ and rejects the submission if any name contains a colon or
 * backslash, ends in a dot or a space, is not valid UTF-8, or is a Windows
 * device name (con, prn, aux, nul, com1 to com9, lpt1 to lpt9), with or
 * without an extension. Windows also refuses the characters < > " | ? * and
 * control characters, and reserves CONIN$, CONOUT$ and the superscript-digit
 * forms COM¹ to COM³ and LPT¹ to LPT³, so they are rejected here too.
 *
 * A file whose deployed name must break these rules (a systemd unit whose
 * escaped name encodes its mount path, for example) keeps a portable name in
 * the repo and is renamed by the packaging step that installs it; see
 * MOUNT_SOURCE in castle-wall-daemon/packaging/arch/build-arch-package.py.
 */
import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const REPO_ROOT = fileURLToPath(new URL("../../../", import.meta.url));

// Matched against the part of a name before its first dot, with trailing spaces
// dropped, case-insensitively, because Windows reserves "nul.txt", "NUL.tar.gz"
// and "CON .txt" as well as "nul".
const DEVICE_NAME = /^(con|prn|aux|nul|conin\$|conout\$|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])$/i;
// Colon and backslash are the directory's own rule; the rest are Windows'.
// eslint-disable-next-line no-control-regex
const FORBIDDEN_CHAR = /[:\\<>"|?*\x00-\x1f]/;

export function nonPortableReason(component: Buffer): string | null {
  let name: string;
  try {
    name = new TextDecoder("utf-8", { fatal: true }).decode(component);
  } catch {
    return "not valid UTF-8";
  }
  const bad = FORBIDDEN_CHAR.exec(name);
  if (bad) return `contains ${JSON.stringify(bad[0])}`;
  if (name.endsWith(".") || name.endsWith(" ")) return "ends in a dot or a space";
  if (DEVICE_NAME.test(name.split(".")[0].trimEnd())) return "is a Windows device name";
  return null;
}

function trackedPaths(): Buffer[] {
  const out = execFileSync("git", ["-C", REPO_ROOT, "ls-files", "-z"], {
    maxBuffer: 256 * 1024 * 1024,
  });
  const paths: Buffer[] = [];
  let start = 0;
  for (let i = 0; i < out.length; i++) {
    if (out[i] === 0) {
      if (i > start) paths.push(out.subarray(start, i));
      start = i + 1;
    }
  }
  return paths;
}

function components(path: Buffer): Buffer[] {
  const parts: Buffer[] = [];
  let start = 0;
  for (let i = 0; i <= path.length; i++) {
    if (i === path.length || path[i] === 0x2f) {
      parts.push(path.subarray(start, i));
      start = i + 1;
    }
  }
  return parts;
}

describe("portable repository file names", () => {
  it("rejects each name shape the plugin directory refuses", () => {
    const b = (s: string) => Buffer.from(s, "utf8");
    expect(nonPortableReason(b("var-lib-sanctuary\\x2dagent.mount"))).toMatch(/contains/);
    expect(nonPortableReason(b("a:b"))).toMatch(/contains/);
    expect(nonPortableReason(b("trailing."))).toMatch(/ends in/);
    expect(nonPortableReason(b("trailing "))).toMatch(/ends in/);
    expect(nonPortableReason(b("NUL.txt"))).toMatch(/device/);
    expect(nonPortableReason(b("com1"))).toMatch(/device/);
    expect(nonPortableReason(b("lpt9.tar.gz"))).toMatch(/device/);
    expect(nonPortableReason(b("CON .txt"))).toMatch(/device/);
    expect(nonPortableReason(b("conin$"))).toMatch(/device/);
    expect(nonPortableReason(b("CONOUT$.log"))).toMatch(/device/);
    expect(nonPortableReason(b("com\u00b9"))).toMatch(/device/);
    expect(nonPortableReason(b("LPT\u00b3.txt"))).toMatch(/device/);
    expect(nonPortableReason(Buffer.from([0x66, 0xff, 0x66]))).toMatch(/UTF-8/);
    expect(nonPortableReason(b("console.ts"))).toBeNull();
    expect(nonPortableReason(b("com10"))).toBeNull();
    expect(nonPortableReason(b(".gitignore"))).toBeNull();
  });

  it("every tracked path is portable", () => {
    const paths = trackedPaths();
    expect(paths.length).toBeGreaterThan(1000);
    const offenders: string[] = [];
    for (const path of paths) {
      for (const part of components(path)) {
        const reason = nonPortableReason(part);
        if (reason) offenders.push(`${JSON.stringify(path.toString("utf8"))}: ${reason}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});
