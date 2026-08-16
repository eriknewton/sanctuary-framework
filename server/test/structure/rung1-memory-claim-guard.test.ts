/**
 * Rung-1 memory claim guard.
 *
 * This is intentionally a bounded lexical guard, not a semantic oracle. It
 * owns the canonical Rung-1 memory surfaces: registered memory-file tool copy
 * and public paragraphs that name Rung-1, a memory-file command, the
 * sovereign-memory substrate, or the memory mirror. A general memory claim
 * that uses none of those markers remains a review responsibility. When a new
 * overclaim wording or canonical marker is identified, add it to the lists
 * below and plant a mutation that proves the new class is rejected.
 */

import { lstat, readdir, readFile } from "node:fs/promises";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { RUNG1_MEMORY_TOOL_DESCRIPTIONS } from "../../src/sdw/memory-file-tools.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..", "..");

const PUBLIC_ROOT_FILES = [
  "README.md",
  "ROADMAP.md",
  "CHANGELOG.md",
  "package.json",
  join("server", "package.json"),
] as const;
const PUBLIC_TREES = ["docs", "plugin", ".claude-plugin"] as const;
const PUBLIC_EXTENSIONS = new Set([".html", ".json", ".md", ".txt", ".yaml", ".yml"]);
const README_WALK_EXCLUSIONS = new Set([".git", "dist", "node_modules", "target"]);

const RUNG1_CONTEXT =
  /\b(?:rung[- ]?1|memory_(?:ingest|emit|transcode|transcode_restore)|sdw|sovereign data warehouse|sovereign[- ]memory substrate|memory(?:[- ]file)? mirror)\b/i;

interface ForbiddenClaimClass {
  readonly id: string;
  readonly pattern: RegExp;
}

/**
 * The explicit lexical boundary. These patterns reject positive claims only
 * inside a canonical Rung-1 context. Direct statements of a limitation pass;
 * provider-invisibility wording remains positive even when it uses "never"
 * or "cannot" and is therefore represented as its own match class.
 */
const FORBIDDEN_CLAIM_CLASSES: readonly ForbiddenClaimClass[] = [
  {
    id: "full-sovereignty",
    pattern: /\b(?:full sovereignty|fully sovereign|complete sovereignty)\b/gi,
  },
  {
    id: "provider-private",
    pattern:
      /\b(?:private|invisible|hidden|opaque)\s+(?:from|to)\s+(?:the\s+)?(?:model(?:\s+provider)?|provider|vendor)\b/gi,
  },
  {
    id: "provider-no-access",
    pattern:
      /\b(?:model(?:\s+provider)?|provider|vendor)\s+(?:cannot|can't|does\s+not|doesn't|never)\s+(?:see|read|access|receive)\b/gi,
  },
  {
    id: "memory-never-sent",
    pattern:
      /\b(?:memory|memories)\s+(?:is|are)\s+never\s+(?:sent|shared|transmitted)\s+to\s+(?:a\s+|the\s+|any\s+)?(?:model(?:\s+provider)?|provider|vendor)\b/gi,
  },
  {
    id: "end-to-end-encryption",
    pattern:
      /\b(?:(?:end[- ]to[- ]end|e2e)(?:\s+\w+){0,2}\s+encrypt(?:ed|ion)|encrypt(?:ed|ion)(?:\s+\w+){0,2}\s+(?:end[- ]to[- ]end|e2e))\b/gi,
  },
] as const;

interface ClaimViolation {
  readonly claimClass: string;
  readonly excerpt: string;
}

function isDirectLimitation(text: string, matchIndex: number): boolean {
  const prefix = text.slice(Math.max(0, matchIndex - 120), matchIndex).toLowerCase();
  return (
    /\b(?:not(?:\s+yet)?|never)\s+(?:[a-z-]+\s+){0,4}$/.test(prefix) ||
    /\b(?:do|does|did|can|could|should|would)\s+not\s+(?:claim|promise|provide|guarantee|mean|assert)\s+(?:[a-z-]+\s+){0,5}$/.test(
      prefix,
    ) ||
    /\bno\s+claim\s+(?:of|to)\s+(?:[a-z-]+\s+){0,4}$/.test(prefix)
  );
}

function claimViolations(text: string, forceRung1Context = false): ClaimViolation[] {
  if (!forceRung1Context && !RUNG1_CONTEXT.test(text)) return [];

  const violations: ClaimViolation[] = [];
  for (const claimClass of FORBIDDEN_CLAIM_CLASSES) {
    claimClass.pattern.lastIndex = 0;
    for (const match of text.matchAll(claimClass.pattern)) {
      const matchIndex = match.index ?? 0;
      if (isDirectLimitation(text, matchIndex)) continue;
      violations.push({
        claimClass: claimClass.id,
        excerpt: text.slice(Math.max(0, matchIndex - 48), matchIndex + match[0].length + 48),
      });
    }
  }
  return violations;
}

async function publicSurfaceFiles(): Promise<string[]> {
  const files = new Set(PUBLIC_ROOT_FILES.map((path) => join(REPO_ROOT, path)));

  async function walkPublicTree(path: string): Promise<void> {
    const info = await lstat(path);
    if (info.isSymbolicLink()) return;
    if (info.isFile()) {
      if (PUBLIC_EXTENSIONS.has(extname(path))) files.add(path);
      return;
    }
    for (const entry of await readdir(path)) {
      await walkPublicTree(join(path, entry));
    }
  }

  async function walkReadmes(path: string): Promise<void> {
    const info = await lstat(path);
    if (info.isSymbolicLink() || info.isFile()) {
      if (info.isFile() && path.endsWith("README.md")) files.add(path);
      return;
    }
    for (const entry of await readdir(path)) {
      if (README_WALK_EXCLUSIONS.has(entry)) continue;
      await walkReadmes(join(path, entry));
    }
  }

  for (const tree of PUBLIC_TREES) await walkPublicTree(join(REPO_ROOT, tree));
  await walkReadmes(REPO_ROOT);
  return [...files].sort();
}

function documentViolations(text: string, markdown: boolean): ClaimViolation[] {
  const violations: ClaimViolation[] = [];
  let rung1Section = false;

  for (const paragraph of text.split(/\n\s*\n/)) {
    const trimmed = paragraph.trim();
    const heading = markdown && /^#{1,6}\s+/m.test(trimmed);
    if (heading) rung1Section = RUNG1_CONTEXT.test(trimmed);
    violations.push(...claimViolations(paragraph, rung1Section));
  }
  return violations;
}

describe("Rung-1 memory claim guard", () => {
  it("reads the production tool descriptions and pins every required honesty bound", () => {
    expect(Object.keys(RUNG1_MEMORY_TOOL_DESCRIPTIONS).sort()).toEqual([
      "memory_emit",
      "memory_ingest",
      "memory_transcode",
      "memory_transcode_restore",
    ]);
    for (const [tool, description] of Object.entries(RUNG1_MEMORY_TOOL_DESCRIPTIONS)) {
      const lower = description.toLowerCase();
      expect(claimViolations(description, true), tool).toEqual([]);
      expect(lower, tool).toContain("plaintext");
      expect(lower, tool).toContain("does not sync");
      expect(lower, tool).toContain("exposed to that vendor at inference");
    }
    expect(RUNG1_MEMORY_TOOL_DESCRIPTIONS.memory_ingest.toLowerCase()).toContain(
      "encrypted copy lives in the vault",
    );
    expect(RUNG1_MEMORY_TOOL_DESCRIPTIONS.memory_transcode.toLowerCase()).toContain(
      "exact source recovery uses the versioned encrypted archive",
    );
    expect(RUNG1_MEMORY_TOOL_DESCRIPTIONS.memory_transcode_restore.toLowerCase()).toContain(
      "completed encrypted sanctuary memory transcode archive",
    );
  });

  it("scans every canonical Rung-1 paragraph on current public surfaces", async () => {
    const violations: Array<{ readonly file: string; readonly violation: ClaimViolation }> = [];
    const files = await publicSurfaceFiles();
    expect(files.map((file) => file.slice(REPO_ROOT.length + 1))).toContain(
      join("server", "src", "README.md"),
    );
    for (const file of files) {
      const text = await readFile(file, "utf8");
      for (const violation of documentViolations(text, extname(file) === ".md")) {
        violations.push({ file: file.slice(REPO_ROOT.length + 1), violation });
      }
    }
    expect(violations).toEqual([]);
  });

  it("fails on a planted positive claim in every forbidden class", () => {
    const planted = [
      "Rung-1 memory provides full sovereignty.",
      "memory_ingest keeps memory private from the model provider.",
      "The sovereign-memory substrate makes provider access invisible to the model.",
      "The SDW vault provides full sovereignty over agent memory.",
      "With the memory mirror, the provider cannot read your memories.",
      "Rung-1 memories are never transmitted to any model provider.",
      "memory_emit provides end-to-end encrypted memory.",
      "memory_transcode keeps memory private from the provider.",
      "memory_transcode_restore provides full sovereignty.",
      "The Rung-1 memory mirror is encrypted end-to-end.",
    ];
    for (const claim of planted) {
      expect(claimViolations(claim), claim).not.toEqual([]);
    }
    expect(
      documentViolations("## Rung-1 Memory\n\nThis provides full sovereignty.", true),
    ).not.toEqual([]);
  });

  it("allows direct bounds but rejects a negated sentence that still adds a positive claim", () => {
    const bounds = [
      "Rung-1 memory does not claim full sovereignty.",
      "memory_ingest is not private from the model provider.",
      "The sovereign-memory substrate is not end-to-end encrypted.",
    ];
    for (const bound of bounds) expect(claimViolations(bound), bound).toEqual([]);

    const mixed =
      "Rung-1 memory is not end-to-end encrypted, but it is private from the model provider.";
    expect(claimViolations(mixed)).toEqual([
      expect.objectContaining({ claimClass: "provider-private" }),
    ]);
  });
});
