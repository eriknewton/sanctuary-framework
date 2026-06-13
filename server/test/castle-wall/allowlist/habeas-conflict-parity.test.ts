/**
 * HABEAS PORT conflict-gate cross-language parity.
 *
 * Loads the shared fixture `fixtures/habeas-conflict-parity.json` and asserts
 * the TS `findHabeasConflicts` decision (conflict vs clean) for every case.
 * The Rust daemon suite (`castle-wall-daemon/tests/integration_habeas_parity.rs`)
 * loads the SAME fixture and must reach the same verdict on every case — so
 * the TS and Linux conflict gates reject identical rule sets.
 *
 * The fixture uses only the host / host_pattern / port axes the Linux
 * RuleMatch models (no ip/cidr), so every case is expressible in both
 * languages. The ip/cidr-only TS cases live in habeas-port.test.ts.
 */

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  findHabeasConflicts,
  findHabeasConflictsInComposed,
  type HabeasWebhookTarget,
} from "../../../src/castle-wall/allowlist/habeas-port.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";

interface ParityCase {
  name: string;
  webhook: HabeasWebhookTarget | null;
  rules: AllowlistRule[];
  expect_conflict: boolean;
}

interface ComposedParityCase {
  name: string;
  rules: AllowlistRule[];
  expect_conflict: boolean;
}

interface ParityFixture {
  habeas_distress_port: number;
  cases: ParityCase[];
  composed_cases: ComposedParityCase[];
}

async function loadFixture(): Promise<ParityFixture> {
  const here = dirname(fileURLToPath(import.meta.url));
  const fixturePath = join(here, "../fixtures/habeas-conflict-parity.json");
  return JSON.parse(await readFile(fixturePath, "utf8")) as ParityFixture;
}

describe("habeas conflict gate — cross-language parity vector", () => {
  it("agrees with the shared fixture on every case (TS side)", async () => {
    const fixture = await loadFixture();
    expect(fixture.cases.length).toBeGreaterThan(0);
    for (const testCase of fixture.cases) {
      const issues = findHabeasConflicts(
        testCase.rules,
        testCase.webhook ?? undefined,
      );
      const conflicted = issues.length > 0;
      expect(conflicted, `case "${testCase.name}"`).toBe(testCase.expect_conflict);
    }
  });

  it("agrees with the shared fixture on every composed case (TS side)", async () => {
    // Composed-manifest gate parity (codex round-4 finding 4): duplicate
    // reserved ids and the always-on-local-lane requirement must produce the
    // same accept/reject verdict in both languages.
    const fixture = await loadFixture();
    expect(fixture.composed_cases.length).toBeGreaterThan(0);
    for (const testCase of fixture.composed_cases) {
      const issues = findHabeasConflictsInComposed(testCase.rules);
      const conflicted = issues.length > 0;
      expect(conflicted, `composed case "${testCase.name}"`).toBe(
        testCase.expect_conflict,
      );
    }
  });
});
