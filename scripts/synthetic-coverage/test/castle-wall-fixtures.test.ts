import { describe, expect, it } from "vitest";
import "../fixtures/castle-wall/boundary-admission.js";
import "../fixtures/castle-wall/deny-by-default.js";
import "../fixtures/castle-wall/custody-key-gate.js";
import "../fixtures/castle-wall/identity-signing-tool-registry-guard.js";
import "../fixtures/castle-wall/sentinel-registration.js";
import { listClaims } from "../registry.js";

const EXPECTED_FIXTURES = [
  "boundary-admission: happy admit",
  "boundary-admission: deny on missing token",
  "boundary-admission: deny on expired token",
  "boundary-admission: deny on revoked principal",
  "boundary-admission: replay rejection",
  "deny-by-default: unconfigured route denies",
  "deny-by-default: unknown verb denies",
  "deny-by-default: malformed request denies",
  "deny-by-default: request without identity context denies",
  "custody-key-gate: gate-open allows",
  "custody-key-gate: gate-closed denies",
  "custody-key-gate: gate-toggle race produces deterministic outcome",
  "identity-signing-tool-registry-guard: tool-registry sign permitted",
  "identity-signing-tool-registry-guard: raw sign rejected",
  "identity-signing-tool-registry-guard: AP2 mandate sign via Key 17 permitted",
  "identity-signing-tool-registry-guard: ERC-8004 identity sign via Key 17 permitted",
  "sentinel-registration: register baseline sentinel",
  "sentinel-registration: register observation sentinel eBPF",
  "sentinel-registration: register observation sentinel auditd",
] as const;

function fixtureByName(name: string) {
  return listClaims()
    .flatMap((claim) => claim.fixtures)
    .find((fixture) => fixture.name === name);
}

describe("Castle Wall synthetic fixtures", () => {
  for (const fixtureName of EXPECTED_FIXTURES) {
    it(`${fixtureName} passes`, async () => {
      const fixture = fixtureByName(fixtureName);
      expect(fixture, `fixture registered: ${fixtureName}`).toBeDefined();
      const result = await fixture!.fn();
      expect(result.passed, result.message).toBe(true);
    });
  }
});
