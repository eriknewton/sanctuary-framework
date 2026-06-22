/**
 * Broker Policy Parser Tests
 */

import { describe, it, expect } from "vitest";
import { parseBrokerPolicy } from "../../../src/disclosure/broker/policy.js";

describe("parseBrokerPolicy", () => {
  it("returns empty when skills section absent", () => {
    expect(parseBrokerPolicy({})).toEqual([]);
    expect(parseBrokerPolicy(undefined)).toEqual([]);
    expect(parseBrokerPolicy(null)).toEqual([]);
  });

  it("parses a simple valid policy", () => {
    const grants = parseBrokerPolicy({
      skills: [
        {
          name: "gmail-triage",
          secrets: [{ name: "gmail_oauth", scope: "read", ttl: 900 }],
        },
      ],
    });
    expect(grants).toEqual([
      { skill: "gmail-triage", secret: "gmail_oauth", scope: "read", ttlSeconds: 900 },
    ]);
  });

  it("defaults scope to read when omitted", () => {
    const grants = parseBrokerPolicy({
      skills: [{ name: "s", secrets: [{ name: "gmail_oauth" }] }],
    });
    expect(grants[0]!.scope).toBe("read");
  });

  it("rejects non-object root", () => {
    expect(() => parseBrokerPolicy("nope")).toThrow(/object/);
    expect(() => parseBrokerPolicy(42)).toThrow(/object/);
  });

  it("rejects non-array skills", () => {
    expect(() => parseBrokerPolicy({ skills: "nope" })).toThrow(/array/);
  });

  it("rejects invalid scope value", () => {
    expect(() =>
      parseBrokerPolicy({
        skills: [{ name: "s", secrets: [{ name: "x", scope: "full" }] }],
      })
    ).toThrow(/read.*rotate/);
  });

  it("rejects invalid ttl values", () => {
    expect(() =>
      parseBrokerPolicy({
        skills: [{ name: "s", secrets: [{ name: "x", ttl: -1 }] }],
      })
    ).toThrow(/positive/);
    expect(() =>
      parseBrokerPolicy({
        skills: [{ name: "s", secrets: [{ name: "x", ttl: "900" }] }],
      })
    ).toThrow(/positive/);
  });

  it("rejects empty skill name", () => {
    expect(() =>
      parseBrokerPolicy({ skills: [{ name: "", secrets: [] }] })
    ).toThrow(/non-empty/);
  });

  it("rejects illegal characters in names", () => {
    expect(() =>
      parseBrokerPolicy({
        skills: [{ name: "bad name", secrets: [] }],
      })
    ).toThrow(/invalid characters/);
    expect(() =>
      parseBrokerPolicy({
        skills: [{ name: "s", secrets: [{ name: "bad name" }] }],
      })
    ).toThrow(/invalid characters/);
  });

  it("rejects duplicate (skill, secret) grants", () => {
    expect(() =>
      parseBrokerPolicy({
        skills: [
          {
            name: "s",
            secrets: [{ name: "x" }, { name: "x" }],
          },
        ],
      })
    ).toThrow(/Duplicate/);
  });

  it("handles multiple skills and secrets", () => {
    const grants = parseBrokerPolicy({
      skills: [
        {
          name: "gmail-triage",
          secrets: [{ name: "gmail_oauth", scope: "read" }],
        },
        {
          name: "gmail-admin",
          secrets: [
            { name: "gmail_oauth", scope: "rotate" },
            { name: "gcal_oauth", scope: "read", ttl: 600 },
          ],
        },
      ],
    });
    expect(grants).toHaveLength(3);
    expect(grants.find((g) => g.skill === "gmail-admin" && g.scope === "rotate")).toBeDefined();
  });
});
