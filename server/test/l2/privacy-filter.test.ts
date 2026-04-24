import { describe, expect, it } from "vitest";
import {
  applyOpenAIPrivacyFilterResult,
  applyLocalPrivacyFilter,
  applyPrivacyPlaceholders,
  PrivacyPlaceholderVault,
} from "../../src/l2-operational/privacy-filter.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { bytesToString } from "../../src/core/encoding.js";

describe("L2 local privacy filter", () => {
  it("redacts common sensitive spans inside strings", () => {
    const result = applyLocalPrivacyFilter({
      prompt:
        "Email jane@example.com, call 415-555-1212, SSN 123-45-6789, api_key=sk-test.",
    });

    expect(result.value).toEqual({
      prompt:
        "Email [EMAIL_REDACTED], call [PHONE_REDACTED], SSN [SSN_REDACTED], api_key=[SECRET_REDACTED]",
    });
    expect(result.findings.map((f) => f.class)).toEqual([
      "email",
      "ssn",
      "phone",
      "secret_assignment",
    ]);
    expect(result.findings.every((f) => f.path === "$.prompt")).toBe(true);
  });

  it("walks nested arrays and objects without changing safe values", () => {
    const result = applyLocalPrivacyFilter({
      messages: [
        { text: "safe" },
        { text: "Contact ops@example.org" },
      ],
      limit: 3,
    });

    expect(result.value).toEqual({
      messages: [
        { text: "safe" },
        { text: "Contact [EMAIL_REDACTED]" },
      ],
      limit: 3,
    });
    expect(result.findings).toEqual([
      { path: "$.messages[1].text", class: "email", action: "redact" },
    ]);
  });

  it("replaces sensitive spans with stable encrypted placeholders", async () => {
    const storage = new MemoryStorage();
    const vault = new PrivacyPlaceholderVault(storage, generateRandomKey());

    const first = await applyPrivacyPlaceholders(
      { prompt: "Email jane@example.com and call 415-555-1212" },
      vault,
      "policy-a"
    );
    const second = await applyPrivacyPlaceholders(
      { prompt: "Email jane@example.com again" },
      vault,
      "policy-a"
    );

    expect(first.value).toEqual({
      prompt: "Email EMAIL_1 and call PHONE_1",
    });
    expect(second.value).toEqual({
      prompt: "Email EMAIL_1 again",
    });
    expect(first.findings).toEqual([
      {
        path: "$.prompt",
        class: "email",
        action: "placeholder",
        placeholder: "EMAIL_1",
      },
      {
        path: "$.prompt",
        class: "phone",
        action: "placeholder",
        placeholder: "PHONE_1",
      },
    ]);
    await expect(vault.resolvePlaceholder("EMAIL_1", "policy-a")).resolves.toBe(
      "jane@example.com"
    );
  });

  it("does not store raw sensitive values in plaintext", async () => {
    const storage = new MemoryStorage();
    const vault = new PrivacyPlaceholderVault(storage, generateRandomKey());

    await applyPrivacyPlaceholders(
      { prompt: "Email jane@example.com" },
      vault,
      "policy-a"
    );

    const entries = await storage.list("_privacy_placeholder_vault");
    expect(entries.length).toBeGreaterThan(0);
    for (const entry of entries) {
      const raw = await storage.read(entry.namespace, entry.key);
      expect(raw).not.toBeNull();
      expect(bytesToString(raw!)).not.toContain("jane@example.com");
    }
  });

  it("adapts OpenAI privacy-filter spans into encrypted placeholders", async () => {
    const storage = new MemoryStorage();
    const vault = new PrivacyPlaceholderVault(storage, generateRandomKey());
    const text = "Jane Smith emailed jane@example.com from 1 Main St.";

    const result = await applyOpenAIPrivacyFilterResult(
      {
        schema_version: 1,
        text,
        detected_spans: [
          {
            label: "private_person",
            start: 0,
            end: 10,
            text: "Jane Smith",
          },
          {
            label: "private_email",
            start: 19,
            end: 35,
            text: "jane@example.com",
          },
          {
            label: "private_address",
            start: 41,
            end: 50,
            text: "1 Main St",
          },
        ],
      },
      vault,
      "opf-policy"
    );

    expect(result.value).toBe("PERSON_1 emailed EMAIL_1 from ADDRESS_1.");
    expect(result.findings.map((f) => f.class)).toEqual([
      "person",
      "email",
      "address",
    ]);
    await expect(vault.resolvePlaceholder("PERSON_1", "opf-policy")).resolves.toBe(
      "Jane Smith"
    );
  });
});
