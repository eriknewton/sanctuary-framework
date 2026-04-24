import { describe, expect, it } from "vitest";
import { applyLocalPrivacyFilter } from "../../src/l2-operational/privacy-filter.js";

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
});

