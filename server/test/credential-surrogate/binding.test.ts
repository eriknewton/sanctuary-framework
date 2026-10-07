/**
 * Tests for the shared element-level binding validators. Three stages read a
 * binding (the policy parser, root arming, the root helper) and they must agree
 * character for character, or a credential is written to a destination one of
 * them would have refused. These are the functions all three call.
 */

import { describe, expect, it } from "vitest";

import {
  MAX_SURROGATE_HEADER_NAME_LENGTH,
  MAX_SURROGATE_HOST_LENGTH,
  SURROGATE_BOUND_PORT,
  SURROGATE_RESERVED_ENV_NAMES,
  isLegalHttpFieldValue,
  validateSurrogateAgentId,
  validateSurrogateEnvName,
  validateSurrogateHeaderName,
  validateSurrogateHost,
  validateSurrogatePort,
  validateSurrogateSecretName,
} from "../../src/credential-surrogate/binding.js";
import { HARNESS_FORBIDDEN_PLIST_ENV } from "../../src/egress-gate/harness-daemon.js";

/**
 * Control bytes are built from their code points rather than written as literal
 * escapes, so this file stays free of bytes that a diff viewer or a terminal
 * would hide. `byte(13)` is CR, `byte(10)` is LF, `byte(0)` is NUL.
 */
function byte(code: number): string {
  return String.fromCharCode(code);
}

const CR = byte(13);
const LF = byte(10);
const NUL = byte(0);
const TAB = byte(9);

describe("reserved env names stay in lockstep with the harness list", () => {
  it("is exactly HARNESS_FORBIDDEN_PLIST_ENV", () => {
    // Duplicated, not imported (see the comment on SURROGATE_RESERVED_ENV_NAMES).
    // This is the pin: a name added to one list and not the other fails here.
    expect([...SURROGATE_RESERVED_ENV_NAMES].sort()).toEqual([...HARNESS_FORBIDDEN_PLIST_ENV].sort());
  });
});

describe("env name", () => {
  it("accepts the wrapper grammar", () => {
    expect(validateSurrogateEnvName("OPENAI_API_KEY")).toBeNull();
    expect(validateSurrogateEnvName("_X")).toBeNull();
    expect(validateSurrogateEnvName("A")).toBeNull();
    expect(validateSurrogateEnvName(`A${"B".repeat(63)}`)).toBeNull();
  });

  it("refuses a leading digit, lowercase, and over-long names", () => {
    expect(validateSurrogateEnvName("1ABC")).toBe("bad_charset");
    expect(validateSurrogateEnvName("openai_api_key")).toBe("bad_charset");
    expect(validateSurrogateEnvName(`A${"B".repeat(64)}`)).toBe("bad_charset");
  });

  it("refuses every reserved name, so a binding cannot route the agent past the gate", () => {
    for (const name of SURROGATE_RESERVED_ENV_NAMES) {
      expect(validateSurrogateEnvName(name)).toBe("reserved_name");
    }
  });

  it("refuses an empty string and a non-string", () => {
    expect(validateSurrogateEnvName("")).toBe("empty");
    expect(validateSurrogateEnvName(7)).toBe("not_a_string");
  });
});

describe("bound header name", () => {
  it("accepts a credential-bearing header", () => {
    expect(validateSurrogateHeaderName("Authorization")).toBeNull();
    expect(validateSurrogateHeaderName("X-Api-Key")).toBeNull();
  });

  it("refuses framing headers, because writing into one is a smuggling primitive", () => {
    expect(validateSurrogateHeaderName("Content-Length")).toBe("forbidden_header");
    expect(validateSurrogateHeaderName("Transfer-Encoding")).toBe("hop_by_hop_header");
    expect(validateSurrogateHeaderName("transfer-encoding")).toBe("hop_by_hop_header");
  });

  it("refuses Host, so a swap cannot retarget the request", () => {
    expect(validateSurrogateHeaderName("Host")).toBe("forbidden_header");
    expect(validateSurrogateHeaderName("host")).toBe("forbidden_header");
  });

  it("refuses protocol-changing and gate-addressed headers", () => {
    expect(validateSurrogateHeaderName("Expect")).toBe("forbidden_header");
    expect(validateSurrogateHeaderName("Upgrade")).toBe("hop_by_hop_header");
    expect(validateSurrogateHeaderName("Connection")).toBe("hop_by_hop_header");
    expect(validateSurrogateHeaderName("Proxy-Authorization")).toBe("forbidden_header");
    expect(validateSurrogateHeaderName("proxy-anything")).toBe("forbidden_header");
  });

  it("refuses a non-token charset and an over-long name", () => {
    expect(validateSurrogateHeaderName("Bad Header")).toBe("bad_charset");
    expect(validateSurrogateHeaderName("Bad:Header")).toBe("bad_charset");
    expect(validateSurrogateHeaderName("A".repeat(MAX_SURROGATE_HEADER_NAME_LENGTH + 1))).toBe("too_long");
  });
});

describe("destination host", () => {
  it("accepts a lowercase DNS name", () => {
    expect(validateSurrogateHost("api.openai.com")).toBeNull();
    expect(validateSurrogateHost("a.b")).toBeNull();
  });

  it("refuses a wildcard, so one binding cannot cover a whole zone", () => {
    expect(validateSurrogateHost("*.openai.com")).toBe("wildcard_host");
  });

  it("refuses an IP literal, because the confidentiality argument is a verified hostname", () => {
    expect(validateSurrogateHost("192.0.2.1")).toBe("ip_literal_host");
    expect(validateSurrogateHost("2001:db8::1")).toBe("ip_literal_host");
  });

  it("refuses uppercase, a bare label, a port suffix and an over-long name", () => {
    expect(validateSurrogateHost("API.openai.com")).toBe("bad_charset");
    expect(validateSurrogateHost("localhost")).toBe("bad_charset");
    expect(validateSurrogateHost("api.openai.com:443")).toBe("ip_literal_host");
    expect(validateSurrogateHost(`${"a".repeat(MAX_SURROGATE_HOST_LENGTH)}.com`)).toBe("too_long");
  });
});

describe("destination port", () => {
  it("accepts only the bound TLS port in slice 1", () => {
    expect(validateSurrogatePort(SURROGATE_BOUND_PORT)).toBeNull();
    expect(validateSurrogatePort(80)).toBe("bad_port");
    expect(validateSurrogatePort(8443)).toBe("bad_port");
    expect(validateSurrogatePort("443")).toBe("bad_port");
    expect(validateSurrogatePort(443.5)).toBe("bad_port");
  });
});

describe("agent id and secret name", () => {
  it("accepts the shapes the gate account and keychain backend accept", () => {
    expect(validateSurrogateAgentId("hermes")).toBeNull();
    expect(validateSurrogateAgentId("agent-1_x")).toBeNull();
    expect(validateSurrogateSecretName("openai-api-key")).toBeNull();
    expect(validateSurrogateSecretName("ns/openai.key:v1")).toBeNull();
  });

  it("refuses shell-metacharacter and path-traversal shapes", () => {
    expect(validateSurrogateAgentId("her mes")).toBe("bad_charset");
    expect(validateSurrogateAgentId("her;mes")).toBe("bad_charset");
    expect(validateSurrogateAgentId("Hermes")).toBe("bad_charset");
    expect(validateSurrogateSecretName("a b")).toBe("bad_charset");
    expect(validateSurrogateSecretName("a$b")).toBe("bad_charset");
  });
});

describe("legal HTTP field value: the header-splitting guard", () => {
  it("accepts visible ASCII, space and tab", () => {
    expect(isLegalHttpFieldValue("Bearer sk-abc123")).toBe(true);
    expect(isLegalHttpFieldValue(`a${TAB}b c`)).toBe(true);
    expect(isLegalHttpFieldValue("!~")).toBe(true);
  });

  it("refuses CR, LF and NUL, so a value cannot split a header or smuggle a request", () => {
    expect(isLegalHttpFieldValue(`a${CR}b`)).toBe(false);
    expect(isLegalHttpFieldValue(`a${LF}b`)).toBe(false);
    expect(isLegalHttpFieldValue(`a${CR}${LF}X-Injected: 1`)).toBe(false);
    expect(isLegalHttpFieldValue(`a${NUL}b`)).toBe(false);
  });

  it("refuses other control bytes and non-ASCII", () => {
    expect(isLegalHttpFieldValue(`a${byte(1)}b`)).toBe(false);
    expect(isLegalHttpFieldValue(`a${byte(127)}b`)).toBe(false);
    expect(isLegalHttpFieldValue("aéb")).toBe(false);
  });
});
