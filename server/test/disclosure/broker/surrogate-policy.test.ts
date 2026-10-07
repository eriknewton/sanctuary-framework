/**
 * Tests for the shared surrogate policy parser.
 *
 * WHAT IT HAS TO GUARANTEE. Four stages read a binding (the broker, the operator
 * CLI, root arming, and the root helper when it loads its table) and this is the
 * only function three of them parse with. A document this parser accepts is a
 * document root will arm from, so every refusal here is a refusal to put a
 * credential somewhere the operator did not write.
 *
 * It refuses whole documents, never partial ones: a partially-read binding set
 * would arm an agent with a destination map nobody authored. And it reports a
 * fixed failure class rather than a message built from the input, because the
 * caller writes that class into the fortress audit chain.
 */

import { describe, expect, it } from "vitest";

import {
  MAX_SURROGATE_BINDINGS_PER_AGENT,
  MAX_SURROGATE_DESTINATIONS_PER_BINDING,
} from "../../../src/credential-surrogate/constants.js";
import {
  SURROGATE_POLICY_VERSION,
  SurrogatePolicyError,
  findSurrogateGrantConflicts,
  parseSurrogatePolicyDocument,
  surrogateBoundSecretNames,
} from "../../../src/disclosure/broker/policy.js";
import type { SkillSecretGrant } from "../../../src/disclosure/broker/token-issuer.js";

function binding(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    secret: "openai-api-key",
    agent: "hermes",
    env: "OPENAI_API_KEY",
    destinations: [{ host: "api.openai.com", port: 443 }],
    header: "Authorization",
    ...over,
  };
}

function doc(bindings: unknown[], over: Record<string, unknown> = {}): unknown {
  return { surrogate_policy_version: SURROGATE_POLICY_VERSION, bindings, ...over };
}

/** Assert the parser refused, and refused with the class the audit line will carry. */
function expectRefusal(raw: unknown, failureClass: string): void {
  try {
    parseSurrogatePolicyDocument(raw);
    throw new Error(`expected a refusal with class ${failureClass}`);
  } catch (err) {
    expect(err).toBeInstanceOf(SurrogatePolicyError);
    expect((err as SurrogatePolicyError).failureClass).toBe(failureClass);
  }
}

describe("document shape", () => {
  it("parses a well-formed single-binding document", () => {
    const parsed = parseSurrogatePolicyDocument(doc([binding()]));
    expect(parsed).toEqual({
      surrogate_policy_version: 1,
      bindings: [
        {
          secret: "openai-api-key",
          agent: "hermes",
          env: "OPENAI_API_KEY",
          destinations: [{ host: "api.openai.com", port: 443 }],
          header: "Authorization",
        },
      ],
    });
  });

  it("parses an empty binding list", () => {
    expect(parseSurrogatePolicyDocument(doc([])).bindings).toEqual([]);
  });

  it("refuses an unknown version rather than reading it as best effort", () => {
    expectRefusal(doc([binding()], { surrogate_policy_version: 2 }), "bad_version");
    expectRefusal(doc([binding()], { surrogate_policy_version: 0 }), "bad_version");
    expectRefusal(doc([binding()], { surrogate_policy_version: "1" }), "bad_version");
  });

  it("refuses a missing version, an unknown top-level key, and a non-object root", () => {
    expectRefusal({ bindings: [] }, "schema_error");
    expectRefusal({ ...(doc([]) as object), extra: 1 }, "schema_error");
    expectRefusal([], "schema_error");
    expectRefusal(null, "schema_error");
    expectRefusal("{}", "schema_error");
  });

  it("refuses bindings that are not an array", () => {
    expectRefusal(doc(undefined as unknown as unknown[]), "schema_error");
    expectRefusal({ surrogate_policy_version: 1, bindings: {} }, "schema_error");
  });
});

describe("binding shape", () => {
  it("refuses an unknown key, so a future field cannot be silently ignored", () => {
    expectRefusal(doc([binding({ ttl: 60 })]), "schema_error");
  });

  it("refuses a missing key", () => {
    const { header: _header, ...withoutHeader } = binding();
    expectRefusal(doc([withoutHeader]), "schema_error");
  });

  it("refuses an env name that is reserved or ill-formed", () => {
    expectRefusal(doc([binding({ env: "HTTP_PROXY" })]), "schema_error");
    expectRefusal(doc([binding({ env: "http_proxy" })]), "schema_error");
    expectRefusal(doc([binding({ env: "lowercase" })]), "schema_error");
    expectRefusal(doc([binding({ env: "1LEADING_DIGIT" })]), "schema_error");
  });

  it("refuses a header the gate must never write into", () => {
    for (const header of ["Host", "Content-Length", "Transfer-Encoding", "Expect", "Upgrade", "Proxy-Authorization"]) {
      expectRefusal(doc([binding({ header })]), "schema_error");
    }
  });

  it("refuses an ill-formed agent id or secret name", () => {
    expectRefusal(doc([binding({ agent: "Hermes" })]), "schema_error");
    expectRefusal(doc([binding({ agent: "her mes" })]), "schema_error");
    expectRefusal(doc([binding({ secret: "a b" })]), "schema_error");
  });
});

describe("destinations", () => {
  it("accepts up to the cap and refuses one over it", () => {
    const hosts = ["a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"];
    const atCap = hosts.slice(0, MAX_SURROGATE_DESTINATIONS_PER_BINDING).map((host) => ({ host, port: 443 }));
    expect(parseSurrogatePolicyDocument(doc([binding({ destinations: atCap })])).bindings[0]?.destinations).toHaveLength(
      MAX_SURROGATE_DESTINATIONS_PER_BINDING,
    );
    const overCap = hosts.slice(0, MAX_SURROGATE_DESTINATIONS_PER_BINDING + 1).map((host) => ({ host, port: 443 }));
    expectRefusal(doc([binding({ destinations: overCap })]), "schema_error");
  });

  it("refuses an empty destination list, so a binding always names where it may be spent", () => {
    expectRefusal(doc([binding({ destinations: [] })]), "schema_error");
  });

  it("refuses a wildcard host and an IP literal", () => {
    expectRefusal(doc([binding({ destinations: [{ host: "*.openai.com", port: 443 }] })]), "schema_error");
    expectRefusal(doc([binding({ destinations: [{ host: "192.0.2.1", port: 443 }] })]), "schema_error");
  });

  it("refuses any port but 443, so the value is only ever written inside TLS", () => {
    expectRefusal(doc([binding({ destinations: [{ host: "api.openai.com", port: 80 }] })]), "schema_error");
    expectRefusal(doc([binding({ destinations: [{ host: "api.openai.com", port: 8443 }] })]), "schema_error");
  });

  it("refuses an unknown key on a destination and a repeated host inside one binding", () => {
    expectRefusal(doc([binding({ destinations: [{ host: "api.openai.com", port: 443, sni: "x" }] })]), "schema_error");
    expectRefusal(
      doc([
        binding({
          destinations: [
            { host: "api.openai.com", port: 443 },
            { host: "api.openai.com", port: 443 },
          ],
        }),
      ]),
      "schema_error",
    );
  });
});

describe("duplicate bindings", () => {
  it("refuses two bindings naming the same secret (round-2 finding B2-S7)", () => {
    expectRefusal(
      doc([binding(), binding({ env: "OTHER_KEY", header: "X-Api-Key" })]),
      "duplicate_binding",
    );
  });

  it("refuses the duplicate even across different agents", () => {
    expectRefusal(doc([binding(), binding({ agent: "other-agent" })]), "duplicate_binding");
  });

  it("accepts distinct secrets for the same agent", () => {
    const parsed = parseSurrogatePolicyDocument(
      doc([binding(), binding({ secret: "other-key", env: "OTHER_KEY", header: "X-Api-Key" })]),
    );
    expect(parsed.bindings).toHaveLength(2);
  });
});

describe("the per-agent cap (AGENTS.md rule 8)", () => {
  function nBindings(n: number, agent = "hermes"): Record<string, unknown>[] {
    return Array.from({ length: n }, (_unused, i) =>
      binding({ secret: `secret-${i}`, env: `KEY_${i}`, agent }),
    );
  }

  it("accepts exactly the cap", () => {
    const parsed = parseSurrogatePolicyDocument(doc(nBindings(MAX_SURROGATE_BINDINGS_PER_AGENT)));
    expect(parsed.bindings).toHaveLength(MAX_SURROGATE_BINDINGS_PER_AGENT);
  });

  it("refuses one over the cap, so the helper's table is bounded where it is built", () => {
    expectRefusal(doc(nBindings(MAX_SURROGATE_BINDINGS_PER_AGENT + 1)), "schema_error");
  });

  it("counts the cap per agent, not per document", () => {
    const twoAgents = [
      ...nBindings(MAX_SURROGATE_BINDINGS_PER_AGENT, "hermes"),
      ...nBindings(MAX_SURROGATE_BINDINGS_PER_AGENT, "other-agent").map((b, i) => ({
        ...b,
        secret: `other-secret-${i}`,
        env: `OTHER_KEY_${i}`,
      })),
    ];
    expect(parseSurrogatePolicyDocument(doc(twoAgents)).bindings).toHaveLength(
      2 * MAX_SURROGATE_BINDINGS_PER_AGENT,
    );
  });
});

describe("the conflict rule against broker grants", () => {
  function grant(secret: string, scope: "read" | "rotate" = "read"): SkillSecretGrant {
    return { skill: "some-skill", secret, scope };
  }

  it("finds a bound secret that also carries a read grant", () => {
    expect(findSurrogateGrantConflicts([binding() as never], [grant("openai-api-key")])).toEqual([
      "openai-api-key",
    ]);
  });

  it("finds a rotate grant too, because every broker scope reads the value", () => {
    expect(
      findSurrogateGrantConflicts([binding() as never], [grant("openai-api-key", "rotate")]),
    ).toEqual(["openai-api-key"]);
  });

  it("reports nothing when the grant names a different secret", () => {
    expect(findSurrogateGrantConflicts([binding() as never], [grant("unrelated-key")])).toEqual([]);
  });

  it("reports each conflicting secret once and sorted, so an audit line is stable", () => {
    const bindings = [
      binding({ secret: "b-key", env: "B_KEY" }),
      binding({ secret: "a-key", env: "A_KEY" }),
    ] as never[];
    const grants = [grant("b-key"), grant("a-key"), { ...grant("a-key"), skill: "second-skill" }];
    expect(findSurrogateGrantConflicts(bindings, grants)).toEqual(["a-key", "b-key"]);
  });

  it("reports nothing for an empty policy or an empty grant set", () => {
    expect(findSurrogateGrantConflicts([], [grant("openai-api-key")])).toEqual([]);
    expect(findSurrogateGrantConflicts([binding() as never], [])).toEqual([]);
  });
});

describe("the required set the token issuer refuses against", () => {
  it("is exactly the bound secret names", () => {
    const parsed = parseSurrogatePolicyDocument(
      doc([binding(), binding({ secret: "other-key", env: "OTHER_KEY", header: "X-Api-Key" })]),
    );
    const names = surrogateBoundSecretNames(parsed.bindings);
    expect([...names].sort()).toEqual(["openai-api-key", "other-key"]);
    expect(names.has("unrelated")).toBe(false);
  });

  it("is empty for a policy with no bindings, which is what makes the set required and not optional", () => {
    expect(surrogateBoundSecretNames([]).size).toBe(0);
  });
});
