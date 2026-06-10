# The Sanctuary Secret Broker

*v0.10.0 feature, native credential broker with per-skill scoped ephemeral tokens.*

Most MCP agents today ask you to drop your credentials into a `.env` file. That file is plaintext, it lives next to your code, and it tends to get committed by accident. Industry leakage data: [29M secrets leaked from public repos in 2025, up 34% YoY](https://gitguardian.com/state-of-secrets-sprawl). This is the gap Sanctuary v0.10.0 closes.

The broker stores credentials in the **macOS Keychain** (Linux / Windows backends coming in v0.10.1), hands out **short-lived, per-skill, scoped tokens** to skills that ask, and writes an **attested audit entry for every operation**. Every component is open source, runs locally, and requires zero external infrastructure.

**Harness compatibility:** the broker is exposed as an MCP server, so any harness that speaks MCP (OpenClaw, Cline, Claude Code, Cursor, LangGraph, Mastra, CrewAI) can consume it. You do not need to wrap your agent in Sanctuary to benefit.

---

## Quick start

```sh
# One-time: install.
npm install -g @sanctuary-framework/mcp-server

# Store a credential (prompts for value; value never appears in argv, shell
# history, or any file outside the keychain).
sanctuary secrets add gmail_oauth_token
Enter value for "gmail_oauth_token": ****************

# Authorize a specific skill to read it.
sanctuary secrets grant gmail-triage gmail_oauth_token --scope read --ttl 900

# Verify.
sanctuary secrets list
  gmail_oauth_token
    granted to: gmail-triage(read)

# See every broker operation.
sanctuary secrets audit
2026-04-17T20:12:03Z  broker_secret_added        success  skill=- secret=gmail_oauth_token
2026-04-17T20:12:14Z  broker_secret_granted      success  skill=gmail-triage secret=gmail_oauth_token
```

That's the entire administrative workflow. Your skills now request tokens through the broker MCP server instead of reading from `.env`.

---

## How skills request credentials

The broker exposes four MCP tools:

| Tool | Purpose |
|------|---------|
| `broker/request_token` | Skill asks for a scoped token (default TTL 15 min, max 1 h). |
| `broker/read_secret` | Skill exchanges the token for the raw credential value. |
| `broker/list_grants` | Self-introspection, which grants exist on this broker. |
| `broker/audit_query` | Read-only access to the broker-scoped audit trail. |

A typical skill flow looks like:

```ts
// 1. Request a token. Scope is bounded by the grant; default is "read".
const { token } = await mcp.callTool("broker/request_token", {
  skill: "gmail-triage",
  secret: "gmail_oauth_token",
});

// 2. Use the token to fetch the value. The broker re-verifies the grant
//    on every read, so revocation takes effect immediately.
const { value } = await mcp.callTool("broker/read_secret", { token });

// 3. Use the value for the actual API call. The token remains valid for
//    its TTL; refresh by repeating step 2 or re-issuing with step 1.
await gmailClient.authenticate(value);
```

If the broker denies the request, the response is a generic `{ "error": "Broker denied" }`. The specific reason (no grant, scope exceeds grant, revoked, expired) is written to the audit trail, not returned to the caller. This is intentional, denial-opacity prevents a compromised skill from probing policy structure.

---

## The policy file

Grants are stored in `~/.sanctuary/broker-policy.json`:

```json
{
  "skills": [
    {
      "name": "gmail-triage",
      "secrets": [
        { "name": "gmail_oauth_token", "scope": "read", "ttl": 900 }
      ]
    },
    {
      "name": "gmail-admin",
      "secrets": [
        { "name": "gmail_oauth_token", "scope": "rotate" },
        { "name": "gcal_oauth_token", "scope": "read", "ttl": 600 }
      ]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `skills[].name` | Must match the `skill` field a skill self-declares when calling `broker/request_token`. |
| `skills[].secrets[].name` | Must match the name you used with `sanctuary secrets add`. |
| `skills[].secrets[].scope` | `"read"` or `"rotate"`. `rotate` implies `read`. |
| `skills[].secrets[].ttl` | Optional TTL cap in seconds; broker clamps at 3600. Omitted = 900s default. |

You can edit this file directly or use `sanctuary secrets grant` / `sanctuary secrets revoke` (they edit it for you and update any in-process broker). Absence of the file, or an empty `skills` array, means **no skill has broker access**: a safe default.

---

## Running the broker MCP server

To expose the broker to your harness, start it as an MCP server:

```sh
sanctuary broker-server
```

This listens on stdio by default, add it to your harness's MCP server config the same way you would add any other MCP server:

```json
{
  "mcpServers": {
    "sanctuary-broker": {
      "command": "npx",
      "args": ["-y", "@sanctuary-framework/mcp-server", "broker-server"]
    }
  }
}
```

The first invocation creates the keychain (`~/Library/Keychains/sanctuary.keychain-db`) and prompts for a passphrase. Subsequent invocations use the passphrase cached by the Sanctuary wrap flow (same passphrase that protects the master key).

---

## Security model

**What the broker guarantees:**

1. **No plaintext credentials on disk outside the keychain.** The raw value travels through the `security` CLI into an AES-encrypted keychain file. It is never written to `.env`, logs, or audit entries.
2. **Every administrative operation is audited** (`broker_secret_added`, `broker_secret_rotated`, `broker_secret_deleted`, `broker_secret_granted`, `broker_secret_revoked`).
3. **Every token issuance, denial, and read is audited** (`broker_token_issued`, `broker_token_denied`, `broker_secret_read`) with skill, secret name (never value), scope, TTL, agent, and principal identity.
4. **Grant revocation takes effect immediately.** The broker re-verifies the current grant on every token use, so removing an entry from the policy file denies the next call.
5. **Tokens are bound** to `(skill, secret, scope, agent, identity_id, expires_at)`. A token issued for `gmail-triage` cannot be replayed by `gmail-admin`.

**What the broker does not claim:**

1. **Defense against a compromised skill during its TTL window.** An attacker who compromises a skill holding a live token has that credential for up to the TTL. Mitigation: aggressive TTLs (15-minute default vs. "hours or days" in competing products), minimum-scope grants, and audit visibility so anomalies are detectable.
2. **Defense against a compromised host.** If an attacker is root on the box while the broker keychain is unlocked, they can invoke `/usr/bin/security` directly and bypass the broker entirely. The defense is *detection*, the Sanctuary audit log on a compromised host shows a gap between the broker's recorded reads and the credential's actual use.
3. **Endpoint-level scope.** A `read` grant on `gmail_oauth_token` lets the skill use the credential for any Gmail API endpoint the token's underlying OAuth scope permits. Endpoint-level constraint matching (e.g., restricting a token to `gmail.metadata.readonly` vs. `gmail.send`) is planned for v0.10.1.

See `Review/Sanctuary/V0.10.0_Spike_ScopedTokenSemantics.md` for the full design rationale.

---

## Operational notes

### Migrating from `.env`

For a skill that currently reads `process.env.GMAIL_OAUTH_TOKEN`:

1. `sanctuary secrets add gmail_oauth_token` (paste the value from your existing `.env`).
2. `sanctuary secrets grant <skill-name> gmail_oauth_token --scope read --ttl 900`.
3. In the skill, replace the env-read with the two-tool broker flow shown above.
4. Remove the credential from `.env`.

A worked example for ClawChief is in `Review/Sanctuary/V0.10.0_WP2_ClawChief_Migration_Recipe.md`.

### After a reboot

The broker keychain is locked at reboot. The next `sanctuary wrap` invocation unlocks it using the Sanctuary passphrase. If the passphrase is not cached (first run on a new machine), you'll be prompted once.

To unlock interactively without starting a wrap:

```sh
SANCTUARY_PASSPHRASE=... sanctuary secrets list
```

### Audit retention

Broker audit entries are stored in the Sanctuary AuditLog (the same one used by Cognitive, Operational, and Verifiable Reputation operations). Retention defaults: 100 MB or 100,000 entries, whichever is reached first. Oldest entries are pruned when the cap is hit.

### Rotation

```sh
sanctuary secrets rotate gmail_oauth_token
# Enter new value: ****************
```

Rotation replaces the stored value atomically. Tokens issued *before* rotation continue to resolve to the NEW value (the broker reads from the keychain on every `read_secret`, not at issuance time). If you want to hard-deny tokens issued before rotation, follow rotate with:

```sh
sanctuary secrets revoke <skill> <secret>
sanctuary secrets grant <skill> <secret>
```

Revoke-then-regrant invalidates outstanding tokens on next use.

---

## Supported platforms

| Platform | Status |
|---|---|
| macOS | ✅ v0.10.0 (Keychain backend) |
| Linux | 🚧 v0.10.1 (libsecret / `secret-tool`) |
| Windows | 🚧 v0.10.1 (Credential Manager) |

The `Backend` interface is pluggable, downstream integrations (HashiCorp Vault, Infisical, 1Password Connect) can ship as separate packages implementing the same interface.
