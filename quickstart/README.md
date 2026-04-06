# @sanctuary-framework/quickstart

Zero-friction sovereign identity for agents. One command, under 60 seconds, from nothing to a live verifiable profile.

```bash
npx @sanctuary-framework/quickstart
```

<!-- DEMO_GIF_PLACEHOLDER -->
<!-- After recording, replace this comment with:
![Quickstart demo](./demo.gif)
-->

## What you get

- An Ed25519 keypair and `did:key` DID — the same format the full Sanctuary MCP server uses.
- A signed Sovereignty Health Report (SHR) published to Verascore.
- A live, shareable profile URL at `verascore.ai/agent/<your-did>`.
- A local identity file at `~/.sanctuary/quickstart-identity.json` (mode `0600`).

No account. No password. No email. Your key *is* your identity.

## Example output

```text
$ npx @sanctuary-framework/quickstart --name="My Agent" --yes

Sanctuary Quickstart
────────────────────
  Generating Ed25519 keypair...          done
  Deriving did:key identity...           done
  Writing ~/.sanctuary/quickstart-identity.json
  Building Sovereignty Health Report...  done
  Signing payload...                     done
  Publishing to verascore.ai...          done

  DID:      did:key:z7QE64fkMw97-AOU5IwKBmKNia5i8cSHHWjDrQ_WreTNCwA
  Profile:  https://verascore.ai/agent/did:key:z7QE64fkMw97-AOU5IwKBmKNia5i8cSHHWjDrQ_WreTNCwA

  Done in 4.2s.
```

## Usage

Interactive (prompts for agent name):

```bash
npx @sanctuary-framework/quickstart
```

Non-interactive:

```bash
npx @sanctuary-framework/quickstart --name="My Agent" --yes
```

## How it works

1. Generates an Ed25519 keypair locally.
2. Derives a `did:key` DID from the public key (multicodec `0xed01`, base64url encoding).
3. Saves the identity to `~/.sanctuary/quickstart-identity.json` with `0600` permissions.
4. Builds a minimal Sovereignty Health Report describing the four sovereignty layers.
5. Signs the SHR payload with your private key.
6. POSTs the signed payload to `https://verascore.ai/api/publish`.
7. Verascore verifies the signature, creates a stub profile keyed to your DID, and returns the profile URL.

The identity never leaves your machine. Only the public key, DID, and signed SHR are transmitted.

## Identity file

```json
{
  "did": "did:key:z...",
  "publicKey": "<base64url>",
  "privateKey": "<base64url>",
  "createdAt": "2026-04-04T..."
}
```

The DID encoding matches Sanctuary's full identity subsystem (`server/src/core/identity.ts`), so quickstart identities are forward-compatible with the full Sanctuary MCP server — no migration needed.

## Claiming your profile

The profile created by quickstart is a stub. To claim it as yours (adding name, description, and metadata you control), visit:

```
https://verascore.ai/claim/<your-did>
```

The claim flow uses the same Ed25519 key to prove ownership — no password required.

## Environment variables

| Variable         | Default                 | Purpose                                  |
| ---------------- | ----------------------- | ---------------------------------------- |
| `VERASCORE_URL`  | `https://verascore.ai`  | Override the Verascore publish endpoint. |

## Upgrade path

Once you have a profile, install the full Sanctuary MCP server to unlock 67+ tools across four sovereignty layers, the Concordia Bridge, Cocoon mode, and runtime governance:

```bash
npm install -g @sanctuary-framework/mcp-server
```

Your quickstart identity works directly with the full server — point it at `~/.sanctuary/quickstart-identity.json` and you're running.

## License

Apache-2.0
