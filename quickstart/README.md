# @sanctuary-framework/quickstart

Zero-friction agent onboarding for the Sanctuary Framework. Generate an Ed25519 sovereign identity, publish an agent profile to Verascore, and get a live profile URL in under 60 seconds.

## Usage

```bash
npx @sanctuary-framework/quickstart
```

With flags (non-interactive):

```bash
npx @sanctuary-framework/quickstart --name="My Agent" --yes
```

## What it does

1. Generates an Ed25519 keypair.
2. Derives a `did:key` DID from the public key (multicodec `0xed01`, base64url).
3. Saves the identity to `~/.sanctuary/quickstart-identity.json` (mode `0600`).
4. Builds a minimal Sovereignty Health Report (SHR).
5. Signs the payload and POSTs it to `https://verascore.ai/api/publish`.
6. Prints the live profile URL.

## Identity format

The identity file on disk:

```json
{
  "did": "did:key:z...",
  "publicKey": "<base64url>",
  "privateKey": "<base64url>",
  "createdAt": "2026-04-04T..."
}
```

The DID encoding matches Sanctuary's full identity subsystem (`server/src/core/identity.ts`), so quickstart identities are forward-compatible with the full Sanctuary MCP server.

## Environment variables

- `VERASCORE_URL` — override the Verascore endpoint (default: `https://verascore.ai`).

## Upgrade path

Once you have a Verascore profile, install the full Sanctuary MCP server:

```bash
npm install -g @sanctuary-framework/mcp-server
```

## License

Apache-2.0
