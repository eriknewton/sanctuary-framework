# @sanctuary-framework/quickstart

Zero-friction sovereign identity for agents. One command, a few seconds, and you have a local Ed25519 identity. Publishing a verifiable profile to Verascore is optional, and nothing is sent unless you say yes.

```bash
npx @sanctuary-framework/quickstart
```

<!-- DEMO_GIF_PLACEHOLDER -->
<!-- After recording, replace this comment with:
![Quickstart demo](./demo.gif)
-->

## What you get

- An Ed25519 keypair and `did:key` DID: the same format the full Sanctuary MCP server uses.
- A local identity file at `~/.sanctuary/quickstart-identity.json` (mode `0600`). This is created on every run.
- If you choose to publish: a signed Sovereignty Health Report (SHR) on Verascore and a public profile URL at `verascore.ai/agent/<your-did>`.

There is no account, password or email to set up: your key *is* your identity.

## Publishing asks first

Quickstart sends nothing to Verascore unless you choose to publish:

| How you run it | What happens |
| --- | --- |
| In a terminal, no publish flag | Shows the destination URL and the exact request body, then asks `Publish this profile to Verascore? [y/N]`. Only `y` or `yes` publishes; Enter means No. |
| `--publish` | Publishes without asking. Use this in scripts. |
| `--no-publish` | Never publishes. |
| No terminal (CI, pipes) and no publish flag | Does not publish, and prints how to publish with `--publish`. |

`--yes` accepts every default without prompting. The publish default is No, so `--yes` on its own does not publish.

Versions before 0.2.0 published on every run. From 0.2.0, publishing is opt-in as described above.

## Example output

```text
$ npx @sanctuary-framework/quickstart --name="My Agent"

✓ Identity created (~/.sanctuary/quickstart-identity.json)
  DID: did:key:z7QE64fkMw97-AOU5IwKBmKNia5i8cSHHWjDrQ_WreTNCwA

Publishing is optional. If you say yes, quickstart sends one HTTP POST.
  To:       https://verascore.ai/api/publish
  Profile:  https://verascore.ai/agent/did%3Akey%3Az7QE64... (public once published)
  Body (sent as compact JSON; nothing else is sent and the private key stays local):
{
  "agentId": "did-key-z7qe64fkmw97-aou5iwkbmknia5i8cshhwjdrq-wretncwa",
  "signature": "<base64url Ed25519 signature>",
  "publicKey": "<base64url public key>",
  "type": "shr",
  "data": { "did": "did:key:z7QE64...", "name": "My Agent", ... }
}

Publish this profile to Verascore? [y/N] y

✓ Profile published
  Profile: https://verascore.ai/agent/did%3Akey%3Az7QE64...
```

## Usage

Interactive (prompts for the agent name, then asks before publishing):

```bash
npx @sanctuary-framework/quickstart
```

Scripted, publishing:

```bash
npx @sanctuary-framework/quickstart --name="My Agent" --publish
```

Local identity only:

```bash
npx @sanctuary-framework/quickstart --name="My Agent" --no-publish
```

`--help` prints every option.

## How it works

1. Generates an Ed25519 keypair locally.
2. Derives a `did:key` DID from the public key (multicodec `0xed01`, base64url encoding). Note: this quickstart still emits the legacy base64url `did:key` shape; the full Sanctuary package now uses the canonical base58btc encoding under the `z` multibase prefix (see [`../docs/DID_ENCODING.md`](../docs/DID_ENCODING.md)).
3. Saves the identity to `~/.sanctuary/quickstart-identity.json` with `0600` permissions. A new run creates a new identity and replaces this file.
4. Builds a minimal Sovereignty Health Report describing the four sovereignty layers and signs it with your private key.
5. Decides whether to publish (see "Publishing asks first"). If you do not publish, it stops here.
6. If you publish, POSTs the signed payload to `https://verascore.ai/api/publish`.
7. Verascore verifies the signature, creates a stub profile keyed to your DID, and returns the profile URL.

The private key never leaves your machine. When you publish, only the public key, DID, agent name and signed SHR are transmitted.

## Identity file

```json
{
  "did": "did:key:z...",
  "publicKey": "<base64url>",
  "privateKey": "<base64url>",
  "createdAt": "2026-04-04T..."
}
```

The DID encoding matches Sanctuary's full identity subsystem (`server/src/core/identity.ts`), so quickstart identities are forward-compatible with the full Sanctuary MCP server, no migration needed.

## Claiming your profile

If you published, the profile created by quickstart is a stub. To claim it as yours (adding name, description, and metadata you control), visit:

```
https://verascore.ai/claim/<your-did>
```

The claim flow uses the same Ed25519 key to prove ownership, no password required.

## Environment variables

| Variable         | Default                 | Purpose                                  |
| ---------------- | ----------------------- | ---------------------------------------- |
| `VERASCORE_URL`  | `https://verascore.ai`  | Override the Verascore publish endpoint. |

## Upgrade path

Once you have an identity, install the full Sanctuary MCP server to unlock 67+ tools across four sovereignty layers, the Concordia Bridge, one-command agent wrap, and runtime governance:

```bash
npm install -g @sanctuary-framework/mcp-server
```

Your quickstart identity works directly with the full server: point it at `~/.sanctuary/quickstart-identity.json` and you're running.

## License

Apache-2.0
