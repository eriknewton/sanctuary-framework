# Sanctuary DID Encoding

## Interop note

Sanctuary identifies agents with a `did:key`-style DID derived from an
Ed25519 public key. The **Sanctuary variant uses base64url multibase
encoding with the `z` prefix**, which is a deliberate departure from the
W3C `did:key` specification (which mandates base58btc under multibase
`z`). If you are integrating Sanctuary agent DIDs into a registry or
verifier that was built against strict `did:key`, you must decode them
using the procedure described below — a stock `did:key` resolver will
**not** recognise them.

This document describes the exact format Sanctuary emits, shows how to
extract the 32-byte Ed25519 public key from a Sanctuary DID, and
provides decoder snippets for integrators.

---

## Format

A Sanctuary DID has the shape:

```
did:key:z<base64url(multicodec || publicKey)>
```

Concretely:

| Component       | Value                                     |
|-----------------|-------------------------------------------|
| Scheme          | `did:`                                    |
| Method          | `key:`                                    |
| Multibase prefix| `z` (literal)                             |
| Body            | base64url-encoded `[0xed, 0x01, ...pub]`  |

- `0xed` is the varint multicodec identifier for Ed25519 public keys.
- `0x01` is the trailing byte of the multicodec varint (the canonical
  multicodec code for `ed25519-pub` is `0xed01`, encoded as
  `[0xed, 0x01]` in practice).
- `pub` is the raw 32-byte Ed25519 public key.
- The 34 bytes `[0xed, 0x01] || pub` are then base64url-encoded
  **without** padding (RFC 4648 §5).

The `z` prefix is retained from the `did:key` convention but, in
Sanctuary, it marks "base64url-encoded body" rather than the
multibase-standard "base58btc". A typical Sanctuary DID looks like:

```
did:key:z7QFhX... (44-47 characters after the z prefix)
```

The exact byte length depends on base64url encoding of 34 bytes (no
padding), which is always 46 characters — so the full DID is
`did:key:z` (9 chars) + 46 chars = **55 characters** total.

---

## Reference implementation

The canonical encoder lives in
[`server/src/core/identity.ts`](../server/src/core/identity.ts):

```typescript
export function publicKeyToDid(publicKey: Uint8Array): string {
  // Multicodec prefix for Ed25519: 0xed 0x01
  const multicodec = new Uint8Array([0xed, 0x01, ...publicKey]);
  return `did:key:z${toBase64url(multicodec)}`;
}
```

`toBase64url` produces standard base64url with `-`/`_` and no `=`
padding (RFC 4648 §5).

---

## Decoder snippet (JavaScript / TypeScript)

```javascript
/**
 * Extract the raw Ed25519 public key from a Sanctuary DID.
 * Returns a 32-byte Uint8Array, or throws on malformed input.
 */
function sanctuaryDidToPublicKey(did) {
  if (!did.startsWith("did:key:z")) {
    throw new Error("Not a Sanctuary DID: missing 'did:key:z' prefix");
  }
  const b64url = did.slice("did:key:z".length);

  // base64url → base64 → bytes
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

  if (bytes.length !== 34) {
    throw new Error(
      `Malformed Sanctuary DID: expected 34 bytes, got ${bytes.length}`,
    );
  }
  if (bytes[0] !== 0xed || bytes[1] !== 0x01) {
    throw new Error(
      "Malformed Sanctuary DID: multicodec prefix is not Ed25519 (0xed 0x01)",
    );
  }
  return bytes.slice(2); // raw 32-byte Ed25519 public key
}
```

---

## Decoder snippet (Python)

```python
import base64

def sanctuary_did_to_public_key(did: str) -> bytes:
    """Extract the 32-byte Ed25519 public key from a Sanctuary DID."""
    prefix = "did:key:z"
    if not did.startswith(prefix):
        raise ValueError("Not a Sanctuary DID: missing 'did:key:z' prefix")
    b64url = did[len(prefix):]
    # Restore padding for urlsafe_b64decode
    padding = "=" * (-len(b64url) % 4)
    raw = base64.urlsafe_b64decode(b64url + padding)
    if len(raw) != 34:
        raise ValueError(f"Expected 34 bytes, got {len(raw)}")
    if raw[0] != 0xED or raw[1] != 0x01:
        raise ValueError("Multicodec prefix is not Ed25519 (0xed 0x01)")
    return raw[2:]
```

---

## Verifying a signature against a Sanctuary DID

Once you have the 32-byte public key, any standard Ed25519 library can
verify a signature:

```javascript
import { ed25519 } from "@noble/curves/ed25519";

const pub = sanctuaryDidToPublicKey(did);         // 32 bytes
const ok = ed25519.verify(signature, message, pub); // boolean
```

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

pub = Ed25519PublicKey.from_public_bytes(sanctuary_did_to_public_key(did))
pub.verify(signature, message)  # raises on failure
```

---

## Relationship to W3C did:key

The W3C `did:key` specification (v0.7) mandates base58btc encoding
(multibase prefix `z`). Sanctuary uses the same `z` multibase marker
but encodes with base64url instead. This is a non-standard choice that
trades interop with generic `did:key` resolvers for:

- Smaller, URL-safe DIDs (base64url is shorter and URL-safe by design)
- Zero runtime cost in JSON contexts
- No need for a base58 dependency on either side of the wire

Integrators who need strict `did:key` compliance should transcode
Sanctuary DIDs to the standard base58btc form, or publish the
Sanctuary public key under an alternative DID method (e.g.
`did:web`). A future major version of Sanctuary may switch to
base58btc to align with the standard; the `did:key:z` prefix is
stable for v0.5.x.

---

## Round-trip verification test

A matching encoder/decoder pair should satisfy:

```javascript
const { ed25519 } = require("@noble/curves/ed25519");

const priv = crypto.randomBytes(32);
const pub = ed25519.getPublicKey(priv);
const did = publicKeyToDid(pub);
const pub2 = sanctuaryDidToPublicKey(did);

console.assert(Buffer.from(pub).equals(Buffer.from(pub2)));
```
