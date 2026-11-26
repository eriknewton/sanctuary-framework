# verify-release trust data

`trusted_root.json` is the Sigstore public-good trusted root that
`sanctuary verify-release` checks npm provenance against. It is production
data: the verifier loads it relative to its own module (`trust-root.ts`) and
never from the install it checks. There is no TUF client and no
`~/.sigstore` cache; the verifier makes no request for trust material.

## Source

- Copy of `targets/trusted_root.json` from the `sigstore/root-signing`
  repository, fetched from
  `https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json`
  on 2026-11-25 at 18:43:03 UTC.
- sha256 `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`.
  Must match `EXPECTED_TRUSTED_ROOT_SHA256` in
  `server/scripts/copy-verify-release-trusted-root.mjs` and `TRUSTED_ROOT_SHA256`
  in `server/test/verify-release/trust-root.test.ts`; the build refuses a root
  whose bytes do not match.

## Validity windows

| Role | Endpoint | Valid from | Valid until |
|---|---|---|---|
| Transparency log | `https://rekor.sigstore.dev` | 2021-01-12T11:53:27Z | open |
| Transparency log | `https://log2025-1.rekor.sigstore.dev` | 2025-09-23T00:00:00Z | open |
| Certificate authority | `https://fulcio.sigstore.dev` | 2021-03-07T03:20:29Z | 2022-12-31T23:59:59.999Z |
| Certificate authority | `https://fulcio.sigstore.dev` | 2022-04-13T20:06:15Z | open |
| CT log | `https://ctfe.sigstore.dev/test` | 2021-03-14T00:00:00Z | 2022-10-31T23:59:59.999Z |
| CT log | `https://ctfe.sigstore.dev/2022` | 2022-10-20T00:00:00Z | open |
| Timestamp authority | `https://timestamp.sigstore.dev/api/v1/timestamp` | 2025-07-04T00:00:00Z | open |

A release signed outside these windows refuses with
`sigstore-invalid:<library code>`, the same reason as any other failed
verification. The command never names a stale root as the cause: once
verification fails, the log time it would judge staleness by is not
authenticated.

## Rotation

Replacing the root is a reviewed change: update `trusted_root.json`, this
README, and both pins named above in one change. A root that is not updated
when Sigstore rotates keys makes newer releases refuse; it never makes them
pass.
