# did:web SSRF Hardening Build Report

Date: 2026-06-09
Branch: `v1.x-did-web-ssrf-hardening-2026-06-09`
Base: `6c5baf7f`

## Findings Closed

H1: SSRF defense in depth
- Added pre-fetch `host_not_allowed` rejection for IP-literal did:web authority hosts, including URL-normalized IPv4 forms such as `0x7f.0.0.1`.
- Added metadata authority host rejection for known metadata DNS names.
- Added DNS preflight for the production/default fetch path. Every resolved address must be public before fetch proceeds.
- Files: `server/src/recognition/did-web.ts`

M1: did:web path segment validation
- `parseDidWeb` now validates `fortress_id` with `FORTRESS_LABEL_RE` and `agent_label` with `AGENT_LABEL_RE`.
- Invalid `?`, `#`, `/`, and encoded-dot style segments fail before URL construction.
- Files: `server/src/recognition/did-web.ts`

M2: response body size cap
- Added `MAX_DID_DOC_BYTES = 256 * 1024`.
- Checks `Content-Length` before reading.
- Streams Response-compatible bodies and cancels once the cap is exceeded.
- Preserves existing lightweight injected fetcher support by falling back to `text()` or `json()` when no stream is exposed.
- Files: `server/src/recognition/did-web.ts`

Manifest authority host cross-check
- Import now parses `manifestDidWeb.identifier` before resolution and rejects if the parsed host differs from `manifestDidWeb.authority_host`.
- Audit records the parsed host that would be fetched.
- Files: `server/src/exit/bundle.ts`

## Tests Added

- SSRF pre-fetch rejection for `169.254.169.254`, `127.0.0.1`, `10.0.0.1`, `0x7f.0.0.1`, and `metadata.google.internal`, including when allowlisted.
- Happy-path public host resolution still passes.
- `parseDidWeb` rejects unsafe fortress and agent labels.
- Oversize `Content-Length` response is rejected.
- Oversize streamed/no-length body is rejected while streaming.
- Small Response-compatible DID document still resolves.
- Signed import fixture with parsed host mismatch rejects before fetch and audits parsed host.
- `.test-baseline` updated from `5423` to `5429`.

## Gate Output

- `npm run typecheck`: passed.
- `npm test -- test/recognition/did-web.test.ts`: passed, 45 tests.
- `npm test -- test/exit/exit-bundle-did-web.test.ts`: passed, 18 tests.

## Deviations

- Initial `npm test -- server/test/recognition/did-web.test.ts` used a repo-root path from inside `server` and Vitest found no files. Reran with `test/recognition/did-web.test.ts`.
- Did not implement pinned-address fetching. The default fetch path now performs DNS resolution and rejects non-public results before fetch, while syntactic IP-literal and metadata host rejection applies to all fetchers. Pinning the connection would require a larger fetcher/TLS contract change.
