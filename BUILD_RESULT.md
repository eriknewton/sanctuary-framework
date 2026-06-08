# English-Policy Fix-Before-Mount Hardening

## What changed

- Hardened English-policy activation lifecycle HTTP routes so activation, revocation, status, and conflict-review paths require an explicit operator bearer token instead of relying on loopback auto-auth.
- Removed live policy and raw conflict data from activation lifecycle responses. The HTTP boundary now returns generic success/failure status plus an operator-facing audit reference.
- Updated the policy CLI draft lifecycle commands to require `SANCTUARY_POLICY_API_TOKEN` and stop printing raw conflict objects from the server.

## Tests

- `cd server && npm run typecheck` — passed.
- `cd server && npm test` — passed: 5457 passed, 8 skipped, 5465 total.
- Baseline floor: `.test-baseline` is 5423; passing count did not drop below baseline.

## Focused coverage added/updated

- `server/test/policy-engine/english-policy-activator.test.ts`
  - Activation route refuses a non-operator caller before policy mutation.
  - Activation, revocation, status, and conflict-review route responses do not return `updated_policy`, full records, or raw conflicts.
  - Activation failures return generic `activation_refused` without detailed policy/conflict data.
- `server/test/cli/singleton-audit-writes.test.ts`
  - Existing activation failure audit test now supplies the required operator API token.

## Assumptions

- The operator-auth primitive for this latent `/api/policy` surface is the existing dashboard/console bearer token. For mutation lifecycle routes, this change intentionally fails closed when no bearer token is configured, even if loopback auto-auth is enabled.
