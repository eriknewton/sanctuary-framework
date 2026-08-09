# NF-07 Stop Button Mutation Proof

Date: 2026-08-09

Scope: NF-07 per-agent network stop, fortress lockdown truthfulness, and unsupported unwrap pre-enqueue refusal.

Note: the spec names `snapshotIsGreen`; this implementation consumes `ResolvedEnforcementAvailability.status`, whose `live` value is derived from the same green/non-green resolver path. The M1 and M2 mutations were applied to the `resolved.status` gate.

## Results

| ID | Result |
|---|---|
| M1 | PASS - non-green enforcement mutation failed the guard test. |
| M2 | PASS - indeterminate enforcement mutation failed the guard test. |
| M3 | PASS - residual-rule mutation failed the guard test. |
| M4 | PASS - reload-confirmation mutation failed the guard test. |
| M5 | PASS - uid/protection-subject mutation failed the guard test. |
| M6 | PASS - habeas-preservation mutation failed the guard test. |
| M7 | PASS - fortress zero-effect audit mutation failed the guard test. |
| M8 | PASS - fortress status-write mutation failed the guard test. |
| M9 | PASS - placeholder-controller mutation failed both wiring guards. |
| M10 | PASS - pre-enqueue unwrap mutation failed the guard test. |
| M11 | PASS - predicate-parity mutation failed the guard test. |
| M12 | PASS - scrub survivor-check mutation failed the guard test. |

## M1 - Enforcement Probe Gate

One-line mutation:

```ts
if (false && resolved.status !== "live") {
```

Test:

```sh
npx vitest run test/castle-wall/provision/agent-stop.test.ts -t "refuses non-green enforcement"
```

Captured failing output:

```text
FAIL  stopAgentEgress > refuses non-green enforcement without removing files
AssertionError: expected Error: stop unexpectedly succeeded to be an instance of AgentEgressStopError
```

## M2 - Indeterminate Is Not Green

One-line mutation:

```ts
if (resolved.status !== "live" && resolved.status !== "undetermined") {
```

Test:

```sh
npx vitest run test/castle-wall/provision/agent-stop.test.ts -t "refuses indeterminate enforcement"
```

Captured failing output:

```text
FAIL  stopAgentEgress > refuses indeterminate enforcement without removing files
AssertionError: expected Error: stop unexpectedly succeeded to be an instance of AgentEgressStopError
```

## M3 - Residual-Rule Assertion

One-line mutation:

```ts
if (false && residual.length !== 0) {
```

Test:

```sh
npx vitest run test/castle-wall/provision/agent-stop.test.ts -t "residual agent-matchable reachability survives"
```

Captured failing output:

```text
FAIL  stopAgentEgress > restores the snapshot and reports failure when residual agent-matchable reachability survives
AssertionError: expected Error: stop unexpectedly succeeded to be an instance of AgentEgressStopError
```

## M4 - Reload Confirmation

One-line mutation:

```ts
if (false && !reload.ok) {
```

Test:

```sh
npx vitest run test/castle-wall/provision/agent-stop.test.ts -t "reports partial on unconfirmed reload"
```

Captured failing output:

```text
FAIL  stopAgentEgress > reports partial on unconfirmed reload and leaves files revoked
AssertionError: expected { outcome: 'engaged', ... } to match object { outcome: 'partial', ... }
Expected outcome: "partial", reload_confirmed: false
Received outcome: "engaged", reload_confirmed: true
```

## M5 - Uid Binding Cross-Check

One-line mutation:

```ts
(false && input.protectionSubject !== expectedSubject)
```

Test:

```sh
npx vitest run test/castle-wall/provision/agent-stop.test.ts -t "protection_subject does not match"
```

Captured failing output:

```text
FAIL  stopAgentEgress > refuses when protection_subject does not match the confined uid
AssertionError: expected Error: stop unexpectedly succeeded to be an instance of AgentEgressStopError
```

## M6 - Habeas Preservation

One-line mutation:

```ts
return true;
```

Test:

```sh
npx vitest run test/castle-wall/provision/agent-stop.test.ts -t "preserves habeas"
```

Captured failing output:

```text
FAIL  stopAgentEgress > revokes agent-matchable allows, preserves habeas and operator rules, and lift restores bytes
AssertionError: expected [ 'agent-allow-a', ... ] to deeply equal [ 'agent-allow-a', 'agent-allow-b' ]
Received extra id: "reserved_habeas_distresslocal"
```

## M7 - Fortress Zero-Effect Record

One-line mutation:

```ts
const operation = "fortress_lockdown_engaged";
```

Test:

```sh
npx vitest run test/hub/fortress-tier1.test.ts -t "all-fail emits fortress_lockdown_failed"
```

Captured failing output:

```text
FAIL  Fortress lockdown zero-effect outcomes > all-fail emits fortress_lockdown_failed, writes no active status, and never emits engaged
AssertionError: expected false to be true
The activity feed did not contain "fortress_lockdown_failed".
```

## M8 - Fortress Status Write

One-line mutation:

```ts
if (this.deps.storagePath) {
```

Test:

```sh
npx vitest run test/hub/fortress-tier1.test.ts -t "all-fail emits fortress_lockdown_failed"
```

Captured failing output:

```text
FAIL  Fortress lockdown zero-effect outcomes > all-fail emits fortress_lockdown_failed, writes no active status, and never emits engaged
AssertionError: expected { active: true, ... } to match object { active: false }
```

## M9 - Wired Controller

Mutation:

```ts
agentController: { supports: () => false, ... } // CapabilityErrorAgentController
```

Test:

```sh
npx vitest run test/dashboard/v1_1/castle-wall-agent-controller.test.ts
```

Captured failing output:

```text
FAIL  CastleWallAgentController > production v1.1 wiring installs the Castle Wall controller and reaches the stop chokepoint
AssertionError: expected { supports: [Function supports], ... } to be an instance of CastleWallAgentController

FAIL  CastleWallAgentController > does not leave the old placeholder controller in the shipped source tree
AssertionError: expected [ Array(1) ] to deeply equal []
Received: server/src/dashboard/v1_1/wiring.ts
```

## M10 - Pre-Enqueue Unwrap Refusal

One-line mutation:

```ts
const executorSupports = true;
```

Test:

```sh
npx vitest run test/hub/hub-v1.1.test.ts -t "refuses unsupported unwrap before creating an approval item"
```

Captured failing output:

```text
FAIL  Hub Tier 1 enqueue executor support > refuses unsupported unwrap before creating an approval item
AssertionError: expected 202 to be 422
```

## M11 - Predicate Parity

One-line mutation:

```ts
return filenames.filter((filename) => filename.endsWith(".json")).length;
```

Test:

```sh
npx vitest run test/castle-wall/provision/agent-stop.test.ts -t "selects the same full set"
```

Captured failing output:

```text
FAIL  agent-matchable allow predicate > selects the same full set the arm guard counts and treats malformed JSON as false
AssertionError: expected 5 to be 1
```

## M12 - Scrub Survivor Check

One-line mutation:

```ts
if (false && survivors.length > 0) {
```

Test:

```sh
npx vitest run test/castle-wall/provision/egress.test.ts -t "selected survivor"
```

Captured failing output:

```text
FAIL  castle-wall/provision/egress: publish + scrub (hermetic tmp fortress) > scrub fails when the verified read-back still sees a selected survivor
AssertionError: promise resolved "{ ... }" instead of rejecting
Received reloadOk: true, removedRuleIds: [ "provisioned-hermes-aaaaaaaaaaaa" ]
```
