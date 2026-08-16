/**
 * THE account-name contract: the single source of truth for what a
 * Sanctuary-provisioned service-account name may look like and which
 * privileged names are refused everywhere.
 *
 * ZERO-IMPORT MODULE, deliberately (modeled on `audit/checkpoint-shape.ts`).
 * Its three consumers sit on both sides of the castle-wall/egress-gate
 * boundary, and two of them (`egress-gate/gate-daemon.ts`,
 * `egress-gate/harness-daemon.ts`) render world-readable LaunchDaemon plists
 * and are kept dependency-light on purpose. They can consume this module
 * precisely because importing it drags in nothing: it must never gain a
 * dependency edge of any kind -- not a static or bare side-effect import,
 * not an `export ... from` re-export, and not a dynamic-import or CommonJS
 * require CALL (the guard scans for those two call shapes anywhere in this
 * file, comments included, which is why this sentence spells them without
 * their parentheses). `test/structure/cross-file-contract-pins.test.ts`
 * fails on any of those shapes and separately asserts that no consumer
 * re-declares these values.
 *
 * HISTORY: until 2026-08-15 (G6) each of the three sites re-declared both
 * values locally, with pin comments and a structural equality test keeping
 * them in lockstep. That made drift DETECTED; single-sourcing makes it
 * impossible by construction. The 2026-08-05 `admin` drift (register G1) is
 * the incident that motivated first the test, then this module.
 */

/**
 * POSIX-ish service-account name: lowercase start, then a conservative
 * charset, 64 chars max. This rejects anything that could smuggle shell
 * metacharacters or spaces into a `dscl`/`sysadminctl` argv, and anything
 * that could smuggle plist markup into a rendered LaunchDaemon.
 */
export const SAFE_SERVICE_ACCOUNT_RE = /^[a-z_][a-z0-9._-]{0,63}$/;

/**
 * Privileged account names no Sanctuary-provisioned service account may take
 * and no Sanctuary daemon may run as. All consuming sites refuse the same
 * set: provisioning (`castle-wall/provision/account.ts`), the egress-gate
 * daemon plist renderer (`egress-gate/gate-daemon.ts`), and the agent-harness
 * daemon plist renderer (`egress-gate/harness-daemon.ts`).
 *
 * DECISION 2026-08-05 (Erik-ratified: WIDEN). An earlier version of this
 * comment (then on `account.ts`) recorded the daemon-side asymmetry as
 * deliberate and warned against reconciling it: the two daemons refused
 * `root`/`_root`/`daemon`/`wheel` only, so `admin` was an illegal agent
 * account name and a LEGAL gate or harness daemon account name. That guidance
 * is retired. On macOS an account named `admin` is conventionally in the
 * `admin` group and therefore holds sudo, so a gate or harness running as it
 * could rewrite the very policy its confinement exists to enforce. All three
 * sites refuse the same five names.
 *
 * WHAT THE WIDENING WAS CHECKED AGAINST, stated exactly as narrowly as it was
 * checked. In THIS REPO nothing is affected: every account name the product
 * uses is prefix-derived (`deriveAgentAccountName` -> `sanctuary-<agentId>`,
 * `deriveGateAccountName` -> `sanctuary-gate-<agentId>`), no CLI flag lets an
 * operator supply an account name, and a repo-wide scan found no default,
 * fixture, doc, test, or derived name equal to a reserved one. That is a
 * statement about the repo, NOT about hosts in the field. The only host
 * evidence is a coordinator check of two machines on 2026-08-05 (Mini1 and
 * Mini2): no Sanctuary daemon runs as `admin` on either -- the harness and
 * the LT executor run as `sanctuary-hermes`, and the castle-wall daemons and
 * signer helpers run as root. Nothing is known about any other host.
 *
 * KNOWN BEHAVIOR CHANGE (of the 2026-08-05 widening), and it is a refusal,
 * not a migration: a plist naming `admin` -- hand-written, or re-rendered
 * from any path that supplies an operator-chosen account name -- now throws
 * at render time where it previously rendered. (An earlier draft of this note
 * claimed a stale PERSISTED `gateAccountName` field was such a path; a
 * re-gate found no reader for one. `arming-wiring.ts` holds the name in
 * memory, and boot derives the gate account from the marker, so the
 * persisted-field route named here did not exist.) Failure mode from the
 * outside: an install or re-arm that used to complete stops with a "refusing
 * to render ... privileged account" error, which is the intended outcome and
 * is loud, never a silent downgrade.
 *
 * Typed `ReadonlySet`, which is a COMPILE-TIME constraint only: the value is
 * a normal mutable `Set`, so a determined consumer could still mutate it at
 * runtime. It is not re-exported through the provision barrel; its importers
 * are the three refusal sites and the structural guard (which iterates the
 * real runtime set and drives every member through each refusal site), and
 * that narrow surface is what actually bounds the exposure.
 */
export const RESERVED_ACCOUNT_NAMES: ReadonlySet<string> = new Set([
  "root",
  "_root",
  "daemon",
  "wheel",
  "admin",
]);
