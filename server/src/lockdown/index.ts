/**
 * Sanctuary Lockdown - Public surface.
 *
 * The coarse fortress lockdown marker. One on-disk record at
 * `lockdown/status.json` (active + activated_at + optional reason),
 * written with restrictive 0o600/0o700 modes, plus the operator
 * banner string consumed by the CLI surfaces.
 *
 * Distinct from the principal-policy gate: lockdown is a single marker
 * for a fortress-wide network revocation event, not the per-operation
 * graduated consent the gate owns.
 */

export * from "./status.js";
