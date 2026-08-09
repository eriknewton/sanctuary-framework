/**
 * Sanctuary Lockdown - Public surface.
 *
 * The coarse global lockdown status flag. One on-disk record at
 * `lockdown/status.json` (active + activated_at + optional reason),
 * written with restrictive 0o600/0o700 modes, plus the operator
 * banner string consumed by the CLI surfaces.
 *
 * Distinct from the principal-policy gate: lockdown is a single
 * fortress-wide boolean read by CLI/banner surfaces today. It does not block
 * writes by itself; write gating must read this status before claiming
 * enforcement.
 */

export * from "./status.js";
