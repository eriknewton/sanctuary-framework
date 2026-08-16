# Custody recovery posture: machine-resident factors never bootstrap human-held custody

Status: ratified security posture (Erik Newton, 2026-07-22). This document records a
deliberate decision so it is never re-litigated as an accidental gap.

## The posture

The OS-keyring custody key (macOS Keychain / Linux Secret Service; see
`src/wrap/keychain-custody.ts`) can **unlock** the fortress master for daily use, but no
CLI verb, MCP tool, or recovery flow may use a keychain-only unlock to **establish new
human-held custody**: that is, to enroll a new passphrase wrap, mint a new recovery
key, or rotate the master. Custody-changing ceremonies require presenting an existing
human-held credential: the fortress passphrase (`sanctuary rotate-master`) or the
recovery key (`sanctuary reset-passphrase` / recovery-unlock enrollment).

## Why

The keychain factor is machine-resident: it is released to any process running in the
user's logged-in session. If it could bootstrap new human-held credentials, then anyone
with momentary access to an unlocked machine (a stolen-but-open laptop, a hostile
process running as the user, a "just borrowing it" housemate) could silently mint
themselves a new recovery key and own the fortress's custody from that point on, without
ever knowing a secret the operator holds. Keeping custody changes gated on a human-held
credential means custody takeover always requires something an attacker at the keyboard
does not have.

This is the same shape as the wall's design rule: every protection is enforced below the
party with an incentive to violate it. The machine is not the custodian; the human is.

## The consequence, stated honestly

If the operator loses **both** human-held factors (passphrase AND recovery key) while
the keychain still unlocks, the fortress keeps working day-to-day but there is **no
supported path to re-establish human-held custody** from that state. The supported
options are exactly the `sanctuary reset-passphrase` menu:

1. **shares**: reconstruct the master from M-of-N recovery shares, if previously
   persisted (not configured by default in v1.0.x).
2. **guardian**: guardian-quorum recovery via the federation, where a mesh exists.
3. **nuke**: destroy and re-initialize, after a Tier-1-gated `state_export` of
   anything worth keeping (the running system can still export while the keychain
   unlocks).

Two of those three are not reachable on a stock fortress today, and the menu says so at
the moment you need it least. `shares` requires `recovery-shares.json` to have been
persisted in advance; `guardian` reports itself unavailable unconditionally, because the
transport ships with the v1.1 full mesh. On a fortress that configured neither, the menu
that appears in this state offers exactly one usable path: `nuke`. Plan for that before
you are in it.

Two failure modes worth knowing before you run `sanctuary reset-passphrase`:

- **It refuses while anything is still running.** The command aborts if `runtime.json`
  exists under the storage path, which it does whenever a dashboard or a wrapped agent
  is live. From the outside this reads as a broken recovery tool at the worst possible
  moment. Close the dashboard and stop every wrapped agent first, then re-run.
- **The export has to come first.** `nuke` destroys state and re-initializes; once it
  completes there is nothing left to export, and the keychain unlock that made the export
  possible is gone with the fortress it unlocked. Run the Tier-1-gated `state_export` and
  confirm the artifact is readable off-host **before** selecting option 3.

An operator who discovers they are in this state should treat the fortress as on
borrowed time: export state through the gated flow, re-initialize, and re-establish
full custody.

## If this is ever relaxed

A future affordance ("re-enroll a passphrase from a keychain unlock") is only
acceptable with, at minimum: (a) fresh OS-level re-authentication of the human
(Touch ID / password re-prompt via the keyring's own auth, not mere session
possession), (b) an interactive TTY ceremony with the same off-host capture +
re-entry verification as `rotate-master`, and (c) an explicit ratified decision
recorded here superseding this posture. Absent all three, the absence of that verb
is the security property, not a missing feature.

## Cross-references

- `src/wrap/keychain-custody.ts`: the machine-resident factor this posture bounds.
- `src/cli/reset-passphrase.ts`: the lost-credential recovery menu (shares/guardian/nuke).
- `src/cli/rotate-master.ts`: passphrase-gated master rotation (the lost-recovery-key remedy).
- `src/core/master-custody.ts`: the custody envelope, wraps, and two-factor floor.
