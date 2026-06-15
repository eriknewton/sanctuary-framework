# Castle Wall headless arm/disarm — SHIPPED in PR #448

Status: **SUPERSEDED 2026-06-10.** This was a design-only document (F1
deliverable 2). Headless arm/disarm now ships as real code in PR #448
(`feat(castle-wall): headless arm/disarm — sanctuary castle-wall enable|disable`),
so the design draft below is retired. The boot service (this directory's
[`castle-wall-macos-boot-service.md`](castle-wall-macos-boot-service.md))
**composes with** #448: the boot service brings the daemon up at reboot; arm
and disarm stay #448's surface.

## What shipped (use this, not the draft)

- `sanctuary castle-wall enable` — arm the content filter headlessly (SSH-safe
  after the one-time GUI content-filter consent). Refuses unless a policy
  daemon socket is reachable (so arming cannot create the deny-all brick);
  `--force` overrides. Verifies the post-change state via the host app's
  `--headless status` rather than assuming success.
- `sanctuary castle-wall disable` — disarm headlessly; an unconditional
  dead-man recovery lever.

Mechanism (as built in #448): the **signed host-app binary itself** is run in a
non-GUI `--headless <enable|disable|status>` mode. Running the host-app binary
is load-bearing because the NEFilterManager configuration is owned by the
signed app identity that created it, so only that binary can toggle `isEnabled`
without re-prompting. The one-time content-filter consent is the only step that
stays GUI (exit code 3 signals it is missing). See the #448 commit and the
Swift `HeadlessFilterCLI` / TypeScript `runEnable` / `runDisable` for the
authoritative behavior, peer-auth, and exit-code contract.

## Why the original CLI-direct path was rejected (kept for the record)

The CLI cannot call `NEFilterManager` directly: the
`com.apple.developer.networking.networkextension` /
`content-filter-provider-systemextension` entitlement is provisioning-profile
gated and attaches only to app bundles, the filter configuration is owned by
the app that saved it, and the calls require a logged-in user context. That is
why #448 mediates through the signed host-app binary rather than entitling the
`sanctuary` CLI. The fully-logged-out path (MDM content-filter payload on a
supervised machine) remains out of scope for a personal fortress.
