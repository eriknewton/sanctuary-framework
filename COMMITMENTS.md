# Sanctuary commitments

This page lists every promise Sanctuary makes to the people who run it. Each promise says how strong its evidence is, where it is enforced, where it holds, what it does not cover, and how you can check it yourself. If a promise here and the [Assurance Matrix](ASSURANCE_MATRIX.md) ever disagree, the matrix is right and this page is wrong.

## How to read a promise

- **Evidence.** *drill* means we ran the shipped product on the named platform and published the record. *tests* means automated tests back it, but no one has yet run it end to end on a real machine and published the result. *stated* means it is our word only: nothing yet would catch us breaking it. We list stated promises anyway, so you can hold us to them.
- **Enforced.** *below the agent* means your operating system enforces it, so an agent cannot switch it off from inside its own account. *cooperative code* means Sanctuary's own program does it; an agent that does not go through Sanctuary is not stopped by it. *release process* means it is a property of how we build and publish releases.
- **Backed by.** The row of the Assurance Matrix that holds the evidence and the full list of gaps.

## How these promises change

A change to any promise below, or to the evidence behind it, is labelled in its pull request, listed under "Commitments changed" in the [changelog](CHANGELOG.md), and published in a preview release (npm's `next` channel) at least seven days before it can reach the stable channel. Nothing updates itself, so you see a change before you could receive it. One exception: when we learn a promise is wider than the truth, we narrow it at once and say so; we do not wait. If the reason is a security problem whose fix is not yet released, the narrowed wording says what the promise now covers and not why, so that it points no one at the problem. A withdrawn promise stays at the bottom of this page with the version that withdrew it.

To compare the promises in two versions, run `git diff v<older> v<newer> -- COMMITMENTS.md` in a clone of this repository. Releases made before this page existed have nothing to compare.

## What no promise here covers

- What your agent sends to the model provider you chose. That provider sees it.
- A machine someone else fully controls: an administrator, malware running as you, or a hosted server you do not own.
- Tools and programs your agent uses that do not go through Sanctuary.

## C-01. Sanctuary does not update itself.

- Backed by: none yet
- Evidence: stated
- Enforced: cooperative code
- Holds on: every install from npm
- Limit: `sanctuary protect` writes one exact version into your harness settings, and a newer version arrives only when you run `protect` again. Any program running as your user account can edit those settings.
- Check it yourself: in your harness settings (for Claude Code, `~/.claude.json`), find `@sanctuary-framework/mcp-server@` and the version number after it.

## C-02. Every 1.8 release carries a signature you can check yourself.

- Backed by: none yet
- Evidence: stated
- Enforced: release process
- Holds on: the npm package `@sanctuary-framework/mcp-server`, releases 1.8.0 and later
- Limit: One signing key, held by the project, signs every release. A valid signature shows the file is the one that key signed. It does not show independent review.
- Check it yourself: follow "Verify Before You Trust" in `SECURITY.md`; the last step is `node scripts/verify-release-artifact.mjs --tarball <file> --manifest release-manifest.json --version <version> --expected-public-key <key>`.

## C-03. Sanctuary makes no network connection you did not ask for.

- Backed by: No unrequested network contact (observed by packet capture)
- Evidence: drill
- Enforced: cooperative code
- Holds on: Linux (Docker container on one x86-64 host); npm package 1.8.4 only
- Limit: This is about Sanctuary's own program, and it is what we saw it do, not proof that it cannot connect. Installing it contacts the npm registry, and in a session started through `npx` the registry is contacted before the server first answers; after that answer, no new connection opened. Update checks, publishing to a public transparency log, and local model downloads connect only when you turn them on. Your agent, your harness and your model provider make their own connections, which this promise does not cover.
- Check it yourself: read `docs/audit/zero-outbound-linux-drill-2026-11-20.md`

## C-04. Your keys are created on your machine, and no copy is sent to us.

- Backed by: none yet
- Evidence: stated
- Enforced: cooperative code
- Holds on: every platform
- Limit: Your keys are protected by your passphrase, your recovery key, and your operating system's keychain where one is used. Anyone who has your passphrase or recovery key, or full control of your machine while Sanctuary is unlocked, can use them. If you choose a hosted setup, you are trusting the host.
- Check it yourself: none yet

## C-05. What Sanctuary stores is encrypted, and a tampered entry fails to open.

- Backed by: State encryption
- Evidence: tests
- Enforced: cooperative code
- Holds on: Cross-platform server storage
- Limit: Tests show the encryption and the tamper refusal. They do not prove how safe your machine's keychain or key hardware is. A program running as you while Sanctuary is unlocked is outside this promise.
- Check it yourself: none yet

## C-06. Actions you require approval for wait for you, and are refused if you cannot be reached.

- Backed by: Approval gating (Tier 1 / Tier 2 / Tier 3 policy)
- Evidence: tests
- Enforced: cooperative code
- Holds on: Cross-platform server
- Limit: This covers actions an agent takes through Sanctuary's tools. An agent that uses other tools, or acts outside Sanctuary, is not gated by it. No end-to-end run through the approval screens has been recorded yet.
- Check it yourself: none yet

## C-07. Sanctuary keeps a tamper-evident record of what it did, and you can check that record.

- Backed by: Tamper-evident audit chain
- Evidence: tests
- Enforced: cooperative code
- Holds on: Cross-platform server audit log
- Limit: Some kinds of deletion can be caught only by checking a copy on another machine, and that independent check has not been run and published yet.
- Check it yourself: `sanctuary audit-chain export --output chain.jsonl`, then `sanctuary audit-chain verify --input chain.jsonl`

## C-08. You can take your data and leave.

- Backed by: Export / exit bundle
- Evidence: tests
- Enforced: cooperative code
- Holds on: Cross-platform server and CLI
- Limit: The dashboard's export is not a complete exit bundle. An import does not yet report every entry it skips. State saved before a change of identity key may not carry across. Some memory held by the Sovereign Data Warehouse is not covered by exit yet.
- Check it yourself: `sanctuary exit export --out ./exit-bundle`, then `sanctuary exit verify ./exit-bundle`

## C-09. On Ubuntu 24.04, an agent in its own account reaches only the destinations your signed policy allows.

- Backed by: Egress enforcement: Linux (Castle Wall Phase 1)
- Evidence: drill
- Enforced: below the agent
- Holds on: Linux (Ubuntu 24.04, x86-64 only)
- Limit: Needs the separate Castle Wall Linux 0.1.0-1 package, installed and armed. Proven for rules naming exact addresses, on fresh installs on three servers from one provider, with a test program standing in for the agent. Rules by hostname, other distributions and processors, and failure cases are not proven. It controls where traffic can go, not what an allowed connection carries.
- Check it yourself: read `docs/audit/castle-wall-linux-install-grade-drill-2026-10-04.md`; check the package with `sha256sum -c sanctuary-castle-wall_0.1.0-1_amd64.deb.sha256`

## C-10. On macOS, an agent in its own account is blocked from destinations your signed policy does not allow, including after restarts you attend.

- Backed by: Egress enforcement: macOS (Castle Wall Phase 1)
- Evidence: drill
- Enforced: below the agent
- Holds on: macOS
- Limit: Needs the Castle Wall app and its system extension, installed and armed. Proven on one Mac running one macOS version. Restarts with no one present, and a record of every connection, are not proven. It controls where traffic can go, not what an allowed connection carries.
- Check it yourself: read the `docs/audit/castle-wall-macos-*` drill records; compare `shasum -a 256 Sanctuary-CastleWall.app.zip` with the SHA-256 in `README.md`

## C-11. An agent confined by Castle Wall cannot rewrite its own network rules.

- Backed by: Egress enforcement: Linux (Castle Wall Phase 1); Egress enforcement: macOS (Castle Wall Phase 1)
- Evidence: tests
- Enforced: below the agent
- Holds on: Linux (Ubuntu 24.04, x86-64 only); macOS
- Limit: The wall applies only rules signed with your key, and the drills ran signed rules. Attempts to change the rules have been tested, not drilled. If an agent can read your signing key, this promise does not hold. It applies only where Castle Wall is installed and armed.
- Check it yourself: none yet

## C-12. Sanctuary's tools never return your private keys.

- Backed by: none yet
- Evidence: stated
- Enforced: cooperative code
- Holds on: every platform
- Limit: Tests cover the export path. No automatic check yet covers every response, log entry and error message.
- Check it yourself: none yet

## Withdrawn

None yet.
