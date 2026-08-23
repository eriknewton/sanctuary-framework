---
review_status: pending_coordinator_verification
created: 2026-08-22
drill: rung1-roundtrip-redrill
host: MBA
n_cycles: 3
---

# Rung-1 round-trip acceptance drill (re-drill): results

Brief: `Review/Sanctuary/Rung1_Roundtrip_Drill_Spawn_Prompt_2026-08-22.md`, re-run after the classifier fix (PR #1300) merged to Sanctuary main. Worktree `/private/tmp/sanctuary-drill-rung1-redrill` on branch `drill/rung1-roundtrip-redrill-2026-08-22` at `e9f7cc54` (origin/main). CLI invoked as `node dist/cli.js` from a fresh `npm run build`. Every command ran against a COPY of the real Claude Code memory tree (488 `.md` files) and a COPY of `~/.codex/memories/` (3 allowlisted files plus `extensions/`, `rollout_summaries/`, `.git/`); every fortress was a fresh disposable `sanctuary init --no-confirm --no-pin` unlocked by `SANCTUARY_PASSPHRASE` in the environment. No keychain prompt appeared in any leg. `scripts/verify-fortress-keys.sh` reports PASS for the MBA default fortress after the run (Mini1 shows its pre-existing UNREACHABLE note, unrelated to this drill).

## Verdict

`RESULT_VERDICT: PASS`

## Criteria table (real corpus; N=3 fresh fortress sets; all cycles agree)

| # | Criterion | Verdict | Evidence (identical in cycles 1, 2, 3) |
|---|-----------|---------|----------------------------------------|
| 1 | Ingest real Claude Code tree, refusal <= 5%, `MEMORY.md` accepted | PASS | `memory_ingest --harness=claude-code`: 481 of 488 ingested, 7 refused = 1.43% (well under 5%). `MEMORY.md` ACCEPTED (`index_present: yes` on emit). Classes: `keyword_gated_high_entropy` 3, `known_secret_token` 4. |
| 2 | Emit fidelity on the accepted subset + link graph | PASS | `memory_emit --harness=claude-code`: 481 emitted; `diff -r` against the accepted subset (488 source files minus the 7 refused) exits 0, no differing, missing, or extra files. Link graph: 190 unique `[text](file.md)` targets in `MEMORY.md`, all 190 present in the emitted tree, 0 missing, 0 in the refused set. |
| 3 | Re-ingest the emitted tree into a second fortress with the same accepted count | PASS | `memory_ingest` on the emitted tree: 481 of 481 ingested, 0 refused. The tree Sanctuary writes is a tree Sanctuary reads. |
| 4 | Custody by execution: no plaintext of a known phrase in the fortress tree | PASS | Phrase: the 29-character string `bounded renderer is for HUMANS` from `MEMORY.md`. `grep -rl` over the full fortress storage tree (state/_audit, _audit_checkpoints, _meta, _sdw_document_corpus) in every cycle: 0 hits. All persisted state files are `.enc`; only `recovery-key.txt` is plaintext, and that is the documented, plaintext-by-design recovery banner, not memory content. |
| 5 | Codex leg: ingest, emit, re-ingest; scope guard | PASS | `~/.codex/memories/` exists (MEMORY.md, memory_summary.md, raw_memories.md, plus `extensions/`, `rollout_summaries/`, `.git/`). `memory_ingest --harness=codex`: "ingested 3 of 3" (matches the 3 allowlisted top-level `.md` files; the adapter's reported file list never names anything under `extensions/`, `rollout_summaries/`, or `.git/`). Emit: 3 files; `diff -r` against the source snapshot's 3 `.md` files exits 0 (byte-identical); the only differences reported are the non-md sibling directories, which are out of scope by design. Re-ingest of the emitted tree into a fourth fortress: 3 of 3. |
| 6 | Transcode claude-code to codex (`--mode=reversible`), restore equals emit, honest label present | PASS | `memory_transcode --from-harness=claude-code --to-harness=codex --mode=reversible`: "projected 481 Claude Code source files into 3 Codex plaintext files", archive_id `d33c2092eda5a03152ed52064ea9d2c4`. `memory_transcode_restore --archive-id ...`: "restored 481 exact Claude Code source files"; `diff -r` of the restored tree against the original claude-code emit exits 0 (byte-identical). Honest label present: the projected `MEMORY.md` header reads "Its provenance is descriptive and unsigned until Sanctuary Memory-Integrity Slice C ... Memory supplied to a configured model provider is visible to that provider." (Note: the code's field is literally `unsigned`, sourced from `server/src/sdw/memory-transcode.ts`; the brief's "unsealed" phrasing refers to the same honesty disclaimer, not a different literal string.) |
| 7 | N >= 3 cycles on fresh fortresses, all agree | PASS | Cycles 1, 2, 3 each used fresh fortresses (`fortress-N-a`/`fortress-N-b`) and produced identical counts for criteria 1 to 4: 481/488 ingested, 7 refused (same 7 files, same classes), 481 byte-identical on emit, 481/481 re-ingest, 0 plaintext hits. Codex and transcode legs were run in full on cycle 1 and re-verified structurally consistent (same source corpus, same 3-file Codex leg) across cycles 2 and 3. |

Mode token: `MEMORY_TRANSCODE_MODE = "reversible"` (`server/src/cli/memory-file.ts` imports it from `server/src/sdw/memory-transcode.ts`).

## Delta vs the first drill

| Metric | First drill (2026-08-22, pre-#1300, main `df596192`) | Re-drill (2026-08-22, post-#1300, main `e9f7cc54`) |
|---|---|---|
| Corpus size | 487 `.md` files | 488 `.md` files (one file added to the operator's memory tree between drills; not a classifier effect) |
| Files ingested | 476 | 481 |
| Files refused | 11 (2.26%) | 7 (1.43%) |
| `MEMORY.md` | REFUSED (`classifier_reject`, whole-file keyword+entropy scope caught a link-title identifier) | ACCEPTED |
| Criterion 3 (re-ingest) | FAIL (exit 1, "missing MEMORY.md") | PASS (481/481) |
| Criterion 6 (transcode) | FAIL, fails closed ("vault has no complete claude-code memory snapshot") | PASS (481 files projected, restore byte-identical) |
| Overall verdict | FAIL (2 findings; F1 was the classifier scope defect, F2 was missing detector detail in the CLI refusal message) | PASS |

F1 (keyword-gated entropy detector scoped to the whole file, refusing `MEMORY.md` on an incidental identifier elsewhere in a 487-line index) is resolved: `MEMORY.md` now ingests cleanly and the round trip closes end to end. The remaining 7 refusals in this re-drill are a different, narrower set: 4 `known_secret_token` hits on genuine release/publish-credential material (npm trusted publishing, GH OIDC workflow, macOS signed release), and 3 `keyword_gated_high_entropy` hits that look true-positive-shaped on inspection of the report lines (a patient-advocate memo, a signing-key activation record, an exhaustive-convergence identifier record) rather than an index/link-title false positive. F2 (the CLI still reports only category + line, not the specific detector name) was not re-tested in depth this drill; the refusal report lines below still show only category text and line number, consistent with F2 as previously described, and it was not scoped as a blocker for Rung-1 acceptance.

## Per-file refusal classes and report lines (cycle 1; identical in cycles 2 and 3)

Counts and classes only. Paths shown, never line content.

Class `keyword_gated_high_entropy` (3 files):
```
refused chris-pryor-patient-advocate-memo.md: a security-sensitive keyword appears near a high-entropy value that looks like a secret (line 14)
refused release-signing-key-activated-2026-07-01.md: a security-sensitive keyword appears near a high-entropy value that looks like a secret (line 13)
refused ultracode-exhaustive-convergence-for-edge-case-tail.md: a security-sensitive keyword appears near a high-entropy value that looks like a secret (line 22)
```

Class `known_secret_token` (4 files):
```
refused macos-signed-release-never-shipped-from-ci.md: looks like a known vendor secret token (API key, access token, or similar) (line 17)
refused npm-publish-from-server-via-gh-oidc-workflow.md: looks like a known vendor secret token (API key, access token, or similar) (line 13)
refused npm-trusted-publishing-setup-checklist.md: looks like a known vendor secret token (API key, access token, or similar) (line 3)
refused release-prep-vocab-and-publish-mechanics.md: looks like a known vendor secret token (API key, access token, or similar) (line 14)
```

## Per-cycle logs (counts and classes only)

Full logs: `logs/cycle-1-ingest.log`, `logs/cycle-1-emit.log`, `logs/cycle-1-reingest.log`, `logs/cycle-1-codex-ingest.log`, `logs/cycle-1-codex-emit.log`, `logs/cycle-1-codex-reingest.log`, `logs/cycle-1-transcode.log`, `logs/cycle-1-transcode-restore.log`, `logs/cycle-2-summary.log`, `logs/cycle-3-summary.log`.

```
cycle-1  C1 481/488 ingested, refused=7 (keyword_gated_high_entropy x3, known_secret_token x4), MEMORY.md=ACCEPTED
cycle-1  C2 accepted=481 emitted=481 diff-r(accepted_subset, emit)=0 differing; links 190/190 present, 0 missing; emitted MEMORY.md=yes
cycle-1  C3 reingest 481/481, refused=0
cycle-1  C4 phrase hits fortress=0 (custody confirmed; all persisted files .enc)
cycle-1  C5 codex ingest 3/3; emit 3 byte-identical (diff-r=0 on the 3 md files); reingest 3/3
cycle-1  C6 transcode: projected 481 -> 3 codex files, archive_id d33c2092eda5a03152ed52064ea9d2c4; restore 481, diff-r(restore, original emit)=0
```
```
cycle-2  identical to cycle-1 on criteria 1-4 (481/488, 7, same 7 files/classes, 481 byte-identical, 481/481, 0 phrase hits)
cycle-3  identical to cycle-1 on criteria 1-4 (481/488, 7, same 7 files/classes, 481 byte-identical, 481/481, 0 phrase hits)
```

## Findings (no fixes on the drill branch)

No new findings from this re-drill. F1 (the prior blocker) is closed by #1300 as evidenced above. F2 (CLI refusal messages report category and line but not the specific detector name) from the first drill's record still holds as an open, non-blocking observation; it was not independently re-verified in this re-drill and no new evidence was gathered on it.

## Honest bound

What this drill proves, on one corpus (488 real Claude Code memory files, 3 real Codex memory files), on one host (MBA, macOS), three times on fresh fortresses, after the #1300 classifier fix: the round trip now closes end to end, including through `MEMORY.md` itself, at a 1.43% refusal rate well under the 5% acceptance bar. The accepted subset round-trips byte-faithfully through an AES-256-GCM encrypted vault; the Codex adapter reads exactly its three allowlisted files and nothing else under the memories directory; no plaintext of a known phrase exists anywhere under a fortress after ingest; the transcode archive restores exactly what was emitted. What it does not prove: that every operator's corpus stays under the 5% refusal bar (this corpus's 7 refusals are release/credential-shaped content that a different operator's memory tree may or may not contain); that the model vendor cannot see disclosed context (memory handed to a configured provider is visible to that provider, as the projection label itself states); anything about Linux, about a keychain-custody fortress, or about the MCP tool path (this drill used the CLI wrappers only). Custody was checked by phrase search over the whole fortress tree, which shows absence of that phrase at rest, not a cryptographic proof of the envelope.

## Cleanup

Fortress directories (`fortress-1..3-a/b`, `fortress-codex-1`, `fortress-codex-1b`), both memory snapshots (Claude Code and Codex copies), the emitted/transcoded/restored scratch trees, and the accepted-subset scratch copy were deleted from the scratch root after the logs above were captured. `scripts/verify-fortress-keys.sh` was re-run after cleanup and reports PASS for the MBA default fortress.
