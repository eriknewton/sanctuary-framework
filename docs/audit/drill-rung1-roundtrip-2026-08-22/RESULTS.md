---
review_status: pending_coordinator_verification
created: 2026-08-22
drill: rung1-roundtrip
host: MBA
n_cycles: 3
supplementary_cycles: 1
---

# Rung-1 round-trip acceptance drill: results

Brief: `Review/Sanctuary/Rung1_Roundtrip_Drill_Spawn_Prompt_2026-08-22.md`. Worktree `/private/tmp/sanctuary-drill-rung1` on branch `drill/rung1-roundtrip-2026-08-22` at `df596192` (origin/main). CLI invoked as `node dist/cli.js` from a fresh `npm run build`. Every command ran against a COPY of the real Claude Code memory tree (487 `.md` files) and a COPY of `~/.codex/memories/`; every fortress was a fresh disposable `sanctuary init --no-confirm --no-pin --no-identity --recovery-out <scratch>` unlocked by `SANCTUARY_PASSPHRASE` in the environment. No keychain prompt appeared in any leg. `scripts/verify-fortress-keys.sh` reports PASS after the run.

## Verdict

`RESULT_VERDICT: FAIL (2 findings)`

One root cause produces every failed criterion: the secret classifier refuses the real `MEMORY.md`, so the mirror has no index, the emitted tree cannot be re-ingested, and transcode refuses to run. Everything downstream of that index refusal works, shown by a clearly labelled supplementary cycle on a scrubbed copy (one 46-character identifier in `MEMORY.md` replaced with a placeholder, the 10 other refused files removed): 477/477 ingested, 477/477 byte-identical on emit, re-ingest 477/477, transcode plus restore byte-identical to the emit. The supplementary cycle is evidence about the pipeline, never acceptance evidence; the acceptance criteria were declared against the real corpus and are scored against it.

## Criteria table (real corpus; N=3 fresh fortress sets; all cycles agree)

| # | Criterion | Verdict | Evidence (identical in cycles 1, 2, 3) |
|---|-----------|---------|----------------------------------------|
| 1 | Ingest real Claude Code tree, refusal <= 5%, `MEMORY.md` accepted | FAIL | `memory_ingest --harness=claude-code`: 476 of 487 ingested, 11 refused = 2.26% (rate PASSES). `MEMORY.md` REFUSED (`classifier_reject`), so the criterion fails on its second clause. Classes: `keyword_gated_high_entropy` 7, `known_secret_token` 4. |
| 2 | Emit fidelity on the accepted subset + link graph | PASS with delta | `memory_emit --harness=claude-code`: 476 emitted; 476/476 byte-identical to source (`cmp` per file), 0 differ, 0 missing, 0 extra; `diff -rq` reports nothing except the 11 "only in source" files, and that set equals the refused set exactly. Link graph: 189 `[text](file.md)` targets in `MEMORY.md`, 189 accepted, 189 present in the emitted tree, 0 missing. Delta: the emitted tree has no `MEMORY.md` (`index_present: no`) because it was refused at ingest. |
| 3 | Re-ingest the emitted tree into a second fortress with the same accepted count | FAIL | `memory_ingest` on the emitted tree exits 1: "Claude Code memory directory is missing MEMORY.md". Consequence of criterion 1, fail-closed as designed. |
| 4 | Custody by execution: no plaintext of a known phrase in the fortress tree | PASS | Two phrases per cycle: P1 = a 35-character link title from `MEMORY.md` that also appears in an accepted file; P2 = a 40-character body line from the first accepted file. Control: both found in the emitted plaintext tree (1 file each). `grep -rlF` over the whole fortress (977 files; namespaces `_audit _audit_checkpoints _meta _sdw_document_corpus sdw_memory_locks`): 0 hits for P1, 0 hits for P2, in every cycle. One raw passage file opened per cycle under `state/_sdw_document_corpus/` (1889 to 3547 bytes): a JSON envelope `{"v":1,"alg":"aes-256-gcm","iv":...,"ct":...}`; P2 absent. Audit entries are hash-chained envelopes with `encrypted_payload_bytes`; no phrase appears there either. |
| 5 | Codex leg: ingest, emit, re-ingest; scope guard | PASS | `~/.codex/memories/` exists (MEMORY.md, memory_summary.md, raw_memories.md plus `extensions/` and `rollout_summaries/`). Scope guard by execution: three canary `.md` files carrying a unique phrase were planted in the COPY (one under `extensions/`, one under `rollout_summaries/`, one loose non-allowlisted top-level file). `memory_ingest --harness=codex`: "ingested 3 of 3" (the source count is 3, so the canaries were never enumerated); canary phrase hits under the fortress = 0, in the emitted tree = 0. Emit: 3 files, each byte-identical to its source. Re-ingest of the emitted tree into a fourth fortress: 3 of 3. |
| 6 | Transcode claude-code to codex (`--mode=reversible`), restore equals emit, honest label present | FAIL (fails closed) | `memory_transcode --from-harness=claude-code --to-harness=codex --mode=reversible` exits 1: "vault has no complete claude-code memory snapshot: MEMORY.md is absent". Consequence of criterion 1. Restore therefore NOT-RUN on the real corpus. Label check performed on the supplementary cycle (below). |
| 7 | N >= 3 cycles on fresh fortresses, all agree | PASS (as a measurement) | Cycles 1, 2, 3 each used four fresh fortresses (`fortress-N-a..d`) and produced identical counts for every line above: 476/487, 11 refused, 476 byte-identical, 189/189 links, 0/0 phrase hits, codex 3/3 + 3/3, transcode refused. |

Mode token: `MEMORY_TRANSCODE_MODE = "reversible"` (`server/src/cli/memory-file.ts` imports it from `server/src/sdw/memory-transcode.ts:40`).

## Supplementary cycle S1 (scrubbed copy; NOT acceptance evidence)

Purpose: show whether the round trip closes once the index refusal is removed, so the coordinator can size the fix. Source: a copy of the snapshot with the 10 refused non-index files deleted and the single entropy-tripping 46-character identifier in `MEMORY.md` replaced with `DRILL-SCRUBBED-TOKEN` (477 files). Fresh fortresses `fortress-S1-a..d`.

- Ingest: 477 of 477, 0 refused, `MEMORY.md` accepted.
- Emit: 477 emitted, 477/477 byte-identical, `index_present: yes`; link graph 189/189.
- Re-ingest of the emitted tree: 477 of 477 (criterion-3 shape closes).
- Custody: P1 (58 chars) and P2 (40 chars) 0 hits under the fortress, 1 hit each in the emitted plaintext tree.
- Codex leg: same as the real cycles (3/3, byte-identical, canaries unseen, 3/3 re-ingest).
- Transcode: "projected 477 Claude Code source files into 3 Codex plaintext files"; `memory_transcode_restore --archive-id <32-hex>`: "restored 477 exact Claude Code source files"; `diff -rq restore emit-cc` = 0 lines (restore equals the original emit byte for byte).
- Honest label: the projected `MEMORY.md` carries the code's provenance label ("Its provenance is descriptive and unsigned until Sanctuary Memory-Integrity Slice C ... Memory supplied to a configured model provider is visible to that provider"), 1 hit. The literal string `memory_class` appears in none of the three projected files and in none of `server/src/sdw/memory-transcode.ts`, `server/src/sdw/adapters/*.ts`, `server/src/cli/memory-file.ts`; the brief's phrase "where the code says it is" resolves to the unsigned-provenance sentence above, which is present. Recorded as observed, no verdict claimed beyond that.

## Per-cycle logs (counts and classes only)

Full per-cycle summaries: `logs/cycle-1-summary.log`, `logs/cycle-2-summary.log`, `logs/cycle-3-summary.log`, `logs/cycle-S1-summary.log`. Detector attribution: `logs/refusal-attribution.log`.

```
cycle-1  C1 476/487 ingested, refused=11 (classifier_reject x11), MEMORY.md=REFUSED
cycle-1  C2 accepted=476 byte_identical=476 differ=0 missing=0 extra=0; delta(11)==refused set; links 189/189; emitted MEMORY.md=no
cycle-1  C3 reingest exit=1 (missing MEMORY.md)
cycle-1  C4 P1 hits fortress=0 (control emit=1); P2 hits fortress=0 (control emit=1); raw passage file: aes-256-gcm envelope, P2 absent
cycle-1  C5 codex ingest 3/3; emit 3 byte-identical; canary hits fortress=0 emit=0; reingest 3/3
cycle-1  C6 transcode exit=1 (MEMORY.md absent in vault); restore NOT-RUN
```
```
cycle-2  identical to cycle-1 on every count (476/487, 11, 476/476, 189/189, 0/0, 3/3, 3/3, transcode refused)
cycle-3  identical to cycle-1 on every count (476/487, 11, 476/476, 189/189, 0/0, 3/3, 3/3, transcode refused)
```
```
cycle-S1 (scrubbed copy) C1 477/477 refused=0 MEMORY.md=ACCEPTED; C2 477/477 identical, links 189/189, MEMORY.md emitted;
         C3 reingest 477/477; C4 0/0 hits (controls 1/1); C5 3/3, 3/3; C6 transcode 477 -> 3 files, restore 477, restore==emit (0 diff lines)
```

## Findings (no fixes on the drill branch)

**F1 (HIGH for Rung-1 acceptance): the keyword-gated entropy detector is scoped to the whole file, so an index file that says "token" anywhere and contains one high-entropy identifier anywhere else is refused as a secret.** Location: `server/src/sdw/write-gate.ts:728-745` (`containsKeywordGatedHighEntropySecret`), reached from `assertSdwClassifierCleanText` at `write-gate.ts:163-166`, which passes the entire passage text as the single entropy context (`[text]`). On the real corpus this refuses `MEMORY.md` (keyword hits: `token` x3, `authorization` x1, anywhere in a 487-entry index; one 46-character identifier at entropy 4.537 against the 4.5 threshold) and 5 of the 6 other `keyword_gated_high_entropy` refusals also fire only at whole-file scope (no single line trips on its own). Because `MEMORY.md` is the index, this one refusal cascades into criteria 3 and 6 (both fail closed, correctly). Minimal fix description: evaluate the keyword gate within a proximity window of the candidate (same line, or N characters) instead of file scope, and treat an unpadded identifier that contains hyphens or underscores mixed with digits as a lower-confidence candidate than a pure base64/hex run; alternatively give the Claude Code adapter a per-line classifier context, mirroring what the metadata path already does at `write-gate.ts:630-636` (it pairs `key\nvalue` as one context). A fix must keep the must-fail corpus green: the 4 `known_secret_token` refusals are true-positive shaped (they fired on the token-prefix detector, not the entropy heuristic) and must still refuse.

**F2 (MEDIUM, operator diagnosability): the CLI drops the per-file detector detail the adapter already returns.** `server/src/sdw/adapters/claude-code-file-adapter.ts:217-221` records `reason: screen.category` and `detail: screen.message`, but `screen.message` is the constant "SDW classifier rejected sensitive material" for every detector (`write-gate.ts:533`), and `server/src/cli/memory-file.ts:139-146` prints only the file name and the category. An operator told "remove the sensitive material from those files" has no way to learn which of nine detectors fired or where; this drill had to mirror the detector list in a scratch script to attribute the 11 refusals. Minimal fix description: make `SdwValidationError` carry a detector name (`private_key_marker`, `known_secret_token`, `jwt`, `url_credential`, `keyword_gated_high_entropy`, ...) and, for line-local detectors, the 1-based line number; print both in the `memory_ingest` refusal list. No secret content is needed for either.

Non-findings worth recording: the 11 refusals are 2.26% of the corpus, well under the 5% bar and down from the 35.5% (147 of 414) recorded in the roadmap row on 2026-08-07; the #1217 classifier fix held on this corpus. The roadmap row `sanctuary-rung1-classifier-refusal-rate` still reads "MEMORY.md among them, so an emitted tree cannot be re-ingested"; that sentence remains true today for a reason narrower than the one it was written for.

## Honest bound

What this drill proves, on one corpus (487 real Claude Code memory files, 3 real Codex memory files), on one host (MBA, macOS), three times on fresh fortresses: the accepted subset round-trips byte-faithfully through an AES-256-GCM encrypted vault; the Codex adapter reads exactly its three allowlisted files and nothing else under the memories directory; no plaintext of two known phrases exists anywhere under a fortress after ingest; the transcode archive restores exactly what was emitted (supplementary cycle only). What it does not prove: that the round trip closes on the real corpus as it stands (it does not, finding F1); that any other operator's corpus stays under the 5% refusal bar; that the model vendor cannot see disclosed context (memory handed to a configured provider is visible to that provider, as the projection label itself says); anything about Linux, about a keychain-custody fortress, or about the MCP tool path (this drill used the CLI wrappers only). Custody was checked by phrase search and one opened envelope per cycle, which shows absence of those phrases at rest, not a cryptographic proof of the envelope.

## Cleanup

Fortress directories (`fortress-1..3-a..d`, `fortress-S1-a..d`, `probe/`), the scrubbed copy, the codex copies with canaries, and both snapshots were deleted from the scratch root after the logs above were captured. The worktree's `server/package-lock.json` churn from `npm install` was left uncommitted.
