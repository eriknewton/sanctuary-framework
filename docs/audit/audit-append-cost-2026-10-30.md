# Audit append cost, 2026-10-30

Warm append discovery now uses one complete names-only listing. Interval
checkpointing reuses that snapshot while the same write lock is held. Those
listings no longer stat entry or checkpoint files; exact-key body reads retain
their custody checks. Entry encryption, chain and anchor formats are unchanged.

This change makes no availability claim. A metadata-only fault on a file the
write does not read is reported by a later sized load or recount. Once a strict
verification read on the writing instance completes with a hard finding, that
instance refuses later appends, as before. A separate reader or a lenient instance
does not stop the writer. There is no autonomous observer or wall-clock detection
guarantee for a writer without reads; a fault that heals before an observing
operation need not be reported.

Retention now uses hysteresis: a due prune targets the configured entry cap less
one percent, rounded down with a minimum margin of one entry, and the byte cap
less the same proportion, subject to keeping one survivor. The default entry
margin is 1,000. Safe pruning still requires an authenticated cut and successful
anchor and deletion operations. A failed recount leaves accounting unknown and
emits one stderr line per fault episode, followed by one line on recovery.
Under a persistent metadata fault, the recount's stat loop runs to the first
faulting file in directory order, up to N - 1 successful stats per append.

On a backend without `listKeys`, discovery retains its entry-prefix sized
listing; legacy non-entry records make its signature differ from the recount's
full population, requiring one sized recount per append, with full accounting
and no pruning delay. The head anchor is in the checkpoint namespace, and lock
files are excluded from storage listings.

Entry persistence, anchoring and interval checkpointing share the existing
30-second hold deadline with the existing 5-second contention timeout; a
checkpoint whose persistence was issued before expiry may land after rejection,
as before. Pending checkpoint state survives rejection, and a successor hold can
retry without being suppressed by an abandoned flight.

Names-only enumeration still allocates and sorts the retained key set. Checkpoint
collection reads every entry body above the sealed tip, and predecessor discovery
reads every checkpoint record. Checkpoint retention remains unbounded over the
fortress lifetime. Retention growth remains unbounded in a headless writer under
a persistent metadata fault (<REGISTER-ID>).

## Measurement method

Candidate rows record the completed measurement on the final source.

The measurement script generates entries through the real audit log using a
fixture wrapper that exposes only the current tail and performs durable writes.
It requires a strict cold load over the full filesystem store before measuring
unwrapped durable appends. A cold load uses a fresh audit-log instance with the
existing OS page cache. Cold-load time is recorded separately. Both versions
use Node v22.23.3 on Linux x86_64 and ext4 with `UV_THREADPOOL_SIZE=1`.
The original base measurements overlapped other work on the same host, including
validation checks during early base samples at 100,000 entries. Those timings
retain that shared load. Candidate figures come from the separate final-source
run. Measured appends include
entry readback, durable entry and anchor writes, and the production write lock.
Interval checkpoints are disabled except for the separate checkpoint-due sample.
Growth and checkpoint-due samples use nonbinding retention caps; cap and
prune-episode samples set the entry cap to 100,000 with a nonbinding byte cap.

Each growth sample contains 100 appends after 1,000, 10,000 or 100,000 entries.
Both cap scenarios start with 100,000 entries. The base records a sample of
655 appends; the candidate records all 2,100 appends, including pruning.
Two additional candidate scenarios each measure one append after 100,000 entries:
a standalone prune episode and an interval-checkpoint-due append. Per-append
records include directory-read, decode, sort and GC time, key-array length,
listing counts, sync counts, prune time, held-lock time and collection time.
Fixture generation is not an append-throughput measurement. Single-append rows
have identical p50, p99, maximum and mean values. Percentiles use the recorded
sorted sample at index floor(sample count times percentile), capped at the last
index. Means divide totals by recorded append count.

Measured candidate `audit-log.ts` SHA-256:
`75f213b31eadcd3cdea3e53e33228b30b2a91dab0c588d4483aa41346ee60dac`.

## Measured results

All six growth samples are complete at 100 appends each. The base cap row is a
655-append sample; the candidate cap row is the full 2,100-append run.
The base at the cap prunes on every append, so its cost per append is steady
across the sample. A full 2,100-append base cap run was not completed because
it takes about 12 hours. Base cap totals cover only the sampled appends;
none are extrapolated to 2,100 appends.

| Scenario | Version | Appends | Status | p50 ms | p99 ms | Maximum ms | Mean ms | Strict cold load ms |
|---|---|---:|---|---:|---:|---:|---:|---:|
| 1,000 growth | Base | 100 | complete | 181.86 | 207.78 | 207.78 | 182.16 | 457.75 |
| 1,000 growth | Candidate | 100 | complete | 12.84 | 27.54 | 27.54 | 13.69 | 474.73 |
| 10,000 growth | Base | 100 | complete | 1,624.04 | 1,843.62 | 1,843.62 | 1,631.89 | 4,547.32 |
| 10,000 growth | Candidate | 100 | complete | 37.51 | 60.23 | 60.23 | 37.69 | 4,301.35 |
| 100,000 growth | Base | 100 | complete | 16,423.41 | 17,724.80 | 17,724.80 | 16,284.43 | 47,535.02 |
| 100,000 growth | Candidate | 100 | complete | 223.25 | 369.15 | 369.15 | 226.83 | 43,104.88 |
| 100,000 cap | Base | 655 | sample | 21,760.22 | 23,431.26 | 23,949.45 | 21,729.62 | 45,225.53 |
| 100,000 cap | Candidate | 2,100 | complete | 218.82 | 286.20 | 10,385.17 | 241.38 | 43,488.77 |
| 100,000 prune-episode | Candidate | 1 | complete | 10,354.35 | 10,354.35 | 10,354.35 | 10,354.35 | 45,564.47 |
| 100,000 checkpoint-due | Candidate | 1 | complete | 23,696.32 | 23,696.32 | 23,696.32 | 23,696.32 | 45,214.53 |

Phase values below are means per append, including prune appends. Decode/list
processing excludes awaited stat time and includes the base's metadata construction.
The key-array column gives the range of the largest array returned in each append.

| Scenario | Version | Directory read ms | Decode/list ms | Sort ms | Stat ms | GC ms | Key-array length |
|---|---|---:|---:|---:|---:|---:|---|
| 1,000 growth | Base | 3.11 | 24.59 | 0.41 | 141.60 | 1.20 | 1,001 to 1,100 |
| 1,000 growth | Candidate | 0.98 | 0.63 | 0.16 | 0.07 | 0.22 | 1,000 to 1,099 |
| 10,000 growth | Base | 23.23 | 249.98 | 5.08 | 1,336.83 | 11.26 | 10,001 to 10,100 |
| 10,000 growth | Candidate | 11.53 | 5.54 | 1.59 | 0.07 | 1.29 | 10,000 to 10,099 |
| 100,000 growth | Base | 282.90 | 2,417.44 | 32.97 | 13,510.61 | 132.65 | 100,001 to 100,100 |
| 100,000 growth | Candidate | 95.22 | 57.54 | 13.62 | 0.07 | 21.08 | 100,000 to 100,099 |
| 100,000 cap | Base | 377.49 | 3,169.39 | 48.39 | 18,056.51 | 167.40 | 100,001 to 100,001 |
| 100,000 cap | Candidate | 94.85 | 57.38 | 13.50 | 8.73 | 20.75 | 99,254 to 100,001 |
| 100,000 prune-episode | Candidate | 246.34 | 870.78 | 34.68 | 5,181.43 | 93.33 | 100,001 to 100,001 |
| 100,000 checkpoint-due | Candidate | 196.42 | 57.61 | 26.23 | 0.08 | 193.35 | 100,000 to 100,000 |

Listing and prune totals cover the recorded appends in each row. Sync counts
include FileHandle syncs; the callback-style fsync count was zero. The first
append includes the existing stale-lock-temp directory sweep. Prune time covers
the rotation call, including its recount and anchor work, when it removed entries.

| Scenario | Version | Sized listings | Sized listings per append | Names listings | Syncs per append | Prune total ms | Prune ms per append |
|---|---|---:|---:|---:|---:|---:|---:|
| 1,000 growth | Base | 300 | 3.000000 | 0 | 9.000 | 0.00 | 0.00 |
| 1,000 growth | Candidate | 0 | 0.000000 | 100 | 9.000 | 0.00 | 0.00 |
| 10,000 growth | Base | 300 | 3.000000 | 0 | 9.000 | 0.00 | 0.00 |
| 10,000 growth | Candidate | 0 | 0.000000 | 100 | 9.000 | 0.00 | 0.00 |
| 100,000 growth | Base | 300 | 3.000000 | 0 | 9.000 | 0.00 | 0.00 |
| 100,000 growth | Candidate | 0 | 0.000000 | 100 | 9.000 | 0.00 | 0.00 |
| 100,000 cap | Base | 2,620 | 4.000000 | 0 | 17.000 | 7,127,048.37 | 10,880.99 |
| 100,000 cap | Candidate | 4 | 0.001905 | 2,100 | 17.342 | 40,122.14 | 19.11 |
| 100,000 prune-episode | Candidate | 1 | 1.000000 | 1 | 3,790.000 | 10,029.57 | 10,029.57 |
| 100,000 checkpoint-due | Candidate | 0 | 0.000000 | 1 | 11.000 | 0.00 | 0.00 |

The base cap sample removed 655 entries over its 655 recorded appends and
held 100,000 entries after the last recorded append. This is the sample boundary.
The candidate cap run made four prunes at zero-based append indices 0, 513,
1,260 and 1,842. It removed 2,502 entries in total and ended with 99,598 retained
entries (100,000 + 2,100 - 2,502), below the 100,000 cap. The standalone prune
removed 540 entries and ended with 99,461 (100,000 + 1 - 540). Candidate growth
runs retained 1,100, 10,100 and 100,100 entries respectively. FileHandle sync totals
were 900 for each growth run, 36,418 for the cap run, 3,790 for the standalone
prune and 11 for the checkpoint-due append.

The prune table reports the rotation hold separately from total append time and
rotation-call time above. The episode budget is floor(configured hold / 3),
10,000 ms for the default 30,000 ms hold, counted from rotation hold entry.
Every observed episode stopped at that budget before its planned 1,001 steps
were complete. The budget is checked between steps; these observed hold times
are measurements, not a hard latency bound. An at-cap episode can exceed the
5-second contention timeout about once per episode, as at the base where every
at-cap hold took about 21 seconds. This does not establish acquisition success
for a contending writer.

| Candidate scenario | Append index (zero-based) | Episode hold ms | Steps | Anchors | Planned steps | Budget stopped |
|---|---:|---:|---:|---:|---:|---|
| 100,000 cap | 0 | 10,007.93 | 513 | 513 | 1,001 | yes |
| 100,000 cap | 513 | 10,007.12 | 747 | 747 | 1,001 | yes |
| 100,000 cap | 1,260 | 10,007.92 | 582 | 582 | 1,001 | yes |
| 100,000 cap | 1,842 | 10,012.28 | 660 | 660 | 1,001 | yes |
| 100,000 prune-episode | 0 | 10,009.88 | 540 | 540 | 1,001 | yes |

The separate checkpoint-due append after 100,000 entries completed with the
following hold and collection timings. Its final retained count was 100,001.
This single observation does not establish an availability or latency guarantee.

| Candidate scenario | Appends | Append ms | Held-lock ms | Collection ms | Sized listings | Names listings | Syncs |
|---|---:|---:|---:|---:|---:|---:|---:|
| 100,000 checkpoint-due | 1 | 23,696.32 | 23,554.67 | 23,268.73 | 0 | 1 | 11 |

Linux measurements do not establish a Darwin directory-capability latency bound.
APFS measurements and worker error-class validation remain separate platform work.

All six candidate scenarios completed on the measured final source.
