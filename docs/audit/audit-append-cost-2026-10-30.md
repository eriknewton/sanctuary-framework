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
`c43b0bb71a69a90a3dbfe8d56db32d760f38f45d99a4c3782221ca8ecba42870`.

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
| 1,000 growth | Candidate | 100 | complete | 20.11 | 25.60 | 25.60 | 19.39 | 464.07 |
| 10,000 growth | Base | 100 | complete | 1,624.04 | 1,843.62 | 1,843.62 | 1,631.89 | 4,547.32 |
| 10,000 growth | Candidate | 100 | complete | 30.87 | 56.99 | 56.99 | 32.11 | 4,336.81 |
| 100,000 growth | Base | 100 | complete | 16,423.41 | 17,724.80 | 17,724.80 | 16,284.43 | 47,535.02 |
| 100,000 growth | Candidate | 100 | complete | 223.42 | 357.61 | 357.61 | 224.70 | 42,729.26 |
| 100,000 cap | Base | 655 | sample | 21,760.22 | 23,431.26 | 23,949.45 | 21,729.62 | 45,225.53 |
| 100,000 cap | Candidate | 2,100 | complete | 220.11 | 279.82 | 10,366.71 | 242.06 | 44,945.22 |
| 100,000 prune-episode | Candidate | 1 | complete | 10,415.98 | 10,415.98 | 10,415.98 | 10,415.98 | 44,847.37 |
| 100,000 checkpoint-due | Candidate | 1 | complete | 23,422.93 | 23,422.93 | 23,422.93 | 23,422.93 | 42,556.43 |

Phase values below are means per append, including prune appends. Decode/list
processing excludes awaited stat time and includes the base's metadata construction.
The key-array column gives the range of the largest array returned in each append.

| Scenario | Version | Directory read ms | Decode/list ms | Sort ms | Stat ms | GC ms | Key-array length |
|---|---|---:|---:|---:|---:|---:|---|
| 1,000 growth | Base | 3.11 | 24.59 | 0.41 | 141.60 | 1.20 | 1,001 to 1,100 |
| 1,000 growth | Candidate | 1.49 | 0.93 | 0.24 | 0.10 | 0.26 | 1,000 to 1,099 |
| 10,000 growth | Base | 23.23 | 249.98 | 5.08 | 1,336.83 | 11.26 | 10,001 to 10,100 |
| 10,000 growth | Candidate | 8.81 | 5.33 | 1.41 | 0.06 | 1.11 | 10,000 to 10,099 |
| 100,000 growth | Base | 282.90 | 2,417.44 | 32.97 | 13,510.61 | 132.65 | 100,001 to 100,100 |
| 100,000 growth | Candidate | 94.94 | 58.01 | 13.59 | 0.06 | 19.81 | 100,000 to 100,099 |
| 100,000 cap | Base | 377.49 | 3,169.39 | 48.39 | 18,056.51 | 167.40 | 100,001 to 100,001 |
| 100,000 cap | Candidate | 92.99 | 60.12 | 13.40 | 8.53 | 19.95 | 99,263 to 100,001 |
| 100,000 prune-episode | Candidate | 298.72 | 854.70 | 29.96 | 4,755.93 | 95.67 | 100,001 to 100,001 |
| 100,000 checkpoint-due | Candidate | 174.75 | 62.24 | 20.04 | 0.09 | 182.69 | 100,000 to 100,000 |

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
| 100,000 cap | Candidate | 4 | 0.001905 | 2,100 | 18.245 | 40,118.81 | 19.10 |
| 100,000 prune-episode | Candidate | 1 | 1.000000 | 1 | 4,490.000 | 10,041.94 | 10,041.94 |
| 100,000 checkpoint-due | Candidate | 0 | 0.000000 | 1 | 11.000 | 0.00 | 0.00 |

The base cap sample removed 655 entries over its 655 recorded appends and
held 100,000 entries after the last recorded append. This is the sample boundary.
The candidate cap run made four prunes at zero-based append indices 0, 696,
1,372 and 2,035. It removed 2,773 entries in total and ended with 99,327 retained
entries (100,000 + 2,100 - 2,773), below the 100,000 cap. The standalone prune
removed 640 entries and ended with 99,361 (100,000 + 1 - 640). Candidate growth
runs retained 1,100, 10,100 and 100,100 entries respectively. FileHandle sync totals
were 900 for each growth run, 38,315 for the cap run, 4,490 for the standalone
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
| 100,000 cap | 0 | 10,005.64 | 696 | 696 | 1,001 | yes |
| 100,000 cap | 696 | 10,006.62 | 676 | 676 | 1,001 | yes |
| 100,000 cap | 1,372 | 10,010.23 | 663 | 663 | 1,001 | yes |
| 100,000 cap | 2,035 | 10,008.21 | 738 | 738 | 1,001 | yes |
| 100,000 prune-episode | 0 | 10,008.59 | 640 | 640 | 1,001 | yes |

The separate checkpoint-due append after 100,000 entries completed with the
following hold and collection timings. Its final retained count was 100,001.
This single observation does not establish an availability or latency guarantee.

| Candidate scenario | Appends | Append ms | Held-lock ms | Collection ms | Sized listings | Names listings | Syncs |
|---|---:|---:|---:|---:|---:|---:|---:|
| 100,000 checkpoint-due | 1 | 23,422.93 | 23,299.73 | 23,022.74 | 0 | 1 | 11 |

Linux measurements do not establish a Darwin directory-capability latency bound.
APFS measurements and worker error-class validation remain separate platform work.

All six candidate scenarios completed on the measured final source.
