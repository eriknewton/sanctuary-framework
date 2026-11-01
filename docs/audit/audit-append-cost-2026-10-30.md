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

The measurement script generates entries through the real audit log using a
fixture wrapper that exposes only the current tail and performs durable writes.
It requires a strict cold load over the full filesystem store before measuring
unwrapped durable appends. A cold load uses a fresh audit-log instance with the
existing OS page cache. Cold-load time is recorded separately. Both versions
use Node v22.23.3 on Linux x86_64 and ext4 with `UV_THREADPOOL_SIZE=1`.
The runs overlapped on the same host. Validation checks also overlapped early
base samples at 100,000 entries. These timings include that shared load. Measured appends include
entry readback, durable entry and anchor writes, and the production write lock.
Interval checkpoints are disabled. Growth samples use nonbinding retention caps;
the cap sample sets the entry cap to 100,000 with a nonbinding byte cap.

Each growth sample contains 100 appends after 1,000, 10,000 or 100,000 entries.
Both cap scenarios start with 100,000 entries. The base records a sample of
655 appends; the candidate records all 2,100 appends, including pruning.
Per-append records include directory-read, decode, sort and GC time, key-array length, sized-listing counts, sync counts and prune time.
Fixture generation is not an append-throughput measurement.

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
| 1,000 growth | Candidate | 100 | complete | 11.48 | 22.78 | 22.78 | 11.83 | 448.50 |
| 10,000 growth | Base | 100 | complete | 1,624.04 | 1,843.62 | 1,843.62 | 1,631.89 | 4,547.32 |
| 10,000 growth | Candidate | 100 | complete | 29.53 | 44.16 | 44.16 | 30.60 | 4,401.91 |
| 100,000 growth | Base | 100 | complete | 16,423.41 | 17,724.80 | 17,724.80 | 16,284.43 | 47,535.02 |
| 100,000 growth | Candidate | 100 | complete | 222.93 | 340.57 | 340.57 | 226.19 | 43,076.28 |
| 100,000 cap | Base | 655 | sample | 21,760.22 | 23,431.26 | 23,949.45 | 21,729.62 | 45,225.53 |
| 100,000 cap | Candidate | 2,100 | complete | 218.07 | 269.54 | 9,136.82 | 232.32 | 42,023.14 |

Phase values below are means per append, including prune appends. Decode/list
processing excludes awaited stat time and includes the base's metadata construction.
The key-array column gives the range of the largest array returned in each append.

| Scenario | Version | Directory read ms | Decode/list ms | Sort ms | Stat ms | GC ms | Key-array length |
|---|---|---:|---:|---:|---:|---:|---|
| 1,000 growth | Base | 3.11 | 24.59 | 0.41 | 141.60 | 1.20 | 1,001 to 1,100 |
| 1,000 growth | Candidate | 0.84 | 0.46 | 0.14 | 0.06 | 0.20 | 1,000 to 1,099 |
| 10,000 growth | Base | 23.23 | 249.98 | 5.08 | 1,336.83 | 11.26 | 10,001 to 10,100 |
| 10,000 growth | Candidate | 8.16 | 4.39 | 1.37 | 0.06 | 1.24 | 10,000 to 10,099 |
| 100,000 growth | Base | 282.90 | 2,417.44 | 32.97 | 13,510.61 | 132.65 | 100,001 to 100,100 |
| 100,000 growth | Candidate | 95.77 | 55.53 | 13.34 | 0.07 | 22.45 | 100,000 to 100,099 |
| 100,000 cap | Base | 377.49 | 3,169.39 | 48.39 | 18,056.51 | 167.40 | 100,001 to 100,001 |
| 100,000 cap | Candidate | 92.56 | 56.06 | 13.43 | 6.35 | 20.85 | 99,000 to 100,001 |

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
| 100,000 cap | Candidate | 3 | 0.001429 | 2,100 | 14.726 | 26,284.25 | 12.52 |

The base cap sample removed 655 entries over its 655 recorded appends and
held 100,000 entries after the last recorded append. This is the sample boundary.
The candidate cap run made three prunes: the initial over-cap prune and two
later hysteresis crossings. It removed 3,003 entries in total and ended
with 99,097 retained entries, below the 100,000 cap.

Linux measurements do not establish a Darwin directory-capability latency bound.
APFS measurements and worker error-class validation remain separate platform work.
