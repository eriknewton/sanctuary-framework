/**
 * StateStore namespace scan -- the ONE shared "page every key, decode each
 * entry" fan-out, with per-entry failure isolation.
 *
 * WHY THIS EXISTS AS A SHARED FUNCTION AND NOT A COPIED LOOP. Several modules
 * persist a record set as one StateStore key per record and then need the whole
 * set back (`file-grant/store.ts`, `operational/task-coordination/
 * task-service.ts`). Every hand-written version of that loop has had to
 * re-learn the same two properties independently, and the copies drifted:
 *
 *   1. PAGE TO EXHAUSTION. `StateStore.list` caps a call at `limit`, so a
 *      single unpaged call silently drops records past the cap. A caller that
 *      reconciles or reports over the result then does so over a truncated set
 *      and reads as complete.
 *   2. ISOLATE THE PER-ENTRY READ. `StateStore.read` can reject for one entry
 *      (an unresolvable writer key, a failed integrity check) while every other
 *      entry in the namespace reads fine. When that rejection propagates out of
 *      the fan-out, the CALLER never runs: a single bad record takes out a
 *      whole listing, a whole endpoint, or a whole reconcile pass.
 *
 * The split of concerns is deliberate. This function owns the MECHANISM (page,
 * read, decode, isolate) and never decides what a failure means. Each caller
 * owns the POLICY, because the right policy genuinely differs: the file-grant
 * reconcile must scrub what it CAN read and then still surface the failure,
 * while a task listing must stay available and record the loss. Copying a
 * policy to N sites is not a class fix; sharing the mechanism and stating the
 * policy per site is.
 *
 * NOT EVERY LISTING LOOP SHOULD ADOPT THIS. A loop whose caller treats "no
 * rows" as a positive verdict must keep propagating, because a skipped entry
 * there is indistinguishable from an absent one and absence would be read as a
 * pass. `castle-wall/observe/store.ts` is exactly that case and deliberately
 * does not use this scan; see the note in its own header.
 */

/**
 * The subset of `StateStore` this scan needs. Narrow on purpose: the scan must
 * never be able to write, and a narrow type keeps test doubles small.
 */
export interface NamespaceScanSource {
  list(
    namespace: string,
    prefix?: string,
    tags?: string[],
    limit?: number,
    offset?: number
  ): Promise<{ keys: Array<{ key: string }>; total: number }>;
  read(namespace: string, key: string): Promise<{ value: string } | null>;
}

/** One entry that could not be read or decoded, with the cause preserved. */
export interface NamespaceScanFailure {
  key: string;
  error: unknown;
}

export interface NamespaceScanResult<T> {
  /** Every entry that read and decoded. Order follows the paged key order. */
  items: T[];
  /** Every entry that did not, in the order encountered. Empty on a clean scan. */
  failures: NamespaceScanFailure[];
}

export interface NamespaceScanOptions {
  /** Restrict the scan to keys under this prefix. */
  prefix?: string;
  /**
   * Keys requested per `list` call. Defaults to `DEFAULT_NAMESPACE_PAGE_SIZE`;
   * the loop pages to exhaustion regardless, so this only trades call count
   * against per-call size.
   */
  pageSize?: number;
}

/**
 * Matches `StateStore.list`'s own default `limit`, so the default scan makes
 * the same number of calls the un-paged callers used to make for a small set.
 */
export const DEFAULT_NAMESPACE_PAGE_SIZE = 100;

/**
 * Page every key in `namespace` (optionally prefix-filtered), read and decode
 * each one, and return the decoded items alongside the per-entry failures.
 *
 * `decode` returning `null` means "this entry is not one of mine, skip it
 * without recording a failure". `decode` THROWING means the entry is present
 * but unusable, and is recorded as a failure.
 *
 * A rejection from `list` itself still propagates: failing to enumerate a
 * namespace is not a per-entry condition, and returning an empty scan for it
 * would let an enumeration outage read as an empty namespace.
 */
export async function scanNamespaceEntries<T>(
  source: NamespaceScanSource,
  namespace: string,
  decode: (value: string, key: string) => T | null,
  options?: NamespaceScanOptions
): Promise<NamespaceScanResult<T>> {
  const pageSize = options?.pageSize ?? DEFAULT_NAMESPACE_PAGE_SIZE;
  const items: T[] = [];
  const failures: NamespaceScanFailure[] = [];
  let offset = 0;

  for (;;) {
    const { keys, total } = await source.list(
      namespace,
      options?.prefix,
      undefined,
      pageSize,
      offset
    );
    for (const { key } of keys) {
      // PER-ENTRY ISOLATION, THE WHOLE POINT OF THIS FUNCTION: one entry's read
      // or decode failure must never keep the caller from seeing the rest, and
      // must never be discarded either -- it is recorded, so the caller can
      // apply its own policy to a partial result rather than mistake it for a
      // complete one.
      try {
        const result = await source.read(namespace, key);
        // Absent between the list and the read (a concurrent delete) is not a
        // failure: nothing was lost that the caller could act on.
        if (!result) continue;
        const decoded = decode(result.value, key);
        if (decoded !== null) items.push(decoded);
      } catch (error) {
        failures.push({ key, error });
      }
    }
    offset += keys.length;
    // Stop when every key is covered, or defensively on an empty page so an
    // unexpected pagination result can never spin forever.
    if (keys.length === 0 || offset >= total) break;
  }

  return { items, failures };
}
