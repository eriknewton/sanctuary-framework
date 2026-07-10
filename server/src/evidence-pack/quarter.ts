/**
 * Sanctuary MCP Server - Law-firm Evidence Pack: calendar-quarter windows
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * The calendar-quarter window layer. This is part of the NEW code the pack
 * adds: the shipped audit log counts by size (FIFO retention), never by
 * calendar period. Everything here is pure and deterministic (UTC), so it is
 * hermetically testable without touching a real fortress.
 */

import type { CalendarQuarter, QuarterWindow } from "./types.js";

/** First (1-based, UTC) month of each quarter. */
const QUARTER_START_MONTH: Record<1 | 2 | 3 | 4, number> = {
  1: 1,
  2: 4,
  3: 7,
  4: 10,
};

/** Parse a `YYYY-Qn` label (e.g. "2026-Q3") into a {@link CalendarQuarter}. */
export function parseQuarterLabel(label: string): CalendarQuarter {
  const match = /^(\d{4})-Q([1-4])$/.exec(label.trim());
  if (!match) {
    throw new Error(
      `Invalid quarter "${label}". Expected the form YYYY-Qn, e.g. 2026-Q3.`
    );
  }
  const year = Number(match[1]);
  const quarter = Number(match[2]) as 1 | 2 | 3 | 4;
  return { year, quarter };
}

/** Canonical `YYYY-Qn` label for a quarter. */
export function quarterLabel(quarter: CalendarQuarter): string {
  return `${quarter.year}-Q${quarter.quarter}`;
}

/**
 * The calendar quarter that contains the given instant (defaults to now).
 * Used as the CLI default so an operator can run "this quarter" with no flag.
 */
export function currentQuarter(now: Date = new Date()): CalendarQuarter {
  const month = now.getUTCMonth(); // 0-based
  const quarter = (Math.floor(month / 3) + 1) as 1 | 2 | 3 | 4;
  return { year: now.getUTCFullYear(), quarter };
}

/**
 * Resolve a calendar quarter to its concrete time window. `start_inclusive` is
 * the first instant of the quarter; `end_exclusive` is the first instant of
 * the next quarter. An entry belongs to the quarter iff
 * `start_inclusive <= timestamp < end_exclusive`.
 */
export function quarterWindow(quarter: CalendarQuarter): QuarterWindow {
  const startMonth0 = QUARTER_START_MONTH[quarter.quarter] - 1;
  const start = new Date(Date.UTC(quarter.year, startMonth0, 1, 0, 0, 0, 0));
  // Adding 3 months to the start; Date.UTC normalizes a month value >= 12 into
  // the following year, so 2026-Q4's end_exclusive is 2027-01-01 automatically.
  const end = new Date(Date.UTC(quarter.year, startMonth0 + 3, 1, 0, 0, 0, 0));
  return {
    quarter,
    label: quarterLabel(quarter),
    start_inclusive: start.toISOString(),
    end_exclusive: end.toISOString(),
  };
}

/**
 * True iff an ISO timestamp falls inside the window (inclusive start, exclusive
 * end). An unparseable timestamp is treated as outside the window (it is never
 * silently counted).
 */
export function isInWindow(timestamp: string, window: QuarterWindow): boolean {
  const t = new Date(timestamp).getTime();
  if (Number.isNaN(t)) return false;
  const start = new Date(window.start_inclusive).getTime();
  const end = new Date(window.end_exclusive).getTime();
  return t >= start && t < end;
}
