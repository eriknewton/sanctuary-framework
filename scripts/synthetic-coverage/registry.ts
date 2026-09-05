export interface FixtureOutcome {
  passed: boolean;
  message?: string;
  durationMs: number;
}

export interface FixtureRun {
  name: string;
  fn: () => Promise<FixtureOutcome>;
}

export interface FixtureClaim {
  id: string;
  label: string;
  fixtures: FixtureRun[];
}

const claims: Map<string, FixtureClaim> = new Map();

function compareClaimIds(a: string, b: string): number {
  const numericA = Number(a);
  const numericB = Number(b);
  if (Number.isFinite(numericA) && Number.isFinite(numericB)) {
    return numericA - numericB;
  }
  return a.localeCompare(b);
}

export function registerFixture(
  claimId: string,
  label: string,
  name: string,
  fn: FixtureRun["fn"],
): void {
  const existing = claims.get(claimId);
  if (existing) {
    // A shared row ID must not merge evidence for different trust claims.
    if (existing.label !== label) {
      throw new Error(`Conflicting labels for assurance row ${claimId}`);
    }
    if (!existing.fixtures.some((fixture) => fixture.name === name)) {
      existing.fixtures.push({ name, fn });
    }
    return;
  }

  claims.set(claimId, {
    id: claimId,
    label,
    fixtures: [{ name, fn }],
  });
}

export function listClaims(): FixtureClaim[] {
  return Array.from(claims.values())
    .sort((a, b) => compareClaimIds(a.id, b.id))
    .map((claim) => ({
      ...claim,
      fixtures: [...claim.fixtures],
    }));
}

export function getClaim(id: string): FixtureClaim | undefined {
  const claim = claims.get(id);
  if (!claim) {
    return undefined;
  }
  return {
    ...claim,
    fixtures: [...claim.fixtures],
  };
}
