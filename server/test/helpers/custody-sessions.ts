import type { EstablishMasterResult } from "../../src/core/master-custody.js";

type CustodySession = Pick<EstablishMasterResult, "masterKey" | "masterWriteBarrier">;

export function createCustodySessionTracker() {
  const sessions = new Set<CustodySession>();
  return {
    track<T extends CustodySession>(session: T): T {
      sessions.add(session);
      return session;
    },
    async release(): Promise<void> {
      const results = await Promise.allSettled([...sessions].map(async session => {
        try {
          await session.masterWriteBarrier?.release();
          sessions.delete(session);
        } finally {
          session.masterKey.fill(0);
        }
      }));
      const failures = results.flatMap(result => result.status === "rejected" ? [result.reason] : []);
      if (failures.length > 0) {
        throw new AggregateError(failures, "Custody session teardown failed");
      }
    },
  };
}
