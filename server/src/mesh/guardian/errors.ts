/**
 * Guardian + recovery-cascade error hierarchy.
 *
 * Every named failure mode in the M-of-N quorum + master-rotation paths surfaces
 * as a typed error so operator-facing surfaces and tests can match by name. No
 * silent degradation — failed quorum verification or stale roster MUST throw.
 */

import { MeshError } from "../errors.js";

export class GuardianError extends MeshError {
  constructor(message: string) {
    super(message);
    this.name = "GuardianError";
  }
}

export class GuardianRosterError extends GuardianError {
  constructor(message: string) {
    super(message);
    this.name = "GuardianRosterError";
  }
}

export class GuardianRosterSignatureError extends GuardianRosterError {
  constructor(message: string) {
    super(message);
    this.name = "GuardianRosterSignatureError";
  }
}

export class GuardianRosterStaleError extends GuardianRosterError {
  constructor(incoming: number, pinned: number) {
    super(
      `incoming guardian-roster version=${incoming} is not greater than pinned version=${pinned} — replay rejected`
    );
    this.name = "GuardianRosterStaleError";
  }
}

export class GuardianQuorumError extends GuardianError {
  constructor(message: string) {
    super(message);
    this.name = "GuardianQuorumError";
  }
}

export class MasterRotationError extends GuardianError {
  constructor(message: string) {
    super(message);
    this.name = "MasterRotationError";
  }
}
