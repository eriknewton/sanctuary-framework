type FederationJob = "fleet" | "renewal" | "guardian";

/** The channel retains one settlement promise per recurring job until disposal. */
export class FederationWork {
  private sealed = false;
  private readonly flights = new Map<FederationJob, Promise<void>>();
  private draining?: Promise<void>;

  get accepting(): boolean { return !this.sealed; }
  get idle(): boolean { return this.flights.size === 0; }

  run(job: FederationJob, action: () => void | Promise<void>): Promise<void> {
    if (this.sealed) return Promise.resolve();
    const prior = this.flights.get(job);
    if (prior) return prior;
    let settle!: () => void;
    const flight = new Promise<void>((resolve) => { settle = resolve; });
    this.flights.set(job, flight);
    const done = () => { this.flights.delete(job); settle(); };
    try {
      const result = action();
      if (result) void result.then(done, done);
      else done();
    } catch { done(); }
    return flight;
  }

  seal(): void { this.sealed = true; }

  // Settlement joins every admitted flight after producer admission closes.
  drain(): Promise<void> {
    this.seal();
    return this.draining ??= Promise.all(this.flights.values()).then(() => undefined);
  }
}
