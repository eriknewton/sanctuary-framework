/** Owns the fixed roster of best-effort work launched during construction. */
export class ConstructionWork {
  // This settlement-only contract must match BuildV11BindingsInputs.constructionWork.
  private readonly tasks: Promise<PromiseSettledResult<unknown>>[] = [];
  private draining?: Promise<void>;

  track(task: Promise<unknown>): void {
    if (this.draining) throw new Error("Construction work registration is sealed");
    this.tasks.push(task.then(
      (value) => ({ status: "fulfilled" as const, value }),
      (reason: unknown) => ({ status: "rejected" as const, reason }),
    ));
  }

  // Call only after the construction producer settles; task failures remain best-effort.
  drain(): Promise<void> {
    return this.draining ??= Promise.all(this.tasks).then(() => undefined);
  }
}
