/** Static authority registry only; no extension payload handler ships in v0. */
export const SNAPSHOT_EXTENSIONS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  "vendor-reconciliation-v0": Object.freeze(["extension:vendor-reconciliation-v0"]),
  "linux-business-v0": Object.freeze(["extension:linux-business-producer-v0", "extension:linux-business-policy-v0"]),
  "model-recorder-v0": Object.freeze(["extension:model-recorder-policy-v0", "extension:model-recorder-session-v0", "extension:model-recorder-extent-v0", "extension:model-recorder-v0"]),
});
export function extensionRolesAllowed(id: string, roles: readonly string[]): boolean {
  // A registered handler may claim only its own role set, and an unregistered id only its own "extension:<id>" role when no registered handler owns that role, so no id can cite a pin issued for a registered handler.
  const registered = Object.hasOwn(SNAPSHOT_EXTENSIONS, id);
  const allowed = registered ? SNAPSHOT_EXTENSIONS[id] : [`extension:${id}`];
  const ownedElsewhere = (role: string) => !registered && Object.values(SNAPSHOT_EXTENSIONS).some(set => set.includes(role));
  return roles.length > 0 && new Set(roles).size === roles.length && roles.every(role => allowed.includes(role) && !ownedElsewhere(role));
}
