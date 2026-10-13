export const HERMES_MEMORY_WIRE_STATE_RECORDED_FOR_2A_II = Object.freeze([
  {
    name: "relay closed then late probe reply",
    reason: "late probe reply lookup depends on abandoned nonce state",
  },
  {
    name: "relay probe reply after timeout",
    reason: "timeout handling moves the issued nonce into abandoned state",
  },
  {
    name: "relay probe reply never accepted connection",
    reason: "connection admission history is owned by the bridge state slice",
  },
] as const);
