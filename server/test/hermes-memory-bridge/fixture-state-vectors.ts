export const HERMES_MEMORY_WIRE_STATE_DEPENDENT_VECTORS = Object.freeze([
  {
    name: "relay frame envelope",
    reason: "public bytes for an admitted connection are checked by bridge connection state",
  },
  {
    name: "relay closed",
    reason: "connection shutdown depends on bridge connection state",
  },
  {
    name: "relay probe reply",
    reason: "probe replies depend on an issued nonce for the connection",
  },
  {
    name: "relay frame bytes",
    reason: "public bytes for an admitted connection are checked by bridge connection state",
  },
  {
    name: "relay closed bytes",
    reason: "connection shutdown depends on bridge connection state",
  },
  {
    name: "relay probe reply bytes",
    reason: "probe replies depend on an issued nonce for the connection",
  },
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
