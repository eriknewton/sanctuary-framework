export type SessionBindingState =
  | "state_BOUND_NAMED"
  | "state_BOUND_SOLE_IDENTITY"
  | "state_UNBOUND_FLAG_OFF"
  | "state_UNBOUND_NO_IDENTITY"
  | "state_UNBOUND_SEVERAL_IDENTITIES"
  | "state_UNBOUND_UNPROVEN"
  | "state_NAMED_EMPTY"
  | "state_NAMED_UNRESOLVED";


/** The frozen boot decision must match createSessionBindingAccessors in session-binding.ts. */
export type SessionBindingBootState = () => SessionBindingState;
