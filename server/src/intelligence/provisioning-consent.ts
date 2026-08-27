/** Closed pre-mutation authorization predicate shared by every P1 path. */
export function localProvisioningPreflightRefusal(
  isTty: boolean,
  preAnswered: boolean | undefined,
): "declined" | "non_tty" | null {
  if (preAnswered === false) return "declined";
  // A positive flag enters the ceremony but never grants headless mutation.
  if (!isTty) return "non_tty";
  return null;
}
