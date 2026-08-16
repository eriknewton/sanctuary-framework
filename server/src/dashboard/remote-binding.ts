/**
 * Shared dashboard remote-bind classifier.
 *
 * Must match `DashboardApprovalChannel.isRemoteBinding` in
 * `principal-policy/dashboard.ts`; both the single-tenant and multi-tenant
 * dashboard guards delegate here so their non-loopback contract cannot drift.
 */
export function isRemoteDashboardBinding(host: string): boolean {
  return host !== "127.0.0.1" && host !== "::1" && host !== "localhost";
}
