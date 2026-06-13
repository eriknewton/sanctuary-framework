/**
 * Plugin substrate — error types.
 *
 * Every rejection on the contract surface carries a NAMED, machine-stable reason so
 * the hostile-fixture suite can assert *which* invariant fired (CLAUDE.md "never
 * silently degrade": a rejection must say why, and the reason must be stable across
 * versions for audit/test traceability).
 *
 * Reasons are a closed enum. Adding a reason is additive; renaming one is a breaking
 * change to the test contract and must be deliberate.
 */

export type SubstrateRejectReason =
  // governance.yaml schema / parse
  | "yaml_anchor_or_alias"
  | "yaml_explicit_tag"
  | "yaml_merge_key"
  | "yaml_duplicate_key"
  | "yaml_non_string_key"
  | "yaml_malformed"
  | "unknown_top_level_key"
  | "unknown_nested_key"
  | "missing_required_field"
  | "invalid_field_value"
  | "invalid_plugin_id"
  | "fail_open_enforcement_fail_mode"
  | "undeclared_field_selector"
  | "undeclared_data_class_endpoint"
  | "manifest_too_large"
  // verdict / wire
  | "verdict_allow_not_permitted"
  | "verdict_unknown_decision"
  | "verdict_vendor_supplied_plugin_error"
  | "verdict_unknown_key"
  | "verdict_nonce_mismatch"
  | "verdict_request_id_mismatch"
  | "verdict_undeclared_signal_key"
  | "frame_too_large"
  | "frame_trailing_bytes"
  | "frame_duplicate_for_request"
  | "json_duplicate_key"
  | "json_prototype_key"
  | "json_non_finite_number"
  | "json_too_deep"
  // bundle / signature
  | "bundle_path_traversal"
  | "bundle_absolute_path"
  | "bundle_leading_slash"
  | "bundle_non_regular_file"
  | "bundle_unlisted_file"
  | "bundle_missing_listed_file"
  | "bundle_signature_file_listed"
  | "bundle_duplicate_signature_file"
  | "bundle_entry_not_executable"
  | "bundle_entry_not_listed"
  | "signature_invalid"
  | "signature_algorithm_unsupported"
  | "signature_signer_unknown"
  | "signature_signer_mismatch"
  | "signature_plugin_mismatch"
  | "descriptor_malformed";

export class SubstrateError extends Error {
  readonly reason: SubstrateRejectReason;

  constructor(reason: SubstrateRejectReason, message: string) {
    super(message);
    this.name = "SubstrateError";
    this.reason = reason;
  }
}

/** Throw a named substrate rejection. */
export function reject(reason: SubstrateRejectReason, message: string): never {
  throw new SubstrateError(reason, message);
}
