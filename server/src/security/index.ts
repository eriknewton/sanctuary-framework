/**
 * Sanctuary Security - Public surface.
 *
 * The prompt-injection detection layer. Scans tool arguments and outbound
 * content for role-override, security-bypass, encoding-evasion, and
 * data-exfiltration signals. The detector always returns a result and
 * never throws; callers gate on the result rather than catching errors.
 *
 * Re-exports the InjectionDetector class plus its config and result types
 * (InjectionDetectorConfig, InjectionSignal, DetectionResult). No CLI or
 * side-effecting entry points live here.
 */

export * from "./injection-detector.js";
