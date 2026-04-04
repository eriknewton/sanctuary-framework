/**
 * Sanctuary MCP Server — Prompt Injection Detection Layer
 *
 * Fast, zero-dependency detection of common prompt injection patterns.
 * Scans tool arguments for role override, security bypass, encoding evasion,
 * data exfiltration, and prompt stuffing signals.
 *
 * SEC-034/SEC-035: Enhanced with Unicode sanitization pre-pass, decoded content
 * re-scanning, token budget analysis, and outbound content scanning.
 *
 * Security invariants:
 * - Always returns a result, never throws
 * - Typical scan completes in < 5ms
 * - False positives minimized via field-aware scanning
 * - Recursive scanning of nested objects/arrays
 * - Outbound scanning catches secret leaks and injection artifact survival
 */

export interface InjectionDetectorConfig {
  enabled: boolean;
  sensitivity: "low" | "medium" | "high";
  on_detection: "escalate" | "block" | "log";
  custom_patterns?: string[];
}

export interface InjectionSignal {
  type: string;
  pattern: string;
  location: string;
  severity: "low" | "medium" | "high";
}

export interface DetectionResult {
  flagged: boolean;
  confidence: number; // 0.0-1.0
  signals: InjectionSignal[];
  recommendation: "allow" | "escalate" | "block";
}

// Pattern definitions for each detection category
const ROLE_OVERRIDE_PATTERNS = [
  /ignore\s+(?:(?:previous|prior|all)\s+)?instructions/i,
  /you\s+are\s+now/i,
  /\bsystem\s*:\s+(?!working|process|design|architecture)/i,
  /forget\s+(?:everything|all|prior)/i,
  /disregard\s+(?:the\s+)?(?:previous\s+)?instructions/i,
  /new\s+instructions\s*:/i,
  /updated?\s+instructions\s*:/i,
];

const SECURITY_BYPASS_PATTERNS = [
  /skip\s+(?:the\s+)?(?:filter|gate|check|verify|approve)/i,
  /bypass\s+(?:the\s+)?(?:filter|gate|security|check)/i,
  /disable\s+(?:the\s+)?(?:filter|gate|approval|security|audit|log|encrypt|verify)/i,
  /do\s+not\s+(?:audit|log|encrypt|verify|approve|check|sign)/i,
];

const TOOL_INVOCATION_PATTERNS = [
  /sanctuary\//i,
  /concordia\//i,
  /bridge_/i,
  /handshake_/i,
];

const URL_PATTERN = /https?:\/\/[^\s"'<>]+/i;
const EMAIL_PATTERN = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;

// ─────────────────────────────────────────────────────────────────────────────
// SEC-034: Invisible Unicode characters used in smuggling attacks
// ─────────────────────────────────────────────────────────────────────────────
const INVISIBLE_CHARS = [
  "\u200B", // Zero-width space
  "\u200C", // Zero-width non-joiner
  "\u200D", // Zero-width joiner
  "\uFEFF", // Zero-width no-break space (BOM)
  "\u00AD", // Soft hyphen
  "\u200E", // Left-to-right mark
  "\u200F", // Right-to-left mark
  "\u2060", // Word joiner
  "\u2061", // Function application
  "\u2062", // Invisible times
  "\u2063", // Invisible separator
  "\u2064", // Invisible plus
  "\u180E", // Mongolian vowel separator
  "\u034F", // Combining grapheme joiner
  "\u061C", // Arabic letter mark
  "\u115F", // Hangul choseong filler
  "\u1160", // Hangul jungseong filler
  "\u17B4", // Khmer vowel inherent AQ
  "\u17B5", // Khmer vowel inherent AA
  "\u3164", // Hangul filler
  "\uFFA0", // Halfwidth hangul filler
];

// Variation selectors: U+FE00–U+FE0F
const VARIATION_SELECTOR_RANGE_START = 0xfe00;
const VARIATION_SELECTOR_RANGE_END = 0xfe0f;

// Zero-width characters (legacy array kept for backward compat in tests)
const ZERO_WIDTH_CHARS = [
  "\u200B", // Zero-width space
  "\u200C", // Zero-width non-joiner
  "\u200D", // Zero-width joiner
  "\uFEFF", // Zero-width no-break space
];

// ─────────────────────────────────────────────────────────────────────────────
// SEC-034: Base64url pattern for encoded content detection
// ─────────────────────────────────────────────────────────────────────────────
const BASE64_STANDARD_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+={0,2}$/;
const BASE64_BLOCK_PATTERN = /[A-Za-z0-9+/]{20,}={0,2}/g;
const HEX_ENCODED_PATTERN = /(?:0x)?[0-9a-fA-F]{20,}/g;
const HTML_ENTITY_PATTERN = /&#(?:x[0-9a-fA-F]{2,4}|[0-9]{2,5});/g;
const URL_ENCODED_PATTERN = /(?:%[0-9a-fA-F]{2}){4,}/g;

// ─────────────────────────────────────────────────────────────────────────────
// SEC-035: Outbound content scanning patterns
// ─────────────────────────────────────────────────────────────────────────────

// API key patterns for common providers
const SECRET_PATTERNS = [
  { pattern: /sk-[a-zA-Z0-9]{20,}/g, name: "openai_api_key" },
  { pattern: /sk-ant-[a-zA-Z0-9_-]{20,}/g, name: "anthropic_api_key" },
  { pattern: /ghp_[a-zA-Z0-9]{36,}/g, name: "github_pat" },
  { pattern: /gho_[a-zA-Z0-9]{36,}/g, name: "github_oauth" },
  { pattern: /ghs_[a-zA-Z0-9]{36,}/g, name: "github_app" },
  { pattern: /github_pat_[a-zA-Z0-9_]{22,}/g, name: "github_fine_grained_pat" },
  { pattern: /AKIA[0-9A-Z]{16}/g, name: "aws_access_key" },
  { pattern: /xoxb-[0-9]{10,}-[a-zA-Z0-9-]+/g, name: "slack_bot_token" },
  { pattern: /xoxp-[0-9]{10,}-[a-zA-Z0-9-]+/g, name: "slack_user_token" },
  { pattern: /xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-z0-9]+/g, name: "slack_app_token" },
  { pattern: /(?:Bearer|bearer)\s+[a-zA-Z0-9._~+/=-]{20,}/g, name: "bearer_token" },
  { pattern: /glpat-[a-zA-Z0-9_-]{20,}/g, name: "gitlab_pat" },
  { pattern: /npm_[a-zA-Z0-9]{36,}/g, name: "npm_token" },
  { pattern: /pypi-[a-zA-Z0-9_-]{20,}/g, name: "pypi_token" },
  { pattern: /AIza[a-zA-Z0-9_-]{35}/g, name: "google_api_key" },
  { pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, name: "sendgrid_api_key" },
  { pattern: /sq0[a-z]{3}-[a-zA-Z0-9_-]{22,}/g, name: "square_api_key" },
  { pattern: /sk_live_[a-zA-Z0-9]{24,}/g, name: "stripe_secret_key" },
  { pattern: /rk_live_[a-zA-Z0-9]{24,}/g, name: "stripe_restricted_key" },
  { pattern: /(?:-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)/g, name: "private_key_pem" },
];

// Data exfiltration via markdown image tags
const MARKDOWN_IMAGE_EXFIL_PATTERN = /!\[[^\]]*\]\(https?:\/\/[^)]*[?&](?:data|secret|key|token|password|auth|session|cookie|api_key|access_token)=/i;

// Internal path leak patterns
const INTERNAL_PATH_PATTERNS = [
  /\/home\/[a-zA-Z0-9_.-]+\//,
  /\/Users\/[a-zA-Z0-9_.-]+\//,
  /[A-Z]:\\(?:Users|Documents|Program Files)\\/,
  /~\/\.(?:ssh|aws|config|gnupg|sanctuary)\//,
  /\/etc\/(?:passwd|shadow|hosts|ssh)/,
  /\/var\/(?:log|run|lib)\//,
];

// Private network patterns
const PRIVATE_NETWORK_PATTERNS = [
  /(?:^|\s|\/\/)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})/,
  /(?:^|\s|\/\/)(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})/,
  /(?:^|\s|\/\/)(?:192\.168\.\d{1,3}\.\d{1,3})/,
  /(?:^|\s|\/\/)localhost(?::\d+)?/,
  /(?:^|\s|\/\/)127\.0\.0\.1/,
  /(?:^|\s|\/\/)0\.0\.0\.0/,
  /(?:^|\s|\/\/)\[?::1\]?/,
];

// Role markers that shouldn't appear in output
const OUTPUT_ROLE_MARKER_PATTERNS = [
  /\bsystem\s*:/i,
  /\[INST\]/,
  /\[\/INST\]/,
  /<\|im_start\|>/,
  /<\|im_end\|>/,
  /<\|system\|>/,
  /<\|user\|>/,
  /<\|assistant\|>/,
  /<<\s*SYS\s*>>/,
  /<<\s*\/SYS\s*>>/,
  /\[SYSTEM\]/,
  /### (?:System|Human|Assistant):/,
];

export class InjectionDetector {
  private config: InjectionDetectorConfig;
  private stats = {
    total_scans: 0,
    total_flags: 0,
    total_blocks: 0,
    signals_by_type: {} as Record<string, number>,
  };

  constructor(config: Partial<InjectionDetectorConfig> = {}) {
    this.config = {
      enabled: config.enabled ?? true,
      sensitivity: config.sensitivity ?? "medium",
      on_detection: config.on_detection ?? "escalate",
      custom_patterns: config.custom_patterns ?? [],
    };
  }

  /**
   * Scan tool arguments for injection signals.
   * @param toolName Full tool name (e.g., "sanctuary/state_read")
   * @param args Tool arguments
   * @returns DetectionResult with all detected signals
   */
  scan(toolName: string, args: Record<string, unknown>): DetectionResult {
    this.stats.total_scans++;

    if (!this.config.enabled) {
      return {
        flagged: false,
        confidence: 0,
        signals: [],
        recommendation: "allow",
      };
    }

    const signals: InjectionSignal[] = [];
    const visited = new Set<unknown>();

    // Recursively scan all string values
    this.scanValue(args, "", toolName, signals, visited);

    const flagged = signals.length > 0;
    if (flagged) {
      this.stats.total_flags++;
    }
    // Always accumulate signal types, even if not flagged (for visibility)
    for (const sig of signals) {
      this.stats.signals_by_type[sig.type] =
        (this.stats.signals_by_type[sig.type] ?? 0) + 1;
    }

    const recommendation = this.computeRecommendation(
      signals,
      this.config.sensitivity
    );

    if (recommendation === "block") {
      this.stats.total_blocks++;
    }

    return {
      flagged,
      confidence: this.computeConfidence(signals),
      signals,
      recommendation,
    };
  }

  /**
   * SEC-035: Scan outbound content for secret leaks, data exfiltration,
   * internal path exposure, and injection artifact survival.
   *
   * @param content The outbound content string to scan
   * @returns DetectionResult with outbound-specific signal types
   */
  scanOutbound(content: string): DetectionResult {
    this.stats.total_scans++;

    if (!this.config.enabled) {
      return {
        flagged: false,
        confidence: 0,
        signals: [],
        recommendation: "allow",
      };
    }

    const signals: InjectionSignal[] = [];

    this.detectSecretPatterns(content, signals);
    this.detectOutboundExfiltration(content, signals);
    this.detectInternalPathLeaks(content, signals);
    this.detectPrivateNetworkLeaks(content, signals);
    this.detectOutputRoleMarkers(content, signals);

    const flagged = signals.length > 0;
    if (flagged) {
      this.stats.total_flags++;
    }

    for (const sig of signals) {
      this.stats.signals_by_type[sig.type] =
        (this.stats.signals_by_type[sig.type] ?? 0) + 1;
    }

    const recommendation = this.computeRecommendation(
      signals,
      this.config.sensitivity
    );

    if (recommendation === "block") {
      this.stats.total_blocks++;
    }

    return {
      flagged,
      confidence: this.computeConfidence(signals),
      signals,
      recommendation,
    };
  }

  /**
   * Recursively scan a value and all nested values.
   */
  private scanValue(
    value: unknown,
    path: string,
    toolName: string,
    signals: InjectionSignal[],
    visited: Set<unknown>
  ): void {
    // Prevent circular reference loops
    if (typeof value === "object" && value !== null) {
      if (visited.has(value)) return;
      visited.add(value);
    }

    if (typeof value === "string") {
      this.scanString(value, path, toolName, signals);
    } else if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        this.scanValue(value[i], `${path}[${i}]`, toolName, signals, visited);
      }
    } else if (typeof value === "object" && value !== null) {
      for (const [key, val] of Object.entries(value)) {
        this.scanValue(val, path ? `${path}.${key}` : key, toolName, signals, visited);
      }
    }
  }

  /**
   * Scan a single string for injection signals.
   */
  private scanString(
    value: string,
    path: string,
    _toolName: string,
    signals: InjectionSignal[]
  ): void {
    // Skip obviously safe fields
    if (this.isSafeField(path)) {
      return;
    }

    const location = path || "root";

    // ─────────────────────────────────────────────────────────────────────
    // SEC-034: Unicode sanitization pre-pass
    // Phase 1: Detect and flag invisible characters BEFORE stripping
    // Phase 2: Strip invisibles, normalize, then run patterns on clean text
    // ─────────────────────────────────────────────────────────────────────
    const invisibleCount = this.countInvisibleChars(value);
    if (invisibleCount > 3) {
      signals.push({
        type: "unicode_smuggling",
        pattern: `invisible_chars_count_${invisibleCount}`,
        location,
        severity: "high",
      });
    }

    // SEC-034: Token budget check — dense Unicode / wallet-drain detection
    this.detectTokenBudgetAttack(value, location, signals);

    // Strip invisible characters for clean pattern matching
    const stripped = this.stripInvisibleChars(value);

    // SEC-032: Normalize Unicode before pattern matching.
    // Two-phase normalization:
    //   1. NFKC: maps fullwidth chars, ligatures, compatibility forms to canonical
    //   2. Confusable mapping: replaces common cross-script lookalikes (Cyrillic→Latin)
    //      that NFKC doesn't cover (they're distinct codepoints, not compatibility equivalents)
    const nfkcOnly = stripped.normalize("NFKC");
    const normalized = this.normalizeConfusables(nfkcOnly);

    // If NFKC normalization changed the stripped string, that's a signal
    // (Compare against stripped, not raw value — invisible char removal is
    //  covered separately by the unicode_smuggling signal above)
    if (nfkcOnly !== stripped) {
      signals.push({
        type: "encoding_evasion",
        pattern: "unicode_normalization_delta",
        location,
        severity: "medium",
      });
    }

    // SEC-034: If confusable normalization changed text (beyond just NFKC),
    // emit both a normalization delta and a specific homoglyph_attack signal
    if (normalized !== nfkcOnly) {
      signals.push({
        type: "encoding_evasion",
        pattern: "unicode_normalization_delta",
        location,
        severity: "medium",
      });
      signals.push({
        type: "homoglyph_attack",
        pattern: "confusable_substitution",
        location,
        severity: "high",
      });
    }

    // ─────────────────────────────────────────────────────────────────────
    // HIGH SEVERITY: Role Override
    // ─────────────────────────────────────────────────────────────────────
    for (const pattern of ROLE_OVERRIDE_PATTERNS) {
      if (pattern.test(normalized)) {
        signals.push({
          type: "role_override",
          pattern: pattern.source,
          location,
          severity: "high",
        });
        break; // Only report one match per field
      }
    }

    // ─────────────────────────────────────────────────────────────────────
    // HIGH SEVERITY: Security Bypass
    // ─────────────────────────────────────────────────────────────────────
    for (const pattern of SECURITY_BYPASS_PATTERNS) {
      if (pattern.test(normalized)) {
        signals.push({
          type: "security_bypass",
          pattern: pattern.source,
          location,
          severity: "high",
        });
        break; // Only report one match per field
      }
    }

    // ─────────────────────────────────────────────────────────────────────
    // MEDIUM SEVERITY: Tool Invocation in Strings
    // ─────────────────────────────────────────────────────────────────────
    if (!this.isToolNameField(path)) {
      for (const pattern of TOOL_INVOCATION_PATTERNS) {
        if (pattern.test(normalized)) {
          signals.push({
            type: "tool_invocation_in_string",
            pattern: pattern.source,
            location,
            severity: "medium",
          });
          break; // Only report one match per field
        }
      }
    }

    // ─────────────────────────────────────────────────────────────────────
    // MEDIUM SEVERITY: Encoding Evasion
    // ─────────────────────────────────────────────────────────────────────
    this.detectEncodingEvasion(value, location, signals);

    // ─────────────────────────────────────────────────────────────────────
    // SEC-034: Decode embedded content and re-scan for injection patterns
    // ─────────────────────────────────────────────────────────────────────
    this.detectEncodedPayloads(value, location, signals);

    // ─────────────────────────────────────────────────────────────────────
    // MEDIUM SEVERITY: Data Exfiltration
    // ─────────────────────────────────────────────────────────────────────
    this.detectDataExfiltration(value, location, signals);

    // ─────────────────────────────────────────────────────────────────────
    // LOW SEVERITY: Prompt Stuffing
    // ─────────────────────────────────────────────────────────────────────
    this.detectPromptStuffing(value, location, signals);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SEC-034: Unicode sanitization helpers
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Count invisible Unicode characters in a string.
   * Includes zero-width chars, soft hyphens, directional marks,
   * variation selectors, and other invisible categories.
   */
  private countInvisibleChars(value: string): number {
    let count = 0;
    for (const ch of value) {
      const cp = ch.codePointAt(0);
      if (cp === undefined) continue;

      // Check against known invisible chars list
      if (INVISIBLE_CHARS.includes(ch)) {
        count++;
        continue;
      }

      // Variation selectors U+FE00–U+FE0F
      if (cp >= VARIATION_SELECTOR_RANGE_START && cp <= VARIATION_SELECTOR_RANGE_END) {
        count++;
        continue;
      }

      // Variation selectors supplement U+E0100–U+E01EF
      if (cp >= 0xe0100 && cp <= 0xe01ef) {
        count++;
        continue;
      }

      // Tag characters U+E0001–U+E007F (used in language tag smuggling)
      if (cp >= 0xe0001 && cp <= 0xe007f) {
        count++;
        continue;
      }

      // Interlinear annotation anchors U+FFF9–U+FFFB
      if (cp >= 0xfff9 && cp <= 0xfffb) {
        count++;
        continue;
      }
    }
    return count;
  }

  /**
   * Strip invisible characters from a string for clean pattern matching.
   * Returns a new string with all invisible chars removed.
   */
  private stripInvisibleChars(value: string): string {
    const chars: string[] = [];
    for (const ch of value) {
      const cp = ch.codePointAt(0);
      if (cp === undefined) continue;

      // Skip known invisible chars
      if (INVISIBLE_CHARS.includes(ch)) continue;

      // Skip variation selectors
      if (cp >= VARIATION_SELECTOR_RANGE_START && cp <= VARIATION_SELECTOR_RANGE_END) continue;

      // Skip variation selectors supplement
      if (cp >= 0xe0100 && cp <= 0xe01ef) continue;

      // Skip tag characters
      if (cp >= 0xe0001 && cp <= 0xe007f) continue;

      // Skip interlinear annotation anchors
      if (cp >= 0xfff9 && cp <= 0xfffb) continue;

      chars.push(ch);
    }
    return chars.join("");
  }

  /**
   * SEC-034: Token budget attack detection.
   * Some Unicode sequences expand dramatically during tokenization (e.g., CJK
   * ideographs, combining characters, emoji sequences). If the estimated token
   * cost per character is anomalously high, this may be a wallet-drain payload.
   *
   * Heuristic: count chars that typically tokenize into multiple tokens.
   * If the ratio of estimated tokens to char count exceeds 3x, flag it.
   */
  private detectTokenBudgetAttack(
    value: string,
    path: string,
    signals: InjectionSignal[]
  ): void {
    // Only check strings of meaningful length
    if (value.length < 20) return;

    let estimatedTokens = 0;
    for (const ch of value) {
      const cp = ch.codePointAt(0);
      if (cp === undefined) continue;

      if (cp <= 0x7f) {
        // ASCII: ~0.25 tokens per char (4 chars per token average)
        estimatedTokens += 0.25;
      } else if (cp <= 0x07ff) {
        // 2-byte UTF-8: ~0.5 tokens per char
        estimatedTokens += 0.5;
      } else if (cp <= 0xffff) {
        // 3-byte UTF-8 (CJK, etc.): ~1-2 tokens per char
        estimatedTokens += 1.5;
      } else {
        // 4-byte UTF-8 (emoji, supplementary): ~2-3 tokens per char
        estimatedTokens += 2.5;
      }
    }

    let charCount = 0;
    for (const _ch of value) { charCount++; } // Actual character count (not byte count)
    const ratio = estimatedTokens / charCount;

    if (ratio > 3.0) {
      signals.push({
        type: "token_budget_attack",
        pattern: `token_char_ratio_${ratio.toFixed(2)}`,
        location: path,
        severity: "medium",
      });
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SEC-034: Encoded payload detection and re-scanning
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Detect encoded content (base64, hex, HTML entities, URL encoding),
   * decode it, and re-scan the decoded content through injection patterns.
   * If the decoded content contains injection patterns, flag as encoding_evasion.
   */
  private detectEncodedPayloads(
    value: string,
    path: string,
    signals: InjectionSignal[]
  ): void {
    const decodedParts: string[] = [];

    // Extract and decode inline base64 blocks (not the whole-string check, which
    // is already in detectEncodingEvasion — this handles embedded blocks)
    const base64Matches = value.match(BASE64_BLOCK_PATTERN);
    if (base64Matches) {
      for (const match of base64Matches) {
        const decoded = this.safeBase64Decode(match);
        if (decoded !== null) {
          decodedParts.push(decoded);
        }
      }
    }

    // Decode hex-encoded strings
    const hexMatches = value.match(HEX_ENCODED_PATTERN);
    if (hexMatches) {
      for (const match of hexMatches) {
        const decoded = this.safeHexDecode(match);
        if (decoded !== null) {
          decodedParts.push(decoded);
        }
      }
    }

    // Decode HTML entities
    if (HTML_ENTITY_PATTERN.test(value)) {
      const decoded = this.decodeHtmlEntities(value);
      if (decoded !== value) {
        decodedParts.push(decoded);
      }
    }

    // Decode URL-encoded sequences
    const urlMatches = value.match(URL_ENCODED_PATTERN);
    if (urlMatches) {
      for (const match of urlMatches) {
        const decoded = this.safeUrlDecode(match);
        if (decoded !== null && decoded !== match) {
          decodedParts.push(decoded);
        }
      }
    }

    // Re-scan decoded content through injection patterns
    for (const decoded of decodedParts) {
      if (this.containsInjectionPatterns(decoded)) {
        signals.push({
          type: "encoding_evasion",
          pattern: "encoded_injection_payload",
          location: path,
          severity: "high",
        });
        return; // One signal is sufficient
      }
    }
  }

  /**
   * Check if a string contains any injection patterns (role override or security bypass).
   */
  private containsInjectionPatterns(value: string): boolean {
    const normalized = this.normalizeConfusables(value.normalize("NFKC"));
    for (const pattern of ROLE_OVERRIDE_PATTERNS) {
      if (pattern.test(normalized)) return true;
    }
    for (const pattern of SECURITY_BYPASS_PATTERNS) {
      if (pattern.test(normalized)) return true;
    }
    return false;
  }

  /**
   * Safely decode a base64 string. Returns null if it's not valid base64
   * or doesn't decode to a meaningful string.
   */
  private safeBase64Decode(value: string): string | null {
    try {
      // Must be valid base64 (standard or URL-safe)
      const cleaned = value.replace(/-/g, "+").replace(/_/g, "/");
      // Pad if needed
      const padded = cleaned + "=".repeat((4 - (cleaned.length % 4)) % 4);
      if (!BASE64_STANDARD_PATTERN.test(padded)) return null;

      const decoded = Buffer.from(padded, "base64").toString("utf-8");
      // Only return if the decoded content looks like text (not binary)
      if (this.looksLikeText(decoded)) {
        return decoded;
      }
      return null;
    } catch {
      return null;
    }
  }

  /**
   * Safely decode a hex string. Returns null on failure.
   */
  private safeHexDecode(value: string): string | null {
    try {
      const hex = value.startsWith("0x") ? value.slice(2) : value;
      if (hex.length % 2 !== 0) return null;
      const decoded = Buffer.from(hex, "hex").toString("utf-8");
      if (this.looksLikeText(decoded)) {
        return decoded;
      }
      return null;
    } catch {
      return null;
    }
  }

  /**
   * Decode HTML numeric entities (&#xHH; and &#DDD;) in a string.
   */
  private decodeHtmlEntities(value: string): string {
    return value.replace(/&#x([0-9a-fA-F]{2,4});/g, (_match, hex: string) => {
      try {
        return String.fromCodePoint(parseInt(hex, 16));
      } catch {
        return _match;
      }
    }).replace(/&#([0-9]{2,5});/g, (_match, dec: string) => {
      try {
        const cp = parseInt(dec, 10);
        if (cp > 0x10ffff) return _match;
        return String.fromCodePoint(cp);
      } catch {
        return _match;
      }
    });
  }

  /**
   * Safely decode a URL-encoded string. Returns null on failure.
   */
  private safeUrlDecode(value: string): string | null {
    try {
      return decodeURIComponent(value);
    } catch {
      return null;
    }
  }

  /**
   * Heuristic: does this look like readable text (vs. binary garbage)?
   * Checks that most characters are printable ASCII or common Unicode.
   */
  private looksLikeText(value: string): boolean {
    if (value.length === 0) return false;
    let printable = 0;
    for (let i = 0; i < value.length; i++) {
      const code = value.charCodeAt(i);
      // Printable ASCII + common Unicode ranges
      if ((code >= 0x20 && code <= 0x7e) || code === 0x0a || code === 0x0d || code === 0x09) {
        printable++;
      } else if (code >= 0x80) {
        // Non-ASCII Unicode — count as printable unless it's a control char
        if (code < 0xa0) continue; // C1 control characters — not printable
        printable++;
      }
    }
    return printable / value.length > 0.7;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SEC-035: Outbound content scanning helpers
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Detect API keys and secrets in outbound content.
   */
  private detectSecretPatterns(
    content: string,
    signals: InjectionSignal[]
  ): void {
    for (const { pattern, name } of SECRET_PATTERNS) {
      // Reset regex state (global flag)
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        signals.push({
          type: "secret_leak",
          pattern: name,
          location: "outbound",
          severity: "high",
        });
      }
    }
  }

  /**
   * Detect data exfiltration via markdown images with data-carrying query params.
   */
  private detectOutboundExfiltration(
    content: string,
    signals: InjectionSignal[]
  ): void {
    if (MARKDOWN_IMAGE_EXFIL_PATTERN.test(content)) {
      signals.push({
        type: "data_exfiltration",
        pattern: "markdown_image_exfil",
        location: "outbound",
        severity: "high",
      });
    }
  }

  /**
   * Detect internal filesystem path leaks in outbound content.
   */
  private detectInternalPathLeaks(
    content: string,
    signals: InjectionSignal[]
  ): void {
    for (const pattern of INTERNAL_PATH_PATTERNS) {
      if (pattern.test(content)) {
        signals.push({
          type: "internal_path_leak",
          pattern: pattern.source,
          location: "outbound",
          severity: "medium",
        });
        return; // One signal is sufficient
      }
    }
  }

  /**
   * Detect private IP addresses and localhost references in outbound content.
   */
  private detectPrivateNetworkLeaks(
    content: string,
    signals: InjectionSignal[]
  ): void {
    for (const pattern of PRIVATE_NETWORK_PATTERNS) {
      if (pattern.test(content)) {
        signals.push({
          type: "private_network_leak",
          pattern: pattern.source,
          location: "outbound",
          severity: "medium",
        });
        return; // One signal is sufficient
      }
    }
  }

  /**
   * Detect role markers / prompt template artifacts in outbound content.
   * These should never appear in agent output — their presence indicates
   * injection artifact survival.
   */
  private detectOutputRoleMarkers(
    content: string,
    signals: InjectionSignal[]
  ): void {
    for (const pattern of OUTPUT_ROLE_MARKER_PATTERNS) {
      if (pattern.test(content)) {
        signals.push({
          type: "injection_artifact",
          pattern: pattern.source,
          location: "outbound",
          severity: "high",
        });
        return; // One signal is sufficient
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Existing detection methods (enhanced)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Detect base64 strings, base64url, and zero-width character evasion.
   */
  private detectEncodingEvasion(
    value: string,
    path: string,
    signals: InjectionSignal[]
  ): void {
    // Base64 detection: alphanumeric + / + = chars, at least 50 chars
    const trimmed = value.trim();
    if (value.length > 50) {
      if (BASE64_STANDARD_PATTERN.test(trimmed)) {
        signals.push({
          type: "encoding_evasion",
          pattern: "base64_string",
          location: path || "root",
          severity: "medium",
        });
      }
      // SEC-034: Also detect base64url encoding
      else if (BASE64URL_PATTERN.test(trimmed) && /[_-]/.test(trimmed)) {
        signals.push({
          type: "encoding_evasion",
          pattern: "base64url_string",
          location: path || "root",
          severity: "medium",
        });
      }
    }

    // Zero-width character detection
    let zeroWidthCount = 0;
    for (const char of ZERO_WIDTH_CHARS) {
      zeroWidthCount += (value.match(new RegExp(char, "g")) || []).length;
    }

    if (zeroWidthCount > 0) {
      signals.push({
        type: "encoding_evasion",
        pattern: "zero_width_characters",
        location: path || "root",
        severity: "medium",
      });
    }

    // Unicode category mixing: presence of multiple distinct Unicode categories
    // suggests obfuscation (e.g., mixing CJK, Latin, Arabic, Cyrillic)
    const hasLatin = /[a-zA-Z]/.test(value);
    const hasCJK = /[\u4E00-\u9FFF\u3040-\u309F\uAC00-\uD7AF]/.test(value);
    const hasArabic = /[\u0600-\u06FF]/.test(value);
    const hasCyrillic = /[\u0400-\u04FF]/.test(value);

    const unicodeCategories = [hasLatin, hasCJK, hasArabic, hasCyrillic].filter(
      (x) => x
    ).length;

    if (unicodeCategories >= 3) {
      signals.push({
        type: "encoding_evasion",
        pattern: "unicode_category_mixing",
        location: path || "root",
        severity: "medium",
      });
    }
  }

  /**
   * Detect URLs and emails in fields that shouldn't have them.
   */
  private detectDataExfiltration(
    value: string,
    path: string,
    signals: InjectionSignal[]
  ): void {
    // Skip obviously safe fields
    if (this.isUrlSafeField(path)) {
      return;
    }

    // URL detection in non-url fields
    if (URL_PATTERN.test(value)) {
      signals.push({
        type: "data_exfiltration",
        pattern: "url_in_string",
        location: path || "root",
        severity: "medium",
      });
    }

    // Email detection in non-email fields
    if (EMAIL_PATTERN.test(value) && !this.isEmailSafeField(path)) {
      signals.push({
        type: "data_exfiltration",
        pattern: "email_in_string",
        location: path || "root",
        severity: "medium",
      });
    }

    // JSON/XML embedded in plain string fields
    // Only flag if it looks like deliberate embedding (not just a URL or normal text)
    if (value.length > 30 && value.length < 10000 && !this.isStructuredField(path)) {
      // Look for actual JSON/XML with content, not just edge cases
      const hasJsonContent = /\{[^}]*"[^"]*"[^}]*\}/.test(value);
      const hasXmlContent = /<[^>]+>[\s\S]*?<\/[^>]+>/.test(value);

      if (hasJsonContent || hasXmlContent) {
        signals.push({
          type: "data_exfiltration",
          pattern: "structured_data_in_string",
          location: path || "root",
          severity: "medium",
        });
      }
    }
  }

  /**
   * Detect prompt stuffing: very large strings or high repetition.
   */
  private detectPromptStuffing(
    value: string,
    path: string,
    signals: InjectionSignal[]
  ): void {
    // Large string detection (> 10KB)
    if (value.length > 10240) {
      signals.push({
        type: "prompt_stuffing",
        pattern: "large_string",
        location: path || "root",
        severity: "low",
      });
    }

    // High repetition detection: same substring repeated 10+ times
    // SEC-031: Uses substring counting instead of regex to prevent ReDoS.
    // Checks a fixed set of window sizes (10, 20, 50) for O(n) performance.
    if (value.length >= 100) {
      const windowSizes = [10, 20, 50];
      for (const windowSize of windowSizes) {
        if (value.length < windowSize * 5) continue;
        const pattern = value.substring(0, windowSize);
        let count = 0;
        let idx = 0;
        while (idx <= value.length - windowSize) {
          if (value.substring(idx, idx + windowSize) === pattern) {
            count++;
            idx += windowSize; // Non-overlapping matches
          } else {
            idx++;
          }
          if (count >= 10) break; // Early exit
        }
        if (count >= 10) {
          signals.push({
            type: "prompt_stuffing",
            pattern: "high_repetition",
            location: path || "root",
            severity: "low",
          });
          break; // Only report once per field
        }
      }
    }
  }

  /**
   * Determine if this field is inherently safe from role override.
   */
  private isSafeField(path: string): boolean {
    // Fields that never contain user instructions
    const safePaths = [
      /\.version$/i,
      /\.timestamp$/i,
      /\.id$/i,
      /\.uuid$/i,
      /\.hash$/i,
      /\.signature$/i,
      /\.public_key$/i,
      /\.private_key$/i,
      /\.did$/i,
      /\.nonce$/i,
      /\.salt$/i,
      /\.iv$/i,
      /^ciphertext$/i,
      /^encrypted$/i,
    ];

    return safePaths.some((p) => p.test(path));
  }

  /**
   * Determine if this is a tool name field (where tool refs are expected).
   */
  private isToolNameField(path: string): boolean {
    const toolFields = [
      /tool_name/i,
      /\.tool$/i,
      /^tool$/i,
      /operation/i,
    ];
    return toolFields.some((p) => p.test(path));
  }

  /**
   * Determine if this field is safe for URLs.
   */
  private isUrlSafeField(path: string): boolean {
    const urlFields = [
      /url/i,
      /endpoint/i,
      /webhook/i,
      /callback/i,
    ];
    return urlFields.some((p) => p.test(path));
  }

  /**
   * Determine if this field is safe for emails.
   */
  private isEmailSafeField(path: string): boolean {
    const emailFields = [
      /email/i,
      /contact/i,
      /recipient/i,
      /sender/i,
      /from/i,
      /to/i,
    ];
    return emailFields.some((p) => p.test(path));
  }

  /**
   * Determine if this field is safe for structured data (JSON/XML).
   */
  private isStructuredField(path: string): boolean {
    const structuredFields = [
      /data/i,
      /payload/i,
      /body/i,
      /json/i,
      /xml/i,
    ];
    return structuredFields.some((p) => p.test(path));
  }

  /**
   * SEC-032/SEC-034: Map common cross-script confusable characters to their
   * Latin equivalents. NFKC normalization handles fullwidth and compatibility
   * forms, but does NOT map Cyrillic/Greek/Armenian/Georgian lookalikes to
   * Latin (they're distinct codepoints by design).
   *
   * Extended to 50+ confusable pairs covering Cyrillic, Greek, Armenian,
   * Georgian, Cherokee, and mathematical/symbol lookalikes.
   */
  private normalizeConfusables(value: string): string {
    // Map of common confusable characters → Latin equivalents
    // Source: Unicode TR39 confusable mappings (subset covering injection-relevant chars)
    const confusables: Record<string, string> = {
      // ── Cyrillic → Latin ──────────────────────────────────────────────
      "\u0410": "A", "\u0430": "a", // А а
      "\u0412": "B", "\u0432": "b", // В в (visual approximation)
      "\u0421": "C", "\u0441": "c", // С с
      "\u0414": "D",                // Д (visual approximation)
      "\u0415": "E", "\u0435": "e", // Е е
      "\u041D": "H", "\u043D": "h", // Н н (visual approximation)
      "\u0406": "I", "\u0456": "i", // І і (Ukrainian I)
      "\u0408": "J",                // Ј (Serbian Je)
      "\u041A": "K", "\u043A": "k", // К к (visual approximation)
      "\u041C": "M", "\u043C": "m", // М м (visual approximation)
      "\u041E": "O", "\u043E": "o", // О о
      "\u0420": "P", "\u0440": "p", // Р р
      "\u0405": "S", "\u0455": "s", // Ѕ ѕ (Macedonian S)
      "\u0422": "T", "\u0442": "t", // Т т (visual approximation)
      "\u0425": "X", "\u0445": "x", // Х х
      "\u0423": "Y", "\u0443": "y", // У у (visual approximation)
      "\u0417": "3",                // З (looks like 3)
      "\u04BB": "h",                // һ (Shha)
      "\u04C0": "I",                // Ӏ (Palochka)
      "\u04CF": "l",                // ӏ (Palochka small)

      // ── Greek → Latin ─────────────────────────────────────────────────
      "\u0391": "A", "\u03B1": "a", // Α α (alpha not exact)
      "\u0392": "B", "\u03B2": "b", // Β β (not exact)
      "\u0393": "G",                // Γ (visual approximation)
      "\u0395": "E", "\u03B5": "e", // Ε ε (not exact)
      "\u0396": "Z", "\u03B6": "z", // Ζ ζ (not exact)
      "\u0397": "H", "\u03B7": "n", // Η η (not exact)
      "\u0399": "I", "\u03B9": "i", // Ι ι
      "\u039A": "K", "\u03BA": "k", // Κ κ
      "\u039C": "M",                // Μ
      "\u039D": "N",                // Ν
      "\u039F": "O", "\u03BF": "o", // Ο ο
      "\u03A1": "P", "\u03C1": "p", // Ρ ρ (not exact)
      "\u03A4": "T", "\u03C4": "t", // Τ τ (not exact)
      "\u03A5": "Y", "\u03C5": "y", // Υ υ (not exact)
      "\u03A7": "X", "\u03C7": "x", // Χ χ (not exact)
      "\u03C9": "w",                // ω (omega, visual approximation)

      // ── Armenian → Latin ──────────────────────────────────────────────
      "\u0555": "O",                // Օ
      "\u0585": "o",                // օ
      "\u054D": "S",                // Ս
      "\u057D": "s",                // ս
      "\u054C": "L",                // Լ (visual approximation)
      "\u0570": "h",                // հ

      // ── Cherokee → Latin ──────────────────────────────────────────────
      "\u13A0": "D",                // Ꭰ
      "\u13B3": "W",                // Ꮃ
      "\u13A1": "R",                // Ꭱ
      "\u13AA": "G",                // Ꭺ (looks like A but maps to G sound)
      "\u13D2": "V",                // Ꮢ (visual approximation)

      // ── Symbols / Mathematical → Latin ────────────────────────────────
      "\u2160": "I",                // Ⅰ (Roman numeral one)
      "\u2164": "V",                // Ⅴ (Roman numeral five)
      "\u2169": "X",                // Ⅹ (Roman numeral ten)
      "\u216C": "L",                // Ⅼ (Roman numeral fifty)
      "\u216D": "C",                // Ⅽ (Roman numeral one hundred)
      "\u216E": "D",                // Ⅾ (Roman numeral five hundred)
      "\u216F": "M",                // Ⅿ (Roman numeral one thousand)
      "\u2170": "i",                // ⅰ (small Roman numeral one)
      "\u2174": "v",                // ⅴ (small Roman numeral five)
      "\u2179": "x",                // ⅹ (small Roman numeral ten)
      "\u217C": "l",                // ⅼ (small Roman numeral fifty)
      "\u217D": "c",                // ⅽ (small Roman numeral one hundred)
      "\u217E": "d",                // ⅾ (small Roman numeral five hundred)
      "\u217F": "m",                // ⅿ (small Roman numeral one thousand)
      "\u0251": "a",                // ɑ (Latin alpha — looks like 'a')
      "\u0261": "g",                // ɡ (Latin small letter script G)
    };

    let result = value;
    // Only scan if the string contains non-ASCII characters (fast path)
    // eslint-disable-next-line no-control-regex
    if (/[^\x00-\x7F]/.test(value)) {
      const chars = [];
      for (const ch of result) {
        chars.push(confusables[ch] ?? ch);
      }
      result = chars.join("");
    }
    return result;
  }

  /**
   * Compute confidence score based on signals.
   * More high-severity signals = higher confidence.
   */
  private computeConfidence(signals: InjectionSignal[]): number {
    if (signals.length === 0) return 0;

    let score = 0;
    let highCount = 0;

    for (const sig of signals) {
      switch (sig.severity) {
        case "high":
          highCount++;
          score += 0.35;
          break;
        case "medium":
          score += 0.15;
          break;
        case "low":
          score += 0.05;
          break;
      }
    }

    // Each additional high-severity signal increases confidence
    if (highCount > 1) {
      score += (highCount - 1) * 0.15;
    }

    // Cap at 1.0
    return Math.min(score, 1.0);
  }

  /**
   * Compute recommendation based on signals and sensitivity.
   */
  private computeRecommendation(
    signals: InjectionSignal[],
    sensitivity: "low" | "medium" | "high"
  ): "allow" | "escalate" | "block" {
    if (signals.length === 0) return "allow";

    const highSeverity = signals.filter((s) => s.severity === "high");
    const mediumSeverity = signals.filter((s) => s.severity === "medium");

    switch (sensitivity) {
      case "low":
        // Only high-severity signals trigger escalation
        return highSeverity.length > 0 ? "escalate" : "allow";

      case "medium":
        // High-severity → block, medium → escalate, low → allow
        if (highSeverity.length > 0) return "block";
        return mediumSeverity.length > 0 ? "escalate" : "allow";

      case "high":
        // High-severity → block, medium → block, low → escalate
        if (highSeverity.length > 0 || mediumSeverity.length > 1) return "block";
        if (mediumSeverity.length > 0) return "block";
        return signals.length > 0 ? "escalate" : "allow";
    }
  }

  /**
   * Get statistics about scans performed.
   */
  getStats(): {
    total_scans: number;
    total_flags: number;
    total_blocks: number;
    signals_by_type: Record<string, number>;
  } {
    return {
      total_scans: this.stats.total_scans,
      total_flags: this.stats.total_flags,
      total_blocks: this.stats.total_blocks,
      signals_by_type: { ...this.stats.signals_by_type },
    };
  }

  /**
   * Reset statistics.
   */
  resetStats(): void {
    this.stats = {
      total_scans: 0,
      total_flags: 0,
      total_blocks: 0,
      signals_by_type: {},
    };
  }
}
