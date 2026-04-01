/**
 * Sanctuary MCP Server — Prompt Injection Detection Layer
 *
 * Fast, zero-dependency detection of common prompt injection patterns.
 * Scans tool arguments for role override, security bypass, encoding evasion,
 * data exfiltration, and prompt stuffing signals.
 *
 * Security invariants:
 * - Always returns a result, never throws
 * - Typical scan completes in < 5ms
 * - False positives minimized via field-aware scanning
 * - Recursive scanning of nested objects/arrays
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

// Zero-width characters that are used in evasion
const ZERO_WIDTH_CHARS = [
  "\u200B", // Zero-width space
  "\u200C", // Zero-width non-joiner
  "\u200D", // Zero-width joiner
  "\uFEFF", // Zero-width no-break space
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

    // SEC-032: Normalize Unicode before pattern matching.
    // Two-phase normalization:
    //   1. NFKC: maps fullwidth chars, ligatures, compatibility forms to canonical
    //   2. Confusable mapping: replaces common cross-script lookalikes (Cyrillic→Latin)
    //      that NFKC doesn't cover (they're distinct codepoints, not compatibility equivalents)
    const normalized = this.normalizeConfusables(value.normalize("NFKC"));

    // If normalization changed the string, that's itself a signal
    if (normalized !== value) {
      signals.push({
        type: "encoding_evasion",
        pattern: "unicode_normalization_delta",
        location,
        severity: "medium",
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
    // MEDIUM SEVERITY: Data Exfiltration
    // ─────────────────────────────────────────────────────────────────────
    this.detectDataExfiltration(value, location, signals);

    // ─────────────────────────────────────────────────────────────────────
    // LOW SEVERITY: Prompt Stuffing
    // ─────────────────────────────────────────────────────────────────────
    this.detectPromptStuffing(value, location, signals);
  }

  /**
   * Detect base64 strings and zero-width character evasion.
   */
  private detectEncodingEvasion(
    value: string,
    path: string,
    signals: InjectionSignal[]
  ): void {
    // Base64 detection: alphanumeric + / + = chars, at least 50 chars
    if (
      value.length > 50 &&
      /^[A-Za-z0-9+/]+={0,2}$/.test(value.trim())
    ) {
      signals.push({
        type: "encoding_evasion",
        pattern: "base64_string",
        location: path || "root",
        severity: "medium",
      });
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
   * SEC-032: Map common cross-script confusable characters to their Latin equivalents.
   * NFKC normalization handles fullwidth and compatibility forms, but does NOT map
   * Cyrillic/Greek lookalikes to Latin (they're distinct codepoints by design).
   * This covers the most common confusables used in injection evasion.
   */
  private normalizeConfusables(value: string): string {
    // Map of common confusable characters → Latin equivalents
    // Source: Unicode TR39 confusable mappings (subset covering injection-relevant chars)
    const confusables: Record<string, string> = {
      // Cyrillic → Latin
      "\u0410": "A", "\u0430": "a", // А а
      "\u0412": "B", "\u0432": "b", // В (not exact) в (not exact)
      "\u0421": "C", "\u0441": "c", // С с
      "\u0415": "E", "\u0435": "e", // Е е
      "\u041D": "H", "\u043D": "h", // Н (not exact) н (not exact)
      "\u041A": "K", "\u043A": "k", // К к (not exact)
      "\u041C": "M", "\u043C": "m", // М (not exact) м (not exact)
      "\u041E": "O", "\u043E": "o", // О о
      "\u0420": "P", "\u0440": "p", // Р р
      "\u0422": "T", "\u0442": "t", // Т (not exact) т (not exact)
      "\u0425": "X", "\u0445": "x", // Х х
      "\u0423": "Y", "\u0443": "y", // У (not exact) у
      // Greek → Latin
      "\u0391": "A", "\u03B1": "a", // Α α (not exact)
      "\u0392": "B", "\u03B2": "b", // Β β (not exact)
      "\u0395": "E", "\u03B5": "e", // Ε ε (not exact)
      "\u0397": "H",                // Η
      "\u0399": "I", "\u03B9": "i", // Ι ι
      "\u039A": "K", "\u03BA": "k", // Κ κ
      "\u039C": "M",                // Μ
      "\u039D": "N",                // Ν
      "\u039F": "O", "\u03BF": "o", // Ο ο
      "\u03A1": "P", "\u03C1": "p", // Ρ ρ (not exact)
      "\u03A4": "T", "\u03C4": "t", // Τ τ (not exact)
      "\u03A5": "Y", "\u03C5": "y", // Υ υ (not exact)
      "\u03A7": "X", "\u03C7": "x", // Χ χ (not exact)
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
