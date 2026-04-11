/**
 * Sanctuary MCP Server — EU AI Act Annex III Classification Helper
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Structured catalog of the eight Annex III high-risk use-case
 * categories under Regulation (EU) 2024/1689, plus a rule-based
 * classifier that takes a free-text agent description and returns
 * candidate categories with an honest confidence signal.
 *
 * HONEST-OVER-OPTIMISTIC: the classifier is rule-based / keyword-
 * weighted. It is NOT a machine-learning model. The `rule_based_
 * confidence` field is a deliberately awkward name so no downstream
 * consumer can mistake it for a model prediction. The classifier
 * narrows the deployer's search; it does not make the legal
 * classification determination. A human reviewer must confirm the
 * final Annex III category before the bundle is filed.
 *
 * NOT LEGAL ADVICE.
 */

// ── Types ────────────────────────────────────────────────────────────

/**
 * One of the eight Annex III high-risk categories (or sub-points
 * within §1, §3, §4, §5, §6, §7, §8 where the regulation
 * enumerates multiple distinct use cases under a single numbered
 * section).
 */
export interface AnnexIIICategory {
  /** Stable ID used in tool output and tests. */
  id: string;
  /** Citation string, e.g., "Annex III §4(a)". */
  citation: string;
  /** Short human-readable title. */
  title: string;
  /**
   * Verbatim regulation text with `[...]` elisions for length.
   * Same discipline as coverage_matrix.ts — never paraphrased.
   */
  verbatim: string;
  /**
   * Keywords that indicate this category when present in an agent
   * description. Each keyword has a weight contributing to the
   * confidence score. Weights are deliberately coarse (1.0 / 0.6 /
   * 0.3) so no one mistakes the scoring for a probabilistic model.
   */
  keywords: Array<{ term: string; weight: number }>;
}

/**
 * One matched category in a classification result.
 */
export interface ClassificationMatch {
  category_id: string;
  citation: string;
  title: string;
  /**
   * Rule-based confidence signal. Deliberately named
   * `rule_based_confidence` rather than `confidence` or
   * `probability` so downstream consumers cannot mistake it for a
   * model prediction. Computed as the sum of matched keyword
   * weights, clamped to [0, 1]. A value of 0.8+ indicates strong
   * keyword overlap; 0.4-0.8 indicates moderate overlap; below 0.4
   * is omitted from results entirely.
   */
  rule_based_confidence: number;
  /** The specific keywords from the catalog that matched the input. */
  matched_keywords: string[];
}

/**
 * Output of classifyAgentDescription().
 */
export interface ClassificationResult {
  /** The input description (lowercased for matching; original case lost). */
  description_fragment: string;
  /**
   * Candidate Annex III categories ordered by rule_based_confidence
   * descending. May be empty if no category matched above the
   * minimum threshold.
   */
  candidates: ClassificationMatch[];
  /**
   * Honest guidance emitted with every result. The classifier never
   * makes the legal call; this text is always present.
   */
  advisory: string;
  /** Matches the regulation version used during classification. */
  regulation_version: string;
}

// ── The catalog ──────────────────────────────────────────────────────

const MIN_CONFIDENCE_THRESHOLD = 0.4;
const W_HIGH = 1.0;
const W_MED = 0.6;
const W_LOW = 0.3;

/**
 * The eight Annex III high-risk categories, broken out where the
 * regulation enumerates multiple sub-points under one section.
 * Verbatim regulation text is quoted with `[...]` elisions.
 *
 * LAST REVIEWED: 2026-04-10 against Regulation (EU) 2024/1689 as
 * published in OJ L, 2024/1689, 12 July 2024.
 */
export const ANNEX_III_CATEGORIES: AnnexIIICategory[] = [
  // §1 — Biometrics
  {
    id: "annex_iii_1_a_remote_biometric_identification",
    citation: "Annex III §1(a)",
    title: "Remote biometric identification systems",
    verbatim:
      '"Remote biometric identification systems [...] excluding AI systems [...] for biometric verification the sole purpose of which is to confirm that a specific natural person is the person he or she claims to be."',
    keywords: [
      { term: "facial recognition", weight: W_HIGH },
      { term: "biometric identification", weight: W_HIGH },
      { term: "face recognition", weight: W_HIGH },
      { term: "identify people", weight: W_MED },
      { term: "identify individuals", weight: W_MED },
      { term: "surveillance camera", weight: W_MED },
      { term: "cctv", weight: W_LOW },
      { term: "camera", weight: W_LOW },
      { term: "biometric", weight: W_LOW },
    ],
  },
  {
    id: "annex_iii_1_b_biometric_categorisation",
    citation: "Annex III §1(b)",
    title: "Biometric categorisation by sensitive attributes",
    verbatim:
      '"Biometric categorisation systems, according to sensitive or protected attributes or characteristics based on the inference of those attributes or characteristics."',
    keywords: [
      { term: "biometric categorisation", weight: W_HIGH },
      { term: "biometric categorization", weight: W_HIGH },
      { term: "classify people by", weight: W_MED },
      { term: "categorize individuals", weight: W_MED },
      { term: "ethnicity", weight: W_MED },
      { term: "gender classification", weight: W_MED },
      { term: "age classification", weight: W_LOW },
      { term: "sensitive attributes", weight: W_LOW },
    ],
  },
  {
    id: "annex_iii_1_c_emotion_recognition",
    citation: "Annex III §1(c)",
    title: "Emotion recognition systems",
    verbatim: '"Emotion recognition systems."',
    keywords: [
      { term: "emotion recognition", weight: W_HIGH },
      { term: "emotion detection", weight: W_HIGH },
      { term: "affect recognition", weight: W_HIGH },
      { term: "sentiment analysis", weight: W_LOW },
      { term: "facial expression", weight: W_MED },
      { term: "mood detection", weight: W_MED },
    ],
  },

  // §2 — Critical infrastructure
  {
    id: "annex_iii_2_critical_infrastructure",
    citation: "Annex III §2",
    title: "Critical infrastructure safety components",
    verbatim:
      '"AI systems intended to be used as safety components in the management and operation of critical digital infrastructure, road traffic, or in the supply of water, gas, heating or electricity."',
    keywords: [
      { term: "critical infrastructure", weight: W_HIGH },
      { term: "safety component", weight: W_HIGH },
      { term: "power grid", weight: W_HIGH },
      { term: "water supply", weight: W_HIGH },
      { term: "gas supply", weight: W_HIGH },
      { term: "electricity grid", weight: W_HIGH },
      { term: "road traffic", weight: W_MED },
      { term: "traffic management", weight: W_MED },
      { term: "energy distribution", weight: W_MED },
      { term: "scada", weight: W_MED },
      { term: "utility network", weight: W_LOW },
    ],
  },

  // §3 — Education
  {
    id: "annex_iii_3_a_education_admission",
    citation: "Annex III §3(a)",
    title: "Education — access and admission decisions",
    verbatim:
      '"AI systems intended to be used to determine access or admission or to assign natural persons to educational and vocational training institutions at all levels."',
    keywords: [
      { term: "admissions", weight: W_HIGH },
      { term: "admission decisions", weight: W_HIGH },
      { term: "school admission", weight: W_HIGH },
      { term: "university admission", weight: W_HIGH },
      { term: "student selection", weight: W_MED },
      { term: "enrollment", weight: W_MED },
      { term: "enrolment", weight: W_MED },
      { term: "applicant scoring education", weight: W_LOW },
    ],
  },
  {
    id: "annex_iii_3_b_education_assessment",
    citation: "Annex III §3(b)",
    title: "Education — learning outcome evaluation",
    verbatim:
      '"AI systems intended to be used to evaluate learning outcomes [...] where those outcomes are used to steer the learning process of natural persons [...]."',
    keywords: [
      { term: "grading", weight: W_HIGH },
      { term: "grade students", weight: W_HIGH },
      { term: "learning outcomes", weight: W_HIGH },
      { term: "student assessment", weight: W_HIGH },
      { term: "evaluate students", weight: W_MED },
      { term: "evaluate learners", weight: W_MED },
      { term: "educational assessment", weight: W_MED },
      { term: "exam scoring", weight: W_MED },
    ],
  },
  {
    id: "annex_iii_3_d_education_proctoring",
    citation: "Annex III §3(d)",
    title: "Education — test proctoring and behaviour monitoring",
    verbatim:
      '"AI systems intended to be used for monitoring and detecting prohibited behaviour of students during tests."',
    keywords: [
      { term: "proctoring", weight: W_HIGH },
      { term: "exam monitoring", weight: W_HIGH },
      { term: "test proctoring", weight: W_HIGH },
      { term: "cheating detection", weight: W_HIGH },
      { term: "plagiarism detection", weight: W_MED },
      { term: "monitor students", weight: W_MED },
    ],
  },

  // §4 — Employment
  {
    id: "annex_iii_4_a_employment_recruitment",
    citation: "Annex III §4(a)",
    title: "Employment — recruitment and candidate evaluation",
    verbatim:
      '"AI systems intended to be used for the recruitment or selection of natural persons, in particular to place targeted job advertisements, to analyse and filter job applications, and to evaluate candidates."',
    keywords: [
      { term: "cv screening", weight: W_HIGH },
      { term: "resume screening", weight: W_HIGH },
      { term: "candidate shortlist", weight: W_HIGH },
      { term: "recruitment", weight: W_HIGH },
      { term: "hiring decisions", weight: W_HIGH },
      { term: "applicant filtering", weight: W_HIGH },
      { term: "job application", weight: W_MED },
      { term: "interview scoring", weight: W_MED },
      { term: "targeted job ad", weight: W_MED },
      { term: "hr screening", weight: W_MED },
      { term: "talent acquisition", weight: W_LOW },
      { term: "hiring", weight: W_LOW },
    ],
  },
  {
    id: "annex_iii_4_b_employment_management",
    citation: "Annex III §4(b)",
    title: "Employment — performance management and termination",
    verbatim:
      '"AI systems intended to be used to make decisions affecting terms of work-related relationships, the promotion or termination of work-related contractual relationships, to allocate tasks [...] and to monitor and evaluate the performance and behaviour of persons in such relationships."',
    keywords: [
      { term: "performance review", weight: W_HIGH },
      { term: "performance evaluation", weight: W_HIGH },
      { term: "termination decisions", weight: W_HIGH },
      { term: "worker monitoring", weight: W_HIGH },
      { term: "employee monitoring", weight: W_HIGH },
      { term: "task allocation", weight: W_MED },
      { term: "promotion decisions", weight: W_MED },
      { term: "gig worker", weight: W_MED },
      { term: "productivity tracking", weight: W_LOW },
    ],
  },

  // §5 — Essential services
  {
    id: "annex_iii_5_a_public_benefits",
    citation: "Annex III §5(a)",
    title: "Essential services — public benefit eligibility",
    verbatim:
      '"AI systems intended to be used by public authorities or on behalf of public authorities to evaluate the eligibility of natural persons for essential public assistance benefits and services [...]."',
    keywords: [
      { term: "welfare eligibility", weight: W_HIGH },
      { term: "benefit eligibility", weight: W_HIGH },
      { term: "public benefits", weight: W_HIGH },
      { term: "social security", weight: W_HIGH },
      { term: "public assistance", weight: W_HIGH },
      { term: "housing benefit", weight: W_MED },
      { term: "unemployment benefit", weight: W_MED },
    ],
  },
  {
    id: "annex_iii_5_b_creditworthiness",
    citation: "Annex III §5(b)",
    title: "Essential services — creditworthiness and credit scoring",
    verbatim:
      '"AI systems intended to be used to evaluate the creditworthiness of natural persons or establish their credit score, with the exception of AI systems used for the purpose of detecting financial fraud."',
    keywords: [
      { term: "credit scoring", weight: W_HIGH },
      { term: "creditworthiness", weight: W_HIGH },
      { term: "loan approval", weight: W_HIGH },
      { term: "credit decisions", weight: W_HIGH },
      { term: "credit risk", weight: W_HIGH },
      { term: "lending decisions", weight: W_HIGH },
      { term: "mortgage approval", weight: W_MED },
    ],
  },
  {
    id: "annex_iii_5_c_insurance_pricing",
    citation: "Annex III §5(c)",
    title: "Essential services — insurance risk assessment and pricing",
    verbatim:
      '"AI systems intended to be used for risk assessment and pricing in relation to natural persons in the case of life and health insurance."',
    keywords: [
      { term: "life insurance", weight: W_HIGH },
      { term: "health insurance", weight: W_HIGH },
      { term: "insurance pricing", weight: W_HIGH },
      { term: "underwriting", weight: W_HIGH },
      { term: "insurance risk", weight: W_HIGH },
      { term: "actuarial", weight: W_MED },
    ],
  },
  {
    id: "annex_iii_5_d_emergency_call_dispatch",
    citation: "Annex III §5(d)",
    title: "Essential services — emergency call triage and dispatch",
    verbatim:
      '"AI systems intended to be used to evaluate and classify emergency calls by natural persons or to be used to dispatch, or to establish priority in the dispatching of, emergency first response services [...]."',
    keywords: [
      { term: "emergency dispatch", weight: W_HIGH },
      { term: "emergency triage", weight: W_HIGH },
      { term: "911 triage", weight: W_HIGH },
      { term: "112 triage", weight: W_HIGH },
      { term: "first responder dispatch", weight: W_HIGH },
      { term: "ambulance dispatch", weight: W_MED },
    ],
  },

  // §6 — Law enforcement
  {
    id: "annex_iii_6_law_enforcement",
    citation: "Annex III §6",
    title: "Law enforcement — risk assessment, polygraphs, profiling",
    verbatim:
      '"AI systems intended to be used by or on behalf of law enforcement authorities [...] to assess the risk of a natural person becoming the victim of criminal offences [...] as polygraphs or similar tools [...] to evaluate the reliability of evidence [...] to assess the risk of [...] offending or re-offending [...] for profiling of natural persons [...]."',
    keywords: [
      { term: "predictive policing", weight: W_HIGH },
      { term: "recidivism prediction", weight: W_HIGH },
      { term: "reoffending risk", weight: W_HIGH },
      { term: "law enforcement", weight: W_HIGH },
      { term: "criminal profiling", weight: W_HIGH },
      { term: "polygraph", weight: W_HIGH },
      { term: "lie detector", weight: W_MED },
      { term: "crime prediction", weight: W_MED },
      { term: "parole decision", weight: W_MED },
      { term: "evidence reliability", weight: W_LOW },
    ],
  },

  // §7 — Migration, asylum, border control
  {
    id: "annex_iii_7_migration_border",
    citation: "Annex III §7",
    title: "Migration, asylum and border control",
    verbatim:
      '"AI systems intended to be used by or on behalf of competent public authorities [...] as polygraphs or similar tools; to assess a risk, including a security risk, a risk of irregular migration, or a health risk [...]; to assist [...] for the examination of applications for asylum, visa or residence permits [...]; for the purpose of detecting, recognising or identifying natural persons [...]."',
    keywords: [
      { term: "asylum", weight: W_HIGH },
      { term: "visa application", weight: W_HIGH },
      { term: "residence permit", weight: W_HIGH },
      { term: "border control", weight: W_HIGH },
      { term: "migration risk", weight: W_HIGH },
      { term: "immigration", weight: W_MED },
      { term: "refugee processing", weight: W_MED },
    ],
  },

  // §8 — Administration of justice and democratic processes
  {
    id: "annex_iii_8_a_administration_of_justice",
    citation: "Annex III §8(a)",
    title: "Administration of justice — assistance to judicial authorities",
    verbatim:
      '"AI systems intended to be used by a judicial authority or on their behalf to assist a judicial authority in researching and interpreting facts and the law and in applying the law to a concrete set of facts [...]."',
    keywords: [
      { term: "judicial research", weight: W_HIGH },
      { term: "legal research", weight: W_HIGH },
      { term: "case law research", weight: W_HIGH },
      { term: "judge assistant", weight: W_HIGH },
      { term: "court decision support", weight: W_HIGH },
      { term: "legal research assistant", weight: W_MED },
    ],
  },
  {
    id: "annex_iii_8_b_democratic_processes",
    citation: "Annex III §8(b)",
    title: "Democratic processes — influencing elections and voting",
    verbatim:
      '"AI systems intended to be used for influencing the outcome of an election or referendum or the voting behaviour of natural persons [...]."',
    keywords: [
      { term: "election campaign", weight: W_HIGH },
      { term: "voter targeting", weight: W_HIGH },
      { term: "political microtargeting", weight: W_HIGH },
      { term: "referendum campaign", weight: W_HIGH },
      { term: "voter persuasion", weight: W_HIGH },
      { term: "election outcome", weight: W_MED },
    ],
  },
];

// ── Classifier ───────────────────────────────────────────────────────

const CLASSIFIER_ADVISORY =
  "This classification is a RULE-BASED keyword match, NOT a machine-" +
  "learning model prediction, and NOT legal advice. The rule_based_" +
  "confidence score reflects the sum of matched keyword weights, " +
  "clamped to [0, 1]. Use this to narrow the deployer's review — the " +
  "final Annex III classification determination must be made by a " +
  "human reviewer against the full regulation text (Annex III of " +
  "Regulation (EU) 2024/1689). An empty result means no category " +
  "cleared the minimum threshold; it does NOT mean the agent is out " +
  "of scope of the Act.";

export const ANNEX_III_REGULATION_VERSION =
  "EU AI Act Regulation (EU) 2024/1689, as of 2026-04-10";

/**
 * Normalize a text string for keyword matching: lowercase, collapse
 * whitespace, strip punctuation that would break multi-word keyword
 * matches. Deliberately simple — no stemming, no synonyms.
 */
function normalizeForMatching(text: string): string {
  return text
    .toLowerCase()
    .replace(/[,.;:!?()\[\]{}"']/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Classify a free-text agent description into zero or more candidate
 * Annex III categories.
 *
 * Returns all candidates that clear MIN_CONFIDENCE_THRESHOLD (0.4),
 * ordered by rule_based_confidence descending. May return an empty
 * array if nothing matches — the advisory field always reminds the
 * caller this does not mean "out of scope".
 */
export function classifyAgentDescription(
  description: string
): ClassificationResult {
  const normalized = normalizeForMatching(description);
  const candidates: ClassificationMatch[] = [];

  for (const category of ANNEX_III_CATEGORIES) {
    let score = 0;
    const matched: string[] = [];
    for (const { term, weight } of category.keywords) {
      if (normalized.includes(term)) {
        score += weight;
        matched.push(term);
      }
    }
    if (score >= MIN_CONFIDENCE_THRESHOLD) {
      candidates.push({
        category_id: category.id,
        citation: category.citation,
        title: category.title,
        rule_based_confidence: Math.min(1, score),
        matched_keywords: matched,
      });
    }
  }

  candidates.sort(
    (a, b) => b.rule_based_confidence - a.rule_based_confidence
  );

  // Truncate the description for the result fragment to keep tool
  // output compact — full description is the caller's input.
  const fragment =
    description.length > 200
      ? description.slice(0, 200) + "..."
      : description;

  return {
    description_fragment: fragment,
    candidates,
    advisory: CLASSIFIER_ADVISORY,
    regulation_version: ANNEX_III_REGULATION_VERSION,
  };
}

/**
 * Look up a single category by ID.
 */
export function annexIIICategoryById(
  id: string
): AnnexIIICategory | undefined {
  return ANNEX_III_CATEGORIES.find((c) => c.id === id);
}
