import {
  CONCIERGE_READ_SURFACES,
  ConciergeReadError,
  ConciergeUnavailableError,
  type ConciergeAskRequest,
  type ConciergeAskResponse,
  type ConciergeContextBundle,
  type ConciergeSelectorLike,
  type ConciergeStatus,
} from "./concierge-types.js";
import { compileConciergePrompt, isSummarizationQuery } from "./prompt-builder.js";
// Mints the unforgeable first-party-context claim; see the claim site in `ask`.
import { claimFirstPartyContext } from "../intelligence/types.js";

export interface ConciergeContextReaderLike {
  readContext(request: ConciergeAskRequest): Promise<ConciergeContextBundle>;
}

export interface ConciergeServiceOptions {
  reader: ConciergeContextReaderLike;
  selector: ConciergeSelectorLike;
  onReadObserved?: (surface: string, question: string) => Promise<void> | void;
}

export class ConciergeService {
  private readonly reader: ConciergeContextReaderLike;
  private readonly selector: ConciergeSelectorLike;
  private readonly onReadObserved?: (surface: string, question: string) => Promise<void> | void;

  constructor(options: ConciergeServiceOptions) {
    this.reader = options.reader;
    this.selector = options.selector;
    this.onReadObserved = options.onReadObserved;
  }

  async ask(
    request: ConciergeAskRequest,
    onToken?: (token: string) => void,
  ): Promise<ConciergeAskResponse> {
    const question = request.question.trim();
    if (!question) {
      throw new ConciergeReadError("question must not be empty");
    }

    let context: ConciergeContextBundle;
    try {
      context = await this.reader.readContext(request);
      await Promise.all(
        context.read_surfaces.map((surface) =>
          this.onReadObserved?.(surface, question),
        ),
      );
    } catch (cause) {
      throw new ConciergeReadError("concierge could not read sanctuary state", cause);
    }

    // ZZZZ: deterministic short-circuit for summarization queries against
    // empty context. When the operator asks "summarize fortress activity"
    // and the context contains zero concrete events, return a factual
    // "no activity" response without invoking the LLM. This prevents
    // Phi-4 from filling the void with plausible-sounding fabrications.
    if (isSummarizationQuery(question) && isEmptyContext(context)) {
      const answer = "No fortress activity recorded in the requested window.";
      if (onToken) onToken(answer);
      return {
        answer,
        model: "deterministic",
        provider: "deterministic",
        read_surfaces: context.read_surfaces,
        context,
      };
    }

    try {
      const handle = await this.selector.getSubstrate("concierge");
      if (!handle.capability.summarize) {
        throw new ConciergeUnavailableError(
          "concierge substrate is disabled or does not support summarization",
        );
      }
      // INVARIANT: the claim names the compiled prompt's SYSTEM MESSAGE and
      // nothing else. That message is built entirely from fixed strings in
      // `prompt-builder.ts`; everything after it, the operator's question and
      // the bounded projection of this fortress's records, quotes text this
      // runtime did not author and is screened as untrusted.
      //
      // The earlier shape of this claim covered the whole compiled prompt
      // whenever `includePayloads` was off, and that was false: `includePayloads`
      // gates only the raw state-store VALUE, while audit `details`, task
      // titles, state-store keys and tags reach the briefing either way, so an
      // agent writing long names could grow the exempt segment. Assembling
      // bytes locally is not the same as authoring them.
      //
      // The claim is a branded object, not a string: this is the one code path
      // that compiles the fortress briefing, so it is the one call site that
      // may mint one. MUST MATCH the check in `compiled-context/compiler.ts`,
      // which re-verifies the prefix against the context it is handed and also
      // requires the surface to be in `FIRST_PARTY_CONTEXT_SURFACES`.
      const compiled = compileConciergePrompt({ question, context });
      const response = await this.selector.invokeSummarize("concierge", {
        kind: "summarize",
        context: compiled.context,
        query: question,
        maxTokens: 512,
        contextProvenance: claimFirstPartyContext(compiled.firstPartyPrefix),
      });
      if (response.failureClass || response.body.kind !== "summarize") {
        throw new ConciergeUnavailableError(
          `concierge substrate unavailable: ${response.failureClass ?? "invalid_response"}`,
        );
      }
      const answer = response.body.text;
      onToken?.(answer);
      return {
        answer,
        model: response.servedBy === handle.substrate ? handle.displayLabel : response.servedBy,
        provider: response.servedBy,
        read_surfaces: context.read_surfaces,
        context,
      };
    } catch (cause) {
      if (cause instanceof ConciergeUnavailableError) throw cause;
      throw new ConciergeUnavailableError("concierge provider unavailable", cause);
    }
  }

  async status(): Promise<ConciergeStatus> {
    const [handle, report] = await Promise.all([
      this.selector.getSubstrate("concierge"),
      this.selector.getOperatorVisibleStatus(),
    ]);
    const surface = report.surfaces.find((entry) => entry.surface === "concierge");
    if (!surface) {
      throw new ConciergeUnavailableError("concierge selector status is unavailable");
    }
    return {
      provider: handle.substrate,
      configured: handle.substrate !== "disabled",
      reachable: surface.health !== "unavailable",
      model: handle.displayLabel,
      read_surfaces: [...CONCIERGE_READ_SURFACES],
      fallback: this.selector.getConfig().fallback.concierge,
      message:
        surface.health === "ok"
          ? `Concierge ready via ${handle.displayLabel}`
          : `Concierge ${surface.health}: ${surface.failureClass ?? "unknown"}`,
    };
  }

  configuredReadSurfaces(): string[] {
    return [...CONCIERGE_READ_SURFACES];
  }
}

/**
 * ZZZZ: check whether the context bundle contains zero concrete events.
 * A context is "empty" when the audit log has no entries, the inbox has
 * no pending items, and the task state has no tasks.
 */
function isEmptyContext(context: ConciergeContextBundle): boolean {
  return (
    context.audit_log.entries.length === 0 &&
    context.approval_inbox.pending_count === 0 &&
    context.task_state.total === 0
  );
}
