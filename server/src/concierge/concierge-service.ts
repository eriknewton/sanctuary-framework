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
import { buildConciergePrompt, isSummarizationQuery } from "./prompt-builder.js";

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
      // INVARIANT: `contextProvenance` may be claimed only while every byte of
      // the compiled prompt is this runtime's own — its system template plus
      // the bounded, structured summaries `SanctuaryContextReader` builds from
      // local records. `includePayloads` is the one switch that embeds raw
      // state-store payload bytes an agent authored, so it drops the claim and
      // the whole artifact is sized as untrusted again. The operator's
      // `question` rides in `query`, which is untrusted on every path.
      const contextIsFirstPartyOnly = request.includePayloads !== true;
      const response = await this.selector.invokeSummarize("concierge", {
        kind: "summarize",
        context: JSON.stringify(buildConciergePrompt({ question, context })),
        query: question,
        maxTokens: 512,
        ...(contextIsFirstPartyOnly
          ? { contextProvenance: "first_party_runtime" as const }
          : {}),
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
