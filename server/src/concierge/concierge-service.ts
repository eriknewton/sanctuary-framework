import {
  CONCIERGE_READ_SURFACES,
  ConciergeReadError,
  ConciergeUnavailableError,
  type ConciergeAskRequest,
  type ConciergeAskResponse,
  type ConciergeContextBundle,
  type ConciergeStatus,
  type VeniceClientLike,
} from "./concierge-types.js";
import { buildConciergePrompt, isSummarizationQuery } from "./prompt-builder.js";

export interface ConciergeContextReaderLike {
  readContext(request: ConciergeAskRequest): Promise<ConciergeContextBundle>;
}

export interface ConciergeServiceOptions {
  reader: ConciergeContextReaderLike;
  venice: VeniceClientLike;
  onReadObserved?: (surface: string, question: string) => Promise<void> | void;
}

export class ConciergeService {
  private readonly reader: ConciergeContextReaderLike;
  private readonly venice: VeniceClientLike;
  private readonly onReadObserved?: (surface: string, question: string) => Promise<void> | void;

  constructor(options: ConciergeServiceOptions) {
    this.reader = options.reader;
    this.venice = options.venice;
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
        provider: "venice",
        read_surfaces: context.read_surfaces,
        context,
      };
    }

    try {
      const answer = await this.venice.complete({
        messages: buildConciergePrompt({ question, context }),
        stream: request.stream !== false,
        onToken,
      });
      return {
        answer,
        model: this.venice.model(),
        provider: "venice",
        read_surfaces: context.read_surfaces,
        context,
      };
    } catch (cause) {
      if (cause instanceof ConciergeUnavailableError) throw cause;
      throw new ConciergeUnavailableError("concierge provider unavailable", cause);
    }
  }

  async status(): Promise<ConciergeStatus> {
    return this.venice.checkStatus();
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
