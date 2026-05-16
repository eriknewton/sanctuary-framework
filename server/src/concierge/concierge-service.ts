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
import { buildConciergePrompt } from "./prompt-builder.js";

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
