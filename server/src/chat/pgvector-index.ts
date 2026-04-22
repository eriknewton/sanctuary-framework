/**
 * Sanctuary Chat v1.0 — Postgres + pgvector Indexer
 *
 * Indexes chat messages for semantic retrieval via pgvector.
 * Writes on message receive; deletion cascades on retention sweep.
 * Vector search exposed as a read-only API consumed by the console.
 *
 * pgvector extension check on boot; surfaces a clean error if missing.
 *
 * WP-MVP-7: spawn prompt §8 (Postgres + pgvector indexing).
 */

import { CHAT_MESSAGES_TABLE, EMBEDDING_DIMENSION } from "./constants.js";
import { ChatIndexError } from "./errors.js";
import type { ChatLogEntry, ChatMessageRow, ChatSearchResult } from "./types.js";

// ═══════════════════════════════════════════════════════════════════════
// Indexer interface
// ═══════════════════════════════════════════════════════════════════════

/**
 * Postgres client interface. Matches the `pg` module's Pool/Client shape
 * so production can wire the real pg Pool and tests can wire a mock.
 */
export interface PgClient {
  query(text: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

/**
 * Embedding function. Accepts message text, returns a float vector.
 * Production wires a real embedding model; tests wire a deterministic fixture.
 */
export type EmbedFn = (text: string) => Promise<number[]>;

// ═══════════════════════════════════════════════════════════════════════
// pgvector indexer
// ═══════════════════════════════════════════════════════════════════════

export class ChatPgVectorIndex {
  private client: PgClient;
  private embedFn: EmbedFn;
  private initialized = false;

  constructor(client: PgClient, embedFn: EmbedFn) {
    this.client = client;
    this.embedFn = embedFn;
  }

  /**
   * Initialize: check pgvector extension and create table if needed.
   * Throws ChatIndexError if pgvector is not available.
   */
  async initialize(): Promise<void> {
    // Check pgvector extension
    try {
      await this.client.query("CREATE EXTENSION IF NOT EXISTS vector");
    } catch (err) {
      throw new ChatIndexError(
        `pgvector extension not available. Install it with: CREATE EXTENSION vector; Error: ${(err as Error).message}`
      );
    }

    // Create chat_messages table with embedding column
    await this.client.query(`
      CREATE TABLE IF NOT EXISTS ${CHAT_MESSAGES_TABLE} (
        id TEXT PRIMARY KEY,
        group_id TEXT NOT NULL,
        sender_id TEXT NOT NULL,
        content TEXT NOT NULL,
        sent_at TIMESTAMPTZ NOT NULL,
        stored_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        target TEXT NOT NULL,
        fortress_id TEXT NOT NULL,
        embedding vector(${EMBEDDING_DIMENSION})
      )
    `);

    // Create indexes for common queries
    await this.client.query(`
      CREATE INDEX IF NOT EXISTS idx_${CHAT_MESSAGES_TABLE}_group_id
      ON ${CHAT_MESSAGES_TABLE} (group_id)
    `);
    await this.client.query(`
      CREATE INDEX IF NOT EXISTS idx_${CHAT_MESSAGES_TABLE}_fortress_id
      ON ${CHAT_MESSAGES_TABLE} (fortress_id)
    `);
    await this.client.query(`
      CREATE INDEX IF NOT EXISTS idx_${CHAT_MESSAGES_TABLE}_sent_at
      ON ${CHAT_MESSAGES_TABLE} (sent_at)
    `);

    // Create HNSW index for vector similarity search
    await this.client.query(`
      CREATE INDEX IF NOT EXISTS idx_${CHAT_MESSAGES_TABLE}_embedding
      ON ${CHAT_MESSAGES_TABLE}
      USING hnsw (embedding vector_cosine_ops)
    `);

    this.initialized = true;
  }

  /**
   * Index a chat message. Computes embedding and inserts into Postgres.
   */
  async indexMessage(entry: ChatLogEntry): Promise<void> {
    if (!this.initialized) {
      throw new ChatIndexError("pgvector index not initialized; call initialize() first");
    }

    const embedding = await this.embedFn(entry.content);
    if (embedding.length !== EMBEDDING_DIMENSION) {
      throw new ChatIndexError(
        `embedding dimension mismatch: expected ${EMBEDDING_DIMENSION}, got ${embedding.length}`
      );
    }

    const vectorStr = `[${embedding.join(",")}]`;
    await this.client.query(
      `INSERT INTO ${CHAT_MESSAGES_TABLE}
       (id, group_id, sender_id, content, sent_at, stored_at, target, fortress_id, embedding)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (id) DO NOTHING`,
      [
        entry.message_id,
        entry.group_id,
        entry.sender_id,
        entry.content,
        entry.sent_at,
        entry.stored_at,
        entry.target,
        entry.fortress_id,
        vectorStr,
      ]
    );
  }

  /**
   * Delete a message from the index (for retention sweep).
   */
  async deleteMessage(messageId: string): Promise<void> {
    if (!this.initialized) return;
    await this.client.query(
      `DELETE FROM ${CHAT_MESSAGES_TABLE} WHERE id = $1`,
      [messageId]
    );
  }

  /**
   * Delete all messages for a fortress (for bulk retention sweep).
   */
  async deleteByFortress(fortressId: string): Promise<number> {
    if (!this.initialized) return 0;
    const result = await this.client.query(
      `DELETE FROM ${CHAT_MESSAGES_TABLE} WHERE fortress_id = $1`,
      [fortressId]
    );
    return (result as { rows: unknown[]; rowCount?: number }).rowCount ?? 0;
  }

  /**
   * Semantic search: find messages similar to a query string.
   * Uses cosine similarity via pgvector.
   *
   * Test note: uses a deterministic embedding fixture, not a live model
   * call (no network at test time per acceptance criterion 6).
   */
  async search(params: {
    query: string;
    fortress_id: string;
    limit?: number;
  }): Promise<ChatSearchResult[]> {
    if (!this.initialized) {
      throw new ChatIndexError("pgvector index not initialized; call initialize() first");
    }

    const queryEmbedding = await this.embedFn(params.query);
    const vectorStr = `[${queryEmbedding.join(",")}]`;
    const limit = params.limit ?? 10;

    const result = await this.client.query(
      `SELECT id, group_id, sender_id, content, sent_at, stored_at, target, fortress_id,
              1 - (embedding <=> $1::vector) AS similarity
       FROM ${CHAT_MESSAGES_TABLE}
       WHERE fortress_id = $2
       ORDER BY embedding <=> $1::vector
       LIMIT $3`,
      [vectorStr, params.fortress_id, limit]
    );

    return result.rows.map((row) => ({
      message: {
        message_id: row.id as string,
        group_id: row.group_id as string,
        sender_id: row.sender_id as string,
        content: row.content as string,
        sent_at: row.sent_at as string,
        stored_at: row.stored_at as string,
        target: row.target as string,
        fortress_id: row.fortress_id as string,
      },
      similarity: row.similarity as number,
    }));
  }

  /**
   * Count indexed messages for a fortress.
   */
  async countByFortress(fortressId: string): Promise<number> {
    if (!this.initialized) return 0;
    const result = await this.client.query(
      `SELECT COUNT(*) as count FROM ${CHAT_MESSAGES_TABLE} WHERE fortress_id = $1`,
      [fortressId]
    );
    return parseInt(result.rows[0]?.count as string ?? "0", 10);
  }

  /**
   * Delete messages older than a cutoff (for retention sweep integration).
   * Returns count of deleted messages.
   */
  async deleteOlderThan(fortressId: string, cutoffIso: string): Promise<number> {
    if (!this.initialized) return 0;
    const result = await this.client.query(
      `DELETE FROM ${CHAT_MESSAGES_TABLE}
       WHERE fortress_id = $1 AND sent_at < $2`,
      [fortressId, cutoffIso]
    );
    return (result as { rows: unknown[]; rowCount?: number }).rowCount ?? 0;
  }

  isInitialized(): boolean {
    return this.initialized;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// In-memory mock for testing (no Postgres required)
// ═══════════════════════════════════════════════════════════════════════

/**
 * In-memory pgvector mock that provides cosine similarity search
 * using a deterministic embedding function. For testing only.
 */
export class InMemoryPgVectorIndex {
  private messages = new Map<string, ChatMessageRow>();
  private embedFn: EmbedFn;

  constructor(embedFn: EmbedFn) {
    this.embedFn = embedFn;
  }

  async indexMessage(entry: ChatLogEntry): Promise<void> {
    const embedding = await this.embedFn(entry.content);
    this.messages.set(entry.message_id, {
      id: entry.message_id,
      group_id: entry.group_id,
      sender_id: entry.sender_id,
      content: entry.content,
      sent_at: entry.sent_at,
      stored_at: entry.stored_at,
      target: entry.target,
      fortress_id: entry.fortress_id,
      embedding,
    });
  }

  async deleteMessage(messageId: string): Promise<void> {
    this.messages.delete(messageId);
  }

  async deleteOlderThan(fortressId: string, cutoffIso: string): Promise<number> {
    const cutoff = new Date(cutoffIso).getTime();
    let count = 0;
    for (const [id, msg] of this.messages) {
      if (msg.fortress_id === fortressId && new Date(msg.sent_at).getTime() < cutoff) {
        this.messages.delete(id);
        count++;
      }
    }
    return count;
  }

  async search(params: {
    query: string;
    fortress_id: string;
    limit?: number;
  }): Promise<ChatSearchResult[]> {
    const queryEmbedding = await this.embedFn(params.query);
    const limit = params.limit ?? 10;

    const results: ChatSearchResult[] = [];
    for (const msg of this.messages.values()) {
      if (msg.fortress_id !== params.fortress_id) continue;
      const similarity = cosineSimilarity(queryEmbedding, msg.embedding);
      results.push({
        message: {
          message_id: msg.id,
          group_id: msg.group_id,
          sender_id: msg.sender_id,
          content: msg.content,
          sent_at: msg.sent_at,
          stored_at: msg.stored_at,
          target: msg.target,
          fortress_id: msg.fortress_id,
        },
        similarity,
      });
    }

    return results
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, limit);
  }

  async countByFortress(fortressId: string): Promise<number> {
    let count = 0;
    for (const msg of this.messages.values()) {
      if (msg.fortress_id === fortressId) count++;
    }
    return count;
  }

  count(): number {
    return this.messages.size;
  }
}

/** Cosine similarity between two vectors. */
function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length) return 0;
  let dotProduct = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i++) {
    dotProduct += a[i]! * b[i]!;
    normA += a[i]! * a[i]!;
    normB += b[i]! * b[i]!;
  }
  const denominator = Math.sqrt(normA) * Math.sqrt(normB);
  return denominator === 0 ? 0 : dotProduct / denominator;
}
