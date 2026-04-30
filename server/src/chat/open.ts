/**
 * Sanctuary MCP Server — Operator Chat: Open Helper (v1.2.x F9)
 *
 * Lightweight bootstrap used by the standalone `sanctuary chat-server`
 * MCP subcommand. Opens a ready-to-use OperatorChatService against the
 * shared fortress storage without spinning up the full
 * createSanctuaryServer() — we only need the master key, storage,
 * audit log, and chat store.
 *
 * Mirrors the shape of `l3-disclosure/broker/open.ts` so the two
 * subcommands ("broker-server" and "chat-server") share the same
 * passphrase-resolution + master-key derivation discipline. Cross-
 * process shape: the dashboard process and this subprocess derive the
 * same fortress master key from the same passphrase via Argon2id over
 * the persisted key-params, so encrypted records written by either
 * process decrypt cleanly under the other's instance.
 *
 * The chat-server only ever uses the direct-agent surface of
 * OperatorChatService, so concierge context providers, PII filter, and
 * substrate selector are intentionally absent here. The concierge
 * surface lives in the dashboard process; this subprocess is the
 * harness-side reply hook only.
 */

import { FilesystemStorage } from "../storage/filesystem.js";
import { loadConfig } from "../config.js";
import {
  deriveMasterKey,
  type KeyDerivationParams,
} from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";
import { AuditLog } from "../l2-operational/audit-log.js";
import { getOrCreatePassphrase } from "../cocoon/passphrase.js";
import { OperatorChatService } from "./operator-chat-service.js";
import { OperatorChatStore } from "./operator-chat-store.js";

export interface OpenOperatorChatOptions {
  /** Override passphrase (otherwise resolved via cocoon/passphrase). */
  passphrase?: string;
  /** Override storage path (otherwise config.storage_path). */
  storagePath?: string;
  /**
   * Override identity id (otherwise SANCTUARY_IDENTITY_ID env var, with
   * fallback to "sanctuary-chat" matching broker-server's posture).
   */
  identityId?: string;
}

export interface OpenOperatorChatHandle {
  /** Service instance ready for direct-agent calls. */
  service: OperatorChatService;
  /** Drain pending audit writes before the caller exits. */
  close: () => Promise<void>;
}

export async function openOperatorChat(
  opts: OpenOperatorChatOptions = {},
): Promise<OpenOperatorChatHandle> {
  // 1. Resolve or load Sanctuary config for storage path.
  const config = await loadConfig();
  const storagePath = opts.storagePath ?? config.storage_path;
  const storage = new FilesystemStorage(`${storagePath}/state`);

  // 2. Resolve passphrase — same resolution the wrap CLI + broker use.
  let passphrase = opts.passphrase ?? process.env.SANCTUARY_PASSPHRASE;
  if (!passphrase) {
    const resolved = await getOrCreatePassphrase();
    passphrase = resolved.value;
  }

  // 3. Derive master key (mirrors broker/open.ts).
  let existingParams: KeyDerivationParams | undefined;
  try {
    const raw = await storage.read("_meta", "key-params");
    if (raw) {
      existingParams = JSON.parse(bytesToString(raw));
    }
  } catch {
    /* first run — params not yet persisted */
  }
  const { key: masterKey, params } = await deriveMasterKey(
    passphrase,
    existingParams,
  );
  if (!existingParams) {
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params)),
    );
  }

  // 4. Audit log — shares storage with the main server so audit queries
  // see chat-server entries alongside L1/L2/L4 entries.
  const auditLog = new AuditLog(storage, masterKey);

  // 5. Chat store + service. No concierge wiring — the chat-server
  // subprocess only uses the direct-agent surface (recordAgentReply +
  // findActiveSessionForAgent + advancePollCursor).
  const store = new OperatorChatStore(storage, masterKey);
  const identityId =
    opts.identityId ?? process.env.SANCTUARY_IDENTITY_ID ?? "sanctuary-chat";
  const service = new OperatorChatService({
    store,
    auditLog,
    identityId,
  });

  return {
    service,
    close: async () => {
      // Drain pending audit writes before the caller exits.
      await auditLog.flush();
    },
  };
}
