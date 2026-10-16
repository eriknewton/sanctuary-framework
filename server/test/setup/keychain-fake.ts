/** Install and reset the shared in-memory credential store for each Vitest case. */
import { beforeEach } from "vitest";
import { clearInMemoryKeychainStore, installInMemoryKeychainStore } from "./keychain-memory-store.js";
export { installInMemoryKeychainStore } from "./keychain-memory-store.js";
installInMemoryKeychainStore();
beforeEach(clearInMemoryKeychainStore);
