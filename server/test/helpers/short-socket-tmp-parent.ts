import { tmpdir } from "node:os";

// macOS socket fixtures use a short canonical parent; other platforms honor the caller's temp root.
export const SHORT_SOCKET_TMP_PARENT = process.platform === "darwin" ? "/private/tmp" : tmpdir();
