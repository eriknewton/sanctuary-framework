import { createServer } from "node:net";

/**
 * Ask the OS for a currently-free TCP port (bind to 0, read the assigned port,
 * release it). Replaces the legacy `NNNN + Math.random()*M` port pickers, which
 * collide under vitest parallel file execution and flake with EADDRINUSE. A tiny
 * TOCTOU window remains between release and the caller's own bind, but it is
 * vanishingly small vs the birthday-collision rate of random ports.
 */
export async function getFreePort(): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      srv.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}
