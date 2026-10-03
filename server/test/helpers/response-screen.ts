/** Synchronous scanner fixture for existing router unit tests; worker tests use the real runtime. */
import { InjectionDetector } from "../../src/security/injection-detector.js";
import { ResponseScreen } from "../../src/proxy/response-screen.js";
import { ResponseController, ResponseSession } from "../../src/proxy/response-runtime.js";
export function unitResponseScreen(controller = new ResponseController()): ResponseScreen {
  const detector = new InjectionDetector();
  return {
    session: new ResponseSession(controller),
    assertReady() {},
    async screen(text: string) {
      const result = detector.scanResponseBudgeted(text);
      return { label: result.result.signals.length ? "label_suspected" : "label_untrusted", signalCount: result.result.signals.length };
    },
  } as unknown as ResponseScreen;
}
