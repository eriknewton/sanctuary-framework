import {lstatSync} from "node:fs";
import {BUSINESS_EVIDENCE} from "../../src/linux-business/profile-selection.js";

/** This sole host probe fails loudly; children still receive explicit isolated roots. */
export default function selectorHostPrecondition(): void {
  if (process.platform !== "linux") return;
  for (const path of BUSINESS_EVIDENCE) {
    try { lstatSync(path); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw new Error(`Selector host precondition cannot inspect ${path}`, {cause: error});
    }
    throw new Error(`Selector host precondition found enrollment at ${path}`);
  }
}
