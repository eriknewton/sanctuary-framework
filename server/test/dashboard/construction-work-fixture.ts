import { ConstructionWork } from "../../src/dashboard/construction-work.js";
import { buildV11Bindings as buildBindings, type BuildV11BindingsInputs } from "../../src/dashboard/v1_1/wiring.js";

/** Direct builder fixtures settle their construction work before returning. */
export async function buildV11Bindings(inputs: Omit<BuildV11BindingsInputs, "constructionWork">) {
  const constructionWork = new ConstructionWork();
  try {
    return buildBindings({ ...inputs, constructionWork });
  } finally {
    await constructionWork.drain();
  }
}
