/**
 * Post-build script: copies agent template directories (JSON + markdown files)
 * from src/templates/<name>/ into dist/templates/<name>/ so they ship in the
 * npm artifact. tsup only bundles TypeScript; these non-TS assets need an
 * explicit copy step.
 */
import { cpSync, existsSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const srcTemplates = join(__dirname, "..", "src", "templates");
const distTemplates = join(__dirname, "..", "dist", "templates");

const TEMPLATE_DIRS = [
  "research-assistant",
  "handoff-coordinator",
  "planner",
  "ops-runner",
  "coding-assistant",
];

mkdirSync(distTemplates, { recursive: true });

for (const name of TEMPLATE_DIRS) {
  const src = join(srcTemplates, name);
  if (!existsSync(src)) {
    console.warn(`copy-templates: skipping ${name} (not found at ${src})`);
    continue;
  }
  const dest = join(distTemplates, name);
  cpSync(src, dest, { recursive: true });
  console.log(`copy-templates: ${name} -> dist/templates/${name}`);
}
