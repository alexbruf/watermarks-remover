// Build a single self-contained HTML page (engine inlined) from template.html.
// Usage: node web/build.mjs [out.html]   (run ../build.sh first)
import fs from "node:fs";
import path from "node:path";
const here = path.dirname(new URL(import.meta.url).pathname);
const root = path.join(here, "..");
const glue = fs.readFileSync(path.join(root, "pkg/watermarks_remover.js"), "utf8")
  .replace(/^export function /gm, "function ")
  .replace(/^export \{[^}]*\};?\s*$/gm, "");
const wasm = fs.readFileSync(path.join(root, "pkg/watermarks_remover_bg.wasm")).toString("base64");
const sample = fs.readFileSync(path.join(root, "../tests/fixtures/sample_c2pa.avif")).toString("base64");
const out = fs.readFileSync(path.join(here, "template.html"), "utf8")
  .replace("/*__WM_GLUE__*/", () => glue)
  .replace("__WM_WASM_B64__", () => wasm)
  .replace("__WM_SAMPLE_B64__", () => sample);
// Standalone page (open from disk or any static host) plus the bare body used for claude.ai artifacts.
const page = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0">\n${out}\n</body></html>\n`;
const dest = process.argv[2] || path.join(root, "pkg/watermarks-remover.html");
fs.writeFileSync(dest, page);
fs.writeFileSync(path.join(root, "pkg/artifact.html"), out);
console.log(`${dest} ${(page.length / 1048576).toFixed(2)} MB`);
