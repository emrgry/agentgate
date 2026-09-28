#!/usr/bin/env node
// Tiny shim: run the TypeScript sources through tsx (no build step for the MVP).
import { register } from "tsx/esm/api";

register();

// Any crash outside the main flow (e.g. inside a socket callback) must still be a
// "blocked" outcome, never an ambiguous one. Nothing is executed from these paths.
const crash = (err) => {
  process.stderr.write(`agentgate: fatal: ${err && err.stack ? err.stack : err}\n`);
  process.exit(77);
};
process.on("uncaughtException", crash);
process.on("unhandledRejection", crash);
const { main } = await import("../src/main.ts");

let code;
try {
  code = await main(process.argv.slice(2));
} catch (err) {
  // Unexpected crash: never leave a wrapped action in an ambiguous state.
  process.stderr.write(`agentgate: fatal: ${err && err.stack ? err.stack : err}\n`);
  code = 77;
}
process.exitCode = code;
// Let stdout/stderr drain, but never hang on a stray handle.
setTimeout(() => process.exit(code), 1500).unref();
