/**
 * Entry point of the release bundle (lib/agentgate.mjs); the dev equivalent is
 * bin/agentgate.mjs (tsx). Crash handlers are installed BEFORE the CLI is loaded, so even
 * a module-initialisation failure ends as "blocked" (77), never as an ambiguous code.
 */
const crash = (err: unknown) => {
  process.stderr.write(`agentgate: fatal: ${err instanceof Error && err.stack ? err.stack : String(err)}\n`);
  process.exit(77);
};
process.on("uncaughtException", crash);
process.on("unhandledRejection", crash);

let code: number;
try {
  const { main } = await import("./main.ts");
  code = await main(process.argv.slice(2));
} catch (err) {
  process.stderr.write(`agentgate: fatal: ${err instanceof Error && err.stack ? err.stack : String(err)}\n`);
  code = 77;
}
process.exitCode = code;
// Let stdout/stderr drain, but never hang on a stray handle.
setTimeout(() => process.exit(code), 1500).unref();

export {};
