import { EXIT } from "../exit-codes.ts";
import { layout, RELEASE } from "../install-layout.ts";
import { out } from "../output.ts";
import { CLI_VERSION } from "../version.ts";

/** `agentgate version`: version, install type and where it runs from. */
export function versionCommand(): number {
  const l = layout();
  out(`agentgate ${CLI_VERSION}`);
  if (l.kind === "release") {
    out(`install   release (${RELEASE?.target ?? "unknown target"}, bundled node ${process.version})`);
    out(`path      ${l.root}${l.stable !== l.root ? `  (via ${l.stable})` : ""}`);
  } else {
    out(`install   dev checkout (node ${process.version} at ${process.execPath})`);
    out(`path      ${l.root}`);
  }
  return EXIT.OK;
}
