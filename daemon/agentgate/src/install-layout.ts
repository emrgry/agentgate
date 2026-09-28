import { existsSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Where this `agentgate` runs from, and which paths get PERSISTED into other programs'
 * configuration (launchd plist, Claude Code / Codex hook commands, MCP wrap entries,
 * rewritten `agentgate exec` commands).
 *
 * - dev checkout (tsx): paths inside the repository, exactly as before.
 * - release build (esbuild bundle, `__AGENTGATE_RELEASE__` defined at build time):
 *     <install>/versions/<version>/{bin,libexec/node,lib}   ← this process (physical path)
 *     <install>/current → versions/<version>                ← what gets persisted
 *   so `agentgate update` can swap `current` without breaking any installed hook.
 */

interface ReleaseInfo {
  version: string;
  target: string;
  node: string;
}
declare const __AGENTGATE_RELEASE__: ReleaseInfo | undefined;

export const RELEASE: ReleaseInfo | null = typeof __AGENTGATE_RELEASE__ === "object" && __AGENTGATE_RELEASE__ ? __AGENTGATE_RELEASE__ : null;

export interface Layout {
  kind: "release" | "dev";
  /** Physical directory of the running installation (versions/<v> or the repo root). */
  root: string;
  /** Directory persisted into configs: <install>/current for installed releases. */
  stable: string;
  /** Directory holding versions/ + current (installed releases only). */
  installHome: string | null;
  /** CLI launcher used in persisted commands (exec rewrites, MCP wraps, plist). */
  cli: string;
  /** Fail-closed Claude Code hook shim used in persisted hook commands. */
  hookShim: string;
  /** Node binary pinned as AGENTGATE_NODE in persisted commands. */
  node: string;
  /** launchd ProgramArguments for `agentgate serve`. */
  serveArgs: string[];
  /** Module `agentgate serve` imports (the API server). */
  apiMain: string;
  /** Install locations an agent must never modify (merged into the hook guard). */
  protectedDirs: string[];
  /** ~/.local/bin/agentgate (the PATH shim written by install.sh). */
  pathShim: string;
}

export interface LayoutInputs {
  release: ReleaseInfo | null;
  /** Directory of the module computing the layout (src/ in dev, lib/ in a release). */
  moduleDir: string;
  execPath: string;
  home: string;
  exists?: (p: string) => boolean;
  realpath?: (p: string) => string;
}

export function computeLayout(i: LayoutInputs): Layout {
  const exists = i.exists ?? existsSync;
  const real = i.realpath ?? ((p: string) => (exists(p) ? realpathSync(p) : p));
  const pathShim = join(i.home, ".local", "bin", "agentgate");
  // Always protected, whatever this process is: an agent must not swap an installed release.
  const defaultInstall = join(i.home, ".agentgate");
  const alwaysProtected = [join(defaultInstall, "versions"), join(defaultInstall, "current"), join(defaultInstall, "previous")];

  if (!i.release) {
    // moduleDir = <repo>/daemon/agentgate/src
    const repo = resolve(i.moduleDir, "..", "..", "..");
    const bin = join(repo, "daemon", "agentgate", "bin");
    return {
      kind: "dev",
      root: repo,
      stable: repo,
      installHome: null,
      cli: join(bin, "agentgate.sh"),
      hookShim: join(bin, "agentgate-hook.sh"),
      node: i.execPath,
      serveArgs: [i.execPath, join(bin, "agentgate.mjs"), "serve"],
      apiMain: join(repo, "apps", "api", "src", "main.ts"),
      protectedDirs: [
        join(repo, "daemon", "agentgate"),
        join(repo, "adapters", "claude-code"),
        join(repo, "adapters", "cursor"),
        join(repo, "adapters", "codex"),
        join(repo, "adapters", "generic"),
        join(repo, "packages"),
        join(repo, "node_modules"),
        join(repo, "apps", "api", ".data"),
        ...alwaysProtected,
      ],
      pathShim,
    };
  }

  // moduleDir = <root>/lib
  const root = real(resolve(i.moduleDir, ".."));
  const parent = dirname(root);
  const installHome = basename(parent) === "versions" ? dirname(parent) : null;
  const current = installHome ? join(installHome, "current") : null;
  const stable = current && exists(current) ? current : root;
  const protectedDirs = [root, stable, pathShim, ...alwaysProtected];
  if (installHome) protectedDirs.push(join(installHome, "versions"), join(installHome, "current"), join(installHome, "previous"));
  return {
    kind: "release",
    root,
    stable,
    installHome,
    cli: join(stable, "bin", "agentgate"),
    hookShim: join(stable, "bin", "agentgate-hook.sh"),
    node: join(stable, "libexec", "node"),
    serveArgs: [join(stable, "bin", "agentgate"), "serve"],
    apiMain: join(root, "lib", "api.mjs"),
    protectedDirs: [...new Set(protectedDirs)],
    pathShim,
  };
}

let cached: Layout | null = null;

/** Layout of the running process (memoized). */
export function layout(): Layout {
  cached ??= computeLayout({
    release: RELEASE,
    moduleDir: dirname(fileURLToPath(import.meta.url)),
    execPath: process.execPath,
    home: homedir(),
  });
  return cached;
}
