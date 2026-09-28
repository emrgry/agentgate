import { homedir } from "node:os";
import { posix } from "node:path";

/** Where relative paths and `~` resolve. `cwd` normally comes from `action.cwd`. */
export interface PathContext {
  cwd?: string;
  home?: string;
}

export function defaultHome(): string {
  try {
    return homedir();
  } catch {
    return "/nonexistent-home";
  }
}

/** A path we cannot resolve statically (`$VAR`, globs, command substitution). */
export function isDynamicPath(p: string): boolean {
  return /[$`*?[\]{}]/.test(p.replace(/^\$\{?HOME\}?(?=\/|$)/, ""));
}

/**
 * Normalize a path for matching: expands `~`, `$HOME` and `${HOME}`, resolves relative
 * paths against `cwd` (when it is absolute), collapses `.`/`..`/`//` and strips a trailing
 * slash. Relative paths without a usable cwd stay relative (normalized). `~user/…` is kept
 * literally (we do not know other users' homes).
 */
export function normalizePath(raw: string, ctx: PathContext = {}): string {
  const home = ctx.home ?? defaultHome();
  let p = raw;
  if (p === "~" || p.startsWith("~/")) p = home + p.slice(1);
  else p = p.replace(/^\$\{?HOME\}?(?=\/|$)/, home);
  if (p === "") return p;
  let out: string;
  if (p.startsWith("/")) out = posix.normalize(p);
  else if (ctx.cwd && ctx.cwd.startsWith("/")) out = posix.resolve(ctx.cwd, p);
  else out = posix.normalize(p);
  if (out.length > 1 && out.endsWith("/")) out = out.slice(0, -1);
  return out;
}

const TEMP_ROOTS = ["/tmp", "/private/tmp", "/var/tmp", "/var/folders", "/private/var/folders"];

/** True if the (normalized) path is inside the project (cwd) or a temp directory. */
export function isInsideProject(normalized: string, ctx: PathContext = {}): boolean {
  if (TEMP_ROOTS.some((t) => normalized === t || normalized.startsWith(`${t}/`))) return true;
  if (normalized.startsWith("/")) {
    const cwd = ctx.cwd && ctx.cwd.startsWith("/") ? posix.normalize(ctx.cwd).replace(/(.)\/$/, "$1") : null;
    if (!cwd || cwd === "/") return false;
    return normalized === cwd || normalized.startsWith(`${cwd}/`);
  }
  // Relative with no known cwd: inside unless it climbs out.
  return normalized !== ".." && !normalized.startsWith("../") && !normalized.startsWith("~");
}

/**
 * Compile a path glob: `**` any number of segments, `*` within a segment, `?` one char.
 * `~` expands to home. Patterns that are not absolute (`/`, `~`) or `**`-rooted match at
 * any depth (`crontab` ≡ `**∕crontab`).
 */
export function compilePathGlob(pattern: string, ctx: PathContext = {}): RegExp {
  const home = ctx.home ?? defaultHome();
  let p = pattern.trim();
  if (p === "~" || p.startsWith("~/")) p = home + p.slice(1);
  if (!p.startsWith("/") && !p.startsWith("**")) p = `**/${p}`;
  let re = "";
  for (let i = 0; i < p.length; i++) {
    const ch = p[i]!;
    if (ch === "*" && p[i + 1] === "*") {
      const slashAfter = p[i + 2] === "/";
      const slashBefore = i > 0 && p[i - 1] === "/";
      if (slashAfter) {
        re += "(?:.*/)?";
        i += 2;
      } else if (slashBefore && i + 2 === p.length) {
        re = re.slice(0, -1) + "(?:/.*)?";
        i += 1;
      } else {
        re += ".*";
        i += 1;
      }
    } else if (ch === "*") re += "[^/]*";
    else if (ch === "?") re += "[^/]";
    else re += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

/** The literal directory prefix of a pattern (before any glob), home-expanded, or null. */
function literalPrefix(pattern: string, ctx: PathContext): string | null {
  const home = ctx.home ?? defaultHome();
  let p = pattern.trim();
  if (p === "~" || p.startsWith("~/")) p = home + p.slice(1);
  if (!p.startsWith("/")) return null;
  const cut = p.search(/[*?[]/);
  const lit = (cut < 0 ? p : p.slice(0, cut)).replace(/\/+$/, "");
  return lit || null;
}

/**
 * Does `target` (normalized) fall under any pattern? For deletions/moves, a target that
 * is an *ancestor* of a protected location also matches (`mv ~ /tmp/x` removes `~/.ssh`).
 */
export function pathMatchesAny(target: string, patterns: string[], ctx: PathContext, isDelete: boolean): boolean {
  for (const pat of patterns) {
    const re = compilePathGlob(pat, ctx);
    if (re.test(target) || re.test(`${target}/`)) return true;
    if (isDelete && target.startsWith("/")) {
      const lit = literalPrefix(pat, ctx);
      if (lit && (target === "/" || lit === target || lit.startsWith(`${target}/`))) return true;
    }
  }
  return false;
}

/** String paths inside structured filesystem arguments (`path`, `file_path`, `paths`, …). */
export function structuredPaths(args: Record<string, unknown> | undefined): string[] {
  if (!args) return [];
  const out: string[] = [];
  for (const [k, v] of Object.entries(args)) {
    if (!/(^|_)(path|paths|file|target|destination|dest|source)$/i.test(k)) continue;
    if (typeof v === "string") out.push(v);
    else if (Array.isArray(v)) for (const x of v) if (typeof x === "string") out.push(x);
  }
  return out;
}
