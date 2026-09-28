import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { accessSync, constants as fsc, readFileSync, realpathSync, statSync } from "node:fs";
import { basename, isAbsolute, join, resolve } from "node:path";
import { analyzeShell, effectiveArgv, tokenize } from "@agentgate/policy-engine";
import type { ActionDraft } from "@agentgate/protocol";

/**
 * H2: bind the approval to what will actually execute, not just the command text.
 *
 * Stored in `action.arguments.exec_context` — part of the action hash (core hashes
 * `arguments`), so the server-signed approval token covers it:
 *   path       PATH captured at approval time; the executor runs with exactly this PATH
 *   bins       first word of every segment → absolute realpath (null = not found/builtin)
 *   scripts    interpreter script files (bash/sh/node/python … <file>) and directly
 *              executed files inside the project → sha256
 *   git_push   effective push URL + refspec for every `git push`
 *   git_hooks  "disabled" unless AGENTGATE_ALLOW_GIT_HOOKS=1 at approval time; the
 *              executor enforces it with core.hooksPath=/dev/null (via GIT_CONFIG_*)
 * The executor recomputes this from the command it received, with the approved PATH, and
 * refuses (77) on any difference. Everything is best effort *at approval*; at execution a
 * difference always blocks.
 */

export interface GitPush {
  remote: string;
  url: string | null;
  refspec: string;
}

export interface ExecContext {
  v: 2;
  path: string;
  bins: Record<string, string | null>;
  scripts: Record<string, string | null>;
  git_push: GitPush[];
  git_hooks: "disabled" | "allowed";
}

const SHELL_WORDS = new Set([
  "cd", "export", "unset", "set", "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case",
  "esac", "in", "function", "return", "exit", "local", "read", "shift", "trap", "wait", "true", "false", ":", "[", "[[",
  "test", "echo", "printf", "pwd", "alias", "unalias", "type", "hash", "umask", "ulimit", "{", "}", "(", ")", "!", "eval",
  "source", ".", "exec", "command", "builtin", "let", "declare", "typeset", "readonly", "getopts", "jobs", "fg", "bg",
]);
const INTERPRETERS = new Set(["bash", "sh", "zsh", "dash", "ksh", "node", "python", "python3", "ruby", "perl", "php", "deno", "bun", "tsx", "ts-node"]);
/** Interpreter flags that take the next word as a value (so it is not the script). */
const FLAG_WITH_VALUE = new Set(["-m", "-W", "-X", "-O", "-r", "--require", "--import", "--loader", "-I"]);

export const DANGEROUS_ENV = [
  /^GIT_/, /^LD_/, /^DYLD_/, /^BASH_ENV$/, /^ENV$/, /^PROMPT_COMMAND$/, /^NODE_OPTIONS$/, /^NODE_PATH$/, /^PYTHONSTARTUP$/,
  /^PYTHONPATH$/, /^PYTHONHOME$/, /^PERL5OPT$/, /^PERL5LIB$/, /^PERLLIB$/, /^RUBYOPT$/, /^RUBYLIB$/, /^ZDOTDIR$/,
  /^SHELLOPTS$/, /^BASHOPTS$/, /^IFS$/, /^CDPATH$/, /^GLOBIGNORE$/, /^JAVA_TOOL_OPTIONS$/, /^_JAVA_OPTIONS$/,
  /^JDK_JAVA_OPTIONS$/, /^NPM_CONFIG_/i, /^BASH_FUNC_/, /^SSH_ASKPASS$/, /^EDITOR$/, /^VISUAL$/, /^PAGER$/, /^LESSOPEN$/,
];

function sha256File(p: string): string | null {
  try {
    if (!statSync(p).isFile()) return null;
    return createHash("sha256").update(readFileSync(p)).digest("hex");
  } catch {
    return null;
  }
}

function real(p: string): string | null {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
}

export function resolveBinary(word: string, path: string, cwd: string): string | null {
  if (word.includes("/")) return real(isAbsolute(word) ? word : resolve(cwd, word));
  for (const dir of path.split(":")) {
    if (!dir) continue;
    const cand = join(isAbsolute(dir) ? dir : resolve(cwd, dir), word);
    try {
      accessSync(cand, fsc.X_OK);
      if (statSync(cand).isFile()) return real(cand);
    } catch {
      /* next */
    }
  }
  return null;
}

function within(root: string, p: string): boolean {
  const r = real(root) ?? root;
  return p === r || p.startsWith(`${r}/`);
}

function git(cwd: string, path: string, args: string[]): string | null {
  try {
    const out = execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 3_000,
      // Never let the environment redirect which repo/config git reads.
      env: { PATH: path, HOME: process.env.HOME ?? "", LANG: "C" },
    }).trim();
    return out || null;
  } catch {
    return null;
  }
}

/** git [global opts] push [opts] [remote] [refspec…] → effective push target. */
function gitPushTarget(argv: string[], cwd: string, path: string): GitPush | null {
  let i = 1;
  let repoDir = cwd;
  while (i < argv.length && argv[i]!.startsWith("-")) {
    const a = argv[i]!;
    if (a === "-C" && argv[i + 1]) {
      repoDir = resolve(repoDir, argv[i + 1]!);
      i += 2;
      continue;
    }
    if (a === "-c" || a === "--git-dir" || a === "--work-tree" || a === "--namespace") {
      // --git-dir/--work-tree change what is pushed: make the binding reflect it.
      if (a === "--git-dir" && argv[i + 1]) repoDir = resolve(repoDir, argv[i + 1]!);
      i += 2;
      continue;
    }
    i++;
  }
  if (argv[i] !== "push") return null;
  const positional: string[] = [];
  for (let j = i + 1; j < argv.length; j++) {
    const a = argv[j]!;
    if (a === "--") {
      positional.push(...argv.slice(j + 1));
      break;
    }
    if (a.startsWith("--repo=")) {
      positional.unshift(a.slice(7));
      continue;
    }
    if (a === "-o" || a === "--push-option" || a === "--receive-pack" || a === "--exec" || a === "--repo") {
      if (a === "--repo" && argv[j + 1]) positional.unshift(argv[j + 1]!);
      j++;
      continue;
    }
    if (a.startsWith("-")) continue;
    positional.push(a);
  }
  const branch = git(repoDir, path, ["rev-parse", "--abbrev-ref", "HEAD"]);
  let remote = positional[0];
  if (!remote) {
    remote =
      (branch && git(repoDir, path, ["config", `branch.${branch}.pushRemote`])) ||
      git(repoDir, path, ["config", "remote.pushDefault"]) ||
      (branch && git(repoDir, path, ["config", `branch.${branch}.remote`])) ||
      "origin";
  }
  const isUrl = /[:/]/.test(remote);
  const url = isUrl ? remote : git(repoDir, path, ["remote", "get-url", "--push", remote]);
  const refspec = positional.slice(1).join(" ") || `(default: ${branch ?? "current branch"})`;
  return { remote, url, refspec };
}

export function computeExecContext(command: string, cwd: string, opts: { path: string; gitHooks: "disabled" | "allowed" }): ExecContext {
  const ctx: ExecContext = { v: 2, path: opts.path, bins: {}, scripts: {}, git_push: [], git_hooks: opts.gitHooks };
  let segments: string[];
  try {
    const a = analyzeShell(command);
    segments = a.segments.length ? a.segments : [command.trim()];
  } catch {
    segments = [command.trim()];
  }
  segments.forEach((seg, idx) => {
    let argv: string[];
    try {
      argv = effectiveArgv(seg);
    } catch {
      return;
    }
    // Wrappers (sudo, env, nohup, time …) are what really executes: bind them too.
    try {
      const rawBin = tokenize(seg).find((w) => !/^[A-Za-z_][A-Za-z0-9_]*=/.test(w));
      if (rawBin && rawBin !== argv[0] && !SHELL_WORDS.has(rawBin) && !/[$`]/.test(rawBin)) {
        ctx.bins[`${idx}:${rawBin}`] = resolveBinary(rawBin, opts.path, cwd);
      }
    } catch {
      /* ignore */
    }
    const bin = argv[0];
    if (!bin || SHELL_WORDS.has(bin) || bin.includes("$") || bin.includes("`")) return;
    const key = `${idx}:${bin}`;
    const resolved = resolveBinary(bin, opts.path, cwd);
    ctx.bins[key] = resolved;
    // Directly executed files inside the project (./deploy.sh) are content-bound too.
    if (resolved && within(cwd, resolved)) ctx.scripts[`${idx}:${bin}`] = sha256File(resolved);

    const name = basename(bin);
    if (INTERPRETERS.has(name)) {
      for (let j = 1; j < argv.length; j++) {
        const a = argv[j]!;
        if (a === "-c" || a === "-e" || a === "--eval" || a === "-p") break; // inline code: nothing to bind
        if (FLAG_WITH_VALUE.has(a)) {
          j++;
          continue;
        }
        if (a.startsWith("-")) continue;
        const file = isAbsolute(a) ? a : resolve(cwd, a);
        ctx.scripts[`${idx}:${a}`] = sha256File(file);
        break;
      }
    }
    if (name === "git") {
      const p = gitPushTarget(argv, cwd, opts.path);
      if (p) ctx.git_push.push(p);
    }
  });
  return ctx;
}

export function hasGit(ctx: ExecContext): boolean {
  return Object.keys(ctx.bins).some((k) => basename(k.split(":").slice(1).join(":")) === "git");
}

/** Adds the binding (hashed) plus display-only hints to a shell draft. */
export function bindExecContext(draft: ActionDraft, ctx: ExecContext): ActionDraft {
  const out: ActionDraft = {
    ...draft,
    action: { ...draft.action, arguments: { ...(draft.action.arguments ?? {}), exec_context: ctx } },
    resource: { ...(draft.resource ?? {}) },
    context: { ...(draft.context ?? {}) },
  };
  const push = ctx.git_push[0];
  if (push && !out.resource.name) {
    out.resource.type = "git_remote";
    out.resource.name = `${push.url ?? `${push.remote} (unresolved)`} ${push.refspec}`.slice(0, 512);
  }
  if (hasGit(ctx)) out.context.git_hooks = ctx.git_hooks === "disabled" ? "disabled for this command" : "allowed";
  return out;
}

export function execContextOf(draft: ActionDraft): ExecContext | null {
  const c = (draft.action.arguments as Record<string, unknown> | undefined)?.exec_context as ExecContext | undefined;
  return c && c.v === 2 ? c : null;
}

/** Draft without the binding (for policy evaluation: PATH strings must not sway risk). */
export function withoutExecContext(draft: ActionDraft): ActionDraft {
  const args = { ...((draft.action.arguments as Record<string, unknown>) ?? {}) };
  delete args.exec_context;
  const action = { ...draft.action };
  if (Object.keys(args).length) action.arguments = args;
  else delete action.arguments;
  return { ...draft, action };
}

/** First difference between approved and current binding, as a block reason. */
export function diffExecContext(approved: ExecContext, current: ExecContext): { reason: string; detail: string } | null {
  const keys = new Set([...Object.keys(approved.bins), ...Object.keys(current.bins)]);
  for (const k of keys) {
    if ((approved.bins[k] ?? null) !== (current.bins[k] ?? null)) {
      return { reason: "binary_changed", detail: `${k.split(":").slice(1).join(":")} resolves to ${current.bins[k] ?? "nothing"} (approved: ${approved.bins[k] ?? "nothing"})` };
    }
  }
  const sk = new Set([...Object.keys(approved.scripts), ...Object.keys(current.scripts)]);
  for (const k of sk) {
    if ((approved.scripts[k] ?? null) !== (current.scripts[k] ?? null)) {
      return { reason: "script_changed", detail: `${k.split(":").slice(1).join(":")} changed since approval` };
    }
  }
  if (JSON.stringify(approved.git_push) !== JSON.stringify(current.git_push)) {
    const a = approved.git_push.map((p) => `${p.url} ${p.refspec}`).join(", ");
    const c = current.git_push.map((p) => `${p.url} ${p.refspec}`).join(", ");
    return { reason: "push_target_changed", detail: `push target is now ${c || "none"} (approved: ${a || "none"})` };
  }
  return null;
}

/** The environment an approved command runs with: approved PATH, no injection vectors. */
export function scrubbedEnv(base: NodeJS.ProcessEnv, ctx: ExecContext): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(base)) {
    if (v === undefined || DANGEROUS_ENV.some((re) => re.test(k))) continue;
    if (k.startsWith("AGENTGATE_")) continue;
    env[k] = v;
  }
  env.PATH = ctx.path;
  if (ctx.git_hooks === "disabled") {
    env.GIT_CONFIG_COUNT = "1";
    env.GIT_CONFIG_KEY_0 = "core.hooksPath";
    env.GIT_CONFIG_VALUE_0 = "/dev/null";
  }
  return env;
}

export function gitHooksSetting(env: NodeJS.ProcessEnv = process.env): "disabled" | "allowed" {
  return env.AGENTGATE_ALLOW_GIT_HOOKS === "1" ? "allowed" : "disabled";
}
