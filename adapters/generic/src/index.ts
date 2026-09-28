import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, extname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { z } from "zod";
import type { AgentProvider, NormalizedEvent, TurnCommand, TurnParser } from "@agentgate/adapters";
import { isQuestion, summarizeToolInput } from "@agentgate/adapter-claude-code";
import { ActionDraft } from "@agentgate/protocol";

/**
 * Config-driven provider (`~/.agentgate/providers/*.yaml`, plus built-in profiles) for CLIs
 * without a dedicated adapter — Hermes and others. Kept deliberately small: a command line,
 * how the prompt is passed, how to resume, and how to read JSONL (or plain text) output.
 */

// ── schema ───────────────────────────────────────────────────────────────────

const identifier = z.string().regex(/^[a-z][a-z0-9_-]{0,63}$/, "must be a lowercase id");
/** Either the value of `type_field`, or {dotted.path: value} pairs that must all match. */
const Match = z.union([z.string().min(1), z.record(z.string(), z.union([z.string(), z.number(), z.boolean()]))]);
const Prompt = z.object({ via: z.enum(["stdin", "arg", "flag"]), flag: z.string().optional() }).strict().refine((p) => p.via !== "flag" || !!p.flag, "prompt.flag is required when via: flag");
const Command = z.object({ args: z.array(z.string()), prompt: Prompt }).strict();
const Jsonl = z
  .object({
    type_field: z.string().default("type"),
    assistant_text: z.object({ match: Match, path: z.string(), mode: z.enum(["delta", "full"]).default("full") }).strict(),
    final_text: z.object({ match: Match, path: z.string() }).strict().optional(),
    session_id: z.object({ match: Match, path: z.string() }).strict(),
    tool_call: z.object({ match: Match, name: z.string(), input: z.string() }).strict().optional(),
    tool_result: z.object({ match: Match, output: z.string(), error: z.string().optional() }).strict().optional(),
    usage: z.object({ match: Match, path: z.string() }).strict().optional(),
    done: z.object({ match: Match }).strict(),
    error: z.object({ match: Match, path: z.string() }).strict().optional(),
  })
  .strict();
const Output = z
  .object({
    format: z.enum(["text", "jsonl"]),
    jsonl: Jsonl.optional(),
    text: z.object({ session_id_regex: z.string().optional() }).strict().optional(),
  })
  .strict()
  .refine((o) => o.format !== "jsonl" || !!o.jsonl, "output.jsonl is required when format: jsonl");

export const ProviderProfile = z
  .object({
    id: identifier,
    display_name: z.string().min(1).max(64),
    binary: z.string().min(1),
    cwd_flag: z.string().optional(),
    env: z.record(z.string(), z.string()).optional(),
    command: Command,
    resume: z
      .object({ args: z.array(z.string()), prompt: Prompt.optional() })
      .strict()
      .refine((r) => r.args.some((a) => a.includes("{session_id}")), "resume.args must contain {session_id}")
      .optional(),
    output: Output,
    approval: z
      .object({
        mode: z.enum(["hook", "sandbox-only", "none"]),
        hook: z
          .object({
            home_env: z.string(),
            copy_from: z.string().optional(),
            config_file: z.string(),
            config_patch: z.record(z.string(), z.unknown()),
          })
          .strict()
          .optional(),
      })
      .strict()
      .refine((a) => a.mode !== "hook" || !!a.hook, "approval.hook is required when mode: hook"),
    signals: z
      .object({ interrupt: z.string().default("SIGINT"), terminate: z.string().default("SIGTERM"), grace_ms: z.number().int().positive().default(5000) })
      .strict()
      .default({}),
    success_exit_codes: z.array(z.number().int()).default([0]),
    timeout_ms: z.number().int().positive().optional(),
    detect: z
      .object({
        help_args: z.array(z.string()),
        contains: z.string(),
        fallback: z.object({ command: Command.optional(), output: Output, resume: z.null().optional() }).strict(),
      })
      .strict()
      .optional(),
  })
  .strict();
export type ProviderProfile = z.infer<typeof ProviderProfile>;

export interface ProfileLoadResult {
  profiles: ProviderProfile[];
  errors: Array<{ file: string; error: string }>;
}

/** Built-in profiles shipped with AgentGate (profiles/*.yaml). */
export const BUILTIN_PROFILES_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..", "profiles");

export function parseProfile(text: string, file = "<inline>"): ProviderProfile {
  let raw: unknown;
  try {
    raw = parseYaml(text);
  } catch (err) {
    throw new Error(`${file}: invalid YAML (${(err as Error).message.split("\n")[0]})`);
  }
  const r = ProviderProfile.safeParse(raw);
  if (!r.success) {
    const i = r.error.issues[0]!;
    throw new Error(`${file}: ${i.path.join(".") || "(root)"}: ${i.message}`);
  }
  return r.data;
}

/** Loads every *.yaml/*.yml in the dirs; later dirs override earlier ones by id. Never throws. */
export function loadProfiles(dirs: string[]): ProfileLoadResult {
  const byId = new Map<string, ProviderProfile>();
  const errors: ProfileLoadResult["errors"] = [];
  for (const d of dirs) {
    let names: string[] = [];
    try {
      names = readdirSync(d).filter((n) => [".yaml", ".yml"].includes(extname(n))).sort();
    } catch {
      continue;
    }
    for (const n of names) {
      const file = join(d, n);
      try {
        const p = parseProfile(readFileSync(file, "utf8"), file);
        byId.set(p.id, p);
      } catch (err) {
        errors.push({ file, error: (err as Error).message });
      }
    }
  }
  return { profiles: [...byId.values()], errors };
}

// ── parsing ─────────────────────────────────────────────────────────────────

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

export function getPath(o: unknown, path: string): unknown {
  let cur: unknown = o;
  for (const k of path.split(".")) {
    if (!isObj(cur)) return undefined;
    cur = cur[k];
  }
  return cur;
}

function matches(o: Json, m: z.infer<typeof Match>, typeField: string): boolean {
  if (typeof m === "string") return o[typeField] === m;
  return Object.entries(m).every(([k, v]) => getPath(o, k) === v);
}

const asText = (v: unknown) => (typeof v === "string" ? v : v === undefined || v === null ? "" : JSON.stringify(v));
const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : null);

function usageFrom(v: unknown): Record<string, number | null> {
  if (typeof v === "number") return { cost_usd: null, input_tokens: null, output_tokens: v, duration_ms: null, num_turns: null };
  const o = isObj(v) ? v : {};
  return {
    cost_usd: num(o.cost_usd ?? o.total_cost_usd),
    input_tokens: num(o.input_tokens ?? o.input ?? o.prompt_tokens),
    output_tokens: num(o.output_tokens ?? o.output ?? o.completion_tokens),
    duration_ms: num(o.duration_ms),
    num_turns: null,
  };
}

interface ActiveMode {
  command: ProviderProfile["command"];
  output: z.infer<typeof Output>;
  resume: ProviderProfile["resume"] | null;
}

export function createTurnParser(mode: ActiveMode, successCodes: number[], gated: boolean): TurnParser {
  const cfg = mode.output;
  let buffer = "";
  let textAll = "";
  let usage: Record<string, number | null> = usageFrom(undefined);
  let error: string | null = null;
  let done = false;
  let finalText: string | null = null;
  const flush = (): NormalizedEvent[] => {
    if (!buffer.trim()) return [];
    const ev: NormalizedEvent = { type: "message.assistant", payload: { text: buffer } };
    buffer = "";
    return [ev];
  };
  const result = (ok: boolean): NormalizedEvent => ({
    type: "provider.turn_result",
    payload: { ok, text: finalText, error: ok ? null : (error ?? "turn failed"), usage },
  });

  if (cfg.format === "text") {
    return {
      line(l) {
        textAll += `${l}\n`;
        return [];
      },
      end(code) {
        const out: NormalizedEvent[] = [];
        const re = cfg.text?.session_id_regex ? new RegExp(cfg.text.session_id_regex) : null;
        const sid = re ? textAll.match(re)?.[1] : undefined;
        if (sid) out.push({ type: "provider.session", payload: { provider_session_id: sid } });
        const text = textAll.trim();
        finalText = text || null;
        if (text) out.push({ type: "message.assistant", payload: { text } });
        const ok = code !== null && successCodes.includes(code);
        if (!ok) error = `exited with code ${code}`;
        out.push(result(ok));
        return out;
      },
    };
  }

  const j = cfg.jsonl!;
  return {
    line(l) {
      const s = l.trim();
      if (!s.startsWith("{")) return [];
      let o: unknown;
      try {
        o = JSON.parse(s);
      } catch {
        return [];
      }
      if (!isObj(o)) return [];
      const out: NormalizedEvent[] = [];
      if (matches(o, j.session_id.match, j.type_field)) {
        const sid = getPath(o, j.session_id.path);
        if (typeof sid === "string" && sid) out.push({ type: "provider.session", payload: { provider_session_id: sid } });
      }
      if (matches(o, j.assistant_text.match, j.type_field)) {
        const t = asText(getPath(o, j.assistant_text.path));
        if (j.assistant_text.mode === "delta") buffer += t;
        else if (t.trim()) out.push({ type: "message.assistant", payload: { text: t } });
      }
      if (j.tool_call && matches(o, j.tool_call.match, j.type_field)) {
        out.push(...flush());
        const name = asText(getPath(o, j.tool_call.name)) || "tool";
        const input = getPath(o, j.tool_call.input);
        out.push({ type: "tool.call", payload: { tool: name, summary: summarizeToolInput(name, input) } });
        if (gated) out.push({ type: "provider.tool_started", payload: { kind: "tool", item_id: null, text: name } });
      }
      if (j.tool_result && matches(o, j.tool_result.match, j.type_field)) {
        const err = j.tool_result.error ? getPath(o, j.tool_result.error) : undefined;
        const failed = err === true || (typeof err === "string" && err.length > 0);
        const output = asText(getPath(o, j.tool_result.output));
        out.push({ type: "tool.result", payload: { ok: !failed, summary: output.slice(0, 500), output_tail: output.slice(-8192) } });
        if (gated) out.push({ type: "provider.tool_completed", payload: { kind: "tool", item_id: null, text: "", status: failed ? "failed" : "completed" } });
      }
      if (j.usage && matches(o, j.usage.match, j.type_field)) usage = usageFrom(getPath(o, j.usage.path));
      if (j.error && matches(o, j.error.match, j.type_field)) {
        const e = getPath(o, j.error.path);
        if (typeof e === "string" && e) error = e;
      }
      if (j.final_text && matches(o, j.final_text.match, j.type_field)) {
        const t = getPath(o, j.final_text.path);
        if (typeof t === "string") finalText = t;
      }
      if (matches(o, j.done.match, j.type_field)) {
        out.push(...flush());
        done = true;
        out.push(result(error === null));
      }
      return out;
    },
    end(code) {
      const out = flush();
      if (!done) {
        const ok = code !== null && successCodes.includes(code) && error === null;
        if (!ok && error === null) error = `exited with code ${code} without a result`;
        out.push(result(ok));
      }
      return out;
    },
  };
}

// ── provider ────────────────────────────────────────────────────────────────

export interface GenericProviderOptions {
  /** Absolute binary path override (else profile.binary looked up on the turn PATH). */
  binary?: string;
  /** Hook mode: prepares a per-session home dir with the AgentGate hook; returns env + receipts file. */
  prepareHome?: (profile: ProviderProfile, agentSessionId: string) => { env: Record<string, string>; gateReceipts: string };
}

export function isGated(p: ProviderProfile): boolean {
  return p.approval.mode === "hook";
}

function substitute(args: string[], vars: Record<string, string>): string[] {
  return args.map((a) => a.replace(/\{(session_id|cwd)\}/g, (_, k: string) => vars[k] ?? ""));
}

export function genericProvider(profile: ProviderProfile, o: GenericProviderOptions = {}): AgentProvider & { mode(): "primary" | "fallback" } {
  const binary = o.binary ?? profile.binary;
  let active: ActiveMode = { command: profile.command, output: profile.output, resume: profile.resume ?? null };
  let detected: { at: number; mode: "primary" | "fallback" } | null = null;
  const gated = isGated(profile);
  const provider: AgentProvider & { mode(): "primary" | "fallback" } = {
    id: profile.id,
    binary,
    displayName: profile.display_name,
    get capabilities() {
      return { resume: !!active.resume, pause: "signal" as const, observe: false, cost: false };
    },
    gated,
    mode: () => detected?.mode ?? "primary",
    buildTurnCommand(req): TurnCommand {
      const resuming = !!(req.providerSessionId && active.resume);
      const base = resuming ? substitute(active.resume!.args, { session_id: req.providerSessionId!, cwd: req.cwd }) : substitute(active.command.args, { cwd: req.cwd, session_id: "" });
      const prompt = resuming && active.resume?.prompt ? active.resume.prompt : active.command.prompt;
      const args = [...(profile.cwd_flag ? [profile.cwd_flag, req.cwd] : []), ...base];
      let stdin: string | undefined;
      if (prompt.via === "stdin") stdin = req.instruction;
      else if (prompt.via === "flag") args.push(prompt.flag!, req.instruction);
      else args.push(req.instruction); // via: arg (argv-visible; prefer stdin)
      const home = gated && o.prepareHome && req.sessionId ? o.prepareHome(profile, req.sessionId) : null;
      return {
        cmd: binary,
        args,
        ...(stdin !== undefined ? { stdin } : {}),
        env: { ...(profile.env ?? {}), ...(home?.env ?? {}) },
        ...(home ? { gateReceipts: home.gateReceipts } : {}),
      };
    },
    parseOutputLine: (line) => createTurnParser(active, profile.success_exit_codes, gated).line(line),
    createParser: () => createTurnParser(active, profile.success_exit_codes, gated),
    isQuestion,
    preflight(env) {
      if (!profile.detect) return { ok: true };
      if (!detected || Date.now() - detected.at > 300_000) {
        let help = "";
        try {
          help = execFileSync(binary, profile.detect.help_args, { env, encoding: "utf8", timeout: 5_000, stdio: ["ignore", "pipe", "pipe"] });
        } catch (err) {
          help = String((err as { stdout?: string }).stdout ?? "") + String((err as { stderr?: string }).stderr ?? "");
        }
        const mode = help.includes(profile.detect.contains) ? "primary" : "fallback";
        detected = { at: Date.now(), mode };
        active =
          mode === "primary"
            ? { command: profile.command, output: profile.output, resume: profile.resume ?? null }
            : { command: profile.detect.fallback.command ?? profile.command, output: profile.detect.fallback.output, resume: null };
      }
      return { ok: true };
    },
  };
  return provider;
}

// ── per-session home for hook mode ──────────────────────────────────────────

function expandHome(p: string) {
  return p.startsWith("~/") ? join(homedir(), p.slice(2)) : p;
}

function deepMerge(a: unknown, b: unknown): unknown {
  if (isObj(a) && isObj(b)) {
    const out: Json = { ...a };
    for (const [k, v] of Object.entries(b)) out[k] = k in a ? deepMerge(a[k], v) : v;
    return out;
  }
  return b;
}

function fillHookCommand(v: unknown, cmd: string): unknown {
  if (typeof v === "string") return v.split("{hook_command}").join(cmd);
  if (Array.isArray(v)) return v.map((x) => fillHookCommand(x, cmd));
  if (isObj(v)) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fillHookCommand(x, cmd)]));
  return v;
}

/**
 * Creates `<baseDir>/<sessionId>`: a shallow copy of `copy_from` (top-level files only, 0600)
 * with `config_file` patched to call the AgentGate hook. Returns the env to point the CLI at it.
 */
export function prepareGenericHome(profile: ProviderProfile, o: { baseDir: string; sessionId: string; hookCommand: string }): { env: Record<string, string>; gateReceipts: string } {
  const hook = profile.approval.hook!;
  const dir = join(o.baseDir, profile.id, o.sessionId.replace(/[^A-Za-z0-9_-]/g, "_"));
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const from = hook.copy_from ? expandHome(hook.copy_from) : null;
  if (from && existsSync(from)) {
    for (const n of readdirSync(from)) {
      const src = join(from, n);
      try {
        if (statSync(src).isFile() && statSync(src).size < 1_000_000) {
          copyFileSync(src, join(dir, n));
          chmodSync(join(dir, n), 0o600);
        }
      } catch {
        /* unreadable → skip */
      }
    }
  }
  const cfgPath = join(dir, hook.config_file);
  let current: unknown = {};
  if (existsSync(cfgPath)) {
    try {
      current = parseYaml(readFileSync(cfgPath, "utf8")) ?? {};
    } catch {
      current = {};
    }
  }
  const receipts = join(dir, "agentgate-receipts.jsonl");
  const hookCmd = `AGENTGATE_GATE_RECEIPTS=${JSON.stringify(receipts)} ${o.hookCommand}`;
  writeFileSync(cfgPath, stringifyYaml(deepMerge(current, fillHookCommand(hook.config_patch, hookCmd))), { mode: 0o600 });
  return { env: { [hook.home_env]: dir, AGENTGATE_GATE_RECEIPTS: receipts }, gateReceipts: receipts };
}

// ── hook normalization (generic PreToolUse from Hermes & co) ───────────────────

const SHELL_TOOLS = /^(bash|shell|terminal|run_command|exec_command|execute_command|run_shell_command)$/i;
const WRITE_TOOLS = /^(write|write_file|edit|edit_file|patch|apply_patch|create_file|replace)$/i;

/** Claude-style hook stdin (session_id, cwd, tool_name, tool_input) → canonical action. */
export function normalizeGenericHook(providerId: string, raw: unknown, ctx: { session_id: string; cwd: string }): ActionDraft {
  if (!isObj(raw)) throw new Error("hook input is not an object");
  const tool = typeof raw.tool_name === "string" ? raw.tool_name : typeof raw.name === "string" ? raw.name : "";
  if (!tool) throw new Error("missing tool_name");
  const ti = isObj(raw.tool_input) ? raw.tool_input : isObj(raw.input) ? raw.input : {};
  const cwd = typeof raw.cwd === "string" && raw.cwd ? raw.cwd : ctx.cwd;
  const base = { session_id: ctx.session_id, agent: { type: providerId }, context: typeof raw.session_id === "string" ? { provider_session_id: raw.session_id.slice(0, 256) } : {} };
  if (SHELL_TOOLS.test(tool)) {
    const command = typeof ti.command === "string" ? ti.command : Array.isArray(ti.command) ? ti.command.join(" ") : "";
    return ActionDraft.parse({ ...base, action: { category: "shell", operation: "execute", tool, command, cwd }, resource: {} });
  }
  if (WRITE_TOOLS.test(tool)) {
    const p = typeof ti.path === "string" ? ti.path : typeof ti.file_path === "string" ? ti.file_path : "";
    const path = p ? (isAbsolute(p) ? resolve(p) : resolve(cwd, p)) : "(unknown)";
    return ActionDraft.parse({ ...base, action: { category: "filesystem", operation: "write", tool, arguments: { path }, cwd }, resource: { type: "file", name: path }, ...(p ? {} : { risk: { level: "high", reason: "write without a path" } }) });
  }
  return ActionDraft.parse({
    ...base,
    action: { category: "tool", operation: "invoke", tool: tool.slice(0, 128), arguments: { keys: Object.keys(ti).slice(0, 20) }, cwd },
    resource: {},
    risk: { level: "high", reason: `unrecognized ${providerId} tool ${basename(tool)}` },
  });
}
