import { execFile } from "node:child_process";
import type { AgentProvider, CostKind, NormalizedEvent, TurnCommand } from "@agentgate/adapters";
import { estimateCostUsd } from "./prices.ts";

/**
 * Claude Code provider for the Control Center supervisor (docs/control-center.md).
 *
 * Verified against Claude Code 2.1.283 `-p --output-format stream-json --verbose`
 * (fixtures in test/fixtures):
 *   system/init {session_id, cwd, model, permissionMode}
 *   assistant {message.content: [thinking | text | tool_use{id,name,input}]}  (one line per block)
 *   user {message.content: [tool_result{tool_use_id, content, is_error}]}
 *   system/post_turn_summary {status_category: "completed"|"blocked", needs_action}
 *   result {subtype, is_error, num_turns, result, total_cost_usd, usage{input_tokens,output_tokens}, duration_ms, errors?}
 *   plus rate_limit_event, system/task_summary, … (ignored)
 * `--resume <id>` keeps the same session_id. The prompt is read from stdin (verified),
 * so instructions never land in argv.
 */

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown) => (typeof v === "string" ? v : undefined);
const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : null);
const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/** One-line summary of a tool call's input (display only; the server redacts again). */
export function summarizeToolInput(tool: string, input: unknown): string {
  if (!isObj(input)) return tool;
  const pick = str(input.command) ?? str(input.file_path) ?? str(input.path) ?? str(input.notebook_path) ?? str(input.pattern) ?? str(input.url) ?? str(input.query) ?? str(input.description);
  if (pick) return clip(pick.replace(/\s+/g, " ").trim(), 300);
  const keys = Object.keys(input);
  return keys.length ? `${tool}(${clip(keys.join(", "), 200)})` : tool;
}

function resultText(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) return content.map((c) => (isObj(c) && typeof c.text === "string" ? c.text : "")).join("\n");
  return "";
}

const QUESTION_PATTERNS = [
  /\b(should i|shall i|would you like|do you want|which (one|option|file|approach)|what would you like|how would you like)\b/i,
  /\b(please (confirm|choose|select|clarify|let me know)|let me know (if|which|whether|what|how)|can you (confirm|clarify)|could you (confirm|clarify|tell me))\b/i,
  /\b(waiting for your|your (choice|decision|input|confirmation))\b/i,
  // Turkish (users dictate/write in Turkish; Claude answers in kind)
  /(onay(ın(ı|ızı)?)?\s+(bekliyorum|bekleriz)|onaylar\s*m[ıi]s[ıi]n|ister\s*mis(in|iniz)|hangis(in)?i\s+(tercih|istersin|seçelim)|karar\s+(ver|senin))/i,
];

/** An explicit question label anywhere near the end ("Question:", "**Soru:**"). */
const QUESTION_LABEL = /(^|\n)\s*[*_#>\s-]*(question|soru|sorular)\s*[*_]*\s*:/i;
/**
 * A real question sentence ending in "?" (not inside code): long enough to not be a
 * rhetorical one-word lead-in ("Why? Because…"), and not immediately answered.
 */
const QUESTION_SENTENCE = /(^|[.!:\n]\s*)[^\s?.!][^?.!\n]{14,}\?(?!\s*(because|çünkü|since|as)\b)/i;

function stripCode(text: string): string {
  return text.replace(/```[\s\S]*?```/g, " ").replace(/`[^`\n]*`/g, "x");
}

/** Heuristic: does the turn's last assistant message ask the user something? */
export function isQuestion(text: string): boolean {
  const t = text.trim();
  if (!t) return false;
  const tail = t.slice(-400);
  // Ends with a question (ignoring trailing markdown/emphasis/punctuation noise).
  if (/\?\s*[*_`)\]"'”’]*\s*$/.test(tail)) return true;
  // Questions are often followed by a closing sentence ("…olsun mu? … değiştiririm."):
  // look at the last two prose paragraphs (code blocks removed).
  const prose = stripCode(t).trim();
  const paras = prose.split(/\n\s*\n/).filter((p) => p.trim());
  const recent = paras.slice(-2).join("\n\n").slice(-800);
  if (QUESTION_LABEL.test(recent) && /\?/.test(recent)) return true;
  if (QUESTION_SENTENCE.test(paras.slice(-1).join(""))) return true;
  return QUESTION_PATTERNS.some((re) => re.test(recent));
}

export function parseStreamJsonLine(line: string): NormalizedEvent[] {
  const s = line.trim();
  if (!s.startsWith("{")) return [];
  let o: unknown;
  try {
    o = JSON.parse(s);
  } catch {
    return [];
  }
  if (!isObj(o)) return [];
  const out: NormalizedEvent[] = [];
  const sid = str(o.session_id);
  switch (o.type) {
    case "system":
      if (o.subtype === "init" && sid) {
        out.push({ type: "provider.session", payload: { provider_session_id: sid, model: str(o.model) ?? null, permission_mode: str(o.permissionMode) ?? null } });
      } else if (o.subtype === "api_retry") {
        // Claude Code retries a failed API call (rate limit, overload): counted as a retry.
        out.push({ type: "provider.api_retry", payload: { attempt: num(o.attempt) ?? null, error: str(o.error) ?? null } });
      } else if (o.subtype === "post_turn_summary") {
        out.push({
          type: "provider.turn_hint",
          payload: { status: str(o.status_category) ?? null, needs_action: str(o.needs_action) || null, detail: str(o.status_detail) ?? null },
        });
      }
      break;
    case "assistant": {
      const content = isObj(o.message) && Array.isArray(o.message.content) ? o.message.content : [];
      // Mid-turn cost estimate: per API message usage (repeated per content block → keyed by id).
      if (isObj(o.message) && isObj(o.message.usage)) {
        const u = o.message.usage;
        const model = str(o.message.model) ?? null;
        out.push({
          type: "provider.usage_delta",
          payload: {
            message_id: str(o.message.id) ?? null,
            model,
            input_tokens: num(u.input_tokens),
            output_tokens: num(u.output_tokens),
            cost_usd_estimate: estimateCostUsd(model, u as never),
          },
        });
      }
      for (const c of content) {
        if (!isObj(c)) continue;
        if (c.type === "text" && typeof c.text === "string" && c.text.trim()) out.push({ type: "message.assistant", payload: { text: c.text } });
        if (c.type === "tool_use") {
          const tool = str(c.name) ?? "tool";
          out.push({ type: "tool.call", payload: { tool, summary: summarizeToolInput(tool, c.input), tool_use_id: str(c.id) ?? null } });
        }
      }
      break;
    }
    case "user": {
      const content = isObj(o.message) && Array.isArray(o.message.content) ? o.message.content : [];
      for (const c of content) {
        if (!isObj(c)) continue;
        if (c.type === "tool_result") {
          out.push({
            type: "tool.result",
            // output_tail: internal (test-run detection); the supervisor strips it before storing.
            payload: { tool_use_id: str(c.tool_use_id) ?? null, ok: c.is_error !== true, summary: clip(resultText(c.content).trim(), 500), output_tail: resultText(c.content).slice(-8192) },
          });
        } else if (c.type === "text" && typeof c.text === "string") {
          out.push({ type: "message.user", payload: { text: c.text } });
        }
      }
      break;
    }
    case "result": {
      const usage = isObj(o.usage) ? o.usage : {};
      const errors = Array.isArray(o.errors) ? o.errors.filter((e): e is string => typeof e === "string") : [];
      // Verified: an error can arrive as subtype "success" + is_error:true with the reason in
      // `result` (e.g. "Not logged in · Please run /login", terminal_reason "api_error").
      const isError = o.is_error === true || (typeof o.subtype === "string" && o.subtype !== "success");
      out.push({
        type: "provider.turn_result",
        payload: {
          ok: !isError,
          text: str(o.result) ?? null,
          error: isError
            ? clip(errors.join("; ") || str(o.result) || [str(o.subtype), str(o.terminal_reason)].filter(Boolean).join(": ") || "turn failed", 2000)
            : null,
          subtype: str(o.subtype) ?? null,
          provider_session_id: sid ?? null,
          usage: {
            cost_usd: num(o.total_cost_usd),
            input_tokens: num(usage.input_tokens),
            output_tokens: num(usage.output_tokens),
            duration_ms: num(o.duration_ms),
            num_turns: num(o.num_turns),
          },
        },
      });
      break;
    }
    default:
      break; // rate_limit_event, stream_event, future types: ignored
  }
  return out;
}

/**
 * Observed mode: a Claude Code hook payload → events. Hook stdin has at least
 * {session_id, cwd, hook_event_name}; other fields are event-specific and optional.
 */
export function normalizeClaudeHook(hook: unknown): NormalizedEvent[] {
  if (!isObj(hook)) return [];
  const event = str(hook.hook_event_name);
  const sid = str(hook.session_id);
  if (!event || !sid) return [];
  const base: NormalizedEvent = { type: "provider.hook", payload: { event, provider_session_id: sid, cwd: str(hook.cwd) ?? null } };
  switch (event) {
    case "SessionStart":
      return [base, { type: "session.started", payload: { source: str(hook.source) ?? null } }];
    case "UserPromptSubmit":
      return [base, { type: "message.user", payload: { text: str(hook.prompt) ?? "" } }];
    case "PostToolUse": {
      const tool = str(hook.tool_name) ?? "tool";
      const resp = hook.tool_response;
      const ok = !(isObj(resp) && (resp.success === false || resp.is_error === true || typeof resp.error === "string"));
      return [base, { type: "tool.result", payload: { tool, ok, summary: summarizeToolInput(tool, hook.tool_input) } }];
    }
    case "Notification": {
      const kind = str(hook.notification_type) ?? null;
      const message = str(hook.message) ?? "";
      // idle_prompt / permission_prompt = Claude is waiting for the human.
      const waiting = kind === "idle_prompt" || kind === "permission_prompt" || /waiting for your input|needs your permission/i.test(message);
      return waiting ? [base, { type: "input.required", payload: { prompt: message || "Claude Code is waiting for you", notification_type: kind } }] : [base];
    }
    case "Stop":
      return [base, { type: "turn.completed", payload: { usage: null } }];
    case "SessionEnd":
      return [base, { type: "provider.session_end", payload: { reason: str(hook.reason) ?? null } }];
    default:
      return [base];
  }
}

export interface ClaudeProviderOptions {
  /** Absolute path of the `claude` binary (launchd's PATH is minimal). */
  binary: string;
  /** Extra args (e.g. ["--model","haiku"]); never permission-bypass flags. */
  extraArgs?: string[];
}

const FORBIDDEN = /^--(dangerously-skip-permissions|permission-mode)$|bypassPermissions/;

export function claudeCodeProvider(o: ClaudeProviderOptions): AgentProvider {
  const extra = (o.extraArgs ?? []).filter((a) => !FORBIDDEN.test(a));
  return {
    id: "claude-code",
    binary: o.binary,
    displayName: "Claude Code",
    capabilities: { resume: true, pause: "signal", observe: true, cost: true },
    buildTurnCommand(req): TurnCommand {
      const args = ["-p", "--output-format", "stream-json", "--verbose", "--settings", req.hookSettingsPath];
      if (req.providerSessionId) args.push("--resume", req.providerSessionId);
      args.push(...extra);
      return { cmd: o.binary, args, stdin: req.instruction };
    },
    parseOutputLine: parseStreamJsonLine,
    isQuestion,
    normalizeHook: normalizeClaudeHook,
    detectCostKind: (env) => detectClaudeCostKind(o.binary, env),
  };
}

/**
 * `claude auth status` (JSON): authMethod "claude.ai" → subscription (total_cost_usd is an
 * API-price estimate, not money charged); API key / console login → api. Anything else,
 * or a failure → unknown.
 */
export function detectClaudeCostKind(binary: string, env: NodeJS.ProcessEnv): Promise<CostKind> {
  return new Promise((resolve) => {
    execFile(binary, ["auth", "status"], { env, timeout: 10_000, encoding: "utf8", maxBuffer: 1024 * 1024 }, (_err, stdout) => {
      resolve(costKindFromAuthStatus(String(stdout ?? ""), env));
    });
  });
}

export function costKindFromAuthStatus(stdout: string, env: NodeJS.ProcessEnv = {}): CostKind {
  const m = stdout.match(/\{[\s\S]*\}/);
  let j: Record<string, unknown> | null = null;
  try {
    j = m ? (JSON.parse(m[0]) as Record<string, unknown>) : null;
  } catch {
    j = null;
  }
  const method = typeof j?.authMethod === "string" ? j.authMethod.toLowerCase() : "";
  if (method === "claude.ai" || method === "claudeai" || method === "subscription") return "subscription_estimate";
  if (/api[_-]?key|console|anthropic|bedrock|vertex/.test(method) || (typeof j?.apiKeySource === "string" && j.apiKeySource)) return "api";
  if (!j && env.ANTHROPIC_API_KEY) return "api";
  return "unknown";
}
