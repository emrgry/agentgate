import { existsSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import { describeError } from "../authorize.ts";
import { AgentGateClient } from "../client/index.ts";
import { EXIT } from "../exit-codes.ts";
import { c, log, out } from "../output.ts";
import { requireLogin } from "../runtime.ts";

/**
 * Control Center CLI (local convenience). Uses this machine's agent token over loopback:
 * the local owner may start/instruct/stop/kill LOCAL sessions without a phone signature
 * (they could run the agent directly anyway). Remote control always needs a phone-signed
 * command.
 */

async function client() {
  const config = await requireLogin();
  return new AgentGateClient({ server: config.server, accessToken: config.access_token, debug: log.debug });
}

const statusColor = (s: string) =>
  ["running", "starting", "queued"].includes(s) ? c.cyan(s) : s === "waiting_input" ? c.yellow(s) : ["failed", "killed", "lost"].includes(s) ? c.red(s) : s === "completed" ? c.green(s) : s;

function fmtEvent(e: { seq: number; type: string; payload: any; created_at: string }): string {
  const p = e.payload ?? {};
  const t = e.created_at.slice(11, 19);
  const body =
    e.type === "message.assistant" || e.type === "message.user"
      ? String(p.text ?? "").replace(/\s+/g, " ").slice(0, 200)
      : e.type === "tool.call"
        ? `${p.tool}: ${p.summary}`
        : e.type === "tool.result"
          ? `${p.ok === false ? "✖" : "✔"} ${String(p.summary ?? "").replace(/\s+/g, " ").slice(0, 120)}`
          : e.type === "status.changed"
            ? `${p.from} → ${p.to}${p.reason ? ` (${p.reason})` : ""}`
            : e.type === "input.required"
              ? `❓ ${String(p.prompt ?? "").slice(0, 200)}`
              : e.type === "turn.completed"
                ? `usage ${JSON.stringify(p.usage ?? {})}`
                : JSON.stringify(p).slice(0, 200);
  return `${c.dim(`${t} #${e.seq}`)} ${c.bold(e.type)} ${body}`;
}

export async function sessionCommand(action: string | undefined, args: string[], o: { provider: string; cwd?: string; follow: boolean }): Promise<number> {
  try {
    const api = await client();
    switch (action) {
      case "start": {
        const prompt = args.join(" ").trim();
        if (!prompt) {
          log.fail('usage: agentgate session start [--provider claude-code] [--cwd DIR] "<prompt>"');
          return EXIT.USAGE;
        }
        const cwd = realpathSync(resolve(o.cwd ?? process.cwd()));
        const r = await api.startAgentSession({ provider: o.provider, cwd, prompt });
        out(r.session.id);
        log.ok(`started ${c.bold(r.session.id)} in ${cwd} — follow with: agentgate session tail ${r.session.id}`);
        return EXIT.OK;
      }
      case "list": {
        const r = await api.agentSessions("all");
        if (!r.items.length) out(c.dim("no sessions"));
        for (const s of r.items) {
          const cost = s.usage?.cost_usd != null ? `$${Number(s.usage.cost_usd).toFixed(3)}` : "";
          out(`${s.id}  ${statusColor(s.status).padEnd(22)} ${s.mode.padEnd(8)} ${c.dim(cost.padEnd(8))} ${s.title}`);
        }
        return EXIT.OK;
      }
      case "tail": {
        const id = args[0];
        if (!id) {
          log.fail("usage: agentgate session tail <id>");
          return EXIT.USAGE;
        }
        let after = -1;
        let quietSince = Date.now();
        for (;;) {
          const r = await api.sessionEvents(id, after);
          for (const e of r.items) {
            out(fmtEvent(e));
            after = e.seq;
            quietSince = Date.now();
          }
          if (r.items.length === 200) continue;
          const s = await api.agentSession(id);
          const ended = ["completed", "failed", "stopped", "killed"].includes(s.status) || (s.status === "waiting_input" && !o.follow);
          if (ended && Date.now() - quietSince > 500) {
            out(c.dim(`— ${s.status}${s.pending_interaction_id ? " (question pending: agentgate session send <id> \"…\")" : ""}`));
            return EXIT.OK;
          }
          await new Promise((r2) => setTimeout(r2, 700));
        }
      }
      case "send": {
        const [id, ...rest] = args;
        const text = rest.join(" ").trim();
        if (!id || !text) {
          log.fail('usage: agentgate session send <id> "<text>"');
          return EXIT.USAGE;
        }
        const s = await api.agentSession(id);
        const body = s.pending_interaction_id ? { command: "answer", interaction_id: s.pending_interaction_id, text } : { command: "instruct", text };
        const r = await api.sessionCommand(id, body);
        if (r.status === "rejected") {
          log.fail(r.reason ?? "rejected");
          return EXIT.ERROR;
        }
        log.ok(`${body.command === "answer" ? "answered" : "instruction"} ${r.status}`);
        return EXIT.OK;
      }
      case "stop":
      case "kill":
      case "pause":
      case "resume": {
        const id = args[0];
        if (!id) {
          log.fail(`usage: agentgate session ${action} <id>`);
          return EXIT.USAGE;
        }
        const r = await api.sessionCommand(id, { command: action });
        if (r.status === "rejected") {
          log.fail(r.reason ?? "rejected");
          return EXIT.ERROR;
        }
        log.ok(`${action}: ${r.session.status}`);
        return EXIT.OK;
      }
      default:
        log.fail('usage: agentgate session <start "<prompt>"|list|tail <id>|send <id> "<text>"|stop <id>|kill <id>|pause <id>|resume <id>>');
        return EXIT.USAGE;
    }
  } catch (err) {
    log.fail(describeError(err));
    return EXIT.ERROR;
  }
}

export async function workspaceCommand(action: string | undefined, args: string[], o: { label?: string }): Promise<number> {
  try {
    const api = await client();
    switch (action) {
      case "add": {
        const dir = resolve(args[0] ?? process.cwd());
        if (!existsSync(dir)) {
          log.fail(`not a directory: ${dir}`);
          return EXIT.USAGE;
        }
        const w = await api.addWorkspace(realpathSync(dir), o.label);
        log.ok(`workspace ${c.bold(w.label)} ${c.dim(w.path)} — the phone may start sessions here`);
        return EXIT.OK;
      }
      case "list": {
        const r = await api.workspaces();
        if (!r.items.length) out(c.dim("no workspaces (agentgate workspace add <dir>)"));
        for (const w of r.items) out(`${w.id}  ${w.label.padEnd(20)} ${w.path}${w.ungated_providers?.length ? c.red(`  UNGATED: ${w.ungated_providers.join(", ")}`) : ""}`);
        return EXIT.OK;
      }
      case "remove": {
        const target = args[0] ? resolve(args[0]) : process.cwd();
        const r = await api.workspaces();
        const w = r.items.find((x) => x.id === args[0] || x.path === target || (existsSync(target) && x.path === realpathSync(target)));
        if (!w) {
          log.fail(`no workspace for ${args[0] ?? target}`);
          return EXIT.ERROR;
        }
        await api.removeWorkspace(w.id);
        log.ok(`removed workspace ${w.path}`);
        return EXIT.OK;
      }
      case "allow-ungated":
      case "disallow-ungated": {
        const [dirArg, provider] = args;
        if (!dirArg || !provider) {
          log.fail(`usage: agentgate workspace ${action} <dir> <provider>`);
          return EXIT.USAGE;
        }
        const target = resolve(dirArg);
        const r = await api.workspaces();
        const w = r.items.find((x) => x.id === dirArg || x.path === target || (existsSync(target) && x.path === realpathSync(target)));
        if (!w) {
          log.fail(`no workspace for ${dirArg} (agentgate workspace add ${dirArg} first)`);
          return EXIT.ERROR;
        }
        const allow = action === "allow-ungated";
        await api.allowUngated(w.id, provider, allow);
        if (allow) log.warn(`${provider} may now run UNGATED in ${w.path}: AgentGate will NOT check its tool calls there (the phone shows a red UNGATED badge)`);
        else log.ok(`${provider} is no longer allowed to run ungated in ${w.path}`);
        return EXIT.OK;
      }
      default:
        log.fail("usage: agentgate workspace <add [dir] [--label L]|list|remove <dir|id>|allow-ungated <dir> <provider>|disallow-ungated <dir> <provider>>");
        return EXIT.USAGE;
    }
  } catch (err) {
    log.fail(describeError(err));
    return EXIT.ERROR;
  }
}

/** `agentgate task add <session> "<text>" [--title T]` / `agentgate task list <session>`. */
export async function taskCommand(action: string | undefined, args: string[], o: { title?: string }): Promise<number> {
  try {
    const api = await client();
    const [id, ...rest] = args;
    if (!id) {
      log.fail('usage: agentgate task add <session> "<text>" [--title T] | task list <session>');
      return EXIT.USAGE;
    }
    if (action === "add") {
      const text = rest.join(" ").trim();
      if (!text) {
        log.fail('usage: agentgate task add <session> "<text>"');
        return EXIT.USAGE;
      }
      const r = await api.sessionCommand(id, { command: "enqueue_task", text, ...(o.title ? { title: o.title } : {}) });
      if (r.status === "rejected") {
        log.fail(r.reason ?? "rejected");
        return EXIT.ERROR;
      }
      log.ok(r.status === "applied" ? "task started (session was idle)" : `task queued (${r.session.queued_tasks ?? "?"} waiting)`);
      return EXIT.OK;
    }
    if (action === "list") {
      const r = await api.sessionTasks(id);
      if (!r.items.length) out(c.dim("no tasks"));
      for (const t of r.items) {
        const cost = t.usage?.cost_usd != null ? `$${Number(t.usage.cost_usd).toFixed(3)}` : "";
        out(`${String(t.position).padStart(3)}  ${t.id}  ${statusColor(t.status).padEnd(20)} ${c.dim(cost.padEnd(8))} ${t.title}`);
      }
      return EXIT.OK;
    }
    log.fail('usage: agentgate task add <session> "<text>" | task list <session>');
    return EXIT.USAGE;
  } catch (err) {
    log.fail(describeError(err));
    return EXIT.ERROR;
  }
}

// ── Phase 4: limits + usage ──────────────────────────────────────────────────

export interface LimitFlags {
  session?: string;
  global?: boolean;
  maxCostTask?: string;
  maxCostSession?: string;
  maxSessionMinutes?: string;
  maxTaskMinutes?: string;
  maxRetries?: string;
  maxRssMb?: string;
  onExceed?: string;
}

/** Parses a limit flag: a number, or "none"/"off" to clear it. */
function limitValue(v: string | undefined, int: boolean): number | null | undefined {
  if (v === undefined) return undefined;
  if (/^(none|off|null)$/i.test(v)) return null;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0 || (int && !Number.isInteger(n))) throw new Error(`invalid limit value '${v}'`);
  return n;
}

/**
 * `agentgate limits set [--session ID | --global] --max-cost-task 2 --on-exceed ask …`
 * `agentgate limits show [--session ID]`
 */
export async function limitsCommand(action: string | undefined, f: LimitFlags): Promise<number> {
  try {
    const api = await client();
    if (action === "show") {
      if (f.session) {
        const m = await api.sessionMetrics(f.session);
        out(JSON.stringify({ limits: m.limits, exceeded: m.exceeded, notes: m.notes ?? [] }, null, 2));
      } else {
        const u = await api.usage("today");
        out(JSON.stringify({ global_limits: u.global_limits }, null, 2));
      }
      return EXIT.OK;
    }
    if (action !== "set" || (!f.session && !f.global) || (f.session && f.global)) {
      log.fail("usage: agentgate limits set (--session ID | --global) [--max-cost-task USD] [--max-cost-session USD] [--max-session-minutes N] [--max-task-minutes N] [--max-retries N] [--max-rss-mb N] [--on-exceed notify|ask|pause|stop] | limits show [--session ID]");
      return EXIT.USAGE;
    }
    if (f.onExceed && !["notify", "ask", "pause", "stop"].includes(f.onExceed)) {
      log.fail("--on-exceed must be notify, ask, pause or stop");
      return EXIT.USAGE;
    }
    const limits: Record<string, unknown> = {
      max_cost_usd_per_task: limitValue(f.maxCostTask, false),
      max_cost_usd_per_session: limitValue(f.maxCostSession, false),
      max_session_minutes: limitValue(f.maxSessionMinutes, true),
      max_task_minutes: limitValue(f.maxTaskMinutes, true),
      max_retries: limitValue(f.maxRetries, true),
      max_rss_mb: limitValue(f.maxRssMb, true),
      ...(f.onExceed ? { on_exceed: f.onExceed } : {}),
    };
    for (const k of Object.keys(limits)) if (limits[k] === undefined) delete limits[k];
    const target = f.global ? "global" : f.session!;
    const r = await api.sessionCommand(target, { command: "set_limits", limits });
    if (r.status === "rejected") {
      log.fail(r.reason ?? "rejected");
      return EXIT.ERROR;
    }
    log.ok(`limits set for ${f.global ? "all sessions (defaults)" : `session ${target}`}`);
    return EXIT.OK;
  } catch (err) {
    log.fail(describeError(err));
    return EXIT.ERROR;
  }
}

/** `agentgate usage [--range today|7d|30d]` */
export async function usageCommand(range: string): Promise<number> {
  try {
    if (!["today", "7d", "30d"].includes(range)) {
      log.fail("--range must be today, 7d or 30d");
      return EXIT.USAGE;
    }
    const u = await (await client()).usage(range);
    const money = (v: number | null) => (v === null ? c.dim("n/a") : `$${v.toFixed(2)}`);
    out(`usage (${u.range})  total ${money(u.total_cost_usd)}`);
    for (const p of u.by_provider) {
      out(`  ${p.provider.padEnd(14)} ${String(p.sessions).padStart(4)} sessions  ${money(p.cost_usd).padStart(9)}  in ${p.input_tokens ?? "-"} / out ${p.output_tokens ?? "-"} tokens  ${Math.round(p.duration_ms / 1000)}s`);
    }
    for (const d of u.by_day) out(`  ${d.day}  ${String(d.sessions).padStart(4)} sessions  ${money(d.cost_usd)}`);
    if (u.global_limits) out(`default limits: ${JSON.stringify(u.global_limits)}`);
    return EXIT.OK;
  } catch (err) {
    log.fail(describeError(err));
    return EXIT.ERROR;
  }
}
