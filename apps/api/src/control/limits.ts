import type { Limits, LimitAction } from "@agentgate/protocol";

/** Phase 4 limits: effective limits (session over global) and evaluation. Pure. */

export type LimitKey = Exclude<keyof Limits, "on_exceed">;
export const LIMIT_KEYS: LimitKey[] = ["max_cost_usd_per_task", "max_cost_usd_per_session", "max_session_minutes", "max_task_minutes", "max_retries", "max_rss_mb"];

/** Field-wise: a session value (including an explicit null = "no limit") wins over the global one. */
export function effectiveLimits(global: Limits | null, session: Limits | null): Limits | null {
  if (!global && !session) return null;
  const out: Record<string, unknown> = {};
  for (const k of LIMIT_KEYS) {
    if (session && session[k] !== undefined) out[k] = session[k];
    else if (global && global[k] !== undefined) out[k] = global[k];
  }
  out.on_exceed = (session?.on_exceed ?? global?.on_exceed ?? "ask") as LimitAction;
  return out as Limits;
}

export interface LimitInputs {
  taskCost: number | null;
  sessionCost: number | null;
  /** Only while a turn is running (idle sessions don't burn time). */
  sessionMinutes: number | null;
  taskMinutes: number | null;
  retries: number;
  rssMb: number | null;
}

export interface LimitHit {
  limit: LimitKey;
  value: number;
}

/** Limits exceeded by the inputs. Null inputs (e.g. cost unknown for Codex) never trip. */
export function checkLimits(l: Limits | null, i: LimitInputs): LimitHit[] {
  if (!l) return [];
  const hits: LimitHit[] = [];
  const over = (limit: LimitKey, value: number | null, max: number | null | undefined, strict = true) => {
    if (value === null || max === null || max === undefined) return;
    if (strict ? value > max : value >= max) hits.push({ limit, value: Math.round(value * 10_000) / 10_000 });
  };
  over("max_cost_usd_per_task", i.taskCost, l.max_cost_usd_per_task, false);
  over("max_cost_usd_per_session", i.sessionCost, l.max_cost_usd_per_session, false);
  over("max_session_minutes", i.sessionMinutes, l.max_session_minutes, false);
  over("max_task_minutes", i.taskMinutes, l.max_task_minutes, false);
  over("max_retries", i.retries, l.max_retries);
  over("max_rss_mb", i.rssMb, l.max_rss_mb);
  return hits;
}
