import { execFile, spawn, type ChildProcess } from "node:child_process";
import { accessSync, mkdirSync, readFileSync, realpathSync, constants as fsc, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { promisify } from "node:util";
import { eq } from "drizzle-orm";
import type { AgentProvider, CostKind, NormalizedEvent, TurnParser } from "@agentgate/adapters";
import {
  Limits,
  redactCommandSecrets,
  type AgentSession,
  type ChangeSet,
  type FileDiff,
  type ProviderInfo,
  type PullRequestInfo,
  type ResourceSample,
  type SessionMetrics,
  type SessionStatus,
  type SessionSummary,
  type SessionUsage,
  type TestRun,
  type UsageReport,
} from "@agentgate/protocol";
import type { AgentSessionRow } from "../db/schema.ts";
import type { ServiceDeps, SessionAlertKind } from "../domain/context.ts";
import { DomainError } from "../domain/errors.ts";
import { writeAudit } from "../domain/audit.ts";
import { matchReceipt, readReceipts, type GateReceipt, type ToolSighting } from "./tripwire.ts";
import { captureBase, changeSet, diffStat, fileDiff, snapshotTree, type GitBase } from "./review.ts";
import { isTestCommand, outputTail, parseTestOutput } from "./testruns.ts";
import { orderedTree, parsePs, processTree, realPs, summarize, type PsRow, type PsRunner } from "./resources.ts";
import { checkLimits, effectiveLimits, type LimitHit } from "./limits.ts";
import { gatedRun, parsePrUrl, prPreflight } from "./pr.ts";
import { controlSettings } from "../db/schema.ts";
import { gte } from "drizzle-orm";
import { and, sql } from "drizzle-orm";
import type { TaskRow } from "../db/schema.ts";
import {
  agentSessions,
  appendEvent,
  listTasks,
  tasks,
  toTask,
  cid,
  EMPTY_USAGE,
  workspaces,
  findByProviderSession,
  findManagedByProviderSession,
  sessionEvents,
  getSession,
  interactions,
  sessionsWithStatus,
  toAgentSession,
  updateSession,
} from "./store.ts";

const pexec = promisify(execFile);

/**
 * Control Center supervisor (docs/control-center.md §2A, §5). Provider-agnostic: it runs one
 * provider process per turn (own process group), streams stdout through the provider's
 * parser into session events, and owns the status machine:
 *
 *   start ──▶ starting ──spawn──▶ running ◀──resume── paused
 *                                  │  ▲ └──pause──▶ paused
 *              approval requested  ▼  │ approval resolved
 *                             awaiting_approval
 *   turn end (ok, question)  ─▶ waiting_input + input_required interaction
 *   turn end (ok, no question)─▶ waiting_input (idle; "task completed" notification)
 *   turn end (ok, queued work)─▶ running (next turn, --resume)
 *   turn end (error result)   ─▶ failed
 *   process died, no result   ─▶ failed + session.terminated
 *   stop  (live) ─▶ stopping ─exit─▶ stopped      stop (idle) ─▶ completed (user is done)
 *   kill  (live) ─SIGKILL group─▶ killed
 *   server restart while live ─▶ lost  (instruct ⇒ --resume turn)
 *   instruct/answer from waiting_input | lost | failed | completed ─▶ running (--resume)
 */

export type SessionAlert = SessionAlertKind;

export interface SupervisorOptions {
  providers: Record<string, AgentProvider>;
  /** Claude settings file with the AgentGate PreToolUse/PostToolUse hooks (managed turns). */
  hookSettingsPath: () => string;
  /** Environment for turn processes: the owner's PATH/HOME (launchd's PATH is minimal). */
  turnEnv: () => NodeJS.ProcessEnv;
  /** SIGINT → SIGTERM grace on stop, then SIGKILL after 2× (ms). */
  stopGraceMs?: number;
  /** Global cap on concurrently running turns (AGENTGATE_MAX_CONCURRENT_TURNS, default 4). */
  maxConcurrentTurns?: number;
  /** Tripwire: how long after a provider reports a tool start its hook receipt must exist (ms, default 2000). */
  tripwireGraceMs?: number;
  /** Phase 3/4 housekeeping tick: resource samples, stuck detection, time/RSS limits (ms, default 5000; 0 = manual `tick()`). */
  tickMs?: number;
  /** `ps` snapshot provider (tests inject a fake). */
  ps?: PsRunner;
  /** Auto-continue after background commands of an ended turn finish (default true). */
  autoContinueBackground?: boolean;
  /** "stuck" = running with no events for this long (ms, default 10 min). */
  stuckAfterMs?: number;
  /** open_pr: owner's policy file (merged with the default policy, stricter wins). */
  policyPath?: () => string | null;
  /** open_pr: approvals must carry a verified phone signature. */
  requireDeviceSignatures?: boolean;
  /** open_pr: how long to wait for the phone to approve the push (ms, default 5 min). */
  prApprovalWaitMs?: number;
}

const RING = 120;

interface Live {
  child: ChildProcess;
  pid: number;
  queue: string[];
  stopRequested: boolean;
  killRequested: boolean;
  lastAssistant: string | null;
  hint: { status: string | null; needs_action: string | null } | null;
  result: { ok: boolean; text: string | null; error: string | null; usage: Record<string, number | null> } | null;
  stderrTail: string;
  statusBeforePause: SessionStatus | null;
  approvals: Set<string>;
  timers: NodeJS.Timeout[];
  parser: TurnParser | null;
  /** Gating tripwire state (providers whose hook writes receipts). */
  gate: { file: string; receipts: GateReceipt[]; consumed: Set<number>; byItem: Map<string, number> } | null;
  tripwire: string | null;
  /** Test commands seen in tool.call, by tool_use_id ("" = no id). */
  pendingTests: Map<string, string>;
  /** Every process seen in this turn's tree (pid → start time), for the escaped-descendant kill. */
  seen: Map<number, string>;
  /** SIGSTOPped by an `ask` limit (answer "continue" → SIGCONT). */
  budgetPaused: boolean;
  startedAt: number;
  /** Last tree snapshot (throttle for tool-event snapshots). */
  snapAt: number;
  /** Output files the provider reported for background commands (e.g. Claude's task output). */
  bgOutputs: string[];
  /** Mid-turn cost estimate: per provider message id → USD (sum = this turn's estimate). */
  msgCost: Map<string, number>;
  costEstimate: number;
  costEvalAt: number;
  costEvalTimer: NodeJS.Timeout | null;
  stopReason?: string;
}

export class Supervisor {
  private readonly live = new Map<string, Live>();
  private readonly chains = new Map<string, Promise<unknown>>();
  private readonly approvalToSession = new Map<string, string>();
  /** Turns waiting for a free slot (global concurrency cap), FIFO. */
  private readonly waitingForSlot: Array<{ sessionId: string; instruction: string }> = [];
  private reserved = 0;
  /** Tasks completed in the current auto-advance chain (for "finished all tasks"). */
  private readonly chain = new Map<string, number>();
  /** Phase 4: recent resource samples per session (ring of 120). */
  private readonly samples = new Map<string, ResourceSample[]>();
  /** Limits already handled (or "continue"d) — key session:task:limit. */
  private readonly limitHandled = new Set<string>();
  /** Stuck episodes already notified: session → last_event_at (ms) at notification time. */
  private readonly stuckNotified = new Map<string, number>();
  /** Consecutive failures per session (repeated_failure). */
  private readonly failures = new Map<string, { count: number; errors: string[]; alerted: boolean }>();
  /** Billing kind per provider (detected at start, cached 10 min). */
  private readonly costKinds = new Map<string, { kind: CostKind; at: number }>();

  /** Cached cost kind; refreshes in the background when older than 10 minutes. */
  costKind(providerId: string): CostKind {
    const c = this.costKinds.get(providerId);
    if (!c || Date.now() - c.at > 600_000) void this.refreshCostKind(providerId);
    return c?.kind ?? "unknown";
  }

  private async refreshCostKind(providerId: string): Promise<CostKind> {
    const p = this.o.providers[providerId];
    let kind: CostKind = "unknown";
    try {
      kind = p?.detectCostKind ? await p.detectCostKind(this.o.turnEnv()) : "unknown";
    } catch {
      kind = "unknown";
    }
    this.costKinds.set(providerId, { kind, at: Date.now() });
    return kind;
  }

  /** Mid-turn cost limits: evaluated at most ~1/s while the estimate grows. */
  private scheduleCostCheck(sessionId: string, live: Live) {
    if (live.costEvalTimer) return;
    const wait = Math.max(0, 1_000 - (Date.now() - live.costEvalAt));
    const run = () => {
      live.costEvalTimer = null;
      live.costEvalAt = Date.now();
      void this.bg(sessionId, async () => {
        if (this.live.get(sessionId) !== live) return;
        const row = (await this.deps.db.select().from(agentSessions).where(eq(agentSessions.id, sessionId)))[0];
        if (row) await this.evaluateLimits(row, live, "mid_turn");
      });
    };
    if (wait === 0) run();
    else {
      live.costEvalTimer = setTimeout(run, wait);
      live.timers.push(live.costEvalTimer);
    }
  }

  /** Auto-continue turns since the last user instruction (cap 3). */
  private readonly autoCount = new Map<string, number>();
  /** Continuation waiting for the session to become idle. */
  private readonly pendingContinuation = new Map<string, string>();
  /** Managed turns whose provider session id is not known yet (observe attribution window). */
  private readonly pendingTurns = new Map<string, { cwd: string; userId: string; at: number }>();
  private ticker: NodeJS.Timeout | null = null;
  private closed = false;
  private ticking = false;

  constructor(
    private readonly deps: ServiceDeps,
    private readonly o: SupervisorOptions,
  ) {
    const every = o.tickMs ?? 5_000;
    if (every > 0) {
      this.ticker = setInterval(() => void this.tick().catch(() => {}), every);
      this.ticker.unref();
    }
    // Billing kind per provider (e.g. Claude subscription vs API key), detected at start.
    for (const id of Object.keys(o.providers)) if (o.providers[id]?.detectCostKind) void this.refreshCostKind(id);
  }

  // ── plumbing ────────────────────────────────────────────────────────────────

  /** Serializes all DB work per session so events keep their order. */
  private serial<T>(sessionId: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.chains.get(sessionId) ?? Promise.resolve();
    // After shutdown the database may already be closed: late process exits are not recorded
    // (the next boot marks those sessions lost).
    const run = () => (this.closed ? Promise.resolve(undefined as T) : fn());
    const next = prev.then(run, run);
    this.chains.set(
      sessionId,
      next.catch((err: unknown) => this.deps.logger.error({ err: String(err), session_id: sessionId }, "supervisor step failed")),
    );
    return next;
  }

  /** Fire-and-forget serial step: failures are logged by the chain, never unhandled. */
  private bg(sessionId: string, fn: () => Promise<unknown>): Promise<void> {
    return this.serial(sessionId, fn).then(
      () => {},
      () => {},
    );
  }

  /** Wait until all queued work for a session has been applied (tests, shutdown). */
  async settle(sessionId?: string): Promise<void> {
    for (let i = 0; i < 50; i++) {
      const chains = sessionId ? [this.chains.get(sessionId)] : [...this.chains.values()];
      await Promise.all(chains.map((c) => c?.catch(() => {})));
      const again = sessionId ? [this.chains.get(sessionId)] : [...this.chains.values()];
      if (again.every((c, j) => c === chains[j])) return;
    }
  }

  private async emit(row: AgentSessionRow, type: string, payload: Record<string, unknown>) {
    const ev = await appendEvent(this.deps.db, row.id, type, payload, this.deps.clock.now());
    this.deps.notifier.sessionEvent(row.user_id, ev);
    return ev;
  }

  private publish(row: AgentSessionRow) {
    this.deps.notifier.sessionUpdated(row.user_id, toAgentSession(row));
  }

  private async setStatus(row: AgentSessionRow, to: SessionStatus, reason?: string, patch: Partial<AgentSessionRow> = {}): Promise<AgentSessionRow> {
    const from = row.status;
    const terminal = ["completed", "failed", "stopped", "killed", "lost"].includes(to);
    const next = await updateSession(this.deps.db, row.id, {
      ...patch,
      status: to,
      last_event_at: this.deps.clock.now(),
      ...(terminal && to !== "lost" ? { ended_at: this.deps.clock.now() } : {}),
      ...(terminal ? { pid: null } : {}),
    });
    if (from !== to) await this.emit(next, "status.changed", { from, to, ...(reason ? { reason } : {}) });
    this.publish(next);
    return next;
  }

  private provider(row: AgentSessionRow): AgentProvider {
    const p = this.o.providers[row.provider];
    if (!p) throw new DomainError(400, "unknown_provider", `provider '${row.provider}' is not available on this server`);
    return p;
  }

  private alert(row: AgentSessionRow, kind: SessionAlert) {
    this.deps.notifier.sessionAlert(row.user_id, toAgentSession(row), kind, this.o.providers[row.provider]?.displayName ?? row.provider);
  }

  /** GET /v1/providers: availability = the provider's binary resolves on the owner's PATH. */
  providers(): ProviderInfo[] {
    const path = String(this.o.turnEnv().PATH ?? "");
    const ids = Object.keys(this.o.providers);
    if (!ids.includes("claude-code")) ids.unshift("claude-code");
    return ids.map((id) => {
      const p = this.o.providers[id];
      if (!p) {
        return { id, display_name: "Claude Code", available: false, reason: "claude-code provider not configured on this server", capabilities: { resume: true, pause: true, cost: true, observe: true }, gated: true };
      }
      const found = p.binary ? resolveOnPath(p.binary, path) : null;
      const bin = p.binary ? basename(p.binary) : id;
      return {
        id,
        display_name: p.displayName,
        available: p.binary ? found !== null : true,
        reason: p.binary && !found ? `${bin} not found on PATH` : null,
        capabilities: { resume: p.capabilities.resume, pause: p.capabilities.pause === "signal", cost: p.capabilities.cost, observe: p.capabilities.observe },
        gated: p.gated !== false,
      };
    });
  }

  isLive(sessionId: string) {
    return this.live.has(sessionId);
  }

  // ── lifecycle ───────────────────────────────────────────────────────────────

  /** Boot: sessions whose turn process belonged to a previous server process are lost. */
  async recoverOnBoot(): Promise<number> {
    const rows = await sessionsWithStatus(this.deps.db, ["starting", "running", "awaiting_approval", "paused", "stopping"]);
    // waiting_input with a turn process still attached = held (SIGSTOP) by a budget question.
    // Older rows may carry a stale pid from a finished turn: only budget-held ones count.
    for (const r of await sessionsWithStatus(this.deps.db, ["waiting_input"])) {
      if (r.pid === null) continue;
      const [it] = r.pending_interaction_id ? await this.deps.db.select().from(interactions).where(eq(interactions.id, r.pending_interaction_id)) : [];
      if (it?.kind === "budget" && it.status === "pending") rows.push(r);
      else await updateSession(this.deps.db, r.id, { pid: null });
    }
    for (const r of rows) {
      // Its stdout is gone with the old server: stop the orphan so it can't keep acting unseen.
      if (r.pid) {
        try {
          process.kill(-r.pid, "SIGCONT");
          process.kill(-r.pid, "SIGTERM");
        } catch {
          /* already gone */
        }
      }
      await this.serial(r.id, async () => {
        // The running task failed; the queue stays paused until the user resumes it.
        await this.finishCurrentTask(r, "failed", { error: "server restarted" });
        const row = await this.setStatus(r, "lost", "server restarted while the session was active");
        await this.emit(row, "session.terminated", { reason: "server_restart", resumable: Boolean(row.provider_session_id) });
      });
    }
    // Clean up observed duplicates created by managed turns' own observe hooks (older servers).
    const managed = await this.deps.db.select().from(agentSessions).where(eq(agentSessions.mode, "managed"));
    for (const m of managed) if (m.provider_session_id) await this.removeObservedDuplicates(m.user_id, m.provider, m.provider_session_id);
    return rows.length;
  }

  async start(userId: string, req: { provider: string; cwd: string; prompt: string; title?: string; byDevice: string | null }): Promise<AgentSessionRow> {
    const info = this.providers().find((p) => p.id === req.provider);
    if (!this.o.providers[req.provider] || !info) throw new DomainError(400, "unknown_provider", `provider '${req.provider}' is not configured on this server`);
    if (!info.available) throw new DomainError(400, "provider_unavailable", info.reason ?? `provider '${req.provider}' is not available`);
    const gated = info.gated !== false;
    if (!gated) {
      // Ungated providers (no AgentGate hook) need an explicit opt-in for this exact workspace.
      const [w] = await this.deps.db.select().from(workspaces).where(and(eq(workspaces.user_id, userId), eq(workspaces.path, req.cwd)));
      const allowed = ((w?.ungated_providers as string[] | null) ?? []).includes(req.provider);
      if (!allowed) {
        throw new DomainError(
          403,
          "ungated_provider_not_allowed",
          `${info.display_name}'s tool calls can't be checked by AgentGate; allow it for this workspace first: agentgate workspace allow-ungated ${req.cwd} ${req.provider}`,
        );
      }
    }
    const now = this.deps.clock.now();
    const git = await gitInfo(req.cwd);
    const base = await captureBase(req.cwd, now).catch(() => null);
    const [row] = await this.deps.db
      .insert(agentSessions)
      .values({
        id: cid("ags"),
        user_id: userId,
        provider: req.provider,
        provider_session_id: null,
        mode: "managed",
        title: (req.title?.trim() || firstLine(req.prompt)).slice(0, 200),
        cwd: req.cwd,
        repo: git.repo,
        branch: git.branch,
        status: "starting",
        started_at: now,
        last_event_at: now,
        usage_json: { ...EMPTY_USAGE, cost_kind: this.costKind(req.provider) },
        gated,
        base_json: base,
      })
      .returning();
    await this.serial(row!.id, async () => {
      await this.emit(row!, "session.started", { provider: req.provider, cwd: req.cwd, by_device: req.byDevice, gated });
      const t = await this.createTask(row!, req.prompt, req.title, "running");
      await this.emit(row!, "message.user", { text: req.prompt, task_id: t.id });
      this.publish(await this.refreshCounters(row!.id));
      await this.runTurn(row!.id, req.prompt);
    });
    return (await getSession(this.deps.db, userId, row!.id))!;
  }

  private activeTurns() {
    return this.live.size + this.reserved;
  }

  /**
   * Runs a turn now, or — when the global cap is reached — parks it in `starting`
   * (visible as such) until a slot frees up. Caller holds the session's serial slot.
   */
  private async runTurn(sessionId: string, instruction: string): Promise<void> {
    const cap = this.o.maxConcurrentTurns ?? 4;
    if (this.activeTurns() >= cap) {
      this.waitingForSlot.push({ sessionId, instruction });
      const row = (await this.deps.db.select().from(agentSessions).where(eq(agentSessions.id, sessionId)))[0]!;
      const reason = `waiting for a free slot (${cap} turns already running)`;
      const next = await updateSession(this.deps.db, row.id, { status: "starting", last_event_at: this.deps.clock.now() });
      // Always visible, even if the session was already `starting` (a brand-new session).
      await this.emit(next, "status.changed", { from: row.status, to: "starting", reason });
      this.publish(next);
      return;
    }
    await this.spawnTurn(sessionId, instruction);
  }

  /** Starts parked turns while slots are free. */
  private pump() {
    const cap = this.o.maxConcurrentTurns ?? 4;
    while (this.activeTurns() < cap && this.waitingForSlot.length) {
      const next = this.waitingForSlot.shift()!;
      this.reserved++;
      void this.bg(next.sessionId, async () => {
        try {
          await this.spawnTurn(next.sessionId, next.instruction);
        } finally {
          this.reserved--;
        }
      });
    }
  }

  private isParked(sessionId: string) {
    return this.waitingForSlot.some((w) => w.sessionId === sessionId);
  }

  private unpark(sessionId: string) {
    for (let k = this.waitingForSlot.length - 1; k >= 0; k--) if (this.waitingForSlot[k]!.sessionId === sessionId) this.waitingForSlot.splice(k, 1);
  }

  /** Spawns one provider turn. Caller must hold the session's serial slot. */
  private async spawnTurn(sessionId: string, instruction: string): Promise<void> {
    let row = (await this.deps.db.select().from(agentSessions).where(eq(agentSessions.id, sessionId)))[0]!;
    const provider = this.provider(row);
    const baseEnv = this.o.turnEnv();
    const refuse = async (error: string, reason: string) => {
      await this.finishCurrentTask(row, "failed", { error });
      row = await this.setStatus(row, "failed", reason, { summary_json: await this.summary(row, null, error) });
      await this.emit(row, "session.failed", { error });
      this.alert(row, "task_failed");
    };
    // Fail closed: version/feature checks (e.g. codex too old → hooks may not exist).
    let pf: { ok: boolean; reason?: string } = { ok: true };
    try {
      pf = provider.preflight ? provider.preflight(baseEnv) : { ok: true };
    } catch (err) {
      pf = { ok: false, reason: (err as Error).message };
    }
    if (!pf.ok) return refuse(pf.reason ?? "provider preflight failed", "provider check failed");
    let cmd;
    try {
      cmd = provider.buildTurnCommand({
        instruction,
        ...(row.provider_session_id ? { providerSessionId: row.provider_session_id } : {}),
        cwd: row.cwd,
        hookSettingsPath: this.o.hookSettingsPath(),
        sessionId: row.id,
      });
    } catch (err) {
      return refuse(`could not prepare the turn: ${(err as Error).message}`, "could not start the agent");
    }
    // A session started as gated must stay gated: providers gated via a receipt-writing hook
    // must supply the receipts file, or the turn doesn't run.
    let gate: Live["gate"] = null;
    if (cmd.gateReceipts) {
      try {
        mkdirSync(dirname(cmd.gateReceipts), { recursive: true, mode: 0o700 });
        writeFileSync(cmd.gateReceipts, "", { mode: 0o600 });
        gate = { file: cmd.gateReceipts, receipts: [], consumed: new Set(), byItem: new Map() };
      } catch (err) {
        return refuse(`gating receipts unavailable: ${(err as Error).message}`, "could not start the agent");
      }
    } else if (row.gated && provider.gated === true) {
      return refuse("gating is not configured for this provider (no hook receipts)", "could not start the agent");
    }
    let child: ChildProcess;
    try {
      child = spawn(cmd.cmd, cmd.args, {
        cwd: row.cwd,
        // Both markers are inherited by the provider's hook processes: CONTROL_SESSION ties
        // approvals to this session; MANAGED_SESSION makes installed observe hooks drop their
        // events for this (managed) turn instead of creating a duplicate observed session.
        env: { ...baseEnv, ...cmd.env, AGENTGATE_CONTROL_SESSION: row.id, AGENTGATE_MANAGED_SESSION: row.id },
        detached: true, // own process group → pause/stop/kill reach the whole tree
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (err) {
      await this.finishCurrentTask(row, "failed", { error: (err as Error).message });
      row = await this.setStatus(row, "failed", "could not start the agent");
      await this.emit(row, "session.failed", { error: (err as Error).message });
      this.alert(row, "task_failed");
      return;
    }
    const live: Live = {
      child,
      pid: child.pid ?? 0,
      queue: this.live.get(sessionId)?.queue ?? [],
      stopRequested: false,
      killRequested: false,
      lastAssistant: null,
      hint: null,
      result: null,
      stderrTail: "",
      statusBeforePause: null,
      approvals: new Set(),
      timers: [],
      parser: provider.createParser ? provider.createParser() : null,
      gate,
      tripwire: null,
      pendingTests: new Map(),
      seen: new Map(),
      budgetPaused: false,
      startedAt: this.deps.clock.now().getTime(),
      snapAt: 0,
      bgOutputs: [],
      msgCost: new Map(),
      costEstimate: 0,
      costEvalAt: 0,
      costEvalTimer: null,
    };
    this.live.set(sessionId, live);
    // Until the provider reports its session id, hook events from this cwd may belong to
    // this turn (SessionStart fires before system/init).
    if (!row.provider_session_id) this.pendingTurns.set(sessionId, { cwd: row.cwd, userId: row.user_id, at: Date.now() });
    child.stdin?.on("error", () => {});
    child.stdin?.end(cmd.stdin ?? "");
    child.stderr?.on("data", (d: Buffer) => {
      live.stderrTail = (live.stderrTail + d.toString("utf8")).slice(-2048);
    });
    const rl = createInterface({ input: child.stdout! });
    rl.on("line", (line) => {
      let evs: NormalizedEvent[] = [];
      try {
        evs = live.parser ? live.parser.line(line) : provider.parseOutputLine(line);
      } catch {
        evs = [];
      }
      if (evs.length) void this.bg(sessionId, () => this.onEvents(sessionId, live, evs));
    });
    let spawnError: Error | null = null;
    child.once("error", (err) => (spawnError = err));
    child.once("close", (code, signal) => {
      rl.close();
      let tail: NormalizedEvent[] = [];
      try {
        tail = live.parser ? live.parser.end(code) : [];
      } catch {
        tail = [];
      }
      if (tail.length) void this.bg(sessionId, () => this.onEvents(sessionId, live, tail));
      void this.bg(sessionId, () => this.onTurnEnd(sessionId, live, code, signal, spawnError)).finally(() => this.pump());
    });
    row = await this.setStatus(row, "running", undefined, { pid: live.pid || null, ended_at: null });
  }

  private async onEvents(sessionId: string, live: Live, evs: NormalizedEvent[]) {
    let row = (await this.deps.db.select().from(agentSessions).where(eq(agentSessions.id, sessionId)))[0]!;
    for (const ev of evs) {
      switch (ev.type) {
        case "provider.session": {
          const id = ev.payload.provider_session_id as string;
          this.pendingTurns.delete(sessionId);
          if (id && row.provider_session_id !== id) {
            row = await updateSession(this.deps.db, row.id, { provider_session_id: id });
            this.publish(row);
          }
          if (id) await this.removeObservedDuplicates(row.user_id, row.provider, id);
          break;
        }
        case "provider.turn_hint":
          live.hint = { status: (ev.payload.status as string) ?? null, needs_action: (ev.payload.needs_action as string) ?? null };
          break;
        case "provider.turn_result":
          live.result = ev.payload as unknown as Live["result"];
          break;
        case "provider.tool_started":
        case "provider.tool_completed": {
          if (!live.gate) break;
          const sighting: ToolSighting = { ...(ev.payload as unknown as ToolSighting), phase: ev.type === "provider.tool_started" ? "started" : "completed" };
          if (sighting.phase === "completed" && sighting.status === "declined") break;
          if (sighting.phase === "started") {
            // The hook runs BEFORE the tool: allow a short grace for the receipt to land.
            live.timers.push(setTimeout(() => void this.bg(sessionId, () => this.checkGate(sessionId, live, sighting)), this.o.tripwireGraceMs ?? 2_000));
          } else {
            await this.checkGate(sessionId, live, sighting);
          }
          break;
        }
        case "message.assistant":
          live.lastAssistant = String(ev.payload.text ?? "");
          await this.emit(row, ev.type, ev.payload);
          break;
        case "provider.usage_delta": {
          const est = Number(ev.payload.cost_usd_estimate);
          if (!Number.isFinite(est)) break;
          const key = String(ev.payload.message_id ?? `m${live.msgCost.size}`);
          live.msgCost.set(key, est); // same message repeated per content block → last wins
          live.costEstimate = [...live.msgCost.values()].reduce((a, b) => a + b, 0);
          this.scheduleCostCheck(sessionId, live);
          break;
        }
        case "provider.api_retry":
          row = await updateSession(this.deps.db, row.id, { retries: sql`${agentSessions.retries} + 1` as unknown as number });
          await this.evaluateLimits(row, live, "event");
          break;
        case "tool.call": {
          this.snapshotSoon(live);
          const command = String(ev.payload.summary ?? "");
          if (isShellTool(String(ev.payload.tool ?? "")) && isTestCommand(command)) live.pendingTests.set(String(ev.payload.tool_use_id ?? ""), command);
          await this.emit(row, ev.type, ev.payload);
          break;
        }
        case "tool.result": {
          this.snapshotSoon(live);
          const { output_tail, ...payload } = ev.payload as Record<string, unknown> & { output_tail?: unknown };
          const txt = `${String(payload.summary ?? "")}\n${typeof output_tail === "string" ? output_tail : ""}`;
          if (/running in background|background/i.test(txt)) {
            for (const m of txt.matchAll(/(\/(?:private\/)?tmp\/claude-[^\s'"`)]+)/g)) if (!live.bgOutputs.includes(m[1]!) && live.bgOutputs.length < 10) live.bgOutputs.push(m[1]!);
          }
          await this.emit(row, ev.type, payload);
          const key = String(payload.tool_use_id ?? "");
          const command = live.pendingTests.get(key) ?? (key ? undefined : [...live.pendingTests.values()].at(-1));
          if (command !== undefined) {
            live.pendingTests.delete(key);
            row = await this.recordTestRun(row, command, payload.ok !== false, typeof output_tail === "string" ? output_tail : String(payload.summary ?? ""));
          }
          break;
        }
        default:
          if (!ev.type.startsWith("provider.")) await this.emit(row, ev.type, ev.payload);
      }
    }
  }

  // ── Phase 3: test runs ─────────────────────────────────────────────────────

  private async recordTestRun(row: AgentSessionRow, command: string, exitOk: boolean, output: string): Promise<AgentSessionRow> {
    const counts = parseTestOutput(output);
    const run: TestRun = {
      command: command.slice(0, 1000),
      ok: exitOk && (counts.failed ?? 0) === 0,
      passed: counts.passed,
      failed: counts.failed,
      skipped: counts.skipped,
      output_tail: outputTail(output),
      finished_at: this.deps.clock.now().toISOString(),
    };
    const next = await updateSession(this.deps.db, row.id, { tests_json: run });
    if (row.current_task_id) await this.deps.db.update(tasks).set({ tests_json: run }).where(eq(tasks.id, row.current_task_id));
    const { output_tail: _tail, ...ev } = run;
    await this.emit(next, "test.run", { ...ev, task_id: row.current_task_id });
    return next;
  }

  private async onTurnEnd(sessionId: string, live: Live, code: number | null, signal: NodeJS.Signals | null, spawnError: Error | null) {
    live.timers.forEach(clearTimeout);
    this.pendingTurns.delete(sessionId);
    if (this.live.get(sessionId) === live) this.live.delete(sessionId);
    for (const a of live.approvals) this.approvalToSession.delete(a);
    let row = (await this.deps.db.select().from(agentSessions).where(eq(agentSessions.id, sessionId)))[0]!;
    row = await updateSession(this.deps.db, row.id, { pid: null });
    row = await this.settleLeftovers(row, live).catch(() => row);
    if (row.pending_interaction_id && live.budgetPaused) {
      // The turn ended while held by a budget question: the question is moot now.
      await this.cancelPending(row);
      row = (await this.deps.db.select().from(agentSessions).where(eq(agentSessions.id, sessionId)))[0]!;
    }
    const provider = this.provider(row);
    const r = live.result;

    if (r) {
      // The real total replaces the mid-turn estimate from here on.
      live.costEstimate = 0;
      const kind = this.costKind(row.provider);
      const usage = accumulate((row.usage_json as SessionUsage | null) ?? EMPTY_USAGE, r.usage, kind);
      row = await updateSession(this.deps.db, row.id, { usage_json: usage });
      await this.addTaskUsage(row, r.usage, kind);
      await this.emit(row, "turn.completed", { usage: r.usage, ok: r.ok, task_id: row.current_task_id });
    }
    if (live.tripwire) {
      const error = live.tripwire;
      await this.finishCurrentTask(row, "failed", { error, last: live.lastAssistant });
      row = await this.setStatus(row, "failed", error, { summary_json: await this.summary(row, live.lastAssistant, error) });
      await this.emit(row, "session.failed", { error, gating: "inactive" });
      this.alert(row, this.noteFailure(row, error) ? "repeated_failure" : "task_failed");
      return;
    }
    if (live.killRequested) {
      await this.finishCurrentTask(row, "cancelled", { error: "killed by the user", last: live.lastAssistant });
      row = await this.setStatus(row, "killed", "killed by the user"); // queued tasks stay queued
      return;
    }
    if (live.stopRequested) {
      await this.finishCurrentTask(row, "cancelled", { error: live.stopReason ?? "stopped by the user", last: live.lastAssistant ?? r?.text ?? null });
      row = await this.setStatus(row, "stopped", live.stopReason ?? "stopped by the user", { summary_json: await this.summary(row, live.lastAssistant ?? r?.text ?? null, null, "session") });
      return;
    }
    if (r && r.ok) {
      this.failures.delete(sessionId);
      const last = live.lastAssistant ?? r.text ?? "";
      const summary = await this.summary(row, last, null, "session");
      row = await updateSession(this.deps.db, row.id, { summary_json: summary });
      // Follow-up instructions for the SAME task (instruct while running) — explicit user input.
      const next = live.queue.shift();
      if (next !== undefined) {
        this.live.set(sessionId, { ...live, queue: live.queue }); // keep queue across the next spawn
        await this.emit(row, "message.user", { text: next, task_id: row.current_task_id });
        await this.runTurn(sessionId, next);
        return;
      }
      const asks = live.hint?.status === "blocked" || (provider.isQuestion?.(last) ?? false);
      if (asks) {
        const id = cid("int");
        const prompt = (last || live.hint?.needs_action || "The agent is waiting for your input").slice(0, 4096);
        await this.deps.db.insert(interactions).values({ id, session_id: row.id, kind: "input_required", prompt, status: "pending", created_at: this.deps.clock.now() });
        await this.setCurrentTaskStatus(row, "waiting");
        row = await this.setStatus(row, "waiting_input", "the agent asked a question", { pending_interaction_id: id });
        await this.emit(row, "input.required", { interaction_id: id, prompt, kind: "input_required", task_id: row.current_task_id });
        this.alert(row, "input_required");
        return;
      }
      // Task done → next queued task auto-advances.
      const done = await this.finishCurrentTask(row, "completed", { last });
      const count = (this.chain.get(sessionId) ?? 0) + (done ? 1 : 0);
      this.chain.set(sessionId, count);
      row = (await getSession(this.deps.db, row.user_id, sessionId))!;
      // Limits (cost is only known at turn end): an ask/pause/stop limit holds the queue here.
      if (await this.evaluateLimits(row, undefined, "turn_end")) {
        this.chain.delete(sessionId);
        return;
      }
      row = (await getSession(this.deps.db, row.user_id, sessionId))!;
      // Background commands finished while this turn ran: continue that work before the queue.
      if (await this.runPendingContinuation(row, true)) return;
      if (await this.startNextTask(row)) {
        this.alert(row, "task_completed");
        return;
      }
      this.chain.delete(sessionId);
      row = await this.setStatus(row, "waiting_input", "turn finished; ready for the next instruction", { pending_interaction_id: null });
      this.alert(row, count > 1 ? "all_tasks_completed" : "task_completed");
      return;
    }
    // Failure: the task fails and the queue PAUSES (no auto-advance after a failure).
    this.chain.delete(sessionId);
    if (r && !r.ok) {
      const error = r.error ?? "the turn failed";
      await this.finishCurrentTask(row, "failed", { error, last: live.lastAssistant });
      row = await this.setStatus(row, "failed", "turn failed", { summary_json: await this.summary(row, live.lastAssistant, error, "session") });
      await this.emit(row, "session.failed", { error });
      this.alert(row, this.noteFailure(row, error) ? "repeated_failure" : "task_failed");
      return;
    }
    // No result line: the process died (crash, signal, spawn failure).
    const why = spawnError ? `could not start: ${spawnError.message}` : signal ? `terminated by ${signal}` : `exited with code ${code}`;
    await this.finishCurrentTask(row, "failed", { error: why, last: live.lastAssistant });
    row = await this.setStatus(row, "failed", "agent process ended unexpectedly", { summary_json: await this.summary(row, live.lastAssistant, why, "session") });
    await this.emit(row, "session.terminated", { reason: why, exit_code: code, signal, stderr: live.stderrTail.slice(-1000) });
    this.alert(row, this.noteFailure(row, why) ? "repeated_failure" : "terminated");
  }

  // ── gating tripwire (docs/control-center.md, Phase 2 providers) ────────────────

  /**
   * Every tool the provider reports must have a matching `invoked` receipt from our hook
   * (written before the hook asks anyone). No receipt → the hook did not run → the turn's
   * tool calls are NOT gated: SIGKILL the whole process group and fail the task.
   * A tool that completed although its receipt says "deny" is treated the same way.
   */
  private async checkGate(sessionId: string, live: Live, t: ToolSighting): Promise<void> {
    const gate = live.gate;
    if (!gate || live.tripwire || this.live.get(sessionId) !== live) return;
    let idx = t.item_id ? (gate.byItem.get(t.item_id) ?? -1) : -1;
    if (idx < 0) {
      try {
        gate.receipts = readReceipts(gate.file);
      } catch {
        gate.receipts = [];
      }
      idx = matchReceipt(gate.receipts, gate.consumed, t);
      if (idx >= 0) {
        gate.consumed.add(idx);
        if (t.item_id) gate.byItem.set(t.item_id, idx);
      }
    }
    if (idx < 0) return this.trip(sessionId, live, "gating inactive: tool ran without AgentGate check", t);
    if (t.phase === "completed" && t.status === "completed") {
      const inv = gate.receipts[idx]!;
      const decision = gate.receipts.find((r, k) => k > idx && r.phase === "decision" && sameCall(r, inv));
      if (decision?.decision === "deny") return this.trip(sessionId, live, "gating bypassed: a tool ran although AgentGate blocked it", t);
    }
  }

  private async trip(sessionId: string, live: Live, reason: string, t: ToolSighting) {
    live.tripwire = reason;
    live.queue.length = 0;
    await this.killTree(live);
    const row = (await this.deps.db.select().from(agentSessions).where(eq(agentSessions.id, sessionId)))[0];
    if (!row) return;
    this.deps.logger.warn({ session_id: sessionId, provider: row.provider, kind: t.kind }, "gating tripwire: killed the turn");
    await writeAudit(this.deps.db, {
      userId: row.user_id,
      event: "execution.blocked",
      payload: { label: `${this.o.providers[row.provider]?.displayName ?? row.provider} session (gating tripwire)`, reason, session_id: sessionId, provider: row.provider, tool_kind: t.kind },
      at: this.deps.clock.now(),
    }).catch(() => {});
  }

  // ── tasks ───────────────────────────────────────────────────────────────────

  private taskChanged(userId: string, t: TaskRow) {
    this.deps.notifier.taskUpdated(userId, toTask(t));
  }

  /** Keeps agent_sessions.current_task_id / queued_tasks in sync. */
  private async refreshCounters(sessionId: string): Promise<AgentSessionRow> {
    const all = await listTasks(this.deps.db, sessionId);
    return updateSession(this.deps.db, sessionId, { queued_tasks: all.filter((t) => t.status === "queued").length });
  }

  private async createTask(row: AgentSessionRow, prompt: string, title: string | undefined, status: "queued" | "running", atFront = false): Promise<TaskRow> {
    const now = this.deps.clock.now();
    const all = await listTasks(this.deps.db, row.id);
    let position = all.length ? Math.max(...all.map((t) => t.position)) + 1 : 0;
    if (atFront) {
      // Runs before anything still queued: shift the queue back by one.
      const queued = all.filter((t) => t.status === "queued");
      if (queued.length) {
        position = Math.min(...queued.map((t) => t.position));
        await this.deps.db.update(tasks).set({ position: sql`${tasks.position} + 1` }).where(and(eq(tasks.session_id, row.id), eq(tasks.status, "queued")));
      }
    }
    const [t] = await this.deps.db
      .insert(tasks)
      .values({
        id: cid("tsk"),
        session_id: row.id,
        position,
        title: (title?.trim() || firstLine(prompt)).slice(0, 200),
        prompt: prompt.slice(0, 16_384),
        status,
        created_at: now,
        ...(status === "running" ? { started_at: now, base_json: await captureBase(row.cwd, now).catch(() => null) } : {}),
        usage_json: EMPTY_USAGE,
      })
      .returning();
    if (status === "running") await updateSession(this.deps.db, row.id, { current_task_id: t!.id });
    this.taskChanged(row.user_id, t!);
    return t!;
  }

  private async currentTask(row: AgentSessionRow): Promise<TaskRow | null> {
    if (!row.current_task_id) return null;
    const [t] = await this.deps.db.select().from(tasks).where(eq(tasks.id, row.current_task_id));
    return t ?? null;
  }

  private async setCurrentTaskStatus(row: AgentSessionRow, status: "running" | "waiting") {
    const t = await this.currentTask(row);
    if (!t || t.status === status) return;
    const [u] = await this.deps.db.update(tasks).set({ status, ended_at: null }).where(eq(tasks.id, t.id)).returning();
    this.taskChanged(row.user_id, u!);
  }

  private async addTaskUsage(row: AgentSessionRow, u: Record<string, number | null>, kind?: CostKind) {
    const t = await this.currentTask(row);
    if (!t) return;
    await this.deps.db
      .update(tasks)
      .set({ usage_json: accumulate((t.usage_json as SessionUsage | null) ?? EMPTY_USAGE, u, kind) })
      .where(eq(tasks.id, t.id));
  }

  /** Ends the current task (completed/failed/cancelled). Returns true if there was one. */
  private async finishCurrentTask(
    row: AgentSessionRow,
    status: "completed" | "failed" | "cancelled",
    o: { summary?: SessionSummary; error?: string; last?: string | null },
  ): Promise<boolean> {
    const t = await this.currentTask(row);
    if (!t || !["running", "waiting"].includes(t.status)) return false;
    const summary = o.summary ?? (await this.summary(row, o.last ?? null, o.error ?? null, "task"));
    // Freeze what this task changed (later tasks keep editing the same tree).
    const base = t.base_json as GitBase | null;
    const endTree = base?.top ? await snapshotTree(base.top).catch(() => null) : null;
    const [u] = await this.deps.db
      .update(tasks)
      .set({ status, ended_at: this.deps.clock.now(), summary_json: summary, ...(base ? { base_json: { ...base, end_tree: endTree } } : {}) })
      .where(eq(tasks.id, t.id))
      .returning();
    this.taskChanged(row.user_id, u!);
    await this.refreshCounters(row.id);
    return true;
  }

  /** Starts the first queued task as a --resume turn. Returns false if the queue is empty. */
  private async startNextTask(row: AgentSessionRow): Promise<boolean> {
    const next = (await listTasks(this.deps.db, row.id)).find((t) => t.status === "queued");
    if (!next) return false;
    this.autoCount.delete(row.id); // each task is a user instruction
    const now = this.deps.clock.now();
    const base = await captureBase(row.cwd, now).catch(() => null);
    const [t] = await this.deps.db.update(tasks).set({ status: "running", started_at: now, base_json: base }).where(eq(tasks.id, next.id)).returning();
    this.taskChanged(row.user_id, t!);
    row = await updateSession(this.deps.db, row.id, { current_task_id: t!.id, pending_interaction_id: null });
    this.publish(await this.refreshCounters(row.id));
    await this.emit(row, "message.user", { text: t!.prompt, task_id: t!.id });
    await this.runTurn(row.id, t!.prompt);
    return true;
  }

  /** Numbers relative to the task's base ("task") or the session's base ("session"); HEAD only as a fallback. */
  private async summary(row: AgentSessionRow, lastMessage: string | null, error: string | null, scope: "task" | "session" = "session"): Promise<SessionSummary> {
    let base = (row.base_json as GitBase | null) ?? null;
    if (scope === "task") {
      const t = await this.currentTask(row);
      if (t?.base_json) base = t.base_json as GitBase;
    }
    const git = base ? await diffStat(base, row.cwd) : await gitDiffStat(row.cwd);
    return {
      last_message: lastMessage ? lastMessage.slice(0, 4096) : null,
      files_changed: git?.files ?? null,
      additions: git?.additions ?? null,
      deletions: git?.deletions ?? null,
      changed_files: git?.changed ?? [],
      error: error ? error.slice(0, 2048) : null,
    };
  }

  // ── control commands ──────────────────────────────────────────────────────

  /** Applies a verified command. Returns queued|applied or throws DomainError(409) when not allowed now. */
  command(
    userId: string,
    sessionId: string,
    body: { command: string; text?: string; interaction_id?: string; task_id?: string; position?: number; title?: string; draft?: boolean; base?: string; limits?: unknown; create_branch?: string },
    byDevice: string | null,
  ): Promise<{ status: "queued" | "applied"; session: AgentSession }> {
    return this.serial(sessionId, async () => {
      let row = await getSession(this.deps.db, userId, sessionId);
      if (!row) throw new DomainError(404, "not_found", "session not found");
      const can = toAgentSession(row).can;
      const live = this.live.get(sessionId);
      const deny = (why: string, code = "not_allowed_in_state") => new DomainError(409, code, `${body.command} is not possible while the session is ${row!.status}${why ? ` (${why})` : ""}`);
      let status: "queued" | "applied" = "applied";

      switch (body.command) {
        case "answer": {
          const [it] = await this.deps.db.select().from(interactions).where(eq(interactions.id, body.interaction_id ?? ""));
          if (!it || it.session_id !== sessionId || it.status !== "pending") throw new DomainError(409, "interaction_not_pending", "that question is no longer pending");
          await this.deps.db
            .update(interactions)
            .set({ status: "answered", answer: body.text ?? "", answered_by_device: byDevice, resolved_at: this.deps.clock.now() })
            .where(eq(interactions.id, it.id));
          row = await updateSession(this.deps.db, row.id, { pending_interaction_id: null });
          if (it.kind === "budget") {
            // "continue" → go on (this limit stays suppressed for the task); anything else → stop.
            await this.emit(row, "control.applied", { command: "answer", by_device: byDevice, interaction_id: it.id, kind: "budget" });
            if (/^\s*(continue|yes|ok|go on|resume)\b/i.test(body.text ?? "")) {
              if (live?.budgetPaused) {
                live.budgetPaused = false;
                await this.signalTurn(live, "SIGCONT");
                row = await this.setStatus(row, "running", "continued after a limit");
              } else if (!live && !(await this.startNextTask(row))) {
                row = await this.setStatus(row, "waiting_input", "continued after a limit; ready for the next instruction");
              }
            } else {
              row = await this.stopSession(row, live, "stopped at a limit");
            }
            break;
          }
          status = await this.instruct(row, body.text ?? "", live, byDevice, "answer"); // continues the same task
          break;
        }
        case "enqueue_task": {
          const t = await this.createTask(row, body.text ?? "", body.title, "queued");
          row = await this.refreshCounters(row.id);
          await this.emit(row, "control.applied", { command: "enqueue_task", by_device: byDevice, task_id: t.id });
          status = "queued";
          // Idle (and not parked for a slot) → start right away; failed/stopped/killed resume the queue.
          const cur = await this.currentTask(row);
          const idle =
            !live &&
            !this.isParked(sessionId) &&
            row.mode === "managed" &&
            ((row.status === "waiting_input" && !row.pending_interaction_id) || ["completed", "lost", "failed", "stopped", "killed"].includes(row.status)) &&
            !(cur && cur.status === "waiting");
          if (idle && row.provider_session_id) {
            await this.cancelPending(row);
            if (await this.startNextTask(row)) status = "applied";
          } else {
            this.publish(row);
          }
          break;
        }
        case "cancel_task": {
          const [t] = await this.deps.db.select().from(tasks).where(eq(tasks.id, body.task_id ?? ""));
          if (!t || t.session_id !== sessionId) throw new DomainError(404, "not_found", "task not found");
          if (t.status !== "queued") throw new DomainError(409, "task_not_queued", `only queued tasks can be cancelled (this one is ${t.status}${t.status === "running" ? "; use stop" : ""})`);
          const [u] = await this.deps.db.update(tasks).set({ status: "cancelled", ended_at: this.deps.clock.now() }).where(eq(tasks.id, t.id)).returning();
          this.taskChanged(userId, u!);
          row = await this.refreshCounters(row.id);
          this.publish(row);
          await this.emit(row, "control.applied", { command: "cancel_task", by_device: byDevice, task_id: t.id });
          break;
        }
        case "move_task": {
          const queued = (await listTasks(this.deps.db, sessionId)).filter((t) => t.status === "queued");
          const idx = queued.findIndex((t) => t.id === body.task_id);
          if (idx < 0) throw new DomainError(409, "task_not_queued", "only queued tasks can be moved");
          const slots = queued.map((t) => t.position); // reuse the queued positions, in order
          const [moved] = queued.splice(idx, 1);
          queued.splice(Math.min(body.position ?? 0, queued.length), 0, moved!);
          for (let k = 0; k < queued.length; k++) {
            if (queued[k]!.position !== slots[k]) {
              const [u] = await this.deps.db.update(tasks).set({ position: slots[k]! }).where(eq(tasks.id, queued[k]!.id)).returning();
              this.taskChanged(userId, u!);
            }
          }
          await this.emit(row, "control.applied", { command: "move_task", by_device: byDevice, task_id: body.task_id, position: body.position });
          break;
        }
        case "request_changes": {
          // Review feedback → the next instruction (delivered to the running turn, or a new turn).
          const text = `Review feedback: ${body.text ?? ""}`;
          if (can.instruct && !this.isParked(sessionId)) {
            status = await this.instruct(row, text, live, byDevice, "request_changes");
          } else {
            const t = await this.createTask(row, text, "Review feedback", "queued");
            row = await this.refreshCounters(row.id);
            this.publish(row);
            await this.emit(row, "control.applied", { command: "request_changes", by_device: byDevice, task_id: t.id, queued: true });
            status = "queued";
          }
          break;
        }
        case "approve_next": {
          const all = await listTasks(this.deps.db, sessionId);
          const target = body.task_id ? all.find((t) => t.id === body.task_id) : [...all].reverse().find((t) => ["completed", "failed", "waiting"].includes(t.status));
          if (body.task_id && !target) throw new DomainError(404, "not_found", "task not found");
          if (target && !target.reviewed_at) {
            const [u] = await this.deps.db.update(tasks).set({ reviewed_at: this.deps.clock.now() }).where(eq(tasks.id, target.id)).returning();
            this.taskChanged(userId, u!);
          }
          await this.emit(row, "control.applied", { command: "approve_next", by_device: byDevice, task_id: target?.id ?? null });
          // Continue the queue if it is held (idle, failed or lost) and something is queued.
          const idle =
            !live &&
            !this.isParked(sessionId) &&
            ((row.status === "waiting_input" && !row.pending_interaction_id) || ["failed", "lost", "completed", "stopped"].includes(row.status));
          if (idle && row.provider_session_id && (row.queued_tasks ?? 0) > 0) await this.startNextTask(row);
          break;
        }
        case "open_pr": {
          if (live || this.isParked(sessionId)) throw deny("wait until the agent's turn finishes", "turn_running");
          const pr = row.pr_json as PullRequestInfo | null;
          if (pr && ["open", "draft"].includes(pr.state)) throw new DomainError(409, "pr_exists", `open_pr: a pull request already exists (${pr.url})`);
          const env = this.o.turnEnv();
          // Refusals → 409 with a reason_code; with create_branch on the default branch the new
          // branch is created (git switch -c) only after every check passed.
          const pre = await prPreflight(row.cwd, env, body.create_branch ? { createBranch: body.create_branch } : {});
          if (pre.created) {
            row = await updateSession(this.deps.db, row.id, { branch: pre.branch });
            await this.emit(row, "pr.status", { step: "branch_created", branch: pre.branch, base: pre.defaultBranch });
            this.publish(row);
          }
          await this.emit(row, "control.applied", { command: "open_pr", by_device: byDevice, branch: pre.branch, base: body.base ?? pre.defaultBranch });
          status = "queued";
          const title = (body.title?.trim() || row.title).slice(0, 200);
          void this.openPr(userId, sessionId, { ...pre, title, draft: body.draft === true, base: body.base ?? pre.defaultBranch }).catch(() => {});
          break;
        }
        case "set_limits": {
          const limits = Limits.parse(body.limits ?? {});
          row = await updateSession(this.deps.db, row.id, { limits_json: limits });
          for (const k of [...this.limitHandled]) if (k.startsWith(`${sessionId}:`)) this.limitHandled.delete(k);
          await this.emit(row, "control.applied", { command: "set_limits", by_device: byDevice, limits });
          this.publish(row);
          break;
        }
        case "instruct": {
          if (!can.instruct) throw deny("");
          if (this.isParked(sessionId)) throw deny("waiting for a free slot; add it as a task instead", "waiting_for_slot");
          status = await this.instruct(row, body.text ?? "", live, byDevice, "instruct");
          break;
        }
        case "pause": {
          if (!can.pause || !live) throw deny("nothing is running");
          await this.signalTurn(live, "SIGSTOP"); // whole tree: tool shells run in their own groups
          live.statusBeforePause = row.status as SessionStatus;
          row = await this.setStatus(row, "paused", "paused by the user");
          await this.emit(row, "control.applied", { command: "pause", by_device: byDevice });
          break;
        }
        case "resume": {
          if (can.resume && !live && ["failed", "lost"].includes(row.status)) {
            // Continue a queue that paused after a failed task: next queued task, --resume turn.
            await this.emit(row, "control.applied", { command: "resume", by_device: byDevice, continue_queue: true });
            if (!(await this.startNextTask(row))) throw deny("no queued tasks", "no_queued_tasks");
            break;
          }
          if (!can.resume || !live) throw deny("");
          await this.signalTurn(live, "SIGCONT");
          row = await this.setStatus(row, live.statusBeforePause ?? "running", "resumed by the user");
          live.statusBeforePause = null;
          await this.emit(row, "control.applied", { command: "resume", by_device: byDevice });
          break;
        }
        case "stop": {
          if (!can.stop) throw deny("");
          await this.emit(row, "control.applied", { command: "stop", by_device: byDevice });
          row = await this.stopSession(row, live, null);
          break;
        }
        case "kill": {
          this.pendingContinuation.delete(sessionId);
          if (can.kill && this.isParked(sessionId)) {
            this.unpark(sessionId);
            await this.finishCurrentTask(row, "cancelled", { error: "killed by the user" });
            await this.emit(row, "control.applied", { command: "kill", by_device: byDevice });
            row = await this.setStatus(row, "killed", "killed before it started");
            break;
          }
          if (!live && can.kill && (row.background_json?.length ?? 0) > 0) {
            // Nothing running in the turn, but background processes it left behind.
            const n = row.background_json.length;
            row = await this.endBackground(row, "SIGKILL");
            await this.emit(row, "control.applied", { command: "kill", by_device: byDevice, background_processes_killed: n });
            row = await this.setStatus(row, "killed", "killed by the user (background processes)");
            break;
          }
          if (!can.kill || !live) throw deny("nothing is running");
          live.killRequested = true;
          live.queue.length = 0;
          const escaped = await this.killTree(live);
          if ((row.background_json?.length ?? 0) > 0) row = await this.endBackground(row, "SIGKILL");
          await this.emit(row, "control.applied", { command: "kill", by_device: byDevice, ...(escaped ? { escaped_processes_killed: escaped } : {}) });
          break;
        }
        default:
          throw new DomainError(400, "unknown_command", `unknown command ${body.command}`);
      }
      const fresh = (await getSession(this.deps.db, userId, sessionId))!;
      return { status, session: toAgentSession(fresh) };
    });
  }

  private async instruct(row: AgentSessionRow, text: string, live: Live | undefined, byDevice: string | null, via: string): Promise<"queued" | "applied"> {
    this.autoCount.delete(row.id); // a user instruction resets the auto-continue budget
    if (live) {
      live.queue.push(text);
      await this.emit(row, "control.applied", { command: via, by_device: byDevice, queued: true, position: live.queue.length });
      return "queued";
    }
    if (row.mode === "observed") {
      // "Continue remotely": the conversation continues as a managed --resume turn.
      row = await updateSession(this.deps.db, row.id, { mode: "managed" });
      if (row.status !== "completed" && row.status !== "lost") {
        await this.emit(row, "status.changed", {
          from: row.status,
          to: row.status,
          reason: "continued remotely — if the interactive terminal is still open, don't type there until this turn finishes",
        });
      }
    }
    await this.cancelPending(row);
    await this.emit(row, "control.applied", { command: via, by_device: byDevice });
    // A plain instruction continues the current task (waiting/failed/running); with no
    // current task it becomes a new task that runs before anything still queued.
    const cur = await this.currentTask(row);
    let taskId: string;
    if (cur && ["waiting", "failed", "running"].includes(cur.status)) {
      if (cur.status === "failed") await updateSession(this.deps.db, row.id, { retries: sql`${agentSessions.retries} + 1` as unknown as number }); // a failed task re-run
      const [u] = await this.deps.db.update(tasks).set({ status: "running", ended_at: null }).where(eq(tasks.id, cur.id)).returning();
      this.taskChanged(row.user_id, u!);
      taskId = cur.id;
    } else {
      taskId = (await this.createTask(row, text, undefined, "running", true)).id;
    }
    this.publish(await this.refreshCounters(row.id));
    await this.emit(row, "message.user", { text, task_id: taskId });
    await this.runTurn(row.id, text);
    return "applied";
  }

  /**
   * Stop semantics shared by the stop command, a "stop" budget answer and `on_exceed: stop`:
   * parked → stopped; live → SIGINT, SIGTERM, SIGKILL escalation; idle → completed (or stopped
   * with `reason` when a limit stopped it).
   */
  private async stopSession(row: AgentSessionRow, live: Live | undefined, reason: string | null): Promise<AgentSessionRow> {
    this.pendingContinuation.delete(row.id);
    if (this.isParked(row.id)) {
      this.unpark(row.id);
      await this.finishCurrentTask(row, "cancelled", { error: reason ?? "stopped by the user" });
      return this.setStatus(row, "stopped", reason ?? "stopped before it started");
    }
    if (live) {
      live.stopRequested = true;
      if (reason) live.stopReason = reason;
      live.queue.length = 0;
      live.budgetPaused = false;
      await this.cancelPending(row);
      row = await this.setStatus(row, "stopping", reason ?? "stop requested", { pending_interaction_id: null });
      // The whole tree (tool commands run in their own process groups), then escalation.
      await this.signalTurn(live, "SIGCONT");
      await this.signalTurn(live, "SIGINT");
      const grace = this.o.stopGraceMs ?? 5_000;
      live.timers.push(
        setTimeout(() => void this.signalTurn(live, "SIGTERM"), grace),
        setTimeout(() => void this.signalTurn(live, "SIGKILL"), grace * 2),
      );
      return row;
    }
    await this.cancelPending(row);
    // Idle: background processes left by earlier turns are terminated too.
    if ((row.background_json?.length ?? 0) > 0) row = await this.endBackground(row, "SIGTERM");
    if (reason) return this.setStatus(row, "stopped", reason, { pending_interaction_id: null });
    // Nothing running: the user is done with this session.
    row = await this.setStatus(row, "completed", "ended by the user", { pending_interaction_id: null });
    await this.emit(row, "session.completed", { summary: row.summary_json ?? null });
    return row;
  }

  /**
   * Emergency kill: SIGKILL the process group AND every process that escaped it (setsid /
   * double fork): descendants found by a ppid walk now, plus any process seen in this turn's
   * tree by the sampler that still exists with the same start time. Returns how many
   * processes outside the group were killed.
   */
  private async killTree(live: Live): Promise<number> {
    signalGroup(live.pid, "SIGCONT");
    let escaped = 0;
    try {
      const rows = parsePs(await (this.o.ps ?? realPs)());
      const byPid = new Map(rows.map((r) => [r.pid, r]));
      const targets = new Map<number, string>();
      for (const r of processTree(rows, live.pid)) targets.set(r.pid, r.start);
      for (const [pid, start] of live.seen) if (byPid.get(pid)?.start === start) targets.set(pid, start);
      for (const pid of targets.keys()) {
        if (pid === process.pid || pid <= 1) continue;
        if (byPid.get(pid)?.pgid !== live.pid) escaped++;
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          /* gone */
        }
      }
    } catch {
      /* ps unavailable: the group kill below still happens */
    }
    signalGroup(live.pid, "SIGKILL");
    return escaped;
  }

  /**
   * Background commands left by ended turns: when ALL of a session's recorded background
   * processes have exited, emit process.background_finished and — if enabled and the session
   * is idle — start a follow-up --resume turn so the agent can keep its promise ("I'll let you
   * know when it finishes"). Busy sessions get it when they become idle, before the queue.
   */
  private async watchBackground(): Promise<void> {
    const rows = await this.deps.db.select().from(agentSessions).where(sql`jsonb_array_length(${agentSessions.background_json}) > 0`);
    if (!rows.length) return;
    const ps = await this.psRows();
    if (!ps.length) return; // ps unavailable: don't conclude anything
    for (const r of rows) {
      const recorded = r.background_json ?? [];
      if (this.aliveOf(recorded, ps).length) continue;
      await this.serial(r.id, async () => {
        let row = (await this.deps.db.select().from(agentSessions).where(eq(agentSessions.id, r.id)))[0];
        if (!row || !(row.background_json ?? []).length) return;
        const done = (row.background_json ?? []).map((b) => {
          const started = Date.parse(b.start);
          return { pid: b.pid, command: redactCommandSecrets(b.command), ran_ms: Number.isFinite(started) ? Math.max(0, Date.now() - started) : null, outputs: b.outputs ?? [] };
        });
        row = await updateSession(this.deps.db, row.id, { background_json: [] });
        await this.emit(row, "process.background_finished", { processes: done.map(({ outputs, ...d }) => ({ ...d, exit: null, outputs })) });
            if (this.o.autoContinueBackground === false || row.mode !== "managed" || !row.provider_session_id) return;
        const fmt = (ms: number | null) => (ms === null ? "unknown time" : ms < 90_000 ? `${Math.round(ms / 1000)}s` : `${Math.round(ms / 60_000)}m`);
        const cmds = done.map((d) => `\`${d.command.slice(0, 200)}\` exited (ran ${fmt(d.ran_ms)})`).join("; ");
        const outputs = [...new Set(done.flatMap((d) => d.outputs))];
        const text = `[AgentGate] Background command(s) finished: ${cmds}.${outputs.length ? ` Output file (if Claude reported one): ${outputs.join(", ")}.` : ""} Continue with what you were doing, and report the result to the user.`;
        this.pendingContinuation.set(row.id, text);
        await this.runPendingContinuation(row);
      });
    }
  }

  /** Runs a pending background continuation if the session is idle and under the loop cap. */
  private async runPendingContinuation(row: AgentSessionRow, atTurnEnd = false): Promise<boolean> {
    const text = this.pendingContinuation.get(row.id);
    if (!text) return false;
    // At a successful turn end (no question, no held limit) the session is about to go idle.
    const idle = !this.live.has(row.id) && !this.isParked(row.id) && !row.pending_interaction_id && (atTurnEnd || row.status === "waiting_input");
    if (!idle) return false; // stays pending until the session is idle again
    this.pendingContinuation.delete(row.id);
    const n = this.autoCount.get(row.id) ?? 0;
    if (n >= 3) {
      await this.emit(row, "control.applied", { command: "auto_continue", skipped: "limit of 3 automatic continuations per instruction reached" });
      return false;
    }
    this.autoCount.set(row.id, n + 1);
    await this.emit(row, "message.user", { text, task_id: row.current_task_id, origin: "agentgate" });
    await this.runTurn(row.id, text);
    return true;
  }

  /** Throttled tree snapshot (tool events): remembers descendants while the parent is alive. */
  private snapshotSoon(live: Live) {
    if (Date.now() - live.snapAt < 300) return;
    live.snapAt = Date.now();
    void this.psRows().then((rows) => this.remember(live, rows));
  }

  private async psRows(): Promise<PsRow[]> {
    try {
      return parsePs(await (this.o.ps ?? realPs)());
    } catch {
      return [];
    }
  }

  private remember(live: Live, rows: PsRow[]) {
    for (const r of orderedTree(rows, live.pid)) if (live.seen.size < 5_000) live.seen.set(r.pid, r.start);
  }

  /** Current members of the turn: ordered tree from the leader + remembered processes still alive. */
  private treeTargets(live: Live, rows: PsRow[]): PsRow[] {
    const t = orderedTree(rows, live.pid);
    const ids = new Set(t.map((r) => r.pid));
    const byPid = new Map(rows.map((r) => [r.pid, r]));
    for (const [pid, start] of live.seen) {
      const r = byPid.get(pid);
      if (r && r.start === start && !ids.has(pid)) {
        t.push(r);
        ids.add(pid);
        // …and their descendants (they may have forked since).
        for (const d of orderedTree(rows, pid).slice(1)) if (!ids.has(d.pid)) (t.push(d), ids.add(d.pid));
      }
    }
    return t.filter((r) => r.pid > 1 && r.pid !== process.pid);
  }

  /**
   * Signals the turn's whole DESCENDANT TREE, not just its process group: Claude Code runs Bash
   * tool commands in their own process groups. Order: SIGSTOP children first (deepest last
   * found → first), then the leader's group; SIGCONT the leader's group first, then children.
   */
  private async signalTurn(live: Live, sig: NodeJS.Signals): Promise<number> {
    const rows = await this.psRows();
    this.remember(live, rows);
    const others = this.treeTargets(live, rows).filter((r) => r.pid !== live.pid && r.pgid !== live.pid);
    const send = (pid: number) => {
      try {
        process.kill(pid, sig);
      } catch {
        /* gone */
      }
    };
    if (sig === "SIGSTOP") {
      for (const r of [...others].reverse()) send(r.pid);
      signalGroup(live.pid, sig);
    } else {
      signalGroup(live.pid, sig);
      for (const r of others) send(r.pid);
    }
    return others.length;
  }

  /** Processes (with same start time) still alive among `recorded`. */
  private aliveOf(recorded: Array<{ pid: number; start: string }>, rows: PsRow[]): PsRow[] {
    const byPid = new Map(rows.map((r) => [r.pid, r]));
    return recorded.map((b) => byPid.get(b.pid)).filter((r): r is PsRow => Boolean(r) && recorded.some((b) => b.pid === r!.pid && b.start === r!.start));
  }

  /** Terminates recorded background processes (TERM → KILL after the grace, or KILL now). */
  private async endBackground(row: AgentSessionRow, sig: "SIGTERM" | "SIGKILL"): Promise<AgentSessionRow> {
    const recorded = row.background_json ?? [];
    const alive = this.aliveOf(recorded, await this.psRows());
    this.terminate(alive, sig);
    return updateSession(this.deps.db, row.id, { background_json: [] });
  }

  /** TERM (then KILL after the stop grace, if still the same process) or KILL now. */
  private terminate(procs: PsRow[], sig: "SIGTERM" | "SIGKILL") {
    const send = (pid: number, s: NodeJS.Signals) => {
      try {
        process.kill(pid, "SIGCONT");
        process.kill(pid, s);
      } catch {
        /* gone */
      }
    };
    for (const p of procs) if (p.pid > 1 && p.pid !== process.pid) send(p.pid, sig);
    if (sig === "SIGTERM" && procs.length) {
      const t = setTimeout(async () => {
        for (const p of this.aliveOf(procs, await this.psRows())) send(p.pid, "SIGKILL");
      }, this.o.stopGraceMs ?? 5_000);
      t.unref();
    }
  }

  /**
   * Turn ended. Stop/kill/tripwire: leftovers of the tree are terminated. Otherwise anything
   * still running (e.g. `run_in_background` commands) is recorded as the session's background
   * processes — not killed: the agent may rely on them.
   */
  private async settleLeftovers(row: AgentSessionRow, live: Live): Promise<AgentSessionRow> {
    const rows = await this.psRows();
    const left = this.treeTargets(live, rows).filter((r) => r.pid !== live.pid);
    if (live.killRequested || live.tripwire) {
      this.terminate(left, "SIGKILL");
      return row;
    }
    if (live.stopRequested) {
      this.terminate(left, "SIGTERM");
      return row.background_json?.length ? this.endBackground(row, "SIGTERM") : row;
    }
    const prev = this.aliveOf(row.background_json ?? [], rows);
    const known = new Set(prev.map((p) => p.pid));
    const fresh = left.filter((r) => !known.has(r.pid));
    if (!fresh.length && prev.length === (row.background_json?.length ?? 0)) return row;
    const prevRec = new Map((row.background_json ?? []).map((b) => [b.pid, b]));
    const all = [...prev, ...fresh].slice(0, 50).map((r) => ({ pid: r.pid, start: r.start, command: r.command.slice(0, 500), outputs: prevRec.get(r.pid)?.outputs ?? live.bgOutputs.slice(0, 10) }));
    row = await updateSession(this.deps.db, row.id, { background_json: all });
    for (const r of fresh.slice(0, 50)) await this.emit(row, "process.background", { pid: r.pid, command: redactCommandSecrets(r.command.slice(0, 500)) });
    return row;
  }

  // ── Phase 3: review ─────────────────────────────────────────────────────────

  private async baseFor(row: AgentSessionRow, taskId: string | undefined): Promise<GitBase | null> {
    if (!taskId) return (row.base_json as GitBase | null) ?? null;
    const [t] = await this.deps.db.select().from(tasks).where(and(eq(tasks.id, taskId), eq(tasks.session_id, row.id)));
    if (!t) throw new DomainError(404, "not_found", "task not found");
    return (t.base_json as GitBase | null) ?? null;
  }

  async changes(userId: string, sessionId: string, taskId?: string): Promise<ChangeSet> {
    const row = await getSession(this.deps.db, userId, sessionId);
    if (!row) throw new DomainError(404, "not_found", "session not found");
    const base = await this.baseFor(row, taskId);
    const cs = await changeSet(base, row.cwd).catch(() => null);
    let tests = (row.tests_json as TestRun | null) ?? null;
    if (taskId) tests = ((await this.deps.db.select().from(tasks).where(eq(tasks.id, taskId)))[0]?.tests_json as TestRun | null) ?? null;
    return {
      session_id: row.id,
      task_id: taskId ?? null,
      base_ref: cs?.base_ref ?? null,
      branch: (await gitInfo(row.cwd)).branch,
      files: cs?.files ?? [],
      totals: cs?.totals ?? { files: 0, additions: 0, deletions: 0 },
      tests,
      pr: (row.pr_json as PullRequestInfo | null) ?? null,
      truncated: cs?.truncated ?? false,
    };
  }

  async diff(userId: string, sessionId: string, path: string, taskId?: string): Promise<FileDiff> {
    const row = await getSession(this.deps.db, userId, sessionId);
    if (!row) throw new DomainError(404, "not_found", "session not found");
    return fileDiff(await this.baseFor(row, taskId), row.cwd, path);
  }

  /** Background part of open_pr: gated push → gated `gh pr create` → PullRequestInfo + pr_ready. */
  private async openPr(userId: string, sessionId: string, o: { top: string; branch: string; title: string; draft: boolean; base: string }) {
    const step = (s: string, extra: Record<string, unknown> = {}) =>
      this.serial(sessionId, async () => {
        const row = await getSession(this.deps.db, userId, sessionId);
        if (row) await this.emit(row, "pr.status", { step: s, ...extra });
      });
    const env = this.o.turnEnv();
    const gate = {
      deps: this.deps,
      userId,
      policyPath: this.o.policyPath?.() ?? null,
      requireDeviceSignatures: this.o.requireDeviceSignatures ?? false,
      approvalWaitMs: this.o.prApprovalWaitMs ?? 300_000,
      onStatus: step,
    };
    try {
      await gatedRun(gate, { cmd: "git", args: ["push", "-u", "origin", o.branch], cwd: o.top, env, resource: { type: "git_remote", name: `origin/${o.branch}` }, floorAsk: true, step: "push" });
      const row = (await getSession(this.deps.db, userId, sessionId))!;
      const body = await this.prBody(row);
      const args = ["pr", "create", "--title", o.title, "--body", body, "--head", o.branch, "--base", o.base, ...(o.draft ? ["--draft"] : [])];
      const r = await gatedRun(gate, { cmd: "gh", args, cwd: o.top, env, resource: { type: "github_pr", name: o.branch }, floorAsk: false, step: "create_pr" });
      const pr = parsePrUrl(r.stdout, o.draft, o.title);
      if (!pr) throw new Error("gh pr create did not print a pull request URL");
      await this.serial(sessionId, async () => {
        const cur = await updateSession(this.deps.db, sessionId, { pr_json: pr });
        await this.emit(cur, "pr.opened", { ...pr });
        this.publish(cur);
        this.alert(cur, "pr_ready");
      });
    } catch (err) {
      const error = (err as Error).message.slice(0, 1000);
      await this.serial(sessionId, async () => {
        const cur = await getSession(this.deps.db, userId, sessionId);
        if (cur) await this.emit(cur, "pr.failed", { error });
      });
    }
  }

  /** PR body: the session summary (content the owner already sees on the phone). */
  private async prBody(row: AgentSessionRow): Promise<string> {
    const cs = await changeSet((row.base_json as GitBase | null) ?? null, row.cwd).catch(() => null);
    const tests = row.tests_json as TestRun | null;
    const s = row.summary_json as SessionSummary | null;
    const lines = [
      s?.last_message ? s.last_message.slice(0, 2000) : row.title,
      "",
      cs ? `**Changes:** ${cs.totals.files} files, +${cs.totals.additions} −${cs.totals.deletions}` : "",
      ...(cs?.files.slice(0, 50).map((f) => `- \`${f.path}\` (${f.status})`) ?? []),
      tests ? `\n**Tests:** \`${tests.command}\` — ${tests.ok ? "passed" : "failed"}${tests.passed !== null ? ` (${tests.passed} passed, ${tests.failed ?? 0} failed)` : ""}` : "",
      "",
      `_Opened from AgentGate (${row.provider} session)._`,
    ];
    return redactCommandSecrets(lines.filter((l, i, a) => l !== "" || a[i - 1] !== "").join("\n")).slice(0, 60_000);
  }

  // ── Phase 4: limits, resources, smart notifications ──────────────────────

  async globalLimits(userId: string): Promise<Limits | null> {
    const [r] = await this.deps.db.select().from(controlSettings).where(eq(controlSettings.user_id, userId));
    return (r?.limits_json as Limits | null) ?? null;
  }

  async setGlobalLimits(userId: string, raw: unknown): Promise<Limits> {
    const limits = Limits.parse(raw ?? {});
    const now = this.deps.clock.now();
    await this.deps.db
      .insert(controlSettings)
      .values({ user_id: userId, limits_json: limits, updated_at: now })
      .onConflictDoUpdate({ target: controlSettings.user_id, set: { limits_json: limits, updated_at: now } });
    this.limitHandled.clear();
    return limits;
  }

  /**
   * Evaluates the effective limits for the session. Returns true when the action holds the
   * session (ask / pause / stop) so the caller must not auto-advance the queue.
   */
  private async evaluateLimits(row: AgentSessionRow, live: Live | undefined, when: "event" | "turn_end" | "sample" | "mid_turn"): Promise<boolean> {
    const eff = effectiveLimits(await this.globalLimits(row.user_id), (row.limits_json as Limits | null) ?? null);
    if (!eff) return false;
    const task = await this.currentTask(row);
    const now = this.deps.clock.now();
    const running = Boolean(live) && ["running", "awaiting_approval"].includes(row.status);
    const usage = (row.usage_json as SessionUsage | null) ?? EMPTY_USAGE;
    const taskUsage = (task?.usage_json as SessionUsage | null) ?? null;
    const latest = this.samples.get(row.id)?.at(-1) ?? null;
    // While a turn runs, its cost so far is only an estimate (Claude reports the real total at
    // the end); it is added to what earlier turns really cost.
    const liveEst = running && live && live.costEstimate > 0 ? live.costEstimate : 0;
    const estimated = liveEst > 0;
    const plus = (v: number | null) => (estimated ? (v ?? 0) + liveEst : v);
    const hits = checkLimits(eff, {
      taskCost: plus(taskUsage?.cost_usd ?? null),
      sessionCost: plus(usage.cost_usd),
      sessionMinutes: running ? (now.getTime() - row.started_at.getTime()) / 60_000 : null,
      taskMinutes: running && task?.started_at ? (now.getTime() - task.started_at.getTime()) / 60_000 : null,
      retries: row.retries ?? 0,
      rssMb: running && latest ? latest.rss_mb : null,
    }).filter((h) => !this.limitHandled.has(this.limitKey(row, task?.id, h)));
    if (!hits.length) return false;
    const action = eff.on_exceed ?? "ask";
    const at = now.toISOString();
    for (const h of hits) this.limitHandled.add(this.limitKey(row, task?.id, h));
    const exceeded = [...hits.map((h) => ({ limit: h.limit, value: h.value, at, action })), ...((row.exceeded_json as unknown[]) ?? [])].slice(0, 50);
    row = await updateSession(this.deps.db, row.id, { exceeded_json: exceeded });
    const costKind = this.costKind(row.provider);
    const details = hits.map((h) => limitDetail(h, eff, { estimated: estimated && h.limit.startsWith("max_cost"), costKind }));
    for (const d of details) await this.emit(row, "limit.exceeded", { ...d, action, task_id: task?.id ?? null, when });
    const what = details.map((d) => d.text).join(" ");
    const liveNow = live ?? this.live.get(row.id);
    const alive = Boolean(liveNow) && when !== "turn_end";
    switch (action) {
      case "notify":
        this.alert(row, "budget_exceeded");
        return false;
      case "ask": {
        if (alive && liveNow) {
          await this.signalTurn(liveNow, "SIGSTOP");
          liveNow.budgetPaused = true;
        }
        const id = cid("int");
        const prompt = `${what} Reply "continue" to go on, or "stop".`.slice(0, 4096);
        await this.deps.db.insert(interactions).values({ id, session_id: row.id, kind: "budget", prompt, status: "pending", created_at: now });
        row = await this.setStatus(row, "waiting_input", `limit reached: ${what}`, { pending_interaction_id: id });
        const { text: _t, ...first } = details[0]!;
        await this.emit(row, "input.required", { interaction_id: id, prompt, kind: "budget", task_id: task?.id ?? null, ...first, limits: details.map(({ text: _x, ...d }) => d) });
        this.alert(row, "budget_exceeded");
        return true;
      }
      case "pause":
        if (alive && liveNow) {
          await this.signalTurn(liveNow, "SIGSTOP");
          liveNow.statusBeforePause = row.status as SessionStatus;
          row = await this.setStatus(row, "paused", `limit reached: ${what}`);
        } else {
          row = await this.setStatus(row, "waiting_input", `limit reached: ${what} — queue paused`);
        }
        this.alert(row, "budget_exceeded");
        return true;
      case "stop":
        await this.stopSession(row, alive ? liveNow : undefined, `limit reached: ${what}`);
        this.alert(row, "budget_exceeded");
        return true;
    }
    return false;
  }

  private limitKey(row: AgentSessionRow, taskId: string | undefined, h: LimitHit) {
    return `${row.id}:${taskId ?? "-"}:${h.limit}`;
  }

  /** Returns true when this failure makes a "repeated failure" (3 in a row, or the same error twice). */
  private noteFailure(row: AgentSessionRow, error: string): boolean {
    const f = this.failures.get(row.id) ?? { count: 0, errors: [], alerted: false };
    const norm = error.trim().slice(0, 500);
    const repeat = f.errors.includes(norm);
    f.count++;
    f.errors.push(norm);
    if (f.errors.length > 10) f.errors.shift();
    this.failures.set(row.id, f);
    if ((f.count >= 3 || repeat) && !f.alerted) {
      f.alerted = true;
      return true;
    }
    return false;
  }

  /** Periodic housekeeping (every tickMs; tests call it directly). */
  async tick(): Promise<void> {
    if (this.ticking) return;
    this.ticking = true;
    try {
      const now = this.deps.clock.now();
      if (this.live.size) {
        let rows: ReturnType<typeof parsePs> = [];
        try {
          rows = parsePs(await (this.o.ps ?? realPs)());
        } catch {
          rows = [];
        }
        for (const [sid, live] of this.live) {
          if (!live.pid || live.child.exitCode !== null) continue;
          const tree = processTree(rows, live.pid);
          for (const r of tree) if (live.seen.size < 5_000) live.seen.set(r.pid, r.start);
          const ring = this.samples.get(sid) ?? [];
          ring.push(summarize(tree, now));
          if (ring.length > RING) ring.splice(0, ring.length - RING);
          this.samples.set(sid, ring);
          await this.serial(sid, async () => {
            const row = (await this.deps.db.select().from(agentSessions).where(eq(agentSessions.id, sid)))[0];
            if (row && this.live.get(sid) === live) await this.evaluateLimits(row, live, "sample");
          });
        }
      }
      await this.watchBackground();
      // Stuck: running with no events for stuckAfterMs — one push per episode.
      const after = this.o.stuckAfterMs ?? 600_000;
      for (const r of await sessionsWithStatus(this.deps.db, ["running"])) {
        if (!this.live.has(r.id)) continue;
        const last = r.last_event_at.getTime();
        if (now.getTime() - last < after || this.stuckNotified.get(r.id) === last) continue;
        this.stuckNotified.set(r.id, last);
        this.alert(r, "stuck");
      }
    } finally {
      this.ticking = false;
    }
  }

  async metrics(userId: string, sessionId: string): Promise<SessionMetrics> {
    const row = await getSession(this.deps.db, userId, sessionId);
    if (!row) throw new DomainError(404, "not_found", "session not found");
    const history = this.samples.get(row.id) ?? [];
    const usage = (row.usage_json as SessionUsage | null) ?? EMPTY_USAGE;
    const limits = effectiveLimits(await this.globalLimits(userId), (row.limits_json as Limits | null) ?? null);
    const notes: string[] = [];
    const provider = this.o.providers[row.provider];
    if (usage.cost_usd === null && (provider ? !provider.capabilities.cost : true)) {
      notes.push(`${provider?.displayName ?? row.provider} reports no cost; cost limits are not enforced for this session`);
    }
    return {
      session_id: row.id,
      usage,
      retries: row.retries ?? 0,
      resources: this.live.has(row.id) ? (history.at(-1) ?? null) : null,
      history: history.slice(-RING),
      limits,
      exceeded: ((row.exceeded_json as SessionMetrics["exceeded"] | null) ?? []).slice(0, 50),
      background_processes: this.aliveOf(row.background_json ?? [], row.background_json?.length ? await this.psRows() : []).map((r) => ({ pid: r.pid, command: redactCommandSecrets(r.command.slice(0, 500)) })),
      ...(notes.length ? { notes } : {}),
    };
  }

  async usage(userId: string, range: "today" | "7d" | "30d"): Promise<UsageReport> {
    const now = this.deps.clock.now();
    const dayStart = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
    const since = new Date(range === "today" ? dayStart : dayStart - (range === "7d" ? 6 : 29) * 86_400_000);
    const rows = await this.deps.db.select().from(agentSessions).where(and(eq(agentSessions.user_id, userId), gte(agentSessions.started_at, since)));
    const addN = (a: number | null, b: number | null | undefined) => (b === null || b === undefined ? a : (a ?? 0) + b);
    const byProvider = new Map<string, { provider: string; sessions: number; cost_usd: number | null; input_tokens: number | null; output_tokens: number | null; duration_ms: number; cost_kind?: CostKind }>();
    const byDay = new Map<string, { day: string; cost_usd: number | null; sessions: number }>();
    let total: number | null = null;
    for (const r of rows) {
      const u = (r.usage_json as SessionUsage | null) ?? EMPTY_USAGE;
      const p = byProvider.get(r.provider) ?? { provider: r.provider, sessions: 0, cost_usd: null, input_tokens: null, output_tokens: null, duration_ms: 0 };
      p.sessions++;
      p.cost_usd = addN(p.cost_usd, u.cost_usd);
      p.input_tokens = addN(p.input_tokens, u.input_tokens);
      p.output_tokens = addN(p.output_tokens, u.output_tokens);
      p.duration_ms += u.duration_ms ?? 0;
      if (u.cost_kind) p.cost_kind = u.cost_kind; // rows are in DB order; the last known kind wins
      byProvider.set(r.provider, p);
      const day = r.started_at.toISOString().slice(0, 10);
      const d = byDay.get(day) ?? { day, cost_usd: null, sessions: 0 };
      d.sessions++;
      d.cost_usd = addN(d.cost_usd, u.cost_usd);
      byDay.set(day, d);
      total = addN(total, u.cost_usd);
    }
    const round = (v: number | null) => (v === null ? null : Math.round(v * 1_000_000) / 1_000_000);
    return {
      range,
      total_cost_usd: round(total),
      by_provider: [...byProvider.values()].map((p) => ({ ...p, cost_usd: round(p.cost_usd) })).sort((a, b) => a.provider.localeCompare(b.provider)),
      by_day: [...byDay.values()].map((d) => ({ ...d, cost_usd: round(d.cost_usd) })).sort((a, b) => a.day.localeCompare(b.day)),
      global_limits: await this.globalLimits(userId),
    };
  }

  private async cancelPending(row: AgentSessionRow) {
    if (!row.pending_interaction_id) return;
    await this.deps.db
      .update(interactions)
      .set({ status: "cancelled", resolved_at: this.deps.clock.now() })
      .where(eq(interactions.id, row.pending_interaction_id));
    await updateSession(this.deps.db, row.id, { pending_interaction_id: null });
  }

  // ── approvals raised by a managed turn's PreToolUse hook ──────────────────

  /**
   * Context from the action: `agentgate_control_session` (set by the Codex/generic hooks from
   * AGENTGATE_CONTROL_SESSION) or `claude_session_id` (the Claude Code adapter).
   */
  onApprovalRequested(userId: string, context: Record<string, unknown> | undefined, approvalId: string) {
    const control = typeof context?.agentgate_control_session === "string" ? context.agentgate_control_session : undefined;
    const claude = typeof context?.claude_session_id === "string" ? context.claude_session_id : undefined;
    if (!control && !claude) return;
    void (async () => {
      const row = control
        ? ((await getSession(this.deps.db, userId, control)) ?? null)
        : await findByProviderSession(this.deps.db, userId, "claude-code", claude!);
      if (!row || (control && row.mode !== "managed")) return;
      await this.serial(row.id, async () => {
        const cur = (await getSession(this.deps.db, userId, row.id))!;
        await this.emit(cur, "approval.requested", { approval_id: approvalId });
        const live = this.live.get(row.id);
        if (live && cur.status === "running") {
          live.approvals.add(approvalId);
          this.approvalToSession.set(approvalId, row.id);
          await this.setStatus(cur, "awaiting_approval", "a tool call needs your approval");
        }
      });
    })().catch(() => {});
  }

  onApprovalResolved(userId: string, approvalId: string) {
    const sessionId = this.approvalToSession.get(approvalId);
    if (!sessionId) return;
    this.approvalToSession.delete(approvalId);
    void this.bg(sessionId, async () => {
      const cur = await getSession(this.deps.db, userId, sessionId);
      if (cur && cur.status === "awaiting_approval" && this.live.has(sessionId)) await this.setStatus(cur, "running", "approval resolved");
    });
  }

  // ── observed sessions (installed hooks) ───────────────────────────────────

  async observe(userId: string, provider: string, hook: unknown): Promise<AgentSession | null> {
    const p = this.o.providers[provider];
    if (!p?.normalizeHook) throw new DomainError(400, "unknown_provider", `provider '${provider}' cannot be observed`);
    const evs = p.normalizeHook(hook);
    const meta = evs.find((e) => e.type === "provider.hook")?.payload;
    if (!meta) return null;
    const psid = meta.provider_session_id as string;
    const cwd = (meta.cwd as string | null) ?? "";
    // Hooks fired by a managed turn (installed project/user observe hooks run there too):
    // the managed session reports its own progress, so these events are dropped.
    const marker = (hook as { agentgate_managed_session?: unknown }).agentgate_managed_session;
    if (typeof marker === "string" && marker) {
      const m = await getSession(this.deps.db, userId, marker);
      if (m?.mode === "managed") return toAgentSession(m);
    }
    const managed = await findManagedByProviderSession(this.deps.db, userId, provider, psid);
    if (managed) return toAgentSession(managed);
    // SessionStart can arrive before the turn's system/init: a managed turn just spawned in
    // the same directory, still without a provider session id, owns it.
    const pending = await this.pendingManagedFor(userId, cwd);
    if (pending) return toAgentSession(pending);
    let row = await findByProviderSession(this.deps.db, userId, provider, psid);
    if (row?.mode === "managed") return toAgentSession(row);
    if (!row) {
      const now = this.deps.clock.now();
      const git = cwd ? await gitInfo(cwd) : { repo: null, branch: null };
      const inserted = await this.deps.db
        .insert(agentSessions)
        .values({
          id: cid("ags"),
          user_id: userId,
          provider,
          provider_session_id: psid,
          mode: "observed",
          title: cwd ? basename(cwd) : "Interactive session",
          cwd,
          repo: git.repo,
          branch: git.branch,
          status: "running",
          started_at: now,
          last_event_at: now,
          usage_json: EMPTY_USAGE,
        })
        .returning();
      row = inserted[0]!;
      this.publish(row);
    }
    const id = row!.id;
    return this.serial(id, async () => {
      let cur = (await getSession(this.deps.db, userId, id))!;
      for (const ev of evs) {
        switch (ev.type) {
          case "provider.hook":
            break;
          case "session.started":
            await this.emit(cur, "session.started", { ...ev.payload, mode: "observed" });
            if (cur.status !== "running") cur = await this.setStatus(cur, "running", "interactive session started", { ended_at: null });
            break;
          case "message.user":
            await this.emit(cur, ev.type, ev.payload);
            if (cur.title === basename(cur.cwd) || cur.title === "Interactive session") {
              cur = await updateSession(this.deps.db, cur.id, { title: firstLine(String(ev.payload.text ?? "")).slice(0, 200) || cur.title });
            }
            if (cur.status !== "running") cur = await this.setStatus(cur, "running", "new prompt", { pending_interaction_id: null, ended_at: null });
            break;
          case "input.required": {
            const iid = cid("int");
            const prompt = String(ev.payload.prompt ?? "").slice(0, 4096);
            await this.deps.db.insert(interactions).values({ id: iid, session_id: cur.id, kind: "input_required", prompt, status: "pending", created_at: this.deps.clock.now() });
            cur = await this.setStatus(cur, "waiting_input", "waiting for you in the terminal", { pending_interaction_id: iid });
            await this.emit(cur, "input.required", { interaction_id: iid, prompt });
            this.alert(cur, "input_required");
            break;
          }
          case "turn.completed":
            await this.emit(cur, "turn.completed", ev.payload);
            cur = await updateSession(this.deps.db, cur.id, { summary_json: await this.summary(cur, null, null) });
            cur = await this.setStatus(cur, "waiting_input", "turn finished");
            this.alert(cur, "completed");
            break;
          case "provider.session_end":
            await this.cancelPending(cur);
            cur = await this.setStatus(cur, "completed", `interactive session ended (${ev.payload.reason ?? "exit"})`, { ended_at: this.deps.clock.now() });
            await this.emit(cur, "session.completed", { summary: cur.summary_json ?? null });
            break;
          default:
            if (!ev.type.startsWith("provider.")) await this.emit(cur, ev.type, ev.payload);
        }
      }
      return toAgentSession((await getSession(this.deps.db, userId, id))!);
    });
  }

  private async pendingManagedFor(userId: string, cwd: string): Promise<AgentSessionRow | null> {
    if (!cwd) return null;
    const norm = (p: string) => {
      try {
        return realpathSync(p);
      } catch {
        return p;
      }
    };
    const want = norm(cwd);
    for (const [id, p] of this.pendingTurns) {
      if (Date.now() - p.at > 120_000) {
        this.pendingTurns.delete(id);
        continue;
      }
      if (p.userId === userId && norm(p.cwd) === want) {
        const r = await getSession(this.deps.db, userId, id);
        if (r?.mode === "managed") return r;
      }
    }
    return null;
  }

  /**
   * Observed sessions that duplicate a managed one (same provider session id, created by the
   * managed turn's own observe hooks) are removed with their events and interactions.
   */
  async removeObservedDuplicates(userId: string | null, provider: string, providerSessionId: string): Promise<number> {
    const dups = await this.deps.db
      .select()
      .from(agentSessions)
      .where(and(eq(agentSessions.provider, provider), eq(agentSessions.provider_session_id, providerSessionId), eq(agentSessions.mode, "observed"), ...(userId ? [eq(agentSessions.user_id, userId)] : [])));
    for (const d of dups) {
      await this.deps.db.transaction(async (tx) => {
        await tx.delete(sessionEvents).where(eq(sessionEvents.session_id, d.id));
        await tx.delete(interactions).where(eq(interactions.session_id, d.id));
        await tx.delete(tasks).where(eq(tasks.session_id, d.id));
        await tx.delete(agentSessions).where(eq(agentSessions.id, d.id));
      });
      this.deps.logger.info({ session_id: d.id, provider_session_id: providerSessionId }, "removed observed duplicate of a managed session");
    }
    return dups.length;
  }

  /** Server shutdown: leave turn processes alone? No — stop them; they are resumable (lost). */
  async shutdown(): Promise<void> {
    this.closed = true;
    if (this.ticker) clearInterval(this.ticker);
    this.ticker = null;
    for (const [, l] of this.live) {
      l.timers.forEach(clearTimeout);
      signalGroup(l.pid, "SIGCONT");
      signalGroup(l.pid, "SIGTERM");
    }
  }
}

function resolveOnPath(bin: string, path: string): string | null {
  const ok = (p: string) => {
    try {
      accessSync(p, fsc.X_OK);
      return statSync(p).isFile();
    } catch {
      return false;
    }
  };
  if (bin.includes("/")) return ok(bin) ? bin : null;
  for (const d of path.split(":")) if (d && ok(join(d, bin))) return join(d, bin);
  return null;
}

/** Human text + structured fields for a hit limit (budget prompt, limit.exceeded, input.required). */
export function limitDetail(
  h: LimitHit,
  l: Limits,
  o: { estimated: boolean; costKind: CostKind },
): { limit: string; value: number; limit_value: number; unit: "usd" | "minutes" | "count" | "mb"; estimated: boolean; cost_kind: CostKind; text: string } {
  const limitValue = Number(l[h.limit] ?? 0);
  const base = { limit: h.limit, value: h.value, limit_value: limitValue, estimated: o.estimated, cost_kind: o.costKind };
  const usd = (v: number) => `$${v < 10 ? v.toFixed(2) : v.toFixed(0)}`;
  const min = (v: number) => `${Math.floor(v)} min`;
  switch (h.limit) {
    case "max_cost_usd_per_task":
    case "max_cost_usd_per_session": {
      const est = o.estimated || o.costKind === "subscription_estimate";
      const note = o.costKind === "subscription_estimate" ? " (included in your subscription — estimate)" : o.estimated ? " (estimate)" : "";
      const scope = h.limit === "max_cost_usd_per_task" ? "per-task" : "per-session";
      return { ...base, estimated: est, unit: "usd", text: `${est ? "Estimated cost" : "Cost"} ${usd(h.value)} exceeded your ${usd(limitValue)} ${scope} limit${note}.` };
    }
    case "max_task_minutes":
      return { ...base, unit: "minutes", text: `Task has run ${min(h.value)}, over your ${min(limitValue)} limit.` };
    case "max_session_minutes":
      return { ...base, unit: "minutes", text: `Session has run ${min(h.value)}, over your ${min(limitValue)} limit.` };
    case "max_retries":
      return { ...base, unit: "count", text: `${h.value} retries, over your limit of ${limitValue}.` };
    case "max_rss_mb":
      return { ...base, unit: "mb", text: `Memory use ${Math.round(h.value)} MB, over your ${limitValue} MB limit.` };
  }
}

function isShellTool(tool: string): boolean {
  return /^(bash|shell|terminal|exec_command|run_command|execute_command|run_shell_command)$/i.test(tool);
}

function sameCall(a: GateReceipt, b: GateReceipt): boolean {
  if (a.tool_use_id && b.tool_use_id) return a.tool_use_id === b.tool_use_id;
  return a.kind === b.kind && a.text === b.text && a.paths.join("\0") === b.paths.join("\0");
}

function signalGroup(pid: number, sig: NodeJS.Signals) {
  if (!pid) return;
  try {
    process.kill(-pid, sig);
  } catch {
    try {
      process.kill(pid, sig);
    } catch {
      /* gone */
    }
  }
}

function firstLine(s: string): string {
  return (s.split("\n").find((l) => l.trim()) ?? s).trim().slice(0, 80);
}

function accumulate(prev: SessionUsage, u: Record<string, number | null>, kind?: CostKind): SessionUsage {
  const add = (a: number | null, b: number | null | undefined) => (b === null || b === undefined ? a : (a ?? 0) + b);
  return {
    ...((kind ?? prev.cost_kind) ? { cost_kind: kind ?? prev.cost_kind } : {}),
    cost_usd: add(prev.cost_usd, u.cost_usd),
    input_tokens: add(prev.input_tokens, u.input_tokens),
    output_tokens: add(prev.output_tokens, u.output_tokens),
    duration_ms: add(prev.duration_ms, u.duration_ms),
    turns: prev.turns + 1,
  };
}

async function gitInfo(cwd: string): Promise<{ repo: string | null; branch: string | null }> {
  try {
    const top = (await pexec("git", ["rev-parse", "--show-toplevel"], { cwd, timeout: 3_000 })).stdout.trim();
    const branch = (await pexec("git", ["rev-parse", "--abbrev-ref", "HEAD"], { cwd, timeout: 3_000 }).catch(() => ({ stdout: "" }))).stdout.trim();
    return { repo: basename(top), branch: branch && branch !== "HEAD" ? branch : null };
  } catch {
    return { repo: null, branch: null };
  }
}

/** `git diff --numstat HEAD` (tracked changes) + untracked files, for the summary. */
async function gitDiffStat(cwd: string): Promise<{ files: number; additions: number; deletions: number; changed: string[] } | null> {
  try {
    const num = (await pexec("git", ["diff", "--numstat", "HEAD"], { cwd, timeout: 5_000 })).stdout;
    let additions = 0;
    let deletions = 0;
    const changed: string[] = [];
    for (const l of num.split("\n").filter(Boolean)) {
      const [a, d, f] = l.split("\t");
      additions += Number(a) || 0;
      deletions += Number(d) || 0;
      if (f) changed.push(f);
    }
    const untracked = (await pexec("git", ["ls-files", "--others", "--exclude-standard"], { cwd, timeout: 5_000 })).stdout.split("\n").filter(Boolean);
    changed.push(...untracked);
    return { files: changed.length, additions, deletions, changed: changed.slice(0, 200) };
  } catch {
    return null;
  }
}
