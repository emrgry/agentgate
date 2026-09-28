import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { and, eq } from "drizzle-orm";
import { computeActionHash, newId } from "@agentgate/core";
import { DEFAULT_POLICY_YAML, evaluatePolicy, loadPolicyYaml, type PolicyEvaluation } from "@agentgate/policy-engine";
import { redactCommandSecrets, type ActionDraft, type PullRequestInfo } from "@agentgate/protocol";
import { verifyDecision } from "@agentgate/signing";
import { agents, approvals, devices } from "../db/schema.ts";
import { reportExecution, submitAction } from "../domain/actions.ts";
import type { ServiceDeps } from "../domain/context.ts";
import { DomainError } from "../domain/errors.ts";
import { endSession, startSession } from "../domain/sessions.ts";

/**
 * Phase 3 `open_pr`: push the session's branch and open a GitHub PR with the owner's `gh`.
 *
 * Safety:
 *   - refuses (409) on the default branch, detached HEAD, no `origin`, no commits to propose,
 *     a running turn, or a missing/unauthenticated `gh`;
 *   - never force-pushes (`git push -u origin <branch>` only);
 *   - `git push` and `gh pr create` go through the SAME policy + approval engine as agent
 *     actions (a push is at least "ask"): the signed open_pr command does NOT approve the push;
 *     the phone gets a separate approval request and, for v2 devices, its signed decision is
 *     verified here before anything runs.
 */

const RANK = { allow: 0, ask: 1, deny: 2 } as const;
const CONTROL_MACHINE = "agentgate-control-center";

export interface PrPreflight {
  top: string;
  branch: string;
  defaultBranch: string;
  ahead: number | null;
}

export function run(cmd: string, args: string[], cwd: string, env: NodeJS.ProcessEnv, timeout = 30_000): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((res) => {
    execFile(cmd, args, { cwd, env: { ...env, GIT_TERMINAL_PROMPT: "0", GH_PROMPT_DISABLED: "1", NO_COLOR: "1" }, timeout, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      const code = err ? (typeof (err as { code?: unknown }).code === "number" ? ((err as { code: number }).code) : 127) : 0;
      res({ code, stdout: String(stdout ?? ""), stderr: String(stderr ?? "") });
    });
  });
}

const refuse = (code: string, why: string) => new DomainError(409, code, `open_pr: ${why}`);

export const BRANCH_RE = /^[A-Za-z0-9._/-]{1,100}$/;

/** True for origin URLs gh can open PRs against (github.com, or a host gh is logged in to). */
export function isGithubRemote(url: string, ghHosts: string[] = []): boolean {
  const u = url.trim();
  let host: string | null = null;
  const scp = u.match(/^(?:[^@\s/]+@)?([^:\s/]+):(?!\/)/); // git@github.com:owner/repo.git
  const std = u.match(/^(?:https?|ssh|git|git\+ssh):\/\/(?:[^@/]+@)?([^/:]+)/i);
  if (std) host = std[1]!.toLowerCase();
  else if (scp && !u.startsWith("/") && !u.startsWith(".")) host = scp[1]!.toLowerCase();
  if (!host) return false; // local path, file://, …
  return host === "github.com" || host.endsWith(".github.com") || ghHosts.map((h) => h.toLowerCase()).includes(host);
}

export function validateNewBranch(name: string, defaultBranch: string): string | null {
  if (!BRANCH_RE.test(name)) return "branch names may only use letters, digits, . _ / - (max 100)";
  if (name.includes("..") || name.startsWith("-") || name.startsWith("/") || name.endsWith("/") || name.endsWith(".lock") || name.includes("//")) return "invalid branch name";
  if (name === defaultBranch || name === "HEAD") return `the new branch can't be the default branch (${defaultBranch})`;
  return null;
}

/**
 * Checks everything BEFORE anything is pushed or switched. With `createBranch` on the default
 * branch, the new branch is validated (name, not existing locally or on origin) and then
 * created at HEAD with `git switch -c` (the local default branch itself is unchanged).
 */
export async function prPreflight(cwd: string, env: NodeJS.ProcessEnv, o: { createBranch?: string } = {}): Promise<PrPreflight & { created: boolean }> {
  const g = (args: string[], t?: number) => run("git", args, cwd, env, t);
  const top = await g(["rev-parse", "--show-toplevel"]);
  if (top.code !== 0) throw refuse("not_a_repo", "the session's directory is not a git repository");
  let b = (await g(["symbolic-ref", "--short", "-q", "HEAD"])).stdout.trim();
  if (!b) throw refuse("detached_head", "HEAD is detached — check out a branch first");
  // The configured URL (not insteadOf-rewritten): that's what gh will look at.
  const originUrl = (await g(["config", "--get", "remote.origin.url"])).stdout.trim();
  if (!originUrl) throw refuse("no_origin", "the repository has no 'origin' remote");
  const gh = await run("gh", ["--version"], cwd, env, 10_000);
  if (gh.code !== 0) throw refuse("gh_missing", "GitHub CLI (gh) not found on the computer's PATH — install it and run `gh auth login`");
  const auth = await run("gh", ["auth", "status"], cwd, env, 15_000);
  if (auth.code !== 0) throw refuse("gh_unauthenticated", "gh is not logged in — run `gh auth login` on the computer");
  const ghHosts = [...`${auth.stdout}\n${auth.stderr}`.matchAll(/^\s*(?:✓\s*)?(?:Logged in to\s+)?([a-z0-9.-]+\.[a-z]{2,})\b/gim)].map((m) => m[1]!);
  if (!isGithubRemote(originUrl, ghHosts)) {
    throw refuse("not_github", `origin (${originUrl}) is not a GitHub repository — gh can't open a pull request there; nothing was pushed`);
  }
  let def = (await g(["symbolic-ref", "--short", "-q", "refs/remotes/origin/HEAD"])).stdout.trim().replace(/^origin\//, "");
  if (!def) {
    const ls = await g(["ls-remote", "--symref", "origin", "HEAD"], 15_000);
    def = ls.stdout.match(/^ref: refs\/heads\/(\S+)\s+HEAD/m)?.[1] ?? "";
  }
  if (!def) def = "main";
  const onDefault = b === def || ["main", "master"].includes(b);
  let created = false;
  if (onDefault && !o.createBranch) throw refuse("default_branch", `on the default branch (${b}) — AgentGate won't push it; open the PR on a new branch (create_branch)`);
  let newBranch: string | null = null;
  if (onDefault && o.createBranch) {
    const name = o.createBranch.trim();
    const bad = validateNewBranch(name, def);
    if (bad) throw new DomainError(409, "invalid_branch", `open_pr: ${bad}`);
    const fmt = await g(["check-ref-format", "--branch", name]);
    if (fmt.code !== 0) throw new DomainError(409, "invalid_branch", `open_pr: invalid branch name '${name}'`);
    if ((await g(["show-ref", "--verify", "-q", `refs/heads/${name}`])).code === 0) throw new DomainError(409, "branch_exists", `open_pr: branch '${name}' already exists locally`);
    const remote = await g(["ls-remote", "--heads", "origin", name], 15_000);
    if (remote.code === 0 && remote.stdout.trim()) throw new DomainError(409, "branch_exists", `open_pr: branch '${name}' already exists on origin`);
    newBranch = name;
  }
  let ahead: number | null = null;
  const remoteDef = await g(["rev-parse", "--verify", "-q", `refs/remotes/origin/${def}`]);
  if (remoteDef.code === 0) {
    const c = await g(["rev-list", "--count", `refs/remotes/origin/${def}..HEAD`]);
    ahead = c.code === 0 ? Number(c.stdout.trim()) : null;
    if (ahead === 0) throw refuse("no_commits", `no commits on ${newBranch ?? b} beyond ${def} — nothing to propose`);
  }
  if (newBranch) {
    const sw = await g(["switch", "-c", newBranch]);
    if (sw.code !== 0) throw new DomainError(409, "branch_create_failed", `open_pr: git switch -c ${newBranch} failed: ${sw.stderr.trim().slice(0, 300)}`);
    b = newBranch;
    created = true;
  }
  return { top: top.stdout.trim(), branch: b, defaultBranch: def, ahead, created };
}

export interface GateOptions {
  deps: ServiceDeps;
  userId: string;
  /** Owner's policy file (merged with the default policy; the stricter decision wins). */
  policyPath: string | null;
  requireDeviceSignatures: boolean;
  /** Max wait for the phone (ms). */
  approvalWaitMs: number;
  onStatus: (step: string, extra?: Record<string, unknown>) => Promise<void>;
}

function evaluate(draft: ActionDraft, policyPath: string | null, floorAsk: boolean): PolicyEvaluation {
  const evals = [evaluatePolicy(loadPolicyYaml(DEFAULT_POLICY_YAML), draft)];
  if (policyPath && existsSync(policyPath)) {
    try {
      evals.push(evaluatePolicy(loadPolicyYaml(readFileSync(policyPath, "utf8")), draft));
    } catch {
      // An unreadable/invalid owner policy must not loosen anything: treat as ask.
      evals.push({ ...evals[0]!, decision: "ask", reason: "owner policy unreadable", rule_id: null });
    }
  }
  const worst = evals.reduce((a, e) => (RANK[e.decision] > RANK[a.decision] ? e : a));
  if (floorAsk && worst.decision === "allow") return { ...worst, decision: "ask", reason: "a push always needs your approval", rule_id: worst.rule_id };
  return worst;
}

async function controlAgentSession(o: GateOptions): Promise<string> {
  const { deps, userId } = o;
  let [agent] = await deps.db.select().from(agents).where(and(eq(agents.user_id, userId), eq(agents.machine_id, CONTROL_MACHINE), eq(agents.type, "agentgate")));
  if (!agent) {
    [agent] = await deps.db
      .insert(agents)
      .values({ id: newId("agt"), user_id: userId, name: "Control Center", type: "agentgate", machine_id: CONTROL_MACHINE, created_at: deps.clock.now() })
      .onConflictDoNothing()
      .returning();
    if (!agent) [agent] = await deps.db.select().from(agents).where(and(eq(agents.user_id, userId), eq(agents.machine_id, CONTROL_MACHINE), eq(agents.type, "agentgate")));
  }
  return (await startSession(deps, userId, agent!.id)).id;
}

/**
 * Runs one command through policy → (ask) phone approval → verified decision → execution,
 * reporting the execution like the daemon does. Throws on deny / expiry / bad signature.
 */
export async function gatedRun(o: GateOptions, spec: { cmd: string; args: string[]; cwd: string; env: NodeJS.ProcessEnv; resource?: { type: string; name: string }; floorAsk: boolean; step: string; timeoutMs?: number }) {
  const { deps, userId } = o;
  const sessionId = await controlAgentSession(o);
  try {
    const command = [spec.cmd, ...spec.args.map((a) => (/^[\w./:@=-]+$/.test(a) ? a : `'${a.replace(/'/g, `'\\''`)}'`))].join(" ");
    const draft: ActionDraft = {
      session_id: sessionId,
      agent: { type: "agentgate" },
      action: { category: "shell", operation: "execute", tool: "open_pr", command: command.slice(0, 16_000), cwd: spec.cwd },
      resource: spec.resource ?? {},
      context: {},
    };
    const ev = evaluate(draft, o.policyPath, spec.floorAsk);
    const hash = computeActionHash(draft);
    const rec = await submitAction(deps, userId, {
      action: draft,
      policy: { decision: ev.decision, rule_id: ev.rule_id, risk: ev.risk.level, reason: ev.reason },
      action_hash: hash,
      approval_ttl_seconds: Math.max(30, Math.min(900, Math.floor(o.approvalWaitMs / 1000))),
    });
    const actionId = rec.action.action_id;
    if (ev.decision === "deny") throw new Error(`${spec.step}: denied by policy (${ev.reason})`);
    if (ev.decision === "ask") {
      await o.onStatus(`${spec.step}_awaiting_approval`, { approval_id: rec.approval?.approval_id ?? null });
      const approved = await waitApproval(o, actionId);
      if (approved.status !== "approved") {
        await reportExecution(deps, userId, actionId, { status: "blocked", detail: `approval ${approved.status}` }).catch(() => {});
        throw new Error(`${spec.step}: approval ${approved.status}`);
      }
      if (approved.signed_decision || o.requireDeviceSignatures) {
        const dev = approved.resolved_by_device_id ? (await deps.db.select().from(devices).where(eq(devices.id, approved.resolved_by_device_id)))[0] : undefined;
        const v = approved.signed_decision
          ? verifyDecision(approved.signed_decision, {
              publicKeyFor: (id) => (dev && id === dev.id && !dev.revoked_at ? dev.public_key : null),
              expectedApprovalId: approved.id,
              expectedActionHash: hash,
              expectedSessionId: sessionId,
              now: deps.clock.now(),
              requireDecision: "approve",
            })
          : ({ ok: false, reason: "missing_signature" } as const);
        if (!v.ok) {
          await reportExecution(deps, userId, actionId, { status: "blocked", detail: `signed decision rejected: ${v.reason}` }).catch(() => {});
          throw new Error(`${spec.step}: phone signature rejected (${v.reason})`);
        }
      }
    }
    await o.onStatus(spec.step);
    await reportExecution(deps, userId, actionId, { status: "started" });
    const r = await run(spec.cmd, spec.args, spec.cwd, spec.env, spec.timeoutMs ?? 120_000);
    await reportExecution(deps, userId, actionId, r.code === 0 ? { status: "completed", exit_code: 0 } : { status: "failed", exit_code: r.code, detail: redactCommandSecrets(r.stderr).slice(-1000) });
    if (r.code !== 0) throw new Error(`${spec.step} failed (exit ${r.code}): ${redactCommandSecrets(r.stderr || r.stdout).trim().slice(-500)}`);
    return r;
  } finally {
    await endSession(deps, userId, sessionId).catch(() => {});
  }
}

async function waitApproval(o: GateOptions, actionId: string) {
  const end = Date.now() + o.approvalWaitMs + 5_000;
  for (;;) {
    const [a] = await o.deps.db.select().from(approvals).where(eq(approvals.action_id, actionId));
    if (a && a.status !== "pending") return a;
    if (!a || Date.now() > end) return { ...(a ?? ({} as typeof approvals.$inferSelect)), status: "expired" as const };
    await new Promise((r) => setTimeout(r, 250));
  }
}

export function parsePrUrl(out: string, draft: boolean, title: string): PullRequestInfo | null {
  const m = out.match(/(https?:\/\/\S+\/pull\/(\d+))\s*$/m);
  if (!m) return null;
  return { url: m[1]!, number: Number(m[2]), state: draft ? "draft" : "open", title: title.slice(0, 300) };
}
