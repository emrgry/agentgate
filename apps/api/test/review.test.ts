import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import { claudeCodeProvider } from "@agentgate/adapter-claude-code";
import { ApprovalDetail, ChangeSet, FileDiff } from "@agentgate/protocol";
import { signDecision } from "@agentgate/signing";
import { tasks as tasksTable } from "../src/db/schema.ts";
import type { SupervisorOptions } from "../src/control/supervisor.ts";
import { controlHarness, FAKE_CLAUDE, type Phone } from "./control-harness.ts";

/** Control Center Phase 3: base-relative changes, diffs, test runs, review commands, open_pr. */

const T = 60_000;
const c = controlHarness();
afterEach(() => c.close());
const rnd = (n: number) => new Uint8Array(randomBytes(n));

function gitRepo(): string {
  const d = realpathSync(mkdtempSync(join(tmpdir(), "ag-repo-")));
  const g = (...a: string[]) => execFileSync("git", a, { cwd: d, stdio: "ignore" });
  g("init", "-q", "-b", "main");
  g("config", "user.email", "t@t");
  g("config", "user.name", "t");
  writeFileSync(join(d, "a.txt"), "one\n");
  writeFileSync(join(d, "b.txt"), "bee\n");
  g("add", "-A");
  g("commit", "-qm", "init");
  return d;
}

function fakeGh(): string {
  const bin = realpathSync(mkdtempSync(join(tmpdir(), "ag-ghbin-")));
  writeFileSync(
    join(bin, "gh"),
    `#!/bin/sh
case "$1" in
  --version) [ "$FAKE_GH" = missing ] && exit 127; echo "gh version 2.99.0"; exit 0 ;;
  auth) [ "$FAKE_GH" = unauth ] && { echo "You are not logged into any GitHub hosts" >&2; exit 1; }; exit 0 ;;
  pr) printf '%s\\n' "$*" >> "$FAKE_GH_LOG"; echo "https://github.com/octo/repo/pull/42"; exit 0 ;;
esac
exit 1
`,
  );
  chmodSync(join(bin, "gh"), 0o755);
  return bin;
}

function control(env: Record<string, string> = {}): SupervisorOptions {
  const gh = fakeGh();
  return {
    providers: { "claude-code": claudeCodeProvider({ binary: FAKE_CLAUDE }) },
    hookSettingsPath: () => "/dev/null",
    turnEnv: () => ({ ...process.env, PATH: `${gh}:${process.env.PATH}`, FAKE_GH_LOG: join(gh, "gh.log"), ...env }),
    stopGraceMs: 300,
    tickMs: 0,
    prApprovalWaitMs: 30_000,
  };
}

const changes = async (agent: string, id: string, task?: string) =>
  ChangeSet.parse((await c.inject("GET", `/v1/agent-sessions/${id}/changes${task ? `?task_id=${task}` : ""}`, undefined, { token: agent })).json);

describe("changes + diff relative to the captured base", () => {
  it("pre-dirty files show only the session's edits; per-task change sets are frozen at task end", async () => {
    const dir = gitRepo();
    writeFileSync(join(dir, "a.txt"), "one\ndirty before\n"); // dirty before the session
    writeFileSync(join(dir, "notes.txt"), "untracked before\n");
    const { agent, phone } = await c.server(control());
    const id = await c.start(agent, dir, "write:a.txt=one\\ndirty before\\nby task 1\\n;say:t1");
    await c.until(() => c.session(agent, id), (s) => s.status === "waiting_input");
    await c.cmd(phone, id, { command: "enqueue_task", text: "write:c.txt=new\\n;say:t2" });
    const ts = await c.until(() => c.tasks(agent, id), (x) => x.length === 2 && x[1]!.status === "completed");

    const all = await changes(agent, id);
    expect(all.files.map((f) => [f.path, f.status, f.additions, f.deletions])).toEqual([
      ["a.txt", "modified", 1, 0],
      ["c.txt", "added", 1, 0],
    ]);
    expect(all.base_ref).toMatch(/^[0-9a-f]{40}$/);
    expect(all.branch).toBe("main");
    const t1 = await changes(agent, id, ts[0]!.id);
    const t2 = await changes(agent, id, ts[1]!.id);
    expect(t1.files.map((f) => f.path)).toEqual(["a.txt"]);
    expect(t2.files.map((f) => f.path)).toEqual(["c.txt"]);
    // Summaries use the base too (not HEAD, which would count notes.txt and the pre-dirty line).
    expect(ts[0]!.summary).toMatchObject({ files_changed: 1, additions: 1, changed_files: ["a.txt"] });
    expect((await c.session(agent, id)).summary).toMatchObject({ files_changed: 2, additions: 2 });

    const d = FileDiff.parse((await c.inject("GET", `/v1/agent-sessions/${id}/diff?path=a.txt`, undefined, { token: phone.token })).json);
    expect(d.patch).toContain("+by task 1");
    expect(d.patch).not.toContain("+dirty before");
    for (const bad of ["../etc/passwd", "/etc/passwd", ".git/config", "a/../../x"]) {
      const r = await c.inject("GET", `/v1/agent-sessions/${id}/diff?path=${encodeURIComponent(bad)}`, undefined, { token: phone.token });
      expect(r.status, bad).toBe(400);
    }
    expect((await c.inject("GET", `/v1/agent-sessions/${id}/changes?task_id=tsk_nope`, undefined, { token: agent })).status).toBe(404);
  }, T);

  it("not a git repo → empty change set, no crash", async () => {
    const { agent } = await c.server(control());
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "ag-norepo-")));
    const id = await c.start(agent, dir, "say:hi");
    await c.until(() => c.session(agent, id), (s) => s.status === "waiting_input");
    expect(await changes(agent, id)).toMatchObject({ files: [], base_ref: null, truncated: false });
  }, T);
});

describe("test runs", () => {
  it("a Bash test command + output → TestRun on the session and the task; output tail kept out of the timeline", async () => {
    const dir = gitRepo();
    const { agent } = await c.server(control());
    const out = " Test Files  3 passed (3)\\n      Tests  1 failed | 9 passed (10)\\n API_TOKEN=abc123";
    const id = await c.start(agent, dir, `test:npx vitest run|1|${out};test:ls -la|0|x;say:done`);
    await c.until(() => c.session(agent, id), (s) => s.status === "waiting_input");
    const cs = await changes(agent, id);
    expect(cs.tests).toMatchObject({ command: "npx vitest run", ok: false, passed: 9, failed: 1, skipped: 0 });
    expect(cs.tests!.output_tail).toContain("API_TOKEN=***");
    const t = (await c.tasks(agent, id))[0]!;
    expect((await changes(agent, id, t.id)).tests?.failed).toBe(1);
    const evs = await c.events(agent, id);
    expect(evs.find((e) => e.type === "test.run")!.payload).toMatchObject({ ok: false, passed: 9, failed: 1, task_id: t.id });
    expect(evs.filter((e) => e.type === "tool.result").every((e) => !("output_tail" in e.payload))).toBe(true);
    expect(evs.filter((e) => e.type === "test.run")).toHaveLength(1); // `ls` is not a test run
  }, T);
});

describe("review commands", () => {
  it("request_changes on an idle session → a new turn with the 'Review feedback: ' prefix", async () => {
    const dir = gitRepo();
    const { agent, phone } = await c.server(control());
    const id = await c.start(agent, dir, "say:first");
    await c.until(() => c.session(agent, id), (s) => s.status === "waiting_input");
    expect((await c.cmd(phone, id, { command: "request_changes", text: "say:fixed" })).json.status).toBe("applied");
    const s = await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input" && x.usage.turns === 2);
    const msgs = (await c.events(agent, id)).filter((e) => e.type === "message.user").map((e) => e.payload.text);
    expect(msgs.at(-1)).toBe("Review feedback: say:fixed");
    expect(s.usage.turns).toBe(2);
  }, T);

  it("approve_next marks the task reviewed and continues a queue held after a failure", async () => {
    const dir = gitRepo();
    const { agent, phone } = await c.server(control());
    const id = await c.start(agent, dir, "ticks:3;fail");
    await c.until(() => c.session(agent, id), (s) => s.status === "running");
    await c.cmd(phone, id, { command: "enqueue_task", text: "say:t2 done" });
    await c.until(() => c.session(agent, id), (s) => s.status === "failed");
    const [t1] = await c.tasks(agent, id);
    expect((await c.cmd(phone, id, { command: "approve_next", task_id: t1!.id })).json.status).toBe("applied");
    const ts = await c.until(() => c.tasks(agent, id), (x) => x[1]!.status === "completed");
    expect(ts.map((t) => t.status)).toEqual(["failed", "completed"]);
    const [row] = await c.h.database.db.select().from(tasksTable).where(eq(tasksTable.id, t1!.id));
    expect(row!.reviewed_at).toBeInstanceOf(Date);
  }, T);
});

// ── open_pr ──────────────────────────────────────────────────────────────────

/**
 * Work repo whose origin is a GitHub URL (what gh sees), rewritten by `url.<bare>.insteadOf`
 * so pushes land in a local bare repo. `local: true` keeps a plain local-path origin.
 */
function prRepo(o: { branch?: string; local?: boolean } = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "ag-pr-")));
  const origin = join(root, "origin.git");
  const dir = join(root, "work");
  mkdirSync(dir);
  execFileSync("git", ["init", "-q", "--bare", "-b", "main", origin]);
  const g = (...a: string[]) => execFileSync("git", a, { cwd: dir, stdio: "ignore" });
  g("init", "-q", "-b", "main");
  g("config", "user.email", "t@t");
  g("config", "user.name", "t");
  writeFileSync(join(dir, "a.txt"), "one\n");
  g("add", "-A");
  g("commit", "-qm", "init");
  if (o.local) g("remote", "add", "origin", origin);
  else {
    g("remote", "add", "origin", "https://github.com/octo/repo.git");
    g("config", `url.${origin}.insteadOf`, "https://github.com/octo/repo.git");
  }
  g("push", "-q", "origin", "main");
  g("remote", "set-head", "origin", "main");
  if (o.branch) {
    g("checkout", "-q", "-b", o.branch);
    writeFileSync(join(dir, "feature.txt"), "feature\n");
    g("add", "-A");
    g("commit", "-qm", "feature");
  }
  return { dir, origin };
}

async function approveAll(p: Phone, decision: "approve" | "deny" = "approve") {
  const items = (await c.inject("GET", "/v1/approvals?status=pending", undefined, { token: p.token })).json.items.map((x: unknown) => ApprovalDetail.parse(x));
  for (const a of items) {
    const now = c.h.clock.now();
    const signed = signDecision(
      {
        v: 2,
        approval_id: a.approval.approval_id,
        action_id: a.action.action_id,
        session_id: a.action.session_id,
        action_hash: a.action_hash,
        decision,
        device_id: p.id,
        issued_at: now.toISOString(),
        expires_at: new Date(Math.min(now.getTime() + 60_000, Date.parse(a.approval.expires_at))).toISOString(),
        nonce: Buffer.from(rnd(18)).toString("base64url"),
      },
      p.kp.privateKey,
    );
    const r = await c.inject("POST", `/v1/approvals/${a.approval.approval_id}/${decision}`, { device_id: p.id, signed_decision: signed }, { token: p.token });
    expect(r.status, JSON.stringify(r.json)).toBe(200);
  }
  return items as ApprovalDetail[];
}

describe("open_pr", () => {
  it("push needs its own phone approval (signed command ≠ push approval); then gh pr create → PullRequestInfo + pr_ready", async () => {
    const { dir, origin } = prRepo({ branch: "feat/x" });
    const ctl = control();
    const { agent, phone } = await c.server(ctl, { sessionPushIntervalMs: 0 });
    const id = await c.start(agent, dir, "say:implemented the feature");
    await c.until(() => c.session(agent, id), (s) => s.status === "waiting_input");
    const r = await c.cmd(phone, id, { command: "open_pr", title: "Add feature", draft: true });
    expect(r.json.status).toBe("queued");
    // The push waits for a SEPARATE approval on the phone.
    const pending = await c.until(
      async () => (await c.inject("GET", "/v1/approvals?status=pending", undefined, { token: phone.token })).json.items as any[],
      (x) => x.length === 1,
      20_000,
    );
    expect(pending[0].action.action.command).toBe("git push -u origin feat/x");
    expect(pending[0].action.action.command).not.toMatch(/--force|-f\b/);
    expect(execFileSync("git", ["--git-dir", origin, "branch", "--list", "feat/x"], { encoding: "utf8" }).trim()).toBe(""); // not pushed yet
    // Approve the push (and gh pr create if the policy asks for it too).
    let evs: Array<{ type: string; payload: any }> = [];
    const end = Date.now() + 30_000;
    while (Date.now() < end) {
      await approveAll(phone);
      evs = await c.events(agent, id);
      if (evs.some((e) => e.type === "pr.opened" || e.type === "pr.failed")) break;
      await new Promise((res) => setTimeout(res, 100));
    }
    expect(evs.find((e) => e.type === "pr.failed")).toBeUndefined();
    expect(evs.find((e) => e.type === "pr.opened")!.payload).toEqual({ url: "https://github.com/octo/repo/pull/42", number: 42, state: "draft", title: "Add feature" });
    expect(execFileSync("git", ["--git-dir", origin, "branch", "--list", "feat/x"], { encoding: "utf8" }).trim()).toBe("feat/x");
    const ghLog = readFileSync(String(ctl.turnEnv().FAKE_GH_LOG), "utf8");
    expect(ghLog).toContain("pr create --title Add feature");
    expect(ghLog).toContain("--head feat/x --base main --draft");
    expect((await changes(agent, id)).pr).toMatchObject({ number: 42, state: "draft" });
    expect(c.h.push.sent.some((m) => m.data.session_id === id && m.data.kind === "pr_ready" && m.body === "Claude Code: pull request ready")).toBe(true);
    // A second open_pr is refused while that PR is open.
    const again = await c.cmd(phone, id, { command: "open_pr" });
    expect(again.json).toMatchObject({ status: "rejected" });
    expect(again.json.reason).toMatch(/already exists/);
    expect(again.json.reason_code).toBe("pr_exists");
  }, T);

  it("a denied push → pr.failed, nothing pushed", async () => {
    const { dir, origin } = prRepo({ branch: "feat/y" });
    const { agent, phone } = await c.server(control());
    const id = await c.start(agent, dir, "say:ok");
    await c.until(() => c.session(agent, id), (s) => s.status === "waiting_input");
    await c.cmd(phone, id, { command: "open_pr" });
    await c.until(async () => (await approveAll(phone, "deny")).length, (n) => n === 1, 20_000);
    const evs = await c.until(() => c.events(agent, id), (x) => x.some((e) => e.type === "pr.failed"), 20_000);
    expect(evs.find((e) => e.type === "pr.failed")!.payload.error).toMatch(/push: approval denied/);
    expect(execFileSync("git", ["--git-dir", origin, "branch", "--list", "feat/y"], { encoding: "utf8" }).trim()).toBe("");
  }, T);

  it.each([
    ["on the default branch", {}, {}, /default branch \(main\)/, "default_branch"],
    ["gh missing", { branch: "feat/z" }, { FAKE_GH: "missing" }, /GitHub CLI \(gh\) not found/, "gh_missing"],
    ["gh not logged in", { branch: "feat/z" }, { FAKE_GH: "unauth" }, /gh is not logged in/, "gh_unauthenticated"],
    ["origin is not GitHub (local bare repo)", { branch: "feat/z", local: true }, {}, /is not a GitHub repository.*nothing was pushed/, "not_github"],
  ] as const)("refuses: %s", async (_n, repoOpts, env, re, code) => {
    const { dir } = prRepo(repoOpts);
    const { agent, phone } = await c.server(control(env));
    const id = await c.start(agent, dir, "say:ok");
    await c.until(() => c.session(agent, id), (s) => s.status === "waiting_input");
    const r = await c.cmd(phone, id, { command: "open_pr" });
    expect(r.json.status).toBe("rejected");
    expect(r.json.reason).toMatch(re);
    expect(r.json.reason_code).toBe(code);
    expect((await c.inject("GET", "/v1/approvals?status=pending", undefined, { token: phone.token })).json.items).toEqual([]);
  }, T);

  it("refuses: no commits beyond the default branch; not a repo", async () => {
    const { dir } = prRepo();
    execFileSync("git", ["checkout", "-q", "-b", "empty"], { cwd: dir });
    const { agent, phone } = await c.server(control());
    const id = await c.start(agent, dir, "say:ok");
    await c.until(() => c.session(agent, id), (s) => s.status === "waiting_input");
    const nc = (await c.cmd(phone, id, { command: "open_pr" })).json;
    expect(nc.reason).toMatch(/nothing to propose/);
    expect(nc.reason_code).toBe("no_commits");
    const plain = realpathSync(mkdtempSync(join(tmpdir(), "ag-plain-")));
    const id2 = await c.start(agent, plain, "say:ok");
    await c.until(() => c.session(agent, id2), (s) => s.status === "waiting_input");
    expect((await c.cmd(phone, id2, { command: "open_pr" })).json).toMatchObject({ reason_code: "not_a_repo" });
  }, T);
});

describe("open_pr create_branch (from the default branch)", () => {
  function onMainWithCommit() {
    const r = prRepo();
    const g = (...a: string[]) => execFileSync("git", a, { cwd: r.dir, stdio: "ignore" });
    writeFileSync(join(r.dir, "work.txt"), "agent work\n");
    g("add", "-A");
    g("commit", "-qm", "agent work on main");
    return { ...r, g };
  }

  it("creates the branch at HEAD (main unchanged), pushes only it after approval, PR base = default branch", async () => {
    const { dir, origin } = onMainWithCommit();
    const mainBefore = execFileSync("git", ["rev-parse", "main"], { cwd: dir, encoding: "utf8" }).trim();
    const ctl = control();
    const { agent, phone } = await c.server(ctl, { sessionPushIntervalMs: 0 });
    const id = await c.start(agent, dir, "say:done on main");
    await c.until(() => c.session(agent, id), (s) => s.status === "waiting_input");
    const r = await c.cmd(phone, id, { command: "open_pr", title: "From main", create_branch: "agentgate/fix-1" } as never);
    expect(r.json.status).toBe("queued");
    expect(execFileSync("git", ["symbolic-ref", "--short", "HEAD"], { cwd: dir, encoding: "utf8" }).trim()).toBe("agentgate/fix-1");
    expect(execFileSync("git", ["rev-parse", "main"], { cwd: dir, encoding: "utf8" }).trim()).toBe(mainBefore);
    expect((await c.session(agent, id)).branch).toBe("agentgate/fix-1");
    const pending = await c.until(async () => (await c.inject("GET", "/v1/approvals?status=pending", undefined, { token: phone.token })).json.items as any[], (x) => x.length === 1, 20_000);
    expect(pending[0].action.action.command).toBe("git push -u origin agentgate/fix-1");
    let evs: Array<{ type: string; payload: any }> = [];
    const end = Date.now() + 30_000;
    while (Date.now() < end) {
      await approveAll(phone);
      evs = await c.events(agent, id);
      if (evs.some((e) => e.type === "pr.opened" || e.type === "pr.failed")) break;
      await new Promise((res) => setTimeout(res, 100));
    }
    expect(evs.find((e) => e.type === "pr.opened")).toBeDefined();
    expect(evs.find((e) => e.type === "pr.status" && e.payload.step === "branch_created")!.payload).toMatchObject({ branch: "agentgate/fix-1", base: "main" });
    expect(readFileSync(String(ctl.turnEnv().FAKE_GH_LOG), "utf8")).toContain("--head agentgate/fix-1 --base main");
    expect(execFileSync("git", ["--git-dir", origin, "branch", "--list"], { encoding: "utf8" })).toContain("agentgate/fix-1");
    // origin/main untouched (only the new branch was pushed)
    expect(execFileSync("git", ["--git-dir", origin, "rev-parse", "main"], { encoding: "utf8" }).trim()).not.toBe(mainBefore);
  }, T);

  it.each([
    ["-evil", "invalid_branch"],
    ["a..b", "invalid_branch"],
    ["has space", "invalid_branch"],
    ["main", "invalid_branch"],
    ["x/../y", "invalid_branch"],
  ])("rejects branch name %s (%s) without touching the repo", async (name, code) => {
    const { dir } = onMainWithCommit();
    const { agent, phone } = await c.server(control());
    const id = await c.start(agent, dir, "say:ok");
    await c.until(() => c.session(agent, id), (s) => s.status === "waiting_input");
    const r = await c.cmd(phone, id, { command: "open_pr", create_branch: name } as never);
    expect(r.json).toMatchObject({ status: "rejected", reason_code: code });
    expect(execFileSync("git", ["symbolic-ref", "--short", "HEAD"], { cwd: dir, encoding: "utf8" }).trim()).toBe("main");
  }, T);

  it("rejects a branch that exists locally or on origin", async () => {
    const { dir, g } = onMainWithCommit();
    g("branch", "taken-local");
    g("push", "-q", "origin", "main:taken-remote");
    const { agent, phone } = await c.server(control());
    const id = await c.start(agent, dir, "say:ok");
    await c.until(() => c.session(agent, id), (s) => s.status === "waiting_input");
    for (const [name, where] of [["taken-local", /locally/], ["taken-remote", /on origin/]] as const) {
      const r = await c.cmd(phone, id, { command: "open_pr", create_branch: name } as never);
      expect(r.json).toMatchObject({ status: "rejected", reason_code: "branch_exists" });
      expect(r.json.reason).toMatch(where);
    }
    expect(execFileSync("git", ["symbolic-ref", "--short", "HEAD"], { cwd: dir, encoding: "utf8" }).trim()).toBe("main");
  }, T);

  it("other commands carry reason codes too (e.g. pause while idle → not_allowed_in_state)", async () => {
    const { agent, phone, dir } = await c.server(control());
    const id = await c.start(agent, dir, "say:ok");
    await c.until(() => c.session(agent, id), (s) => s.status === "waiting_input");
    expect((await c.cmd(phone, id, { command: "pause" })).json).toMatchObject({ status: "rejected", reason_code: "not_allowed_in_state" });
    expect((await c.cmd(phone, id, { command: "instruct", text: "say:x" })).json).toMatchObject({ status: "applied", reason_code: null });
  }, T);
});
