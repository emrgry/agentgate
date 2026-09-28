import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { claudeCodeProvider } from "@agentgate/adapter-claude-code";
import { SessionMetrics } from "@agentgate/protocol";
import type { SupervisorOptions } from "../src/control/supervisor.ts";
import { controlHarness, FAKE_CLAUDE } from "./control-harness.ts";

/**
 * Real-device bug: Claude Code runs Bash tool commands in their OWN process group, so signals
 * to the turn's pgid missed them. Pause/resume/stop/kill act on the whole descendant tree;
 * processes that outlive a turn are recorded (and auto-continued when they finish).
 */

const T = 60_000;
const c = controlHarness();
afterEach(() => c.close());

function setup(env: Record<string, string> = {}, extra: Partial<SupervisorOptions> = {}) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "ag-tree-")));
  const pidFile = join(dir, "child.pid");
  const log = join(dir, "agent.log");
  const ctl: SupervisorOptions = {
    providers: { "claude-code": claudeCodeProvider({ binary: FAKE_CLAUDE }) },
    hookSettingsPath: () => "/dev/null",
    turnEnv: () => ({ ...process.env, FAKE_CHILD_PID: pidFile, FAKE_AGENT_LOG: log, ...env }),
    stopGraceMs: 300,
    tickMs: 150,
    ...extra,
  };
  return { ctl, pidFile, log };
}
const state = (pid: number) => {
  try {
    return execFileSync("ps", ["-o", "state=", "-p", String(pid)], { encoding: "utf8" }).trim();
  } catch {
    return ""; // gone
  }
};
const alive = (pid: number) => {
  try {
    process.kill(pid, 0);
    return state(pid) !== "" && !state(pid).startsWith("Z");
  } catch {
    return false;
  }
};
async function childPids(file: string, n = 1): Promise<number[]> {
  const t = await c.until(async () => { try { return readFileSync(file, "utf8"); } catch { return ""; } }, (v) => v.trim().split("\n").filter(Boolean).length >= n);
  return t.trim().split("\n").map(Number);
}
const userMsgs = async (agent: string, id: string) => (await c.events(agent, id)).filter((e) => e.type === "message.user").map((e) => ({ text: String(e.payload.text), origin: e.payload.origin as string | undefined }));

describe("signals reach tool commands in their own process group", () => {
  it("pause freezes the escaped child (state T), resume continues it, stop kills it", async () => {
    const { ctl, pidFile } = setup();
    const { agent, phone, dir } = await c.server(ctl);
    const id = await c.start(agent, dir, "escape");
    await c.until(() => c.session(agent, id), (s) => s.status === "running");
    const [child] = await childPids(pidFile);
    expect(state(child!)).not.toMatch(/^T/);
    await c.cmd(phone, id, { command: "pause" });
    await c.until(async () => state(child!), (s) => s.startsWith("T"), 5_000);
    await c.cmd(phone, id, { command: "resume" });
    await c.until(async () => state(child!), (s) => s !== "" && !s.startsWith("T"), 5_000);
    await c.cmd(phone, id, { command: "stop" });
    await c.until(() => c.session(agent, id), (s) => s.status === "stopped");
    await c.until(async () => alive(child!), (v) => v === false, 5_000);
  }, T);
});

describe("background processes (outlive the turn)", () => {
  it("recorded at turn end (event + metrics), NOT killed; kill on the idle session kills them (no auto-continue)", async () => {
    const { ctl, pidFile } = setup();
    const { agent, phone, dir } = await c.server(ctl);
    const id = await c.start(agent, dir, "bg:30000;say:started it");
    const s = await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input");
    const [child] = await childPids(pidFile);
    const ev = (await c.events(agent, id)).find((e) => e.type === "process.background")!;
    expect(ev.payload).toMatchObject({ pid: child });
    expect(String(ev.payload.command)).toMatch(/setTimeout/);
    expect(alive(child!)).toBe(true);
    const m = SessionMetrics.parse((await c.inject("GET", `/v1/agent-sessions/${id}/metrics`, undefined, { token: agent })).json);
    expect(m.background_processes?.map((p) => p.pid)).toEqual([child]);
    expect(s.can.kill).toBe(true);
    await c.cmd(phone, id, { command: "kill" });
    await c.until(() => c.session(agent, id), (x) => x.status === "killed");
    await c.until(async () => alive(child!), (v) => v === false, 5_000);
    await new Promise((r) => setTimeout(r, 1_000));
    expect((await userMsgs(agent, id)).some((m) => m.origin === "agentgate")).toBe(false);
  }, T);

  it("stop on the idle session terminates them (and no auto-continue follows)", async () => {
    const { ctl, pidFile } = setup();
    const { agent, phone, dir } = await c.server(ctl);
    const id = await c.start(agent, dir, "bg:1500;say:x");
    await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input");
    const [child] = await childPids(pidFile);
    await c.cmd(phone, id, { command: "stop" });
    await c.until(() => c.session(agent, id), (x) => x.status === "completed");
    await c.until(async () => alive(child!), (v) => v === false, 5_000);
    await new Promise((r) => setTimeout(r, 2_000));
    expect((await userMsgs(agent, id)).some((m) => m.origin === "agentgate")).toBe(false);
  }, T);
});

describe("auto-continue when background commands finish", () => {
  it("child exits → process.background_finished + a --resume turn with the AgentGate instruction (origin agentgate)", async () => {
    const { ctl } = setup();
    const { agent, dir } = await c.server(ctl);
    const id = await c.start(agent, dir, "bg:800;say:I'll let you know when it finishes");
    const s = await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input" && x.usage.turns === 2, 20_000);
    const fin = (await c.events(agent, id)).find((e) => e.type === "process.background_finished")!;
    expect(fin.payload.processes[0]).toMatchObject({ exit: null });
    const auto = (await userMsgs(agent, id)).at(-1)!;
    expect(auto.origin).toBe("agentgate");
    expect(auto.text).toMatch(/^\[AgentGate\] Background command\(s\) finished: `.*setTimeout.*` exited \(ran \d+s\)\. Output file \(if Claude reported one\): \/private\/tmp\/claude-501\/proj\/tasks\/b\d+\.output\. Continue with what you were doing, and report the result to the user\.$/);
    expect(s.summary?.last_message).toBe("continued");
  }, T);

  it("loop cap: at most 3 automatic continuations per user instruction", async () => {
    const { ctl } = setup({ FAKE_ON_AGENTGATE: "bg:900;say:again" });
    const { agent, dir } = await c.server(ctl);
    const id = await c.start(agent, dir, "bg:900;say:x");
    const evs = await c.until(() => c.events(agent, id), (x) => x.some((e) => e.type === "control.applied" && e.payload.command === "auto_continue"), 30_000);
    expect(evs.find((e) => e.payload.command === "auto_continue")!.payload.skipped).toMatch(/limit of 3/);
    expect((await userMsgs(agent, id)).filter((m) => m.origin === "agentgate")).toHaveLength(3);
  }, T);

  it("finishes while a queued task runs → continuation after that turn, before the rest of the queue", async () => {
    const { ctl } = setup();
    const { agent, phone, dir } = await c.server(ctl);
    const id = await c.start(agent, dir, "bg:1200;say:t1");
    await c.cmd(phone, id, { command: "enqueue_task", text: "sleep:3000;say:t2" });
    await c.cmd(phone, id, { command: "enqueue_task", text: "say:t3" });
    await c.until(() => c.tasks(agent, id), (x) => x.length === 3 && x[2]!.status === "completed", 30_000);
    await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input");
    const msgs = (await userMsgs(agent, id)).map((m) => (m.origin === "agentgate" ? "AUTO" : m.text));
    expect(msgs).toEqual(["bg:1200;say:t1", "sleep:3000;say:t2", "AUTO", "say:t3"]);
  }, T);
});
