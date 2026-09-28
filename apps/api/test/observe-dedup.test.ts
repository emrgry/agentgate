import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import { claudeCodeProvider } from "@agentgate/adapter-claude-code";
import { agentSessions } from "../src/db/schema.ts";
import type { SupervisorOptions } from "../src/control/supervisor.ts";
import { controlHarness, FAKE_CLAUDE } from "./control-harness.ts";

/**
 * Real-device finding: a managed turn in a project with installed observe hooks also created a
 * duplicate `observed` session (its own SessionStart/Stop hooks). Managed turns must own them.
 */

const T = 60_000;
const c = controlHarness();
afterEach(() => c.close());

function control(env: Record<string, string> = {}): SupervisorOptions {
  return {
    providers: { "claude-code": claudeCodeProvider({ binary: FAKE_CLAUDE }) },
    hookSettingsPath: () => "/dev/null",
    turnEnv: () => ({ ...process.env, ...env }),
    stopGraceMs: 300,
    tickMs: 0,
  };
}
const observe = (agent: string, hook: Record<string, unknown>) => c.inject("POST", "/v1/agent-sessions/observe", { provider: "claude-code", hook }, { token: agent });
const allSessions = async (agent: string) => (await c.inject("GET", "/v1/agent-sessions?status=all", undefined, { token: agent })).json.items as Array<{ id: string; mode: string; provider_session_id: string | null }>;

describe("observe hooks of managed turns", () => {
  it("the turn env carries AGENTGATE_MANAGED_SESSION; hook events with that marker are attributed to the managed session", async () => {
    const log = join(mkdtempSync(join(tmpdir(), "ag-dd-")), "agent.log");
    const { agent, dir } = await c.server(control({ FAKE_AGENT_LOG: log }));
    const id = await c.start(agent, dir, "hang");
    await c.until(() => c.session(agent, id), (s) => s.status === "running");
    const first = await c.until(async () => { try { return readFileSync(log, "utf8"); } catch { return ""; } }, (t) => t.includes("\n"));
    expect(JSON.parse(first.trim().split("\n")[0]!).managed).toBe(id);
    for (const ev of ["SessionStart", "UserPromptSubmit", "Stop"]) {
      const r = await observe(agent, { session_id: "some-other-id", cwd: dir, hook_event_name: ev, agentgate_managed_session: id });
      expect(r.json.session.id).toBe(id);
    }
    expect((await allSessions(agent)).map((s) => s.mode)).toEqual(["managed"]);
  }, T);

  it("SessionStart before the turn's system/init (pending window, same cwd) is not a new observed session", async () => {
    const { agent, dir } = await c.server(control({ FAKE_INIT_DELAY_MS: "1500", FAKE_SESSION_ID: "claude-sid-1" }));
    const id = await c.start(agent, dir, "say:done");
    await c.until(() => c.session(agent, id), (s) => s.status === "running");
    // Hook without a marker (e.g. env not propagated) and before init: still the managed turn.
    const r = await observe(agent, { session_id: "claude-sid-1", cwd: dir, hook_event_name: "SessionStart", source: "startup" });
    expect(r.json.session.id).toBe(id);
    await c.until(() => c.session(agent, id), (s) => s.status === "waiting_input");
    // After init: matched by provider_session_id (Stop hook).
    expect((await observe(agent, { session_id: "claude-sid-1", cwd: dir, hook_event_name: "Stop" })).json.session.id).toBe(id);
    expect((await allSessions(agent)).map((s) => s.mode)).toEqual(["managed"]);
  }, T);

  it("an observed duplicate created before init is removed when the managed turn reports the same session id; boot cleans old ones", async () => {
    const { agent, dir } = await c.server(control({ FAKE_SESSION_ID: "claude-sid-2" }));
    // Duplicate from an older server (created before the managed session learned its id).
    const dup = (await observe(agent, { session_id: "claude-sid-2", cwd: "/elsewhere", hook_event_name: "SessionStart" })).json.session.id as string;
    await observe(agent, { session_id: "claude-sid-2", cwd: "/elsewhere", hook_event_name: "UserPromptSubmit", prompt: "hello" });
    const id = await c.start(agent, dir, "say:done");
    await c.until(() => c.session(agent, id), (s) => s.status === "waiting_input" && s.provider_session_id === "claude-sid-2");
    expect((await allSessions(agent)).map((s) => s.id)).toEqual([id]);
    expect((await c.inject("GET", `/v1/agent-sessions/${dup}`, undefined, { token: agent })).status).toBe(404);

    // Boot cleanup: a leftover observed row sharing a managed session's provider id.
    const [m] = await c.h.database.db.select().from(agentSessions).where(eq(agentSessions.id, id));
    await c.h.database.db.insert(agentSessions).values({ ...m!, id: "ags_leftover", mode: "observed", status: "completed" });
    expect((await allSessions(agent)).length).toBe(2);
    await c.h.supervisor!.recoverOnBoot();
    expect((await allSessions(agent)).map((s) => s.id)).toEqual([id]);
  }, T);

  it("an unrelated interactive session in another directory is still observed", async () => {
    const { agent, dir } = await c.server(control({ FAKE_INIT_DELAY_MS: "1500" }));
    const id = await c.start(agent, dir, "say:done");
    await c.until(() => c.session(agent, id), (s) => s.status === "running");
    const r = await observe(agent, { session_id: "interactive-1", cwd: "/some/other/project", hook_event_name: "SessionStart" });
    expect(r.json.session.mode).toBe("observed");
    expect(r.json.session.id).not.toBe(id);
  }, T);
});
