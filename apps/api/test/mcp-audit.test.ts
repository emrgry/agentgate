import { computeActionHash } from "@agentgate/core";
import type { ActionDraft } from "@agentgate/protocol";
import { afterEach, describe, expect, it } from "vitest";
import { mcpArgsSummary } from "../src/domain/audit.ts";
import { call, createHarness, setup, type Harness } from "./helpers.ts";

let h: Harness | null = null;
afterEach(async () => {
  await h?.close();
  h = null;
});

function mcpDraft(sessionId: string, args: Record<string, unknown>): ActionDraft {
  return {
    session_id: sessionId,
    agent: { type: "claude-desktop", version: "1.2.3" },
    action: {
      category: "mcp",
      operation: "invoke",
      tool: "mail/send_email",
      arguments: { server: "mail", tool: "send_email", arguments: args, annotations: { openWorldHint: true } },
      cwd: "/work",
    },
    resource: { type: "mcp_server", name: "mail" },
    context: {},
  };
}

describe("MCP activity summaries", () => {
  it("label '<server> → <tool>', agent_type/mcp_server/mcp_tool and masked args on every audit entry", async () => {
    const hh = (h = await createHarness());
    const s = await setup(hh);
    const d = mcpDraft(s.sessionId, {
      to: "ceo@example.com",
      subject: "hi",
      api_key: "sk_live_1234567890abcdef",
      auth: { Authorization: "Bearer abcdefghijklmnop", cookie: "sid=1" },
      note: "ghp_abcdefghijklmnopqrstuvwxyz0123",
    });
    const r = await call(hh, "POST", "/v1/actions", s.agentToken, {
      action: d,
      policy: { decision: "ask", rule_id: null, risk: "high", reason: "open world" },
      action_hash: computeActionHash(d),
    });
    expect(r.status).toBe(201);
    await call(hh, "POST", `/v1/approvals/${r.json.approval.approval_id}/approve`, s.deviceToken, { device_id: s.deviceId });
    await call(hh, "POST", `/v1/actions/${r.json.action.action_id}/execution`, s.agentToken, { status: "started" });

    const act = await call(hh, "GET", "/v1/activity", s.deviceToken);
    const mcpItems = act.json.items.filter((i: any) => i.action_id === r.json.action.action_id);
    expect(mcpItems.map((i: any) => i.event).sort()).toEqual(["action.reported", "approval.approved", "approval.requested", "execution.started"]);
    for (const i of mcpItems) {
      expect(i.summary.startsWith("mail → send_email — ")).toBe(true);
      expect(i.payload).toMatchObject({ label: "mail → send_email", agent_type: "claude-desktop", mcp_server: "mail", mcp_tool: "send_email" });
      const args: string = i.payload.mcp_args;
      expect(args).toContain('"to":"ceo@example.com"');
      expect(args).toContain('"api_key":"***"');
      expect(args).toContain('"Authorization":"***"');
      expect(args).toContain('"cookie":"***"');
      for (const secret of ["sk_live_1234567890abcdef", "abcdefghijklmnop", "sid=1", "ghp_abcdefghijklmnopqrstuvwxyz0123"]) expect(args).not.toContain(secret);
    }
  });

  it("mcpArgsSummary: one line, capped, masks nested keys", () => {
    expect(mcpArgsSummary({})).toBe("");
    expect(mcpArgsSummary({ a: "x\ny", nested: [{ password: "p", private_key: "k", credentials: "c" }] })).toBe(
      '{"a":"x\\ny","nested":[{"password":"***","private_key":"***","credentials":"***"}]}',
    );
    expect(mcpArgsSummary({ big: "x".repeat(500) }).length).toBe(200);
  });
});
