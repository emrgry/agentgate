import { afterEach, beforeEach, describe, expect, it } from "vitest";
import WebSocket from "ws";
import { ServerEvent } from "@agentgate/protocol";
import { call, createHarness, setup, submitBody, type Harness } from "./helpers.ts";

let h: Harness;
let base: string;

beforeEach(async () => {
  h = await createHarness();
  await h.app.listen({ port: 0, host: "127.0.0.1" });
  const addr = h.app.server.address();
  if (!addr || typeof addr === "string") throw new Error("no address");
  base = `ws://127.0.0.1:${addr.port}`;
});
afterEach(async () => {
  await h.close();
});

/** Opens a socket and collects parsed ServerEvents. */
async function connect(url: string, headers?: Record<string, string>) {
  const events: ServerEvent[] = [];
  const waiters: Array<{ pred: (e: ServerEvent) => boolean; resolve: (e: ServerEvent) => void }> = [];
  const ws = new WebSocket(url, { headers });
  ws.on("message", (data) => {
    const e = ServerEvent.parse(JSON.parse(data.toString()));
    events.push(e);
    for (const w of [...waiters]) {
      if (w.pred(e)) {
        waiters.splice(waiters.indexOf(w), 1);
        w.resolve(e);
      }
    }
  });
  await new Promise<void>((resolve, reject) => {
    ws.once("open", () => resolve());
    ws.once("error", reject);
    ws.once("unexpected-response", (_req, res) => reject(new Error(`HTTP ${res.statusCode}`)));
  });
  const next = <T extends ServerEvent["type"]>(type: T, timeoutMs = 3000) =>
    new Promise<Extract<ServerEvent, { type: T }>>((resolve, reject) => {
      const found = events.find((e) => e.type === type);
      if (found) {
        events.splice(events.indexOf(found), 1);
        return resolve(found as never);
      }
      const t = setTimeout(() => reject(new Error(`timeout waiting for ${type}`)), timeoutMs);
      waiters.push({
        pred: (e) => e.type === type,
        resolve: (e) => {
          clearTimeout(t);
          events.splice(events.indexOf(e), 1);
          resolve(e as never);
        },
      });
    });
  return { ws, next };
}

describe("websocket", () => {
  it("delivers approval.created to devices and approval.resolved (with token) to the agent", async () => {
    const s = await setup(h);
    const agent = await connect(`${base}/v1/agent/connect?session_id=${s.sessionId}`, {
      authorization: `Bearer ${s.agentToken}`,
    });
    const device = await connect(`${base}/v1/device/connect?access_token=${s.deviceToken}&device_id=${s.deviceId}`);
    expect((await agent.next("hello")).server_time).toBeTruthy();
    await device.next("hello");

    agent.ws.send(JSON.stringify({ type: "ping" }));
    await agent.next("pong");

    const sub = await call(h, "POST", "/v1/actions", s.agentToken, submitBody(s.sessionId));
    const id = sub.json.approval.approval_id;
    const created = await device.next("approval.created");
    expect(created.detail.approval.approval_id).toBe(id);

    const res = await call(h, "POST", `/v1/approvals/${id}/approve`, s.deviceToken, { device_id: s.deviceId });
    const [toAgent, toDevice] = await Promise.all([agent.next("approval.resolved"), device.next("approval.resolved")]);
    expect(toAgent).toMatchObject({ approval_id: id, status: "approved", approval_token: res.json.approval_token });
    expect(toDevice.status).toBe("approved");

    agent.ws.close();
    device.ws.close();
  });

  it("rejects unauthenticated and wrong-audience upgrades", async () => {
    const s = await setup(h);
    await expect(connect(`${base}/v1/agent/connect`)).rejects.toThrow("HTTP 401");
    await expect(connect(`${base}/v1/agent/connect?access_token=${s.deviceToken}`)).rejects.toThrow("HTTP 403");
    await expect(connect(`${base}/v1/agent/connect?access_token=${s.agentToken}&session_id=ses_nope`)).rejects.toThrow(
      "HTTP 404",
    );
  });

  it("agent cancel broadcasts approval.resolved { cancelled } to devices and the agent", async () => {
    const s = await setup(h);
    const agent = await connect(`${base}/v1/agent/connect?session_id=${s.sessionId}`, { authorization: `Bearer ${s.agentToken}` });
    const device = await connect(`${base}/v1/device/connect?access_token=${s.deviceToken}&device_id=${s.deviceId}`);
    await agent.next("hello");
    await device.next("hello");
    const sub = await call(h, "POST", "/v1/actions", s.agentToken, submitBody(s.sessionId));
    const id = sub.json.approval.approval_id;
    await device.next("approval.created");
    const r = await call(h, "POST", `/v1/approvals/${id}/cancel`, s.agentToken, { session_id: s.sessionId, reason: "hook_deadline" });
    expect(r.status).toBe(200);
    const ev = await device.next("approval.resolved");
    expect(ev).toMatchObject({ approval_id: id, status: "cancelled", approval_token: null });
    expect((await agent.next("approval.resolved")).status).toBe("cancelled");
    agent.ws.close();
    device.ws.close();
  });
});
