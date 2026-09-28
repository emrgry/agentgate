import { randomBytes } from "node:crypto";
import { mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect } from "vitest";
import { AgentSession, AgentTask, type CommandBody } from "@agentgate/protocol";
import { commandBodyHash, generateDeviceKeyPair, signCommand, type DeviceKeyPair } from "@agentgate/signing";
import type { SupervisorOptions } from "../src/control/supervisor.ts";
import { createHarness, TestClock, type Harness } from "./helpers.ts";

/** Shared Control Center test plumbing (local-mode server, paired phone, signed commands). */

const here = dirname(fileURLToPath(import.meta.url));
export const FAKE_CLAUDE = join(here, "fake-agent.mjs");
export const FAKE_CODEX = join(here, "fake-codex.mjs");
export const FAKE_HERMES = join(here, "fake-hermes.mjs");
const rnd = (n: number) => new Uint8Array(randomBytes(n));

export type R = { status: number; json: any };
export interface Phone {
  kp: DeviceKeyPair;
  token: string;
  id: string;
}

export function controlHarness() {
  let h: Harness | null = null;
  const api = {
    get h() {
      return h!;
    },
    async close() {
      await h?.close();
      h = null;
    },
    async inject(method: "GET" | "POST" | "DELETE", url: string, body?: unknown, o: { token?: string } = {}): Promise<R> {
      const res = await h!.app.inject({
        method,
        url,
        remoteAddress: "127.0.0.1",
        headers: { ...(o.token ? { authorization: `Bearer ${o.token}` } : {}), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { payload: JSON.stringify(body) } : {}),
      });
      return { status: res.statusCode, json: res.body ? JSON.parse(res.body) : {} };
    },
    async server(control: SupervisorOptions, o: { clock?: TestClock; sessionPushIntervalMs?: number; recoveryProof?: import("../src/domain/device-recovery.ts").RecoveryProofCheck } = {}) {
      const dir = realpathSync(mkdtempSync(join(tmpdir(), "ag-ctl-")));
      h = await createHarness({ mode: "local", openDeviceLogin: false, control, ...(o.clock ? { clock: o.clock } : {}), ...(o.sessionPushIntervalMs !== undefined ? { sessionPushIntervalMs: o.sessionPushIntervalMs } : {}), ...(o.recoveryProof ? { recoveryProof: o.recoveryProof } : {}) });
      await h.app.ready();
      const agent = (await api.inject("POST", "/v1/auth/login", { client: "agent" })).json.access_token as string;
      const kp = generateDeviceKeyPair(rnd);
      const code = (await api.inject("POST", "/v1/pairing", {}, { token: agent })).json.code;
      const r = await api.inject("POST", "/v1/auth/login", { client: "device", pairing_code: code, device_name: "iPhone", device_public_key: kp.publicKey });
      await api.inject("POST", "/v1/devices", { name: "iPhone", platform: "ios", push_token: "ExponentPushToken[p]" }, { token: r.json.access_token });
      const phone: Phone = { kp, token: r.json.access_token as string, id: r.json.device_id as string };
      return { agent, dir, phone };
    },
    sign(kp: DeviceKeyPair, deviceId: string, sessionId: string, body: CommandBody) {
      const now = h!.clock.now().getTime();
      return signCommand(
        { v: 2, kind: "command", command: body.command, session_id: sessionId, payload_hash: commandBodyHash(body), device_id: deviceId, issued_at: new Date(now).toISOString(), expires_at: new Date(now + 60_000).toISOString(), nonce: Buffer.from(rnd(18)).toString("base64url") } as never,
        kp.privateKey,
      );
    },
    cmd(p: Phone, sessionId: string, body: CommandBody) {
      return api.inject("POST", `/v1/agent-sessions/${sessionId}/commands`, { device_id: p.id, body, signed_command: api.sign(p.kp, p.id, sessionId, body) }, { token: p.token });
    },
    async start(agent: string, cwd: string, prompt: string, provider = "claude-code") {
      const r = await api.inject("POST", "/v1/agent-sessions", { cwd, prompt, provider }, { token: agent });
      expect(r.status, JSON.stringify(r.json)).toBe(201);
      return r.json.session.id as string;
    },
    session: async (agent: string, id: string) => AgentSession.parse((await api.inject("GET", `/v1/agent-sessions/${id}`, undefined, { token: agent })).json),
    tasks: async (agent: string, id: string) => (await api.inject("GET", `/v1/agent-sessions/${id}/tasks`, undefined, { token: agent })).json.items.map((t: unknown) => AgentTask.parse(t)) as AgentTask[],
    events: async (agent: string, id: string) => (await api.inject("GET", `/v1/agent-sessions/${id}/events?limit=500`, undefined, { token: agent })).json.items as Array<{ type: string; payload: any }>,
    async until<T>(get: () => Promise<T>, pred: (v: T) => boolean, ms = 60_000): Promise<T> {
      const end = Date.now() + ms;
      for (;;) {
        await h!.supervisor!.settle();
        const v = await get();
        if (pred(v)) return v;
        if (Date.now() > end) throw new Error(`timeout: ${JSON.stringify(v).slice(0, 600)}`);
        await new Promise((r) => setTimeout(r, 50));
      }
    },
  };
  return api;
}
