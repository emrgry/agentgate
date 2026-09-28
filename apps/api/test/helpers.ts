import { computeActionHash, generateSigningKeyPair } from "@agentgate/core";
import type { ActionDraft, SubmitActionRequest } from "@agentgate/protocol";
import { buildApp, type App } from "../src/app.ts";
import { openDatabase, type Database } from "../src/db/client.ts";
import { createSigner } from "../src/keys.ts";
import type { PushMessage, PushSender } from "../src/push/expo.ts";

export class TestClock {
  constructor(private t = Date.parse("2026-09-24T12:00:00.000Z")) {}
  now = () => new Date(this.t);
  advance(ms: number) {
    this.t += ms;
  }
}

export class RecordingPush implements PushSender {
  sent: PushMessage[] = [];
  fail = false;
  async send(messages: PushMessage[]) {
    if (this.fail) throw new Error("expo unreachable");
    this.sent.push(...messages);
  }
}

export interface Harness extends App {
  database: Database;
  clock: TestClock;
  push: RecordingPush;
  close(): Promise<void>;
}

export async function createHarness(
  opts: {
    clock?: TestClock;
    /** Default true for legacy tests; pairing tests pass false (production behavior). */
    openDeviceLogin?: boolean;
    allowRemoteAgentLogin?: boolean;
    rateLimit?: { authPerMinute?: number; defaultPerMinute?: number; pollPerMinute?: number } | false;
    pairingLongPollMs?: number;
    trustedProxies?: string[];
    mode?: "dev" | "local";
    requireDeviceSignatures?: boolean;
    ownerName?: string;
    machineName?: string;
    control?: import("../src/control/supervisor.ts").SupervisorOptions;
    sessionPushIntervalMs?: number;
    recoveryProof?: import("../src/domain/device-recovery.ts").RecoveryProofCheck;
  } = {},
): Promise<Harness> {
  const database = await openDatabase({ kind: "memory" });
  const clock = opts.clock ?? new TestClock();
  const push = new RecordingPush();
  const built = await buildApp({
    db: database.db,
    signer: createSigner(generateSigningKeyPair().privateKeyPem),
    authSecret: "test-secret-test-secret-test-secret",
    push: () => push,
    clock,
    logLevel: false,
    auth: { openDeviceLogin: opts.openDeviceLogin ?? true, allowRemoteAgentLogin: opts.allowRemoteAgentLogin ?? false },
    rateLimit: opts.rateLimit ?? { authPerMinute: 10_000, defaultPerMinute: 100_000, pollPerMinute: 10_000 },
    pairingLongPollMs: opts.pairingLongPollMs ?? 300,
    trustedProxies: opts.trustedProxies ?? [],
    ...(opts.mode ? { mode: opts.mode } : {}),
    ...(opts.requireDeviceSignatures ? { requireDeviceSignatures: true } : {}),
    ...(opts.ownerName ? { ownerName: opts.ownerName } : {}),
    ...(opts.machineName ? { machineName: opts.machineName } : {}),
    ...(opts.control ? { control: opts.control } : {}),
    ...(opts.sessionPushIntervalMs !== undefined ? { sessionPushIntervalMs: opts.sessionPushIntervalMs } : {}),
    ...(opts.recoveryProof ? { recoveryProof: opts.recoveryProof } : {}),
  });
  return {
    ...built,
    database,
    clock,
    push,
    async close() {
      await built.app.close();
      await database.close();
    },
  };
}

type Json = Record<string, any>;

export async function call(
  h: Harness,
  method: "GET" | "POST",
  url: string,
  token?: string,
  body?: unknown,
): Promise<{ status: number; json: Json }> {
  const res = await h.app.inject({
    method,
    url,
    headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
    },
    ...(body !== undefined ? { payload: JSON.stringify(body) } : {}),
  });
  return { status: res.statusCode, json: res.body ? (JSON.parse(res.body) as Json) : {} };
}

export async function login(h: Harness, client: "device" | "agent", email = "dev@example.com") {
  const r = await call(h, "POST", "/v1/auth/login", undefined, { email, client });
  if (r.status !== 200) throw new Error(`login failed: ${JSON.stringify(r.json)}`);
  return r.json.access_token as string;
}

/** login ×2 → register device → register agent → start session. */
export async function setup(h: Harness, email = "dev@example.com") {
  const deviceToken = await login(h, "device", email);
  const agentToken = await login(h, "agent", email);
  const device = await call(h, "POST", "/v1/devices", deviceToken, {
    name: "iPhone",
    platform: "ios",
    push_token: `ExponentPushToken[${email}]`,
  });
  const agent = await call(h, "POST", "/v1/agents", agentToken, {
    name: "Claude Code",
    type: "claude-code",
    machine_id: "mbp-1",
  });
  const session = await call(h, "POST", "/v1/sessions", agentToken, { agent_id: agent.json.id });
  return {
    deviceToken,
    agentToken,
    deviceId: device.json.id as string,
    agentId: agent.json.id as string,
    sessionId: session.json.id as string,
  };
}

export function draft(sessionId: string, command = "git push origin main"): ActionDraft {
  return {
    session_id: sessionId,
    agent: { type: "claude-code", version: "2.0" },
    action: { category: "git", operation: "push", tool: "Bash", command, cwd: "/work/demo" },
    resource: { type: "git_remote", environment: "production", name: "origin/main" },
    context: { repo: "agentgate/demo", branch: "main" },
  };
}

export function submitBody(
  sessionId: string,
  opts: { decision?: "allow" | "ask" | "deny"; command?: string; ttl?: number } = {},
): SubmitActionRequest {
  const d = draft(sessionId, opts.command);
  return {
    action: d,
    policy: { decision: opts.decision ?? "ask", rule_id: "git-push-protected", risk: "high", reason: "pushes to main" },
    action_hash: computeActionHash(d),
    ...(opts.ttl !== undefined ? { approval_ttl_seconds: opts.ttl } : {}),
  };
}
