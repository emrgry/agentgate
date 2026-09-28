import { mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig, prepareDirs } from "../src/config.ts";
import { auditLogs, pairingCodes } from "../src/db/schema.ts";
import { MAX_CODES_PER_HOUR, PAIRING_TTL_MS } from "../src/domain/pairing.ts";
import { call, createHarness, draft, type Harness } from "./helpers.ts";
import { computeActionHash } from "@agentgate/core";

let h: Harness | null = null;
afterEach(async () => {
  await h?.close();
  h = null;
});

async function inject(method: "GET" | "POST", url: string, body?: unknown, o: { token?: string; ip?: string } = {}) {
  const res = await h!.app.inject({
    method,
    url,
    remoteAddress: o.ip ?? "127.0.0.1",
    headers: { ...(o.token ? { authorization: `Bearer ${o.token}` } : {}), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
    ...(body !== undefined ? { payload: JSON.stringify(body) } : {}),
  });
  return { status: res.statusCode, json: res.body ? JSON.parse(res.body) : {} };
}

const agentLogin = async (email = "dev@example.com") => (await inject("POST", "/v1/auth/login", { email, client: "agent" })).json.access_token as string;
const pair = async (token: string) => inject("POST", "/v1/pairing", {}, { token });
const deviceLogin = (email: string, pairing_code?: string, ip = "192.168.1.50") =>
  inject("POST", "/v1/auth/login", { email, client: "device", ...(pairing_code !== undefined ? { pairing_code } : {}) }, { ip });

describe("C2: device pairing", () => {
  it("device login without a pairing code → 401 pairing_required (no user created)", async () => {
    h = await createHarness({ openDeviceLogin: false });
    const r = await deviceLogin("attacker@example.com");
    expect(r.status).toBe(401);
    expect(r.json.error.code).toBe("pairing_required");
  });

  it("happy path: agent (loopback) mints a code → device logs in once with it; audited", async () => {
    h = await createHarness({ openDeviceLogin: false });
    const agent = await agentLogin();
    const p = await pair(agent);
    expect(p.status).toBe(201);
    expect(p.json.code).toMatch(/^[0-9A-HJKMNP-TV-Z]{8}$/);
    expect(Date.parse(p.json.expires_at) - h.clock.now().getTime()).toBe(PAIRING_TTL_MS);

    // formatted, lower-case, with O/I confusables → normalized
    const typed = `${p.json.code.slice(0, 4)}-${p.json.code.slice(4)}`.toLowerCase();
    const ok = await deviceLogin("DEV@example.com", typed);
    expect(ok.status).toBe(200);
    expect(ok.json.access_token).toBeTruthy();
    expect(ok.json.refresh_token).toMatch(/^agr_/); // device-bound refresh token (90 d sliding)
    // device token works for device endpoints
    expect(ok.json.device_id).toMatch(/^dev_/); // bootstrap: first device of the user
    expect((await inject("POST", "/v1/devices", { name: "iPhone", platform: "ios", push_token: null }, { token: ok.json.access_token })).status).toBe(200);

    const again = await deviceLogin("dev@example.com", p.json.code);
    expect(again.status).toBe(401);
    expect(again.json.error.code).toBe("invalid_pairing_code");

    const audit = await h.database.db.select().from(auditLogs).where(eq(auditLogs.event, "device.paired"));
    expect(audit).toHaveLength(1);
    // code stored only as HMAC
    const rows = await h.database.db.select().from(pairingCodes);
    expect(JSON.stringify(rows)).not.toContain(p.json.code);
  });

  it("code of another user / wrong code / expired → 401 invalid_pairing_code", async () => {
    h = await createHarness({ openDeviceLogin: false });
    const alice = await pair(await agentLogin("alice@example.com"));
    await agentLogin("mallory@example.com");
    expect((await deviceLogin("mallory@example.com", alice.json.code)).json.error.code).toBe("invalid_pairing_code");
    expect((await deviceLogin("alice@example.com", "ZZZZZZZZ")).json.error.code).toBe("invalid_pairing_code");
    expect((await deviceLogin("nobody@example.com", alice.json.code)).json.error.code).toBe("invalid_pairing_code");
    h.clock.advance(PAIRING_TTL_MS + 1);
    expect((await deviceLogin("alice@example.com", alice.json.code)).json.error.code).toBe("invalid_pairing_code");
  });

  it("pairing requires an agent token (device token → 403, none → 401)", async () => {
    h = await createHarness({ openDeviceLogin: false });
    const agent = await agentLogin();
    const p = await pair(agent);
    const dev = (await deviceLogin("dev@example.com", p.json.code)).json.access_token;
    expect((await pair(dev)).status).toBe(403);
    expect((await inject("POST", "/v1/pairing", {})).status).toBe(401);
  });

  it("per-user cap on issued codes", async () => {
    h = await createHarness({ openDeviceLogin: false });
    const agent = await agentLogin();
    for (let i = 0; i < MAX_CODES_PER_HOUR; i++) expect((await pair(agent)).status).toBe(201);
    const r = await pair(agent);
    expect(r.status).toBe(429);
    expect(r.json.error.code).toBe("too_many_pairing_codes");
  });

  it("agent login is loopback-only unless explicitly allowed", async () => {
    h = await createHarness({ openDeviceLogin: false });
    const remote = await inject("POST", "/v1/auth/login", { email: "dev@example.com", client: "agent" }, { ip: "192.168.1.9" });
    expect(remote.status).toBe(403);
    expect(remote.json.error.code).toBe("pair_phone_first"); // no paired device → never bootstrapped remotely
    expect((await inject("POST", "/v1/auth/login", { email: "dev@example.com", client: "agent" }, { ip: "::1" })).status).toBe(200);
    await h.close();
    h = await createHarness({ openDeviceLogin: false, allowRemoteAgentLogin: true });
    expect((await inject("POST", "/v1/auth/login", { email: "dev@example.com", client: "agent" }, { ip: "192.168.1.9" })).status).toBe(200);
  });
});

describe("M3: rate limits", () => {
  it("strict limit on auth endpoints → 429 rate_limited; other routes use the moderate limit", async () => {
    h = await createHarness({ openDeviceLogin: false, rateLimit: { authPerMinute: 3, defaultPerMinute: 50 } });
    const codes = [];
    for (let i = 0; i < 4; i++) codes.push((await deviceLogin("x@example.com", "AAAAAAAA", "10.0.0.7")).status);
    expect(codes).toEqual([401, 401, 401, 429]);
    const limited = await deviceLogin("x@example.com", "AAAAAAAA", "10.0.0.7");
    expect(limited.json.error.code).toBe("rate_limited");
    // another IP is unaffected
    expect((await deviceLogin("x@example.com", "AAAAAAAA", "10.0.0.8")).status).toBe(401);
    expect((await inject("GET", "/v1/keys")).status).toBe(200);
  });
});

describe("M1 / M5: display copy and server-side risk", () => {
  it("stores a redacted display_command (hash on the raw command) and max(client, server) risk", async () => {
    h = await createHarness();
    const agent = await agentLogin();
    const ag = await inject("POST", "/v1/agents", { name: "m", type: "cli", machine_id: "m" }, { token: agent });
    const ses = await inject("POST", "/v1/sessions", { agent_id: ag.json.id }, { token: agent });
    const d = { ...draft(ses.json.id, "curl -H 'Authorization: Bearer abcdefghijklmnop' https://api.x && rm -rf /tmp/x"), resource: {} };
    const body = {
      action: d,
      policy: { decision: "ask", rule_id: null, risk: "low", reason: "client says low" },
      action_hash: computeActionHash(d),
    };
    const r = await inject("POST", "/v1/actions", body, { token: agent });
    expect(r.status).toBe(201);
    expect(r.json.action.action.command).toContain("abcdefghijklmnop"); // raw kept for the executor/audit
    expect(r.json.action.action.display_command).toBe("curl -H 'Authorization: Bearer ***' https://api.x && rm -rf /tmp/x");
    expect(r.json.action.risk.level).toBe("critical"); // server classifier: rm -rf
    const activity = await inject("GET", "/v1/activity", undefined, { token: agent });
    expect(JSON.stringify(activity.json)).not.toContain("abcdefghijklmnop");
  });
});

describe("H3 / L1 / prod guard: config", () => {
  const tmp = () => mkdtempSync(join(tmpdir(), "ag-api-cfg-"));

  it("moves secrets out of DATA_DIR into SECRETS_DIR once, 0700 dirs / 0600 files", () => {
    const root = tmp();
    const data = join(root, "data");
    const secrets = join(root, "secrets");
    mkdirSync(join(data, "pglite"), { recursive: true, mode: 0o755 });
    writeFileSync(join(data, "auth-secret"), "old-secret");
    writeFileSync(join(data, "approval-signing-key.pem"), "PEM");
    expect(prepareDirs(data, secrets).sort()).toEqual(["approval-signing-key.pem", "auth-secret"]);
    expect(readFileSync(join(secrets, "auth-secret"), "utf8")).toBe("old-secret");
    expect(existsSync(join(data, "auth-secret"))).toBe(false);
    for (const d of [data, secrets, join(data, "pglite")]) expect(statSync(d).mode & 0o777).toBe(0o700);
    expect(statSync(join(secrets, "auth-secret")).mode & 0o777).toBe(0o600);
    expect(prepareDirs(data, secrets)).toEqual([]); // one-time
    const cfg = loadConfig({ DATA_DIR: data, SECRETS_DIR: secrets });
    expect(cfg.authSecret).toBe("old-secret");
  });

  it("refuses NODE_ENV=production with dev auth", () => {
    const root = tmp();
    expect(() => loadConfig({ NODE_ENV: "production", DATA_DIR: root, SECRETS_DIR: root })).toThrow(/production/);
  });
});
