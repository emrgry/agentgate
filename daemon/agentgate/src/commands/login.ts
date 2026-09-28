import { createPublicKey } from "node:crypto";
import { hostname } from "node:os";
import { AgentGateClient } from "../client/index.ts";
import { DEFAULT_EMAIL, DEFAULT_SERVER, keyFingerprint, loadConfig, newMachineId, paths, saveConfig, type Config } from "../config.ts";
import { acquireLock } from "../auth-session.ts";
import { EXIT } from "../exit-codes.ts";
import { c, log } from "../output.ts";

export function isLoopbackHost(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  return h === "localhost" || h === "::1" || /^127\./.test(h);
}

/** Tailscale CGNAT range 100.64.0.0/10. */
export function isTailscaleIp(host: string): boolean {
  const m = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 100 && b >= 64 && b <= 127;
}

/**
 * Transport check for --server. https: always fine. http: loopback, or a Tailscale
 * address / *.ts.net name (WireGuard already encrypts it), or --insecure-lan.
 */
export function checkServerUrl(url: URL, insecureLan: boolean): { ok: true; note?: string } | { ok: false; error: string } {
  if (url.protocol === "https:") return { ok: true };
  if (url.protocol !== "http:") return { ok: false, error: `unsupported server URL scheme: ${url.protocol}` };
  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (isLoopbackHost(host)) return { ok: true };
  if (isTailscaleIp(host) || host.endsWith(".ts.net")) {
    return { ok: true, note: "plain HTTP over Tailscale is encrypted by WireGuard; for a real certificate use `tailscale serve --bg --https=443 http://127.0.0.1:8787` and https://<host>.<tailnet>.ts.net" };
  }
  if (insecureLan) return { ok: true, note: "--insecure-lan: tokens and approvals travel unencrypted on this network" };
  return { ok: false, error: `refusing plain HTTP to a non-local server (${url.host}). Use https://, or pass --insecure-lan for a trusted LAN (dev only).` };
}

function osPlatform(): "macos" | "linux" | "windows" | undefined {
  return process.platform === "darwin" ? "macos" : process.platform === "linux" ? "linux" : process.platform === "win32" ? "windows" : undefined;
}

const mmss = (ms: number) => {
  const s = Math.max(0, Math.round(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
};

/** 202 → wait for a paired phone to approve this computer. Ctrl-C stops waiting. */
async function waitForPhoneApproval(client: AgentGateClient, p: { pairing_request_id: string; poll_secret: string; expires_at: string }) {
  const deadline = Date.parse(p.expires_at);
  log.step(`${c.yellow("⏳")} Approve this computer on your phone (expires in ${mmss(deadline - Date.now())})…`);
  let interrupted = false;
  const onSig = () => {
    interrupted = true;
  };
  process.once("SIGINT", onSig);
  try {
    while (!interrupted) {
      const r = await Promise.race([
        client.pollPairing(p.pairing_request_id, p.poll_secret),
        new Promise<null>((res) => {
          const t = setInterval(() => {
            if (interrupted) {
              clearInterval(t);
              res(null);
            }
          }, 200);
          t.unref();
        }),
      ]);
      if (!r || interrupted) break;
      if (r.status === "approved" && r.login) return r.login;
      if (r.status === "approved") throw new Error("approved, but the login was already delivered to another poller");
      if (r.status === "denied") throw Object.assign(new Error("this computer was denied on your phone"), { code: EXIT.BLOCKED });
      if (r.status === "expired") throw Object.assign(new Error("the approval request expired — run `agentgate login` again"), { code: EXIT.BLOCKED });
    }
    throw Object.assign(new Error("interrupted — not logged in"), { code: EXIT.INTERRUPTED });
  } finally {
    process.off("SIGINT", onSig);
  }
}

export async function loginCommand(o: {
  server?: string;
  email?: string;
  acceptNewKey?: boolean;
  insecureLan?: boolean;
  /** Local-first server: no email; the server maps this agent to its single owner. */
  localFirst?: boolean;
}): Promise<number> {
  let existing: Config | null = null;
  try {
    existing = loadConfig();
  } catch (err) {
    log.warn(`ignoring unreadable config (${(err as Error).message}); a new one will be written`);
  }
  const server = (o.server ?? existing?.server ?? DEFAULT_SERVER).replace(/\/+$/, "");
  const email = o.localFirst ? undefined : (o.email ?? existing?.email ?? DEFAULT_EMAIL);
  let url: URL;
  try {
    url = new URL(server);
  } catch {
    log.fail(`invalid --server URL: ${server}`);
    return EXIT.USAGE;
  }
  // H4: plain HTTP only where the network itself is private/encrypted.
  const transport = checkServerUrl(url, o.insecureLan === true);
  if (!transport.ok) {
    log.fail(transport.error);
    return EXIT.USAGE;
  }
  if (transport.note) log.warn(transport.note);

  const client = new AgentGateClient({ server, debug: log.debug });
  try {
    // H4: check the signing key BEFORE anything else — never silently re-pin.
    const pre = (await client.keys()).approval_signing_key;
    const pinned = existing?.signing_key;
    if (pinned && pinned.pem.trim() !== pre.pem.trim() && !o.acceptNewKey) {
      log.fail("the server's approval signing key differs from the one pinned at your last login:");
      log.fail(`  pinned: ${keyFingerprint(pinned.pem)} (${pinned.kid}) for ${existing?.server}`);
      log.fail(`  server: ${keyFingerprint(pre.pem)} (${pre.kid}) at ${server}`);
      log.fail("If you rotated the key or switched servers on purpose, re-run with --accept-new-key. Otherwise do NOT: someone may be impersonating your AgentGate server.");
      return EXIT.BLOCKED;
    }
    const first = await client.loginAgent(email, { machine_name: hostname().slice(0, 128), ...(osPlatform() ? { platform: osPlatform() } : {}) });
    let login;
    if ("status" in first && first.status === "pending_approval") {
      // Another computer: a paired phone must approve it (the server never trusts it on its own).
      if (!pinned) log.step(c.dim(`first login to ${server}: will pin signing key ${keyFingerprint(pre.pem)} (${pre.kid})`));
      login = await waitForPhoneApproval(client, first);
      log.ok("approved on your phone");
    } else {
      login = first as Exclude<typeof first, { status: "pending_approval" }>;
    }
    client.setAccessToken(login.access_token);
    log.ok(
      `logged in as ${c.bold(login.user.email)} ${c.dim(`(token expires ${login.expires_at}; ${login.refresh_token ? "auto-refresh enabled" : "server issued no refresh token — re-login when it expires"})`)}`,
    );

    const keys = await client.keys();
    const k = keys.approval_signing_key;
    const pub = createPublicKey(k.pem);
    if (pub.asymmetricKeyType !== "ed25519") throw new Error(`server signing key is ${pub.asymmetricKeyType}, expected ed25519`);
    const fp = keyFingerprint(k.pem);
    const prev = existing?.signing_key;
    if (k.pem.trim() !== pre.pem.trim()) throw new Error("server signing key changed during login — aborting");
    if (prev && prev.pem.trim() !== k.pem.trim()) {
      log.warn(`re-pinning signing key (was ${keyFingerprint(prev.pem)}, now ${fp}) because --accept-new-key was given`);
    }
    log.ok(`pinned approval signing key ${c.bold(k.kid)} ${c.dim(fp)}`);

    const machineId = existing?.machine_id ?? newMachineId();
    const name = hostname();
    const agent = await client.registerAgent({ name, type: "cli", machine_id: machineId });
    log.ok(`registered agent ${c.bold(agent.id)} ${c.dim(`(${name}, machine ${machineId})`)}`);

    const release = await acquireLock(paths.configLock());
    try {
    saveConfig({
      version: 1,
      server,
      machine_id: machineId,
      email: login.user.email,
      user_id: login.user.id,
      access_token: login.access_token,
      token_expires_at: login.expires_at,
      ...(login.refresh_token ? { refresh_token: login.refresh_token } : {}),
      ...(existing?.claude_agent_id && existing.server === server && existing.user_id === login.user.id
        ? { claude_agent_id: existing.claude_agent_id }
        : {}),
      agent_id: agent.id,
      agent_name: agent.name,
      signing_key: { kid: k.kid, alg: "Ed25519", pem: k.pem, pinned_at: new Date().toISOString() },
    });
    } finally {
      release();
    }
    log.ok(`saved ${paths.config()} ${c.dim("(0600)")}`);
    return EXIT.OK;
  } catch (err) {
    const code = (err as { code?: unknown }).code;
    const apiCode = (err as { code?: string }).code;
    if (apiCode === "pair_phone_first") {
      log.fail("login failed: this computer needs approval from a paired phone, but no phone is paired yet.");
      log.fail("Pair your phone first (`agentgate pair` on a computer that is already logged in), then retry.");
      return EXIT.ERROR;
    }
    log.fail(`login failed: ${(err as Error).message}`);
    return typeof code === "number" ? code : EXIT.ERROR;
  }
}
