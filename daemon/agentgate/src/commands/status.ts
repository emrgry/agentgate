import { AgentGateClient, AgentSocket, WsConnectError } from "../client/index.ts";
import { isLoggedIn, keyFingerprint, loadConfig, paths, tokenExpired, type Config } from "../config.ts";
import { EXIT } from "../exit-codes.ts";
import { c, log, out } from "../output.ts";
import { loadEffectivePolicy } from "../policy.ts";
import { needsRefresh, requireLogin } from "../auth-session.ts";
import { printInstallState } from "./install.ts";

const OK = () => c.green("ok");
const BAD = (s: string) => c.red(s);

export async function statusCommand(): Promise<number> {
  let healthy = true;
  let config: Config | null = null;
  try {
    config = loadConfig();
  } catch (err) {
    out(`config        ${BAD(`unreadable: ${(err as Error).message}`)}`);
    return EXIT.ERROR;
  }
  out(`config        ${paths.config()}${config ? "" : c.yellow(" (missing — run `agentgate login`)")}`);

  // Policy
  try {
    const p = loadEffectivePolicy();
    out(`policy        ${p.source} ${c.dim(`(${p.policy.rules.length} rules)`)}`);
  } catch (err) {
    healthy = false;
    out(`policy        ${BAD(`INVALID — requests will be blocked: ${(err as Error).message}`)}`);
  }
  if (!printInstallState(process.cwd())) healthy = false;
  if (!config) return EXIT.ERROR;

  // Transparent refresh (same path the hooks use), so status reflects what hooks will see.
  if (config.access_token && config.refresh_token && needsRefresh(config)) {
    try {
      config = await requireLogin();
      out(`auth          ${c.green("access token refreshed")}`);
    } catch (err) {
      out(`auth          ${BAD(`refresh failed: ${(err as Error).message}`)}`);
    }
  }

  const client = new AgentGateClient({ server: config.server, accessToken: config.access_token, timeoutMs: 5_000, debug: log.debug });

  // Reachability + key pin check
  const t0 = performance.now();
  try {
    const keys = await client.keys();
    out(`server        ${config.server} ${OK()} ${c.dim(`(${Math.round(performance.now() - t0)}ms)`)}`);
    const pinned = config.signing_key;
    if (!pinned) {
      healthy = false;
      out(`signing key   ${BAD("not pinned — run `agentgate login`")}`);
    } else if (pinned.pem.trim() !== keys.approval_signing_key.pem.trim()) {
      healthy = false;
      out(`signing key   ${BAD(`pinned ${keyFingerprint(pinned.pem)} ≠ server ${keyFingerprint(keys.approval_signing_key.pem)} — approvals will fail verification; re-run login if the rotation is expected`)}`);
    } else {
      out(`signing key   ${pinned.kid} ${keyFingerprint(pinned.pem)} ${OK()} ${c.dim("(matches server)")}`);
    }
  } catch (err) {
    healthy = false;
    out(`server        ${config.server} ${BAD(`unreachable: ${(err as Error).message}`)}`);
  }

  // Token
  if (!config.access_token) {
    healthy = false;
    out(`auth          ${BAD("logged out")}`);
  } else if (tokenExpired(config) && !config.refresh_token) {
    healthy = false;
    out(`auth          ${BAD(`token expired at ${config.token_expires_at}`)}`);
  } else {
    const left = config.token_expires_at ? Math.round((Date.parse(config.token_expires_at) - Date.now()) / 60_000) : null;
    out(
      `auth          ${config.email ?? "?"} ${c.dim(`${left !== null ? `(token valid for ~${left}m` : "("}${config.refresh_token ? ", auto-refresh on)" : ", NO refresh token — re-login when it expires)"}`)}`,
    );
  }
  out(`agent         ${config.agent_id ?? c.yellow("not registered")} ${c.dim(config.agent_name ?? "")}`);

  // WebSocket round trip (also proves the token is accepted by the server)
  if (isLoggedIn(config) && !tokenExpired(config)) {
    const r = await wsCheck(client, config.access_token, config.agent_id);
    if (!r.ok) healthy = false;
    out(`websocket     ${r.ok ? `${OK()} ${c.dim(`(ping/pong ${r.rttMs.toFixed(1)}ms)`)}` : BAD(r.error)}`);
  }
  return healthy ? EXIT.OK : EXIT.ERROR;
}

async function wsCheck(
  client: AgentGateClient,
  token: string,
  agentId: string,
): Promise<{ ok: true; rttMs: number } | { ok: false; error: string }> {
  const attempt = async (sessionId?: string) => {
    const s = await AgentSocket.connect({ server: client.server, accessToken: token, sessionId, connectTimeoutMs: 5_000, debug: log.debug });
    try {
      return await s.ping(5_000);
    } finally {
      s.close();
    }
  };
  try {
    return { ok: true, rttMs: await attempt() };
  } catch (err) {
    if (err instanceof WsConnectError && err.status === 401) return { ok: false, error: "token rejected by server (401) — run `agentgate login`" };
    // The server may require session_id: use a throwaway session.
    if (!(err instanceof WsConnectError && err.status && err.status >= 400 && err.status < 500)) {
      return { ok: false, error: (err as Error).message };
    }
  }
  let sessionId: string | undefined;
  try {
    sessionId = (await client.createSession(agentId)).id;
    return { ok: true, rttMs: await attempt(sessionId) };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  } finally {
    if (sessionId) await client.endSession(sessionId, 3_000).catch(() => {});
  }
}
