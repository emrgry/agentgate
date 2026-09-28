import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { describeError } from "../authorize.ts";
import { AgentGateClient } from "../client/index.ts";
import { EXIT } from "../exit-codes.ts";
import { c, log, out } from "../output.ts";
import { requireLogin } from "../runtime.ts";

/**
 * `agentgate devices list | revoke <id> | reset` — local recovery when the phone's key is
 * lost and no other paired device can approve (re-pairing deadlock).
 *
 * Human presence: revoke/reset first run `sudo -v` (password / Touch ID — an agent can't
 * answer it) and fail closed otherwise. Then, still via sudo, a random one-time nonce is
 * written to a ROOT-OWNED file `/tmp/agentgate-recovery-<random>`; the server only accepts
 * POST /v1/devices/recovery (loopback, agent token) when that file exists, is owned by uid 0,
 * is fresh and contains the nonce. A plain `curl` with the agent token can't produce that.
 * Agents are additionally blocked from running `agentgate devices` by the hook guard.
 */

const SUDO = () => process.env.AGENTGATE_SUDO || "/usr/bin/sudo";

async function client() {
  const config = await requireLogin();
  return new AgentGateClient({ server: config.server, accessToken: config.access_token, debug: log.debug });
}

function sudo(args: string[], interactive: boolean): boolean {
  const r = spawnSync(SUDO(), args, { stdio: interactive ? "inherit" : ["ignore", "ignore", "inherit"], timeout: 120_000 });
  return r.status === 0;
}

export async function devicesCommand(action: string | undefined, args: string[]): Promise<number> {
  try {
    if (action === "list" || action === undefined) {
      const r = await (await client()).devicesList();
      if (!r.items.length) out(c.dim("no devices"));
      for (const d of r.items) {
        out(`${d.id}  ${String(d.name).padEnd(20)} ${String(d.platform).padEnd(8)} ${d.revoked_at ? c.red(`revoked ${d.revoked_at}`) : c.green("active")}`);
      }
      return EXIT.OK;
    }
    if (action !== "revoke" && action !== "reset") {
      log.fail("usage: agentgate devices list | revoke <device-id> | reset");
      return EXIT.USAGE;
    }
    const deviceId = args[0];
    if (action === "revoke" && !deviceId) {
      log.fail("usage: agentgate devices revoke <device-id>");
      return EXIT.USAGE;
    }
    out(action === "reset" ? "This revokes EVERY paired phone; the next `agentgate pair` becomes a fresh (bootstrap) pairing." : `This revokes device ${deviceId}.`);
    out("Confirm you are at this computer (sudo):");
    if (!sudo(["-v"], true)) {
      log.fail("sudo authentication failed or was cancelled — nothing changed");
      return EXIT.ERROR;
    }
    const nonce = randomBytes(32).toString("base64url");
    const proof = `/tmp/agentgate-recovery-${randomBytes(16).toString("base64url")}`;
    // noclobber: never write through a pre-existing file/symlink; 0644 so the server can read it.
    const script = 'set -C; umask 022; printf %s "$1" > "$2" && chmod 0644 "$2"';
    if (!sudo(["-n", "/bin/sh", "-c", script, "sh", nonce, proof], false)) {
      log.fail("could not write the recovery proof with sudo — nothing changed");
      return EXIT.ERROR;
    }
    try {
      const r = await (await client()).deviceRecovery({ action, ...(deviceId ? { device_id: deviceId } : {}), nonce, proof_path: proof });
      if (action === "reset") log.ok(`revoked ${r.revoked.length} device(s), expired ${r.expired_pairing_requests} pending pairing request(s) — run \`agentgate pair\` to pair again`);
      else log.ok(r.revoked.length ? `revoked ${deviceId}` : `${deviceId} was already revoked`);
      return EXIT.OK;
    } finally {
      sudo(["-n", "/bin/rm", "-f", proof], false);
    }
  } catch (err) {
    log.fail(describeError(err));
    return EXIT.ERROR;
  }
}
