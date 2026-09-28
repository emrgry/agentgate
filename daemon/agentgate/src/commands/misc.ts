import { loadConfig, paths, redactedConfig, saveConfig, agentgateHome } from "../config.ts";
import { EXIT } from "../exit-codes.ts";
import { c, log, out } from "../output.ts";
import { loadEffectivePolicy } from "../policy.ts";

export function configCommand(o: { policy: boolean }): number {
  if (o.policy) {
    try {
      const p = loadEffectivePolicy();
      out(`# effective policy — source: ${p.source}`);
      out(p.yaml.trimEnd());
      return EXIT.OK;
    } catch (err) {
      log.fail(`${(err as Error).message} (requests will be blocked until fixed)`);
      return EXIT.ERROR;
    }
  }
  try {
    const cfg = loadConfig();
    out(`# ${paths.config()}`);
    if (!cfg) {
      out("# (no config — run `agentgate login`)");
    } else {
      out(JSON.stringify(redactedConfig(cfg), null, 2));
    }
    out(`# home: ${agentgateHome()}  policy: ${paths.policy()}  nonces: ${paths.nonces()}`);
    return EXIT.OK;
  } catch (err) {
    log.fail(`config unreadable: ${(err as Error).message}`);
    return EXIT.ERROR;
  }
}

export function logoutCommand(): number {
  try {
    const cfg = loadConfig();
    if (!cfg || !cfg.access_token) {
      log.step("already logged out");
      return EXIT.OK;
    }
    const { access_token: _t, token_expires_at: _e, refresh_token: _r, ...rest } = cfg;
    saveConfig(rest);
    log.ok(`logged out ${c.dim("(access + refresh token deleted; machine id and pinned key kept)")}`);
    return EXIT.OK;
  } catch (err) {
    log.fail(`logout failed: ${(err as Error).message}`);
    return EXIT.ERROR;
  }
}

const SETTABLE = { public_url: "URL phones/computers use to reach the API (goes into `agentgate pair` QR codes)" } as const;

/** `agentgate config set <key> <value>` / `config unset <key>`. */
export async function configSetCommand(key: string | undefined, value: string | undefined, unset: boolean): Promise<number> {
  if (!key || !(key in SETTABLE)) {
    log.fail(`usage: agentgate config set <key> <value> | config unset <key>   (keys: ${Object.keys(SETTABLE).join(", ")})`);
    return EXIT.USAGE;
  }
  if (!unset) {
    try {
      const u = new URL(value ?? "");
      if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("scheme");
    } catch {
      log.fail(`${key} must be an http(s) URL`);
      return EXIT.USAGE;
    }
  }
  try {
    const { updateConfig } = await import("../auth-session.ts");
    await updateConfig((cfg) => {
      const next = { ...cfg };
      if (unset) delete next.public_url;
      else next.public_url = value!.replace(/\/+$/, "");
      return next;
    });
    log.ok(unset ? `unset ${key}` : `${key} = ${value!.replace(/\/+$/, "")}`);
    return EXIT.OK;
  } catch (err) {
    log.fail(`config ${unset ? "unset" : "set"} failed: ${(err as Error).message}`);
    return EXIT.ERROR;
  }
}
