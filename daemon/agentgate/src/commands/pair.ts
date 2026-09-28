import { hostname, networkInterfaces } from "node:os";
import { publicKeyFingerprint } from "@agentgate/signing";
import { publicKeyFromNodePem } from "@agentgate/signing/node";
import qrcode from "qrcode-terminal";
import { isLoopbackHost } from "./login.ts";
import { describeError } from "../authorize.ts";
import { AgentGateClient } from "../client/index.ts";
import { EXIT } from "../exit-codes.ts";
import { c, log, out } from "../output.ts";
import { requireLogin } from "../runtime.ts";

/**
 * `agentgate pair` — mint a one-time device pairing code (5 min) for the AgentGate app.
 * The phone logs in with {email, client:"device", pairing_code}. Printed to stdout, plus a
 * terminal QR of `agentgate://pair?server=…&email=…&code=…` when stdout is a TTY.
 */
/** Primary LAN IPv4: non-internal, non-link-local; en0 first (macOS Wi-Fi/Ethernet). */
export function primaryLanIPv4(ifaces = networkInterfaces()): string | null {
  const names = Object.keys(ifaces).sort((a, b) => (a === "en0" ? -1 : b === "en0" ? 1 : a.localeCompare(b)));
  for (const n of names) {
    for (const a of ifaces[n] ?? []) {
      if (a.family === "IPv4" && !a.internal && !a.address.startsWith("169.254.")) return a.address;
    }
  }
  return null;
}

/** The server URL the PHONE should use: loopback is replaced by the LAN IP (same port). */
export function advertisedServer(server: string, override?: string, lanIp = primaryLanIPv4()): { url: string; note?: string } {
  if (override) return { url: override.replace(/\/+$/, "") };
  const u = new URL(server);
  if (!isLoopbackHost(u.hostname)) return { url: server.replace(/\/+$/, "") };
  if (!lanIp) return { url: server.replace(/\/+$/, ""), note: "no LAN IPv4 found — the phone cannot reach a loopback URL; pass --advertise-url" };
  u.hostname = lanIp;
  return { url: u.toString().replace(/\/+$/, "") };
}

export async function pairCommand(o: { qr: boolean; advertiseUrl?: string }): Promise<number> {
  try {
    if (o.advertiseUrl) new URL(o.advertiseUrl);
    const config = await requireLogin();
    const client = new AgentGateClient({ server: config.server, accessToken: config.access_token, debug: log.debug });
    const p = await client.pair();
    const shown = `${p.code.slice(0, 4)}-${p.code.slice(4)}`;
    const mins = Math.max(1, Math.round((Date.parse(p.expires_at) - Date.now()) / 60_000));
    // Precedence: --advertise-url > `agentgate config set public_url` > server PUBLIC_URL > LAN substitution.
    const adv = advertisedServer(config.server, o.advertiseUrl ?? config.public_url ?? p.public_url);
    // QR v2 (M7): url + one-time code + the server identity key fingerprint the phone pins
    // (verified via POST /v1/pairing/hello) + machine name. Dev servers also get the email.
    const fp = publicKeyFingerprint(publicKeyFromNodePem(config.signing_key.pem));
    const localOwner = config.email === "owner@agentgate.local";
    const params = new URLSearchParams({ v: "2", url: adv.url, code: p.code, fp, name: hostname().replace(/\.local$/, "") });
    if (!localOwner && config.email) params.set("email", config.email);
    const link = `agentgate://pair?${params.toString()}`;
    out(`Pairing code: ${c.bold(shown)}`);
    out(`Server for the phone: ${adv.url}   key: ${fp}${!localOwner && config.email ? `   email: ${config.email}` : ""}`);
    if (adv.note) out(c.yellow(adv.note));
    if (o.qr && process.stdout.isTTY) qrcode.generate(link, { small: true }, (q) => out(q));
    out("Scan with your iPhone Camera, then tap 'Pair this device'.");
    out("If you already have a paired phone, it will ask you to approve this new device.");
    out(c.dim(`Link: ${link}`));
    out(c.dim(`Single use, expires in ${mins} min (${p.expires_at}). The API must listen on the LAN (HOST=0.0.0.0) for the phone to reach it.`));
    return EXIT.OK;
  } catch (err) {
    log.fail(`pairing failed: ${describeError(err)}`);
    return EXIT.ERROR;
  }
}
