import { BlockList, isIP } from "node:net";
import type { FastifyRequest } from "fastify";

/**
 * Client address and "is this request local?" behind reverse proxies (Fly/Railway edge,
 * nginx, `tailscale serve`, …). Rules:
 *  - Forwarding headers (X-Forwarded-For, Forwarded, X-Real-IP, Tailscale-User-*) are
 *    TRUSTED only when the TCP peer is in TRUSTED_PROXIES (CIDR list, default: none).
 *    Otherwise they are ignored for the client IP and the socket address is used.
 *  - A request that carries ANY forwarding header is never "local", whoever the peer is.
 *    A proxy on the same machine connects from 127.0.0.1; without this rule every proxied
 *    request would pass the agent-login loopback check.
 *  - With trusted proxies, the client IP is the right-most X-Forwarded-For entry that is
 *    not itself a trusted proxy (left entries are client-controlled).
 */

const PROXY_HEADERS = [
  "x-forwarded-for",
  "x-forwarded-proto",
  "x-forwarded-host",
  "x-real-ip",
  "forwarded",
  "fly-client-ip",
  "tailscale-user-login",
  "tailscale-user-name",
  "tailscale-user-profile-pic",
  "tailscale-headers-info",
];

export function isLoopbackIp(ip: string | undefined): boolean {
  if (!ip) return false;
  return ip === "::1" || ip.startsWith("127.") || ip.startsWith("::ffff:127.");
}

const unmap = (ip: string) => (ip.startsWith("::ffff:") && isIP(ip.slice(7)) === 4 ? ip.slice(7) : ip);

export class ProxyPolicy {
  private readonly list = new BlockList();
  readonly entries: string[];

  /** `cidrs`: e.g. ["127.0.0.1/32", "::1/128", "10.0.0.0/8"]; bare IPs allowed. Throws on garbage. */
  constructor(cidrs: string[] = []) {
    this.entries = cidrs.map((s) => s.trim()).filter(Boolean);
    for (const e of this.entries) {
      const [addr, bits] = e.split("/");
      const fam = isIP(addr ?? "");
      if (!fam) throw new Error(`TRUSTED_PROXIES: invalid address '${e}'`);
      const prefix = bits === undefined ? (fam === 4 ? 32 : 128) : Number(bits);
      if (!Number.isInteger(prefix) || prefix < 0 || prefix > (fam === 4 ? 32 : 128)) throw new Error(`TRUSTED_PROXIES: invalid prefix '${e}'`);
      this.list.addSubnet(addr!, prefix, fam === 4 ? "ipv4" : "ipv6");
    }
  }

  static fromEnv(v: string | undefined): ProxyPolicy {
    return new ProxyPolicy((v ?? "").split(","));
  }

  isTrusted(ip: string | undefined): boolean {
    if (!ip) return false;
    const a = unmap(ip);
    const fam = isIP(a);
    return fam !== 0 && this.list.check(a, fam === 4 ? "ipv4" : "ipv6");
  }

  /** Request carries forwarding headers (i.e. claims to have been relayed). */
  hasForwardingHeaders(req: FastifyRequest): boolean {
    return PROXY_HEADERS.some((h) => req.headers[h] !== undefined);
  }

  /** True only for requests that genuinely originate on this machine. */
  isLocalRequest(req: FastifyRequest): boolean {
    return isLoopbackIp(req.ip) && !this.hasForwardingHeaders(req);
  }

  /** Best client IP for logs, audit and rate limiting. */
  clientIp(req: FastifyRequest): string {
    if (!this.isTrusted(req.ip) || !this.hasForwardingHeaders(req)) return req.ip;
    const xff = headerAll(req, "x-forwarded-for")
      .flatMap((v) => v.split(","))
      .map((s) => s.trim())
      .filter(Boolean);
    for (let i = xff.length - 1; i >= 0; i--) {
      const cand = stripPort(xff[i]!);
      if (!isIP(unmap(cand))) break; // garbage: stop, don't trust anything further left
      if (!this.isTrusted(cand)) return cand;
    }
    const fwd = headerAll(req, "forwarded").join(",").match(/for="?\[?([0-9a-fA-F.:]+)\]?/g)?.pop();
    const fwdIp = fwd?.replace(/^for="?\[?/, "").replace(/\]?$/, "");
    if (fwdIp && isIP(fwdIp)) return fwdIp;
    for (const h of ["fly-client-ip", "x-real-ip"]) {
      const v = headerAll(req, h).pop()?.trim();
      if (v && isIP(unmap(v))) return v;
    }
    const login = headerAll(req, "tailscale-user-login").pop();
    return login ? `tailnet:${login}` : req.ip;
  }
}

function headerAll(req: FastifyRequest, name: string): string[] {
  const v = req.headers[name];
  return v === undefined ? [] : Array.isArray(v) ? v : [v];
}

function stripPort(s: string): string {
  if (s.startsWith("[")) return s.slice(1, s.indexOf("]"));
  return /^\d+\.\d+\.\d+\.\d+:\d+$/.test(s) ? s.slice(0, s.lastIndexOf(":")) : s;
}
