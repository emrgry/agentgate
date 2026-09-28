import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Minimal HS256 JWT (node:crypto only). Access tokens for the dev login flow.
 * aud = "device" | "agent"; sub = user id.
 */

export type ClientKind = "device" | "agent";

export const TOKEN_TTL_SECONDS: Record<ClientKind, number> = {
  device: 12 * 60 * 60,
  agent: 60 * 60,
};

const ISSUER = "agentgate";

export interface AccessClaims {
  sub: string;
  email: string;
  aud: ClientKind;
  iat: number;
  exp: number;
  iss: string;
  /** Device tokens issued after pairing are bound to one device record (revocable). */
  did?: string;
}

const b64 = (v: string | Buffer) => Buffer.from(v).toString("base64url");

export function signAccessToken(
  secret: string,
  claims: { sub: string; email: string; aud: ClientKind; did?: string },
  now: Date,
): { token: string; expiresAt: Date } {
  const iat = Math.floor(now.getTime() / 1000);
  const exp = iat + TOKEN_TTL_SECONDS[claims.aud];
  const header = b64(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64(JSON.stringify({ ...claims, iat, exp, iss: ISSUER } satisfies AccessClaims));
  const sig = createHmac("sha256", secret).update(`${header}.${body}`).digest("base64url");
  return { token: `${header}.${body}.${sig}`, expiresAt: new Date(exp * 1000) };
}

export function verifyAccessToken(secret: string, token: string, now: Date): AccessClaims | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, body, sig] = parts as [string, string, string];
  const expected = createHmac("sha256", secret).update(`${header}.${body}`).digest();
  const given = Buffer.from(sig, "base64url");
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  try {
    const h = JSON.parse(Buffer.from(header, "base64url").toString("utf8")) as { alg?: unknown };
    if (h.alg !== "HS256") return null;
    const c = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as Partial<AccessClaims>;
    if (
      typeof c.sub !== "string" ||
      typeof c.email !== "string" ||
      (c.aud !== "device" && c.aud !== "agent") ||
      typeof c.exp !== "number" ||
      typeof c.iat !== "number" ||
      c.iss !== ISSUER ||
      (c.did !== undefined && typeof c.did !== "string")
    ) {
      return null;
    }
    if (Math.floor(now.getTime() / 1000) >= c.exp) return null;
    return c as AccessClaims;
  } catch {
    return null;
  }
}
