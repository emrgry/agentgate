import type { FastifyRequest } from "fastify";
import { verifyAccessToken, type AccessClaims, type ClientKind } from "../auth/tokens.ts";
import type { ServiceDeps } from "../domain/context.ts";
import { DomainError } from "../domain/errors.ts";
import { deviceTokenValid, userExists } from "../domain/identity.ts";

declare module "fastify" {
  interface FastifyRequest {
    auth: AccessClaims | null;
  }
}

function extractToken(req: FastifyRequest, allowQuery: boolean): string | null {
  const header = req.headers.authorization;
  if (header) {
    const m = /^Bearer\s+(\S+)$/i.exec(header);
    return m ? m[1]! : null;
  }
  if (allowQuery) {
    const q = (req.query as Record<string, unknown> | undefined)?.access_token;
    if (typeof q === "string" && q.length > 0) return q;
  }
  return null;
}

/**
 * Returns a preHandler that authenticates the bearer token and (optionally) restricts the
 * token audience. `?access_token=` is accepted only for WebSocket upgrades.
 */
export function requireAuth(
  deps: ServiceDeps,
  secret: string,
  opts: { audience?: ClientKind; allowQueryToken?: boolean } = {},
) {
  return async (req: FastifyRequest): Promise<void> => {
    const token = extractToken(req, opts.allowQueryToken ?? false);
    if (!token) throw new DomainError(401, "unauthorized", "missing bearer token");
    const claims = verifyAccessToken(secret, token, deps.clock.now());
    if (!claims) throw new DomainError(401, "unauthorized", "invalid or expired token");
    if (opts.audience && claims.aud !== opts.audience) {
      throw new DomainError(403, "wrong_client", `this endpoint requires a '${opts.audience}' token`);
    }
    if (!(await userExists(deps, claims.sub))) throw new DomainError(401, "unauthorized", "unknown user");
    // Device-bound tokens die with their device. Legacy device tokens (no did) run to expiry.
    if (claims.aud === "device" && claims.did && !(await deviceTokenValid(deps, claims.sub, claims.did))) {
      throw new DomainError(401, "device_revoked", "this device has been revoked — pair it again");
    }
    req.auth = claims;
  };
}

export function claims(req: FastifyRequest): AccessClaims {
  if (!req.auth) throw new DomainError(401, "unauthorized", "not authenticated");
  return req.auth;
}

/** Strips credentials from URLs before they reach the logs. */
export function redactUrl(url: string): string {
  return url.replace(/([?&]access_token=)[^&]*/gi, "$1[redacted]");
}
