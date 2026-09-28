import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import type { ServiceDeps } from "../domain/context.ts";
import { requireOwnedDevice, touchDevice } from "../domain/identity.ts";
import { requireOwnedSession } from "../domain/sessions.ts";
import { claims, requireAuth } from "../http/auth.ts";
import type { RealtimeHub } from "./hub.ts";
import { DomainError } from "../domain/errors.ts";

const AgentQuery = z.object({ session_id: z.string().min(1).max(64).optional() });
const DeviceQuery = z.object({ device_id: z.string().min(1).max(64).optional() });

/**
 * WS /v1/agent/connect?session_id=…   (agent token)  → approval.resolved for that session
 * WS /v1/device/connect[?device_id=…] (device token) → approval.created / approval.resolved
 * Auth: `Authorization: Bearer` or `?access_token=`. Auth/ownership failures are rejected
 * with an HTTP error before the upgrade.
 */
export function registerRealtimeRoutes(
  app: FastifyInstance,
  deps: ServiceDeps,
  hub: RealtimeHub,
  opts: { authSecret: string },
): void {
  app.get(
    "/v1/agent/connect",
    {
      websocket: true,
      preValidation: [
        requireAuth(deps, opts.authSecret, { audience: "agent", allowQueryToken: true }),
        async (req: FastifyRequest) => {
          const { session_id } = AgentQuery.parse(req.query);
          if (session_id) await requireOwnedSession(deps.db, claims(req).sub, session_id);
        },
      ],
    },
    (socket, req) => {
      const { session_id } = AgentQuery.parse(req.query);
      hub.add(socket, { kind: "agent", userId: claims(req).sub, sessionId: session_id ?? null });
    },
  );

  app.get(
    "/v1/device/connect",
    {
      websocket: true,
      preValidation: [
        requireAuth(deps, opts.authSecret, { audience: "device", allowQueryToken: true }),
        async (req: FastifyRequest) => {
          const { device_id } = DeviceQuery.parse(req.query);
          const did = claims(req).did;
          if (did && device_id && device_id !== did) throw new DomainError(403, "forbidden", "device_id does not match this token");
          if (did) await touchDevice(deps, did);
          if (device_id) {
            await requireOwnedDevice(deps, claims(req).sub, device_id);
            await touchDevice(deps, device_id);
          }
        },
      ],
    },
    (socket, req) => {
      const c = claims(req);
      hub.add(socket, { kind: "device", userId: c.sub, sessionId: null, deviceId: c.did ?? DeviceQuery.parse(req.query).device_id ?? null });
    },
  );
}
