import type { WebSocket } from "ws";
import type { ServerEvent } from "@agentgate/protocol";
import type { Logger } from "../domain/context.ts";

export type ConnectionKind = "agent" | "device";

interface Connection {
  socket: WebSocket;
  kind: ConnectionKind;
  userId: string;
  /** Agent sockets may subscribe to one session; null = all of the user's sessions. */
  sessionId: string | null;
  /** Device sockets: the device id (token `did`, or `?device_id=` for legacy tokens). */
  deviceId?: string | null;
  alive: boolean;
}

/**
 * In-process WebSocket fan-out. Single-node only; for horizontal scaling put a pub/sub
 * (Postgres LISTEN/NOTIFY or Redis) behind `publish*` — the interface stays the same.
 */
export class RealtimeHub {
  private readonly byUser = new Map<string, Set<Connection>>();
  private heartbeat: NodeJS.Timeout | null = null;

  constructor(private readonly logger: Logger) {}

  add(socket: WebSocket, meta: { kind: ConnectionKind; userId: string; sessionId: string | null; deviceId?: string | null }): void {
    const conn: Connection = { socket, ...meta, alive: true };
    let set = this.byUser.get(meta.userId);
    if (!set) this.byUser.set(meta.userId, (set = new Set()));
    set.add(conn);

    socket.on("pong", () => {
      conn.alive = true;
    });
    socket.on("message", (data) => {
      conn.alive = true;
      let msg: unknown;
      try {
        msg = JSON.parse(data.toString());
      } catch {
        return;
      }
      if (msg && typeof msg === "object" && (msg as { type?: unknown }).type === "ping") {
        this.send(conn, { type: "pong" });
      }
    });
    socket.on("close", () => this.remove(conn));
    socket.on("error", () => this.remove(conn));

    this.send(conn, { type: "hello", server_time: new Date().toISOString() });
  }

  private remove(conn: Connection): void {
    const set = this.byUser.get(conn.userId);
    if (!set) return;
    set.delete(conn);
    if (set.size === 0) this.byUser.delete(conn.userId);
  }

  private send(conn: Connection, event: ServerEvent): void {
    if (conn.socket.readyState !== conn.socket.OPEN) return;
    conn.socket.send(JSON.stringify(event), (err) => {
      if (err) this.logger.warn({ err: err.message, kind: conn.kind }, "ws send failed");
    });
  }

  publishToDevices(userId: string, event: ServerEvent): number {
    let n = 0;
    for (const c of this.byUser.get(userId) ?? []) {
      if (c.kind === "device") {
        this.send(c, event);
        n++;
      }
    }
    return n;
  }

  publishToAgents(userId: string, sessionId: string, event: ServerEvent): number {
    let n = 0;
    for (const c of this.byUser.get(userId) ?? []) {
      if (c.kind === "agent" && (c.sessionId === null || c.sessionId === sessionId)) {
        this.send(c, event);
        n++;
      }
    }
    return n;
  }

  /** Closes every socket of a (revoked) device. */
  disconnectDevice(userId: string, deviceId: string): number {
    let n = 0;
    for (const c of [...(this.byUser.get(userId) ?? [])]) {
      if (c.kind === "device" && c.deviceId === deviceId) {
        c.socket.close(4001, "device revoked");
        this.remove(c);
        n++;
      }
    }
    return n;
  }

  connectionCount(): number {
    let n = 0;
    for (const s of this.byUser.values()) n += s.size;
    return n;
  }

  /** Protocol-level ping every interval; sockets that missed the previous pong are dropped. */
  startHeartbeat(intervalMs = 30_000): void {
    this.stopHeartbeat();
    this.heartbeat = setInterval(() => {
      for (const set of this.byUser.values()) {
        for (const c of set) {
          if (!c.alive) {
            c.socket.terminate();
            this.remove(c);
            continue;
          }
          c.alive = false;
          try {
            c.socket.ping();
          } catch {
            /* close handler cleans up */
          }
        }
      }
    }, intervalMs);
    this.heartbeat.unref();
  }

  stopHeartbeat(): void {
    if (this.heartbeat) clearInterval(this.heartbeat);
    this.heartbeat = null;
  }

  closeAll(): void {
    this.stopHeartbeat();
    for (const set of this.byUser.values()) for (const c of set) c.socket.close(1001, "server shutting down");
    this.byUser.clear();
  }
}
