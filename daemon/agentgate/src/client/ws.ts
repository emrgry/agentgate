import { ServerEvent } from "@agentgate/protocol";
import WebSocket from "ws";

/**
 * Agent WebSocket (`/v1/agent/connect`). Auth via `Authorization: Bearer` header
 * (the token never goes into the URL, so it cannot leak into proxy/access logs).
 * Server frames are validated against `ServerEvent`; unknown/invalid frames are
 * ignored — they can never be mistaken for an approval.
 */

export interface AgentSocketOptions {
  server: string;
  accessToken: string;
  sessionId?: string;
  /** Handshake timeout. Default 10 s. */
  connectTimeoutMs?: number;
  onEvent?: (event: ServerEvent) => void;
  /** Called once when the socket closes after having been open. */
  onClose?: (info: { code: number; reason: string }) => void;
  debug?: (msg: string, data?: unknown) => void;
}

export class WsConnectError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "WsConnectError";
  }
}

export function agentSocketUrl(server: string, sessionId?: string): string {
  const u = new URL("/v1/agent/connect", server.replace(/\/+$/, "") + "/");
  u.protocol = u.protocol === "https:" ? "wss:" : "ws:";
  if (sessionId) u.searchParams.set("session_id", sessionId);
  return u.toString();
}

export class AgentSocket {
  private pongWaiters: Array<() => void> = [];
  private closedFlag = false;

  private constructor(
    private readonly ws: WebSocket,
    private readonly opts: AgentSocketOptions,
  ) {
    ws.on("message", (data, isBinary) => {
      if (isBinary) return;
      let json: unknown;
      try {
        json = JSON.parse(data.toString());
      } catch {
        opts.debug?.("ws: ignoring non-JSON frame");
        return;
      }
      const parsed = ServerEvent.safeParse(json);
      if (!parsed.success) {
        opts.debug?.("ws: ignoring unrecognized frame", json);
        return;
      }
      opts.debug?.(`ws ← ${parsed.data.type}`, parsed.data);
      if (parsed.data.type === "pong") {
        const waiters = this.pongWaiters;
        this.pongWaiters = [];
        waiters.forEach((w) => w());
      }
      opts.onEvent?.(parsed.data);
    });
    ws.on("close", (code, reason) => {
      if (this.closedFlag) return;
      this.closedFlag = true;
      opts.debug?.(`ws closed (${code})`);
      opts.onClose?.({ code, reason: reason.toString() });
    });
    ws.on("error", (err) => opts.debug?.(`ws error: ${err.message}`));
  }

  /** Resolves once the socket is open; rejects on handshake failure/timeout. */
  static connect(opts: AgentSocketOptions): Promise<AgentSocket> {
    const url = agentSocketUrl(opts.server, opts.sessionId);
    opts.debug?.(`ws connecting ${url}`);
    return new Promise((resolve, reject) => {
      let settled = false;
      const ws = new WebSocket(url, {
        headers: { authorization: `Bearer ${opts.accessToken}` },
        handshakeTimeout: opts.connectTimeoutMs ?? 10_000,
      });
      const fail = (err: WsConnectError) => {
        if (settled) return;
        settled = true;
        ws.removeAllListeners();
        ws.on("error", () => {});
        ws.terminate();
        reject(err);
      };
      ws.once("unexpected-response", (_req, res) => {
        fail(new WsConnectError(`websocket handshake rejected: HTTP ${res.statusCode}`, res.statusCode));
      });
      ws.once("error", (err) => fail(new WsConnectError(`websocket error: ${err.message}`)));
      ws.once("close", (code) => fail(new WsConnectError(`websocket closed during handshake (${code})`)));
      ws.once("open", () => {
        if (settled) return;
        settled = true;
        ws.removeAllListeners();
        resolve(new AgentSocket(ws, opts));
      });
    });
  }

  get isOpen(): boolean {
    return !this.closedFlag && this.ws.readyState === WebSocket.OPEN;
  }

  /** Sends {"type":"ping"} and resolves with the round-trip time in ms. */
  ping(timeoutMs = 5_000): Promise<number> {
    return new Promise((resolve, reject) => {
      if (!this.isOpen) return reject(new Error("socket not open"));
      const start = performance.now();
      const timer = setTimeout(() => {
        this.pongWaiters = this.pongWaiters.filter((w) => w !== done);
        reject(new Error(`no pong within ${timeoutMs}ms`));
      }, timeoutMs);
      const done = () => {
        clearTimeout(timer);
        resolve(performance.now() - start);
      };
      this.pongWaiters.push(done);
      this.ws.send(JSON.stringify({ type: "ping" }), (err) => {
        if (err) {
          clearTimeout(timer);
          reject(err);
        }
      });
    });
  }

  close(): void {
    this.closedFlag = true;
    this.pongWaiters = [];
    try {
      this.ws.close(1000, "bye");
    } catch {
      /* ignore */
    }
    // Don't let a half-closed socket keep the process alive.
    setTimeout(() => this.ws.terminate(), 500).unref();
  }

  /** Forcefully drop the connection (used when heartbeats fail). */
  terminate(): void {
    this.ws.terminate();
  }
}
