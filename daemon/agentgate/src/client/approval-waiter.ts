import type { ApprovalStatus, ServerEvent } from "@agentgate/protocol";
import type { AgentGateClient } from "./http.ts";
import { AgentSocket, WsConnectError } from "./ws.ts";

/**
 * Waits for the human decision on an approval.
 *
 * Protocol (architecture §7 step 4, protocol/events.ts):
 *  - The socket is opened BEFORE the action is submitted (`ApprovalWaiter.open`), so a
 *    resolution can never be emitted before we're listening. Resolutions that arrive
 *    before `wait()` is called are buffered.
 *  - On disconnect: reconnect with backoff; after every reconnect re-fetch
 *    GET /v1/approvals/:id so a resolution that happened while offline isn't missed.
 *  - Heartbeat: ping every `heartbeatMs`; a missing pong drops and reconnects.
 *  - At the deadline, re-check once via GET (timeout edge) before giving up.
 *
 * The waiter only reports what the server said. It never decides "go": the caller
 * must still verify the token cryptographically. Every non-approved outcome, and every
 * error, is a block.
 */

export type WaitOutcome =
  | { status: "approved"; token: string | null; via: "ws" | "http" }
  | { status: Exclude<ApprovalStatus, "approved" | "pending">; via: "ws" | "http" }
  | { status: "timeout" }
  | { status: "aborted" }
  | { status: "error"; error: Error };

export interface ApprovalWaiterOptions {
  client: AgentGateClient;
  accessToken: string;
  sessionId: string;
  heartbeatMs?: number;
  /** Max delay between reconnect attempts. */
  maxBackoffMs?: number;
  debug?: (msg: string, data?: unknown) => void;
  /** Informational hooks (for UI). */
  onDisconnect?: () => void;
  onReconnect?: () => void;
}

type Resolved = Extract<ServerEvent, { type: "approval.resolved" }>;

export class ApprovalWaiter {
  private socket: AgentSocket | null = null;
  private readonly buffered = new Map<string, Resolved>();
  private listener: ((e: Resolved) => void) | null = null;
  private closeListener: (() => void) | null = null;
  private heartbeat: NodeJS.Timeout | null = null;
  private closed = false;

  private constructor(private readonly opts: ApprovalWaiterOptions) {}

  /** Opens the agent socket. Rejects if it cannot be established (caller blocks). */
  static async open(opts: ApprovalWaiterOptions): Promise<ApprovalWaiter> {
    const w = new ApprovalWaiter(opts);
    await w.connect();
    return w;
  }

  private async connect(): Promise<void> {
    this.socket = await AgentSocket.connect({
      server: this.opts.client.server,
      accessToken: this.opts.accessToken,
      sessionId: this.opts.sessionId,
      debug: this.opts.debug,
      onEvent: (e) => {
        if (e.type !== "approval.resolved") return;
        if (this.listener) this.listener(e);
        else this.buffered.set(e.approval_id, e);
      },
      onClose: () => {
        this.stopHeartbeat();
        this.socket = null;
        if (!this.closed) this.closeListener?.();
      },
    });
    this.startHeartbeat();
  }

  private startHeartbeat() {
    this.stopHeartbeat();
    const every = this.opts.heartbeatMs ?? 15_000;
    this.heartbeat = setInterval(() => {
      const s = this.socket;
      if (!s) return;
      s.ping(Math.min(every, 10_000)).catch(() => {
        this.opts.debug?.("ws heartbeat failed; dropping connection");
        s.terminate();
      });
    }, every);
    this.heartbeat.unref();
  }

  private stopHeartbeat() {
    if (this.heartbeat) clearInterval(this.heartbeat);
    this.heartbeat = null;
  }

  /**
   * Wait for approvalId to resolve, up to timeoutMs. Never throws: errors are
   * returned as { status: "error" } (callers block).
   */
  wait(approvalId: string, timeoutMs: number, signal?: AbortSignal): Promise<WaitOutcome> {
    return new Promise<WaitOutcome>((resolve) => {
      let done = false;
      let timer: NodeJS.Timeout | null = null;
      let reconnecting = false;

      const finish = (o: WaitOutcome) => {
        if (done) return;
        done = true;
        if (timer) clearTimeout(timer);
        this.listener = null;
        this.closeListener = null;
        signal?.removeEventListener("abort", onAbort);
        resolve(o);
      };

      const fromEvent = (e: Resolved): WaitOutcome | null => {
        if (e.approval_id !== approvalId || e.status === "pending") return null;
        if (e.status === "approved") return { status: "approved", token: e.approval_token, via: "ws" };
        return { status: e.status, via: "ws" };
      };

      /** GET /v1/approvals/:id → outcome if terminal, null if still pending. */
      const recheck = async (): Promise<WaitOutcome | null> => {
        const { detail, approval_token } = await this.opts.client.getApproval(approvalId);
        const st = detail.approval.status;
        if (detail.approval.approval_id !== approvalId) throw new Error("approval id mismatch in GET response");
        if (st === "pending") return null;
        if (st === "approved") return { status: "approved", token: approval_token, via: "http" };
        return { status: st, via: "http" };
      };

      const onAbort = () => finish({ status: "aborted" });
      if (signal?.aborted) return finish({ status: "aborted" });
      signal?.addEventListener("abort", onAbort, { once: true });

      // 1) anything that already arrived
      const early = this.buffered.get(approvalId);
      if (early) {
        this.buffered.delete(approvalId);
        const o = fromEvent(early);
        if (o) return finish(o);
      }

      // 2) live events
      this.listener = (e) => {
        const o = fromEvent(e);
        if (o) finish(o);
      };

      // 3) deadline: re-check once, then give up
      timer = setTimeout(() => {
        recheck()
          .then((o) => finish(o ?? { status: "timeout" }))
          .catch(() => finish({ status: "timeout" }));
      }, timeoutMs);

      // 4) reconnect loop
      const reconnect = async () => {
        if (reconnecting || done) return;
        reconnecting = true;
        this.opts.onDisconnect?.();
        let delay = 250;
        while (!done && !this.closed) {
          await sleep(delay);
          if (done || this.closed) break;
          try {
            await this.connect();
          } catch (err) {
            if (err instanceof WsConnectError && err.status && err.status >= 400 && err.status < 500) {
              // Auth / session rejected: waiting longer can't help.
              finish({ status: "error", error: err });
              break;
            }
            this.opts.debug?.(`reconnect failed: ${(err as Error).message}`);
            delay = Math.min(delay * 2, this.opts.maxBackoffMs ?? 5_000);
            continue;
          }
          if (done) break;
          this.opts.onReconnect?.();
          // Resolution may have happened while we were offline.
          try {
            const o = await recheck();
            if (o) finish(o);
          } catch (err) {
            // Socket is back; live events + the deadline re-check still apply.
            this.opts.debug?.(`re-fetch after reconnect failed: ${(err as Error).message}`);
          }
          break;
        }
        reconnecting = false;
      };
      this.closeListener = () => void reconnect();
      if (!this.socket) void reconnect();
    });
  }

  close(): void {
    this.closed = true;
    this.stopHeartbeat();
    this.listener = null;
    this.closeListener = null;
    this.socket?.close();
    this.socket = null;
  }
}

function sleep(ms: number) {
  return new Promise<void>((r) => setTimeout(r, ms));
}
