/**
 * AgentGate API client (HTTP + WebSocket). No CLI dependencies: candidate for
 * extraction into `packages/sdk` once a second consumer (Claude Code adapter) exists.
 */
export * from "./http.ts";
export * from "./ws.ts";
export * from "./approval-waiter.ts";
