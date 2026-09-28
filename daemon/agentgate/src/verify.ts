import { computeActionHash, verifyApprovalToken, type NonceStore } from "@agentgate/core";
import type { ActionDraft, ApprovalTokenPayload, DecisionPayloadV2 } from "@agentgate/protocol";
import { verifyDecision } from "@agentgate/signing";
import type { DeviceKeyLookup } from "./device-keys.ts";

export type GateFailure =
  | "no_token"
  | "malformed"
  | "bad_signature"
  | "invalid_payload"
  | "expired"
  | "hash_mismatch"
  | "approval_mismatch"
  | "replayed"
  | "binding_mismatch"
  | "internal_error"
  // v2 (phone-signed) specific
  | "unknown_device"
  | "lifetime_too_long"
  | "session_mismatch"
  | "not_approved"
  | "v1_not_accepted"
  | "no_device_keys";

export type GateResult =
  | { ok: true; payload: ApprovalTokenPayload | DecisionPayloadV2; version: 1 | 2; command: string; cwd: string | undefined; hash: string }
  | { ok: false; reason: GateFailure; detail: string };

export interface GateInput {
  /** Token received from the server (WS event or GET). */
  token: string | null | undefined;
  /** The draft that will actually be executed (its command/cwd are what gets spawned). */
  executable: ActionDraft;
  /** Pinned key from config — never a freshly fetched one. */
  publicKeyPem: string;
  approvalId: string;
  actionId: string;
  sessionId: string;
  /** Omit to verify without consuming the nonce (the hook pre-check); the executor MUST pass it. */
  nonceStore?: NonceStore;
  now?: Date;
  /** Shell executors need a command to spawn (default). Structured actions (Write/Edit/MCP) don't. */
  requireCommand?: boolean;
  /** Pinned device keys (M7). Required to accept v2 phone-signed decisions. */
  deviceKeys?: DeviceKeyLookup;
  /** Refuse v1 server-signed tokens (new local-first installs). */
  requireDeviceSignatures?: boolean;
}

/**
 * The execution gate. Recomputes the action hash from the exact draft whose command
 * will be spawned and verifies the approval token against it. The returned
 * `command`/`cwd` are taken from that same draft, so the caller cannot accidentally
 * execute something other than what was verified. Never throws.
 */
export function gateExecution(i: GateInput): GateResult {
  try {
    if (!i.token) return { ok: false, reason: "no_token", detail: "approved but no approval token was received" };
    const hash = computeActionHash(i.executable);
    const command = i.executable.action.command ?? "";
    if (i.requireCommand !== false && !command) {
      return { ok: false, reason: "internal_error", detail: "no command to execute" };
    }
    if (i.token.startsWith("v2.")) {
      // Phone-signed decision: verified against the phone's pinned key — the server can't forge it.
      if (!i.deviceKeys) return { ok: false, reason: "no_device_keys", detail: "no pinned device keys to verify a phone-signed decision" };
      let lastDevice = "";
      const v = verifyDecision(i.token, {
        publicKeyFor: (id) => {
          lastDevice = id;
          return i.deviceKeys!.publicKeyFor(id);
        },
        expectedApprovalId: i.approvalId,
        expectedActionHash: hash,
        expectedSessionId: i.sessionId,
        requireDecision: "approve",
        ...(i.nonceStore ? { nonceStore: i.nonceStore } : {}),
        ...(i.now ? { now: i.now } : {}),
      });
      if (!v.ok) {
        const detail = v.reason === "unknown_device" && lastDevice ? i.deviceKeys.whyNot(lastDevice) : describe(v.reason);
        return { ok: false, reason: v.reason, detail };
      }
      if (v.payload.action_id !== i.actionId) return { ok: false, reason: "binding_mismatch", detail: "decision is bound to a different action" };
      return { ok: true, payload: v.payload, version: 2, command, cwd: i.executable.action.cwd, hash };
    }
    if (i.requireDeviceSignatures) {
      return { ok: false, reason: "v1_not_accepted", detail: "this install only accepts phone-signed (v2) approvals" };
    }
    const r = verifyApprovalToken(i.token, {
      publicKeyPem: i.publicKeyPem,
      expectedActionHash: hash,
      expectedApprovalId: i.approvalId,
      ...(i.nonceStore ? { nonceStore: i.nonceStore } : {}),
      now: i.now,
    });
    if (!r.ok) return { ok: false, reason: r.reason, detail: describe(r.reason) };
    if (r.payload.action_id !== i.actionId || r.payload.session_id !== i.sessionId) {
      return { ok: false, reason: "binding_mismatch", detail: "token is bound to a different action/session" };
    }
    return { ok: true, payload: r.payload, version: 1, command, cwd: i.executable.action.cwd, hash };
  } catch (err) {
    return { ok: false, reason: "internal_error", detail: (err as Error).message };
  }
}

function describe(reason: GateFailure): string {
  switch (reason) {
    case "hash_mismatch":
      return "the command about to run differs from the one that was approved";
    case "bad_signature":
      return "token signature does not match the pinned server key";
    case "expired":
      return "approval token expired";
    case "replayed":
      return "approval token was already used";
    case "approval_mismatch":
      return "token belongs to a different approval";
    case "unknown_device":
      return "decision signed by an unknown or untrusted device";
    case "lifetime_too_long":
      return "decision validity window is too long";
    case "session_mismatch":
      return "decision belongs to a different session";
    case "not_approved":
      return "the signed decision is not an approval";
    case "malformed":
      return "token is malformed";
    case "invalid_payload":
      return "token payload is invalid";
    default:
      return reason;
  }
}
