import { describe, expect, it } from "vitest";
import { APPROVAL_STATUSES, type ApprovalStatus } from "@agentgate/protocol";
import {
  ApprovalTransitionError,
  isExpired,
  isTerminal,
  transitionApproval,
  type ApprovalEvent,
} from "../src/index.ts";
import { at, makeApproval } from "./fixtures.ts";

const EXPIRES_MS = 120_000;
const beforeExpiry = at(1_000);
const atExpiry = at(EXPIRES_MS);
const afterExpiry = at(EXPIRES_MS + 1);

const EVENTS: ApprovalEvent[] = [
  { type: "approve", device_id: "dev_1" },
  { type: "deny", device_id: "dev_1" },
  { type: "expire" },
  { type: "cancel", reason: "session ended" },
];

describe("transitionApproval — valid transitions from pending", () => {
  it("approve → approved, records decision, device and time", () => {
    const next = transitionApproval(makeApproval(), { type: "approve", device_id: "dev_9" }, beforeExpiry);
    expect(next).toMatchObject({
      status: "approved",
      decision: "approve",
      resolved_by_device_id: "dev_9",
      resolved_at: beforeExpiry.toISOString(),
    });
  });

  it("deny → denied, records decision, device and time", () => {
    const next = transitionApproval(makeApproval(), { type: "deny", device_id: "dev_9" }, beforeExpiry);
    expect(next).toMatchObject({
      status: "denied",
      decision: "deny",
      resolved_by_device_id: "dev_9",
      resolved_at: beforeExpiry.toISOString(),
    });
  });

  it("expire at exactly expires_at → expired", () => {
    const next = transitionApproval(makeApproval(), { type: "expire" }, atExpiry);
    expect(next).toMatchObject({ status: "expired", decision: null, resolved_at: atExpiry.toISOString() });
  });

  it("expire after expires_at → expired", () => {
    expect(transitionApproval(makeApproval(), { type: "expire" }, afterExpiry).status).toBe("expired");
  });

  it("cancel → cancelled", () => {
    const next = transitionApproval(makeApproval(), { type: "cancel", reason: "agent exited" }, beforeExpiry);
    expect(next).toMatchObject({ status: "cancelled", decision: null, resolved_at: beforeExpiry.toISOString() });
    expect(next.resolved_by_device_id).toBeNull();
  });

  it("cancel is allowed even after expires_at (session ended)", () => {
    expect(transitionApproval(makeApproval(), { type: "cancel" }, afterExpiry).status).toBe("cancelled");
  });

  it("preserves identity fields", () => {
    const a = makeApproval();
    const next = transitionApproval(a, { type: "approve", device_id: "d" }, beforeExpiry);
    expect(next.approval_id).toBe(a.approval_id);
    expect(next.action_id).toBe(a.action_id);
    expect(next.requested_at).toBe(a.requested_at);
    expect(next.expires_at).toBe(a.expires_at);
  });
});

describe("transitionApproval — late decisions fail closed", () => {
  it.each([
    ["approve at expires_at", { type: "approve", device_id: "d" } as const, atExpiry],
    ["approve after expires_at", { type: "approve", device_id: "d" } as const, afterExpiry],
    ["deny at expires_at", { type: "deny", device_id: "d" } as const, atExpiry],
    ["deny after expires_at", { type: "deny", device_id: "d" } as const, afterExpiry],
  ])("%s → expired, with no decision and no device", (_name, event, now) => {
    const next = transitionApproval(makeApproval(), event, now);
    expect(next.status).toBe("expired");
    expect(next.decision).toBeNull();
    expect(next.resolved_by_device_id).toBeNull();
    expect(next.resolved_at).toBe(now.toISOString());
  });

  it("approve 1 ms before expires_at still succeeds", () => {
    expect(transitionApproval(makeApproval(), { type: "approve", device_id: "d" }, at(EXPIRES_MS - 1)).status).toBe(
      "approved",
    );
  });

  it("treats an unparseable expires_at as expired (approve cannot succeed)", () => {
    const bad = makeApproval({ expires_at: "not-a-date" });
    expect(transitionApproval(bad, { type: "approve", device_id: "d" }, beforeExpiry).status).toBe("expired");
  });

  it("never approves with an invalid `now` (throws or resolves non-approved)", () => {
    let status: string | undefined;
    try {
      status = transitionApproval(makeApproval(), { type: "approve", device_id: "d" }, new Date(NaN)).status;
    } catch {
      status = "threw";
    }
    expect(status).not.toBe("approved");
  });
});

describe("transitionApproval — invalid transitions", () => {
  it("expire before expires_at throws ApprovalTransitionError", () => {
    const fn = () => transitionApproval(makeApproval(), { type: "expire" }, beforeExpiry);
    expect(fn).toThrow(ApprovalTransitionError);
    expect(fn).toThrow(/has not reached expires_at/);
  });

  const terminal = APPROVAL_STATUSES.filter((s) => s !== "pending");
  const cases = terminal.flatMap((status) =>
    EVENTS.flatMap((event) => [beforeExpiry, afterExpiry].map((now) => [status, event.type, event, now] as const)),
  );

  it.each(cases)("terminal %s rejects %s (now=%#)", (status, _type, event, now) => {
    const approval = makeApproval({
      status,
      decision: status === "approved" ? "approve" : status === "denied" ? "deny" : null,
      resolved_at: beforeExpiry.toISOString(),
    });
    let err: unknown;
    try {
      transitionApproval(approval, event, now);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ApprovalTransitionError);
    expect((err as ApprovalTransitionError).from).toBe(status);
    expect((err as ApprovalTransitionError).event).toBe(event.type);
  });

  it("covers every terminal status × every event", () => {
    expect(new Set(cases.map((c) => `${c[0]}:${c[1]}`)).size).toBe(4 * 4);
  });
});

describe("transitionApproval — purity", () => {
  it.each(EVENTS)("does not mutate its input (%o)", (event) => {
    const input = makeApproval();
    const snapshot = structuredClone(input);
    const frozen = Object.freeze(input);
    const now = event.type === "expire" ? afterExpiry : beforeExpiry;
    const next = transitionApproval(frozen, event, now);
    expect(input).toEqual(snapshot);
    expect(next).not.toBe(input);
  });

  it("does not mutate input when throwing", () => {
    const input = Object.freeze(makeApproval({ status: "approved", decision: "approve" }));
    const snapshot = structuredClone(input);
    expect(() => transitionApproval(input, { type: "deny", device_id: "d" }, beforeExpiry)).toThrow();
    expect(input).toEqual(snapshot);
  });
});

describe("isTerminal / isExpired", () => {
  it.each(APPROVAL_STATUSES.map((s) => [s, s !== "pending"] as [ApprovalStatus, boolean]))(
    "isTerminal(%s) === %s",
    (status, expected) => {
      expect(isTerminal(status)).toBe(expected);
    },
  );

  it("isExpired boundary is inclusive of expires_at", () => {
    const a = makeApproval();
    expect(isExpired(a, at(EXPIRES_MS - 1))).toBe(false);
    expect(isExpired(a, atExpiry)).toBe(true);
    expect(isExpired(a, afterExpiry)).toBe(true);
  });

  it("isExpired fails closed on garbage", () => {
    expect(isExpired({ expires_at: "garbage" }, beforeExpiry)).toBe(true);
    expect(isExpired(makeApproval(), new Date("nope"))).toBe(true);
  });
});
