import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { computeActionHash, generateSigningKeyPair, newNonce, signApprovalToken } from "@agentgate/core";
import type { ApprovalTokenPayload } from "@agentgate/protocol";
import { describe, expect, it } from "vitest";
import { buildShellDraft, commandFromArgv } from "../src/action.ts";
import { FileNonceStore } from "../src/nonce-store.ts";
import { redact, redactString } from "../src/output.ts";
import { gateExecution } from "../src/verify.ts";

const keys = generateSigningKeyPair();
const draft = buildShellDraft({ sessionId: "ses_1", agentType: "cli", command: "git push origin main", cwd: "/work" });
const hash = computeActionHash(draft);

function token(over: Partial<ApprovalTokenPayload> = {}, pk = keys.privateKeyPem) {
  return signApprovalToken(
    {
      v: 1,
      approval_id: "apr_1",
      action_id: "act_1",
      session_id: "ses_1",
      action_hash: hash,
      decision: "approved",
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      nonce: newNonce(),
      issued_at: new Date().toISOString(),
      ...over,
    },
    pk,
  );
}

const store = () => new FileNonceStore(join(mkdtempSync(join(tmpdir(), "ag-nonce-")), "nonces"));
const base = () => ({ publicKeyPem: keys.publicKeyPem, approvalId: "apr_1", actionId: "act_1", sessionId: "ses_1", nonceStore: store(), executable: draft });

describe("gateExecution", () => {
  it("accepts a valid token and returns exactly the verified command", () => {
    const r = gateExecution({ ...base(), token: token() });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.command).toBe("git push origin main");
      expect(r.cwd).toBe("/work");
    }
  });

  it.each([
    ["no_token", () => ({ token: null })],
    ["malformed", () => ({ token: "not-a-token" })],
    ["bad_signature", () => ({ token: token({}, generateSigningKeyPair().privateKeyPem) })],
    ["expired", () => ({ token: token({ expires_at: new Date(Date.now() - 1).toISOString() }) })],
    ["approval_mismatch", () => ({ token: token({ approval_id: "apr_other" }) })],
    ["binding_mismatch", () => ({ token: token({ action_id: "act_other" }) })],
    [
      "hash_mismatch",
      () => ({
        token: token(),
        executable: { ...draft, action: { ...draft.action, command: "git push --force origin main" } },
      }),
    ],
    ["hash_mismatch", () => ({ token: token(), executable: { ...draft, action: { ...draft.action, cwd: "/elsewhere" } } })],
    ["bad_signature", () => ({ token: token(), publicKeyPem: generateSigningKeyPair().publicKeyPem })],
  ] as const)("rejects: %s", (reason, over) => {
    const r = gateExecution({ ...base(), ...over() } as Parameters<typeof gateExecution>[0]);
    expect(r).toMatchObject({ ok: false, reason });
  });

  it("structured (non-shell) actions: verifiable with requireCommand=false, rejected otherwise", () => {
    const fsDraft = { ...draft, action: { category: "filesystem", operation: "write", tool: "Write", arguments: { path: "/work/.env" }, cwd: "/work" } };
    const t = signApprovalToken(
      {
        v: 1, approval_id: "apr_1", action_id: "act_1", session_id: "ses_1", action_hash: computeActionHash(fsDraft),
        decision: "approved", expires_at: new Date(Date.now() + 60_000).toISOString(), nonce: newNonce(), issued_at: new Date().toISOString(),
      },
      keys.privateKeyPem,
    );
    expect(gateExecution({ ...base(), executable: fsDraft, token: t }).ok).toBe(false);
    expect(gateExecution({ ...base(), executable: fsDraft, token: t, requireCommand: false }).ok).toBe(true);
  });

  it("without a nonce store the token is verified but not consumed", () => {
    const t = token();
    expect(gateExecution({ ...base(), token: t, nonceStore: undefined }).ok).toBe(true);
    expect(gateExecution({ ...base(), token: t, nonceStore: undefined }).ok).toBe(true);
  });

  it("never throws on garbage key material", () => {
    const r = gateExecution({ ...base(), token: token(), publicKeyPem: "garbage" });
    expect(r.ok).toBe(false);
  });

  it("single use: a token is rejected on replay, across store instances (persistent)", () => {
    const dir = join(mkdtempSync(join(tmpdir(), "ag-nonce-")), "nonces");
    const t = token();
    const first = gateExecution({ ...base(), token: t, nonceStore: new FileNonceStore(dir) });
    const second = gateExecution({ ...base(), token: t, nonceStore: new FileNonceStore(dir) });
    expect(first.ok).toBe(true);
    expect(second).toMatchObject({ ok: false, reason: "replayed" });
  });
});

describe("FileNonceStore", () => {
  it("refuses path-like nonces", () => {
    const s = store();
    expect(s.consume("../../etc/passwd", new Date(Date.now() + 1000))).toBe(false);
  });
  it("consumes once", () => {
    const s = store();
    const n = newNonce();
    expect(s.consume(n, new Date(Date.now() + 1000))).toBe(true);
    expect(s.consume(n, new Date(Date.now() + 1000))).toBe(false);
  });
});

describe("commandFromArgv", () => {
  it("single argument is a verbatim shell line", () => {
    expect(commandFromArgv(["git status && ls"])).toBe("git status && ls");
  });
  it("multiple arguments are quoted to preserve argv meaning", () => {
    expect(commandFromArgv(["echo", "a b", "it's", "&&", "x"])).toBe(`echo 'a b' 'it'\\''s' '&&' x`);
  });
});

describe("redaction", () => {
  it("redacts bearer tokens and approval tokens", () => {
    expect(redactString("Authorization: Bearer abc.def-123")).toBe("Authorization: Bearer [REDACTED]");
    expect(redactString("ws://h/v1/agent/connect?access_token=sekrit&x=1")).toContain("access_token=[REDACTED]");
    expect(redact({ access_token: "t", nested: { approval_token: "x" }, ok: 1 })).toEqual({
      access_token: "[REDACTED]",
      nested: { approval_token: "[REDACTED]" },
      ok: 1,
    });
  });
});

import { masksEarlierFailures } from "../src/shell-status.ts";
describe("masksEarlierFailures", () => {
  it.each([
    ["a && b && c", false],
    ["a || b", false],
    ["a | b", false],
    ["a 2>&1 && b", false],
    ['git commit -m "line1\n\nline2" && git push', false],
    ["git commit -m \"$(cat <<'EOF'\nmsg; with semicolon\n\nEOF\n)\" && git push", false],
    ["a &&\n  b", false],
    ["echo 'x; y'", false],
    ["a;", false],
    ["a; b", true],
    ["a && b 2>&1; git log --oneline -1", true],
    ["a\nb", true],
    ["a & b", true],
    ["cat <<EOF\nx; y\nEOF\necho after", true],
  ])("%j → %s", (cmd, expected) => {
    expect(masksEarlierFailures(cmd)).toBe(expected);
  });
});
