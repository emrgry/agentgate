import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { captureBase, changeSet, fileDiff, redactPatch, safeRepoPath } from "../src/control/review.ts";
import { isTestCommand, outputTail, parseTestOutput } from "../src/control/testruns.ts";
import { parsePs, processTree, summarize } from "../src/control/resources.ts";
import { checkLimits, effectiveLimits } from "../src/control/limits.ts";
import { matchReceipt, type GateReceipt } from "../src/control/tripwire.ts";

/** Pure / git-level units for Control Center Phases 2–4. */

function repo(): string {
  const d = realpathSync(mkdtempSync(join(tmpdir(), "ag-rev-")));
  const g = (...a: string[]) => execFileSync("git", a, { cwd: d, stdio: "ignore" });
  g("init", "-q", "-b", "main");
  g("config", "user.email", "t@t");
  g("config", "user.name", "t");
  writeFileSync(join(d, "a.txt"), "one\ntwo\nthree\n");
  writeFileSync(join(d, "keep.txt"), "keep\n");
  writeFileSync(join(d, ".gitignore"), "ignored/\n");
  g("add", "-A");
  g("commit", "-qm", "init");
  return d;
}

describe("review: diff against the captured base", () => {
  it("pre-dirty and pre-untracked files only show the session's own changes; new/deleted/renamed/binary detected", async () => {
    const d = repo();
    // Dirty BEFORE the session: a.txt modified, pre.txt untracked, ignored file.
    writeFileSync(join(d, "a.txt"), "one\ntwo (dirty before)\nthree\n");
    writeFileSync(join(d, "pre.txt"), "untracked before\n");
    mkdirSync(join(d, "ignored"));
    writeFileSync(join(d, "ignored", "x"), "x");
    const base = await captureBase(d, new Date());
    expect(base?.tree).toMatch(/^[0-9a-f]{40}$/);
    // Nothing changed yet → empty change set (HEAD-based diff would show a.txt + pre.txt).
    expect((await changeSet(base, d))!.files).toEqual([]);
    // The session's work:
    writeFileSync(join(d, "a.txt"), "one\ntwo (dirty before)\nthree\nfour\n");
    writeFileSync(join(d, "new.txt"), "brand new\n");
    execFileSync("git", ["mv", "keep.txt", "kept.txt"], { cwd: d });
    writeFileSync(join(d, "img.bin"), Buffer.from([0, 1, 2, 3, 0, 255, 0]));
    writeFileSync(join(d, "ignored", "y"), "y");
    const cs = (await changeSet(base, d))!;
    const byPath = Object.fromEntries(cs.files.map((f) => [f.path, f]));
    expect(Object.keys(byPath).sort()).toEqual(["a.txt", "img.bin", "kept.txt", "new.txt"]);
    expect(byPath["a.txt"]).toMatchObject({ status: "modified", additions: 1, deletions: 0, binary: false });
    expect(byPath["new.txt"]).toMatchObject({ status: "added", additions: 1 });
    expect(byPath["kept.txt"]).toMatchObject({ status: "renamed", old_path: "keep.txt" });
    expect(byPath["img.bin"]).toMatchObject({ binary: true, additions: null });
    expect(cs.totals).toMatchObject({ files: 4, additions: 2, deletions: 0 });
    expect(cs.truncated).toBe(false);
    // The user's real index was not touched.
    expect(execFileSync("git", ["diff", "--cached", "--name-only"], { cwd: d, encoding: "utf8" }).trim()).toBe("kept.txt"); // only the user's own `git mv`
    // File diff: only the session's hunk.
    const fd = await fileDiff(base, d, "a.txt");
    expect(fd.patch).toContain("+four");
    expect(fd.patch).not.toContain("+two (dirty before)");
    expect((await fileDiff(base, d, "img.bin")).binary).toBe(true);
  });

  it("caps at 1000 files and sets truncated", async () => {
    const d = repo();
    const base = await captureBase(d, new Date());
    mkdirSync(join(d, "many"));
    for (let i = 0; i < 1005; i++) writeFileSync(join(d, "many", `f${i}.txt`), `${i}\n`);
    const cs = (await changeSet(base, d))!;
    expect(cs.files).toHaveLength(1000);
    expect(cs.totals.files).toBe(1005);
    expect(cs.truncated).toBe(true);
  });

  it("path validation: traversal, absolute, .git and symlink escapes are rejected", () => {
    const d = repo();
    const outside = realpathSync(mkdtempSync(join(tmpdir(), "ag-out-")));
    writeFileSync(join(outside, "secret"), "s");
    symlinkSync(outside, join(d, "link-dir"));
    symlinkSync(join(outside, "secret"), join(d, "link-file"));
    for (const bad of ["../x", "a/../../x", "/etc/passwd", "~/x", "", ".git/config", "link-dir/secret", "link-file", "x\0y"]) {
      expect(() => safeRepoPath(d, bad), bad).toThrow(/inside the repository/);
    }
    expect(safeRepoPath(d, "a.txt")).toBe("a.txt");
    expect(safeRepoPath(d, "./sub/../a.txt")).toBe("a.txt");
    expect(safeRepoPath(d, "deleted/dir/file.txt")).toBe("deleted/dir/file.txt"); // nearest existing parent = repo
  });

  it("patch redaction: known token formats everywhere; every value in sensitive files", () => {
    const p = redactPatch("src/x.ts", "+const k = 'ghp_abcdefghijklmnopqrstuvwxyz0123';\n+API_KEY=abc123");
    expect(p).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz0123");
    expect(p).toContain("API_KEY=***");
    const env = redactPatch(".env", "--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-DB_URL=postgres://u:p@h/db\n+PLAIN=hello");
    expect(env).toContain("-DB_URL=***");
    expect(env).toContain("+PLAIN=***");
    expect(env).toContain("+++ b/.env");
  });
});

describe("test runs", () => {
  it.each([
    ["npm test", true],
    ["pnpm run test:unit", true],
    ["yarn test --watch=false", true],
    ["npx vitest run", true],
    ["bash -lc 'npm test'", true],
    ["pytest -q tests/", true],
    ["python3 -m pytest", true],
    ["go test ./...", true],
    ["cargo test --all", true],
    ["node --test", true],
    ["ls -la", false],
    ["cat test.txt", false],
    ["git commit -m 'add test'", false],
  ])("isTestCommand(%s) = %s", (cmd, want) => expect(isTestCommand(cmd)).toBe(want));

  it.each([
    ["vitest", " Test Files  2 passed (2)\n      Tests  1 failed | 9 passed | 2 skipped (12)\n", { passed: 9, failed: 1, skipped: 2 }],
    ["jest", "Tests:       1 failed, 2 skipped, 10 passed, 13 total\n", { passed: 10, failed: 1, skipped: 2 }],
    ["pytest", "===== 2 failed, 10 passed, 1 skipped in 0.52s =====\n", { passed: 10, failed: 2, skipped: 1 }],
    ["pytest ok", "5 passed in 0.10s\n", { passed: 5, failed: 0, skipped: 0 }],
    ["cargo", "test result: ok. 5 passed; 0 failed; 1 ignored; 0 measured\ntest result: FAILED. 2 passed; 1 failed; 0 ignored;\n", { passed: 7, failed: 1, skipped: 1 }],
    ["mocha", "  5 passing (20ms)\n  2 failing\n  1 pending\n", { passed: 5, failed: 2, skipped: 1 }],
    ["tap", "# tests 6\n# pass 5\n# fail 1\n# skipped 0\n", { passed: 5, failed: 1, skipped: 0 }],
    ["go -v", "=== RUN TestA\n--- PASS: TestA (0.00s)\n--- FAIL: TestB (0.00s)\n--- SKIP: TestC\nFAIL\n", { passed: 1, failed: 1, skipped: 1 }],
    ["go pkgs", "ok  \texample.com/a\t0.1s\nFAIL\texample.com/b\t0.2s\n", { passed: null, failed: 1, skipped: null }],
    ["unknown", "all good\n", { passed: null, failed: null, skipped: null }],
    ["ansi vitest", "\u001b[2m      Tests \u001b[22m \u001b[1m\u001b[32m3 passed\u001b[39m\u001b[22m\u001b[90m (3)\u001b[39m\n", { passed: 3, failed: 0, skipped: 0 }],
  ])("parseTestOutput %s", (_n, out, want) => expect(parseTestOutput(out)).toEqual(want));

  it("output tail ≤ 4 KB and redacted", () => {
    const t = outputTail(`${"x".repeat(10_000)}\nTOKEN=supersecret\n`);
    expect(t.length).toBeLessThanOrEqual(4096);
    expect(t).toContain("TOKEN=***");
  });
});

describe("resources (fake ps)", () => {
  const PS = [
    "    1     0     1   0.0   1000 Sat Sep 26 10:00:00 2026",
    "  100     1   100  50.0  20480 Sat Sep 26 12:00:00 2026", // turn leader
    "  101   100   100  25.5  10240 Sat Sep 26 12:00:01 2026", // same group
    "  102   101   102  10.0   5120 Sat Sep 26 12:00:02 2026", // setsid child (escaped group), still a descendant
    "  103   102   102   1,5   1024 Sat Sep 26 12:00:03 2026", // its child (decimal comma locale)
    "  200     1   200  99.0 999999 Sat Sep 26 12:00:00 2026", // unrelated
  ].join("\n");
  it("sums the group + ppid descendants; ignores others", () => {
    const rows = parsePs(PS);
    expect(rows).toHaveLength(6);
    const tree = processTree(rows, 100);
    expect(tree.map((r) => r.pid).sort()).toEqual([100, 101, 102, 103]);
    expect(summarize(tree, new Date("2026-09-26T12:00:05Z"))).toEqual({ at: "2026-09-26T12:00:05.000Z", cpu_percent: 87, rss_mb: 36, processes: 4 });
    expect(processTree(rows, 0)).toEqual([]);
    const withCmd = parsePs("  300   100   300   0.0   100 Sat Sep 26 12:00:00 2026 /bin/zsh -c sleep 45");
    expect(withCmd[0]).toMatchObject({ pid: 300, start: "Sat Sep 26 12:00:00 2026", command: "/bin/zsh -c sleep 45" });
  });
});

describe("limits", () => {
  it("session values override global field-wise; null clears", () => {
    const eff = effectiveLimits({ max_cost_usd_per_task: 2, max_retries: 3, on_exceed: "notify" }, { max_retries: null, max_rss_mb: 500, on_exceed: "stop" });
    expect(eff).toEqual({ max_cost_usd_per_task: 2, max_retries: null, max_rss_mb: 500, on_exceed: "stop" });
    expect(effectiveLimits(null, null)).toBeNull();
  });
  it("null cost never trips cost limits; each limit is compared", () => {
    const l = { max_cost_usd_per_task: 1, max_cost_usd_per_session: 5, max_session_minutes: 10, max_task_minutes: 5, max_retries: 2, max_rss_mb: 100, on_exceed: "ask" as const };
    expect(checkLimits(l, { taskCost: null, sessionCost: null, sessionMinutes: null, taskMinutes: null, retries: 0, rssMb: null })).toEqual([]);
    expect(checkLimits(l, { taskCost: 1, sessionCost: 5.5, sessionMinutes: 10, taskMinutes: 4, retries: 3, rssMb: 101 }).map((h) => h.limit)).toEqual([
      "max_cost_usd_per_task",
      "max_cost_usd_per_session",
      "max_session_minutes",
      "max_retries",
      "max_rss_mb",
    ]);
  });
});

describe("tripwire matching", () => {
  const r = (x: Partial<GateReceipt>): GateReceipt => ({ phase: "invoked", kind: "shell", text: "", paths: [], tool_use_id: null, ...x });
  it("prefers id, then text, then paths, then oldest compatible; consumed receipts don't match twice", () => {
    const rs = [r({ text: "ls" }), r({ text: "npm test" }), r({ kind: "file", paths: ["/w/a.txt"] }), r({ tool_use_id: "call_9", text: "x" }), r({ phase: "decision", text: "zzz" })];
    expect(matchReceipt(rs, new Set(), { phase: "started", kind: "shell", item_id: "call_9" })).toBe(3);
    expect(matchReceipt(rs, new Set(), { phase: "started", kind: "shell", text: "bash -lc 'npm test'" })).toBe(1);
    expect(matchReceipt(rs, new Set(), { phase: "started", kind: "file", paths: ["a.txt"] })).toBe(2);
    expect(matchReceipt(rs, new Set([0, 1, 3]), { phase: "started", kind: "shell", text: "other" })).toBe(-1);
    expect(matchReceipt(rs, new Set([0]), { phase: "started", kind: "tool", text: "whatever" })).toBe(1); // generic: any kind
    expect(matchReceipt([], new Set(), { phase: "started", kind: "shell" })).toBe(-1);
    expect(matchReceipt([r({ phase: "decision" })], new Set(), { phase: "started", kind: "shell" })).toBe(-1);
  });
});
