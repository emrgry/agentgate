import { redactCommandSecrets } from "@agentgate/protocol";

/**
 * Phase 3: detects test runs among the agent's shell tool calls and parses their counts.
 * Parsers are best effort: unknown formats give null counts (ok still comes from the exit).
 */

const RUNNERS: RegExp[] = [
  /\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?test(?::[\w:-]+)?\b/,
  /\b(?:npx|pnpm\s+exec|yarn|bunx)\s+(?:vitest|jest|mocha|playwright\s+test|ava|tap)\b/,
  /(?:^|[\s;&|/])(?:vitest|jest|mocha|pytest|py\.test|phpunit|rspec|ava)(?:\s|$)/,
  /\bpython\d*(?:\.\d+)?\s+-m\s+(?:pytest|unittest)\b/,
  /\bgo\s+test\b/,
  /\bcargo\s+(?:test|nextest\s+run)\b/,
  /\bdeno\s+test\b/,
  /\bbun\s+test\b/,
  /\bnode\s+--test\b/,
  /\bmix\s+test\b/,
  /\bdotnet\s+test\b/,
  /\b(?:\.\/)?gradlew?\s+(?:\S+\s+)*test\b/,
  /\bmvn\s+(?:\S+\s+)*test\b/,
  /\bmake\s+(?:test|check)\b/,
  /\btox\b/,
];

export function isTestCommand(command: string): boolean {
  const c = command.trim();
  if (!c) return false;
  return RUNNERS.some((re) => re.test(c));
}

export interface TestCounts {
  passed: number | null;
  failed: number | null;
  skipped: number | null;
}

const n = (s: string | undefined) => (s === undefined ? 0 : Number(s));

/** Parses the summary of the common runners. Last matching summary wins (watch/re-runs). */
export function parseTestOutput(output: string): TestCounts {
  // eslint-disable-next-line no-control-regex
  const text = output.replace(/\u001b\[[0-9;]*m/g, "");
  const lines = text.split("\n");
  const none: TestCounts = { passed: null, failed: null, skipped: null };

  // vitest: " Tests  1 failed | 9 passed | 2 skipped (12)"
  for (const l of [...lines].reverse()) {
    const m = l.match(/^\s*Tests\s{2,}(.+?)\s*\(\d+\)\s*$/);
    if (m) {
      const part = (k: string) => m[1]!.match(new RegExp(`(\\d+) ${k}`))?.[1];
      return { passed: n(part("passed")), failed: n(part("failed")), skipped: n(part("skipped")) + n(part("todo")) };
    }
  }
  // jest: "Tests:       1 failed, 2 skipped, 10 passed, 13 total"
  for (const l of [...lines].reverse()) {
    const m = l.match(/^\s*Tests:\s+(.+total)/);
    if (m) {
      const part = (k: string) => m[1]!.match(new RegExp(`(\\d+) ${k}`))?.[1];
      return { passed: n(part("passed")), failed: n(part("failed")), skipped: n(part("skipped")) + n(part("todo")) };
    }
  }
  // pytest: "==== 2 failed, 10 passed, 1 skipped in 0.52s ====" / "5 passed in 0.1s"
  for (const l of [...lines].reverse()) {
    if (/(\d+) (passed|failed|error|errors)\b.*\bin [\d.]+s/.test(l)) {
      const part = (k: string) => l.match(new RegExp(`(\\d+) ${k}\\b`))?.[1];
      return { passed: n(part("passed")), failed: n(part("failed")) + n(part("errors?")), skipped: n(part("skipped")) + n(part("xfailed")) };
    }
  }
  // cargo: "test result: ok. 5 passed; 0 failed; 1 ignored; ..." (one per crate → sum)
  const cargo = lines.map((l) => l.match(/test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored/)).filter(Boolean) as RegExpMatchArray[];
  if (cargo.length) {
    return cargo.reduce<TestCounts>((acc, m) => ({ passed: acc.passed! + n(m[1]), failed: acc.failed! + n(m[2]), skipped: acc.skipped! + n(m[3]) }), { passed: 0, failed: 0, skipped: 0 });
  }
  // mocha: "  5 passing (20ms)", "  2 failing", "  1 pending"
  const passing = text.match(/^\s*(\d+) passing\b/m);
  if (passing) return { passed: n(passing[1]), failed: n(text.match(/^\s*(\d+) failing\b/m)?.[1]), skipped: n(text.match(/^\s*(\d+) pending\b/m)?.[1]) };
  // node:test / TAP: "# pass 5", "# fail 1", "# skipped 0"
  const tapPass = text.match(/^# pass (\d+)/m);
  if (tapPass) return { passed: n(tapPass[1]), failed: n(text.match(/^# fail (\d+)/m)?.[1]), skipped: n(text.match(/^# skip(?:ped)? (\d+)/m)?.[1]) + n(text.match(/^# todo (\d+)/m)?.[1]) };
  // go test -v: "--- PASS:", "--- FAIL:", "--- SKIP:"; otherwise package lines "ok  pkg" / "FAIL pkg".
  const goPass = (text.match(/^\s*--- PASS:/gm) ?? []).length;
  const goFail = (text.match(/^\s*--- FAIL:/gm) ?? []).length;
  const goSkip = (text.match(/^\s*--- SKIP:/gm) ?? []).length;
  if (goPass + goFail + goSkip > 0) return { passed: goPass, failed: goFail, skipped: goSkip };
  const pkgOk = (text.match(/^ok\s+\S+/gm) ?? []).length;
  const pkgFail = (text.match(/^FAIL\s+\S+/gm) ?? []).length;
  if (pkgOk + pkgFail > 0) return { passed: null, failed: pkgFail, skipped: null };
  return none;
}

export const MAX_TAIL = 4096;

/** Last ≤ 4 KB of output (whole lines when possible), secrets masked. */
export function outputTail(output: string): string {
  const red = redactCommandSecrets(output.replace(/\u001b\[[0-9;]*m/g, ""));
  if (red.length <= MAX_TAIL) return red;
  const cut = red.slice(-MAX_TAIL + 2);
  const nl = cut.indexOf("\n");
  return `…${nl >= 0 && nl < 200 ? cut.slice(nl) : cut}`.slice(-MAX_TAIL);
}
