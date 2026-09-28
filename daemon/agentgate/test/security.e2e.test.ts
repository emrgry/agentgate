import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateSigningKeyPair } from "@agentgate/core";
import { afterEach, describe, expect, it } from "vitest";
import { FakeServer, type FakeServerOptions } from "./fake-server.ts";
import { makeEnv, runCli, runProcess, type RunResult } from "./helpers.ts";

/** Security pass: H2 execution binding, H3/H4 guard, H4 login, C2 `agentgate pair`. */

const HOOK_SHIM = join(dirname(fileURLToPath(import.meta.url)), "..", "bin", "agentgate-hook.sh");
const T = 30_000;
const POLICY = `version: 1
defaults: { low: allow, medium: allow, high: ask, critical: ask }
rules:
  - { id: ask-touch, match: { command_prefix: touch }, decision: ask }
  - { id: ask-bash, match: { command_prefix: bash }, decision: ask }
  - { id: ask-push, match: { command_prefix: "git push" }, decision: ask }
`;

let server: FakeServer | null = null;
afterEach(async () => {
  await server?.stop();
  server = null;
});

async function setup(opts: FakeServerOptions = {}) {
  server = await new FakeServer(opts).start();
  return { s: server, ...makeEnv({ server: server.url, token: server.token, publicKeyPem: server.keys.publicKeyPem, policy: POLICY }) };
}

const input = (tool_name: string, tool_input: Record<string, unknown>, cwd: string) =>
  JSON.stringify({ session_id: "claude-sec", cwd, hook_event_name: "PreToolUse", tool_name, tool_input, tool_use_id: "toolu_s", transcript_path: "/t" });

const hook = (stdin: string, o: { home: string; cwd: string; env?: Record<string, string> }) =>
  runProcess(HOOK_SHIM, [], { home: o.home, cwd: o.cwd, input: stdin, env: { AGENTGATE_NODE: process.execPath, ...o.env } });

const decision = (r: RunResult) => JSON.parse(r.stdout).hookSpecificOutput;
const tool = (cmd: string, o: { home: string; cwd: string; env?: Record<string, string> }) =>
  runProcess("/bin/zsh", ["-c", cmd], { home: o.home, cwd: o.cwd, bareEnv: true, env: { PATH: "/usr/bin:/bin", ...o.env } });

function exe(path: string, body: string) {
  writeFileSync(path, `#!/bin/sh\n${body}\n`);
  chmodSync(path, 0o755);
}

async function approve(t: Awaited<ReturnType<typeof setup>>, command: string, env?: Record<string, string>) {
  const r = await hook(input("Bash", { command }, t.work), { home: t.home, cwd: t.work, ...(env ? { env } : {}) });
  expect(r.stderr).toBe("");
  expect(r.code).toBe(0);
  return decision(r).updatedInput.command as string;
}

describe("H2: execution binding", () => {
  it("binary swapped via an earlier PATH dir after approval → 77 binary_changed, nothing runs", async () => {
    const t = await setup();
    const a = join(t.work, "binA");
    const b = join(t.work, "binB");
    mkdirSync(a);
    mkdirSync(b);
    exe(join(a, "touch"), `/usr/bin/touch "$@"`);
    const path = `${b}:${a}:/usr/bin:/bin`;
    const wrapped = await approve(t, `touch ${t.work}/ok`, { PATH: path });
    exe(join(b, "touch"), `echo EVIL > ${t.work}/pwned`);
    const r = await tool(wrapped, { home: t.home, cwd: t.work });
    expect(r.code).toBe(77);
    expect(r.stderr).toMatch(/agentgate: BLOCKED \[binary_changed\]/);
    expect(existsSync(join(t.work, "pwned"))).toBe(false);
    expect(existsSync(join(t.work, "ok"))).toBe(false);
  }, T);

  it("script modified after approval → 77 script_changed", async () => {
    const t = await setup();
    writeFileSync(join(t.work, "s.sh"), "touch ran\n");
    const wrapped = await approve(t, "bash s.sh");
    writeFileSync(join(t.work, "s.sh"), "touch pwned\n");
    const r = await tool(wrapped, { home: t.home, cwd: t.work });
    expect(r.code).toBe(77);
    expect(r.stderr).toMatch(/\[script_changed\]/);
    expect(existsSync(join(t.work, "pwned"))).toBe(false);
  }, T);

  it("unchanged script runs; approved PATH is used; injection env vars are scrubbed", async () => {
    const t = await setup();
    writeFileSync(join(t.work, "s.sh"), "env > envout\n");
    const wrapped = await approve(t, "bash s.sh", { PATH: "/usr/bin:/bin:/usr/sbin" });
    const r = await tool(wrapped, { home: t.home, cwd: t.work, env: { NODE_OPTIONS: "--require /tmp/evil.js", GIT_DIR: "/tmp/evil", DYLD_INSERT_LIBRARIES: "/x", BASH_ENV: "/x", KEEP_ME: "1" } });
    expect(r.code).toBe(0);
    const env = readFileSync(join(t.work, "envout"), "utf8");
    expect(env).toMatch(/^PATH=\/usr\/bin:\/bin:\/usr\/sbin$/m);
    for (const k of ["NODE_OPTIONS", "GIT_DIR", "DYLD_INSERT_LIBRARIES", "BASH_ENV"]) expect(env).not.toMatch(new RegExp(`^${k}=`, "m"));
    expect(env).toMatch(/^KEEP_ME=1$/m);
  }, T);

  describe("git push", () => {
    function repos(work: string) {
      const g = (cwd: string, ...a: string[]) => execFileSync("git", a, { cwd, stdio: "ignore" });
      const A = join(work, "A.git");
      const B = join(work, "B.git");
      g(work, "init", "-q", "--bare", "-b", "main", A);
      g(work, "init", "-q", "--bare", "-b", "main", B);
      const repo = join(work, "repo");
      mkdirSync(repo);
      g(repo, "init", "-q", "-b", "main");
      g(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "c1");
      g(repo, "remote", "add", "origin", A);
      mkdirSync(join(repo, ".git", "hooks"), { recursive: true });
      exe(join(repo, ".git", "hooks", "pre-push"), `touch ${work}/hook-ran`);
      return { A, B, repo, g };
    }

    it("push target + refspec shown in resource, hooks disabled, push lands", async () => {
      const t = await setup();
      const { A, repo } = repos(t.work);
      const r = await hook(input("Bash", { command: "git push origin main" }, repo), { home: t.home, cwd: repo });
      expect(r.code).toBe(0);
      const sub = t.s.requests.find((q) => q.path === "/v1/actions")!.body as any;
      expect(sub.action.resource).toMatchObject({ type: "git_remote", name: `${A} main` });
      expect(sub.action.context.git_hooks).toBe("disabled for this command");
      expect(sub.action.action.arguments.exec_context.git_push).toEqual([{ remote: "origin", url: A, refspec: "main" }]);
      const x = await tool(decision(r).updatedInput.command, { home: t.home, cwd: repo });
      expect(x.code).toBe(0);
      expect(execFileSync("git", ["--git-dir", A, "rev-parse", "main"]).toString().trim()).toMatch(/^[0-9a-f]{40}$/);
      expect(existsSync(join(t.work, "hook-ran"))).toBe(false); // core.hooksPath=/dev/null
    }, T);

    it("remote URL changed after approval → 77 push_target_changed, nothing pushed", async () => {
      const t = await setup();
      const { B, repo, g } = repos(t.work);
      const r = await hook(input("Bash", { command: "git push origin main" }, repo), { home: t.home, cwd: repo });
      g(repo, "remote", "set-url", "origin", B);
      const x = await tool(decision(r).updatedInput.command, { home: t.home, cwd: repo });
      expect(x.code).toBe(77);
      expect(x.stderr).toMatch(/\[push_target_changed\]/);
      expect(() => execFileSync("git", ["--git-dir", B, "rev-parse", "main"], { stdio: "ignore" })).toThrow();
    }, T);
  });
});

describe("H3/H4: hook guard", () => {
  it("agent running `agentgate pair` → exit 2, reported as denied", async () => {
    const t = await setup();
    const r = await hook(input("Bash", { command: "agentgate pair" }, t.work), { home: t.home, cwd: t.work });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/may not run `agentgate pair`/);
    const sub = t.s.requests.find((q) => q.path === "/v1/actions")!.body as any;
    expect(sub.policy.decision).toBe("deny");
  }, T);

  it("Write to .claude/settings.local.json → exit 2", async () => {
    const t = await setup();
    const r = await hook(input("Write", { file_path: ".claude/settings.local.json", content: "{}" }, t.work), { home: t.home, cwd: t.work });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/hook settings/);
  }, T);

  it("Read of AGENTGATE_HOME/config.json → ask (approval requested); ordinary Read → no output", async () => {
    const t = await setup();
    const sensitive = await hook(input("Read", { file_path: join(t.home, "config.json") }, t.work), { home: t.home, cwd: t.work });
    expect(sensitive.code).toBe(0);
    expect(decision(sensitive).permissionDecision).toBe("allow"); // fake server auto-approves
    expect(t.s.approvals.size).toBe(1);
    const plain = await hook(input("Read", { file_path: "README.md" }, t.work), { home: t.home, cwd: t.work });
    expect(plain).toMatchObject({ code: 0, stdout: "" });
    expect(t.s.count("POST", "/v1/actions")).toBe(1);
  }, T);
});

describe("H4: login", () => {
  it("refuses a changed signing key without --accept-new-key; re-pins with it", async () => {
    const t = await setup();
    const cfgPath = join(t.home, "config.json");
    const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
    cfg.signing_key.pem = generateSigningKeyPair().publicKeyPem; // pinned ≠ server
    writeFileSync(cfgPath, JSON.stringify(cfg), { mode: 0o600 });
    const r = await runCli(["login", "--server", t.s.url], { home: t.home, cwd: t.work });
    expect(r.code).toBe(77);
    expect(r.stderr).toMatch(/pinned: SHA256:[0-9a-f]{16}/);
    expect(r.stderr).toMatch(/server: SHA256:[0-9a-f]{16}/);
    expect(t.s.count("POST", "/v1/auth/login")).toBe(0);
    const ok = await runCli(["login", "--server", t.s.url, "--accept-new-key"], { home: t.home, cwd: t.work });
    expect(ok.code).toBe(0);
    expect(JSON.parse(readFileSync(cfgPath, "utf8")).signing_key.pem).toBe(t.s.keys.publicKeyPem);
  }, T);

  it("requires HTTPS for non-loopback servers unless --insecure-lan", async () => {
    const t = await setup();
    const r = await runCli(["login", "--server", "http://192.0.2.10:8787"], { home: t.home, cwd: t.work });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/refusing plain HTTP/);
    const lan = await runCli(["login", "--server", "http://192.0.2.10:1", "--insecure-lan"], { home: t.home, cwd: t.work });
    expect(lan.stderr).not.toMatch(/refusing plain HTTP/); // gets past the check (then fails to connect)
  }, T);
});

describe("C2: agentgate pair", () => {
  it("prints the formatted one-time code", async () => {
    const t = await setup();
    const r = await runCli(["pair", "--no-qr"], { home: t.home, cwd: t.work });
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/Pairing code: 7KQ2-MZ9D/);
    expect(r.stdout).toMatch(/Scan with your iPhone Camera, then tap 'Pair this device'/);
    expect(r.stdout).toMatch(/it will ask you to approve this new device/);
    // loopback server is replaced by a LAN address (or a clear note when there is none)
    expect(r.stdout).not.toMatch(/Server for the phone: http:\/\/127\.0\.0\.1/);
    const o = await runCli(["pair", "--no-qr", "--advertise-url", "http://10.9.8.7:8787"], { home: t.home, cwd: t.work });
    expect(o.stdout).toMatch(/Server for the phone: http:\/\/10\.9\.8\.7:8787/);
    const link = new URL(o.stdout.match(/agentgate:\/\/pair\?\S+/)![0]);
    expect(Object.fromEntries(link.searchParams)).toMatchObject({ v: "2", url: "http://10.9.8.7:8787", code: "7KQ2MZ9D", email: "dev@agentgate.local" });
    expect(link.searchParams.get("fp")).toMatch(/^[A-Za-z0-9_-]{22}$/);
  }, T);

  it("advertisedServer / primaryLanIPv4", async () => {
    const { advertisedServer, primaryLanIPv4 } = await import("../src/commands/pair.ts");
    const ifaces = {
      lo0: [{ family: "IPv4", internal: true, address: "127.0.0.1" }],
      utun3: [{ family: "IPv4", internal: false, address: "169.254.3.4" }],
      en5: [{ family: "IPv4", internal: false, address: "10.0.0.9" }],
      en0: [{ family: "IPv6", internal: false, address: "fe80::1" }, { family: "IPv4", internal: false, address: "192.168.1.110" }],
    } as any;
    expect(primaryLanIPv4(ifaces)).toBe("192.168.1.110");
    expect(advertisedServer("http://localhost:8787", undefined, "192.168.1.110").url).toBe("http://192.168.1.110:8787");
    expect(advertisedServer("https://ag.example.com", undefined, "192.168.1.110").url).toBe("https://ag.example.com");
    expect(advertisedServer("http://127.0.0.1:8787", "http://x:1/", "1.2.3.4").url).toBe("http://x:1");
    expect(advertisedServer("http://127.0.0.1:8787", undefined, null).note).toMatch(/--advertise-url/);
  });
});
