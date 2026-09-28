/**
 * Release end-to-end smoke test (macOS host only, opt-in: AGENTGATE_RELEASE_E2E=1 or
 * `npm run test:release-e2e`). Builds real tarballs for this Mac, signs them with a
 * throw-away key, publishes them in a local file:// "GitHub releases" tree and then, in a
 * TEMP HOME (never the real ~/.agentgate or launchd):
 *
 *   install.sh --no-setup → shim works with PATH=/usr/bin:/bin → hook shim fails closed →
 *   setup (fake launchctl, real bundled server + PGlite) → install claude-code / mcp wrap
 *   reference ~/.agentgate/current → agentgate update to a second signed build (server
 *   restarted through the new version) → tampered release refused → rollback → uninstall.
 */
import { spawn, spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { arch, platform, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const ENABLED = process.env.AGENTGATE_RELEASE_E2E === "1" && platform() === "darwin";
const TARGET = `darwin-${arch() === "arm64" ? "arm64" : "x64"}`;
const FAKE_LAUNCHCTL = join(REPO, "daemon", "agentgate", "test", "fake-launchctl.mjs");
const MIN_PATH = "/usr/bin:/bin";
const OPENSSL3 = ["/opt/homebrew/bin/openssl", "/usr/local/bin/openssl"].some((p) => existsSync(p) && /^OpenSSL [3-9]/.test(spawnSync(p, ["version"], { encoding: "utf8" }).stdout ?? ""));

interface R {
  code: number | null;
  stdout: string;
  stderr: string;
}
function run(file: string, args: string[], env: Record<string, string>, o: { input?: string; cwd?: string } = {}): Promise<R> {
  return new Promise((ok, fail) => {
    const child = spawn(file, args, { env, cwd: o.cwd ?? tmpdir(), stdio: [o.input === undefined ? "ignore" : "pipe", "pipe", "pipe"] });
    if (o.input !== undefined) child.stdin!.end(o.input);
    let stdout = "";
    let stderr = "";
    child.stdout!.on("data", (d) => (stdout += d));
    child.stderr!.on("data", (d) => (stderr += d));
    child.on("error", fail);
    child.on("close", (code) => ok({ code, stdout, stderr }));
  });
}
const freePort = () =>
  new Promise<number>((ok) => {
    const s = createServer().listen(0, "127.0.0.1", () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => ok(p));
    });
  });

describe.skipIf(!ENABLED)("release e2e (install.sh → update → uninstall, temp HOME)", () => {
  let root: string;
  let home: string;
  let base: string;
  let pub: string;
  let seed: string;
  let port: number;
  const ag = () => join(home, ".agentgate");
  const shim = () => join(home, ".local", "bin", "agentgate");
  // Minimal environment for the installed CLI (plus the test seams for launchd).
  const env = (extra: Record<string, string> = {}) => ({
    HOME: home,
    PATH: MIN_PATH,
    NO_COLOR: "1",
    AGENTGATE_LAUNCHCTL: FAKE_LAUNCHCTL,
    AGENTGATE_SETUP_PLATFORM: "darwin",
    FAKE_LAUNCHD_DIR: join(root, "launchd"),
    // fake-launchctl.mjs is a node script; only IT needs node on PATH.
    ...extra,
  });
  const launchdEnv = (extra: Record<string, string> = {}) => env({ PATH: `${MIN_PATH}:${dirname(process.execPath)}`, ...extra });

  function buildAndPublish(version: string, latest: boolean) {
    const out = join(root, `build-${version}`);
    const b = spawnSync(process.execPath, [join(REPO, "scripts", "build-release.mjs"), "--targets", TARGET, "--out", out, "--version-override", version], {
      cwd: REPO,
      env: { ...process.env, AGENTGATE_RELEASE_PUBLIC_KEY: pub },
      encoding: "utf8",
    });
    expect(b.status, b.stderr).toBe(0);
    const s = spawnSync(process.execPath, ["--import", "tsx", join(REPO, "scripts", "sign-release.mjs"), out], {
      cwd: REPO,
      env: { ...process.env, AGENTGATE_RELEASE_SIGNING_KEY: seed, AGENTGATE_RELEASE_PUBLIC_KEY: pub },
      encoding: "utf8",
    });
    expect(s.status, s.stderr).toBe(0);
    for (const d of [join(base, "download", `v${version}`), ...(latest ? [join(base, "latest", "download")] : [])]) {
      rmSync(d, { recursive: true, force: true });
      mkdirSync(d, { recursive: true });
      cpSync(out, d, { recursive: true });
    }
    return out;
  }

  beforeAll(async () => {
    root = realpathSync(mkdtempSync(join(tmpdir(), "agentgate-release-e2e-")));
    home = join(root, "home");
    base = join(root, "releases");
    mkdirSync(home, { recursive: true });
    const kp = generateKeyPairSync("ed25519");
    seed = kp.privateKey.export({ format: "der", type: "pkcs8" }).subarray(16).toString("base64url");
    pub = kp.publicKey.export({ format: "der", type: "spki" }).subarray(12).toString("base64url");
    port = await freePort();
    buildAndPublish("0.1.0", true);
  });

  afterAll(() => {
    if (!root) return;
    // Never leave a server running.
    spawnSync(FAKE_LAUNCHCTL, ["bootout", "x"], { env: { ...process.env, FAKE_LAUNCHD_DIR: join(root, "launchd") } });
    if (process.env.AGENTGATE_KEEP_E2E !== "1") rmSync(root, { recursive: true, force: true });
  });

  it("artifacts: tarball layout, SHA256SUMS, signature, installer with the key", () => {
    const out = join(root, "build-0.1.0");
    const name = `agentgate-0.1.0-${TARGET}.tar.gz`;
    const list = spawnSync("tar", ["-tzf", join(out, name)], { encoding: "utf8" }).stdout.split("\n");
    for (const f of ["bin/agentgate", "bin/agentgate-hook.sh", "libexec/node", "lib/agentgate.mjs", "lib/api.mjs", "lib/pglite.wasm", "lib/pglite.data", "lib/initdb.wasm", "lib/profiles/hermes.yaml", "VERSION"]) {
      expect(list, f).toContain(f);
    }
    expect(list.some((f) => f.includes("node_modules"))).toBe(false);
    expect(readFileSync(join(out, "SHA256SUMS"), "utf8")).toMatch(new RegExp(`^[0-9a-f]{64}  ${name.replace(/\./g, "\\.")}\\n$`));
    expect(readFileSync(join(out, "SHA256SUMS.sig"), "utf8")).toMatch(/^[A-Za-z0-9_-]{86}\n$/);
    const installer = readFileSync(join(out, "install.sh"), "utf8");
    expect(installer).toContain("-----BEGIN PUBLIC KEY-----");
    expect(installer).not.toContain("__AGENTGATE_RELEASE_PUBKEY_PEM__");
  });

  it("install.sh --dry-run changes nothing", async () => {
    const r = await run("/bin/sh", [join(root, "build-0.1.0", "install.sh"), "--dry-run"], env({ AGENTGATE_RELEASE_BASE_URL: pathToFileURL(base).href }));
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain(`platform        ${TARGET}`);
    expect(existsSync(ag())).toBe(false);
  });

  it("install.sh installs into the temp HOME with verified checksum (+ signature when OpenSSL 3 exists)", async () => {
    const r = await run("/bin/sh", [join(root, "build-0.1.0", "install.sh"), "--no-setup"], env({ AGENTGATE_RELEASE_BASE_URL: pathToFileURL(base).href, ...(OPENSSL3 ? { AGENTGATE_REQUIRE_SIGNATURE: "1" } : {}) }));
    expect(r.code, `${r.stdout}\n${r.stderr}`).toBe(0);
    expect(r.stdout).toContain("checksum verified");
    if (OPENSSL3) expect(r.stdout).toContain("signature verified");
    expect(r.stderr).toContain("is not on your PATH");
    expect(readlinkSync(join(ag(), "current"))).toBe("versions/0.1.0");
    expect(readFileSync(shim(), "utf8")).toContain("# agentgate-path-shim");
    // Idempotent re-run.
    const again = await run("/bin/sh", [join(root, "build-0.1.0", "install.sh"), "--no-setup"], env({ AGENTGATE_RELEASE_BASE_URL: pathToFileURL(base).href }));
    expect(again.code, again.stderr).toBe(0);
    expect(readlinkSync(join(ag(), "current"))).toBe("versions/0.1.0");
  });

  it("install.sh refuses a tampered tarball", async () => {
    const evil = join(root, "evil");
    cpSync(join(base, "latest", "download"), join(evil, "latest", "download"), { recursive: true });
    const tb = join(evil, "latest", "download", `agentgate-0.1.0-${TARGET}.tar.gz`);
    const bytes = readFileSync(tb);
    bytes[bytes.length - 100] ^= 0xff;
    writeFileSync(tb, bytes);
    const h2 = join(root, "home-evil");
    mkdirSync(h2);
    const r = await run("/bin/sh", [join(root, "build-0.1.0", "install.sh"), "--no-setup"], { ...env(), HOME: h2, AGENTGATE_RELEASE_BASE_URL: pathToFileURL(evil).href });
    expect(r.code).not.toBe(0);
    expect(r.stderr).toMatch(/checksum mismatch/);
    expect(existsSync(join(h2, ".agentgate", "current"))).toBe(false);
  });

  it("the shim runs with PATH=/usr/bin:/bin and ignores NODE_OPTIONS", async () => {
    const v = await run(shim(), ["version"], env({ NODE_OPTIONS: "--require /nonexistent/evil.js" }));
    expect(v.code, v.stderr).toBe(0);
    expect(v.stdout).toContain("agentgate 0.1.0");
    expect(v.stdout).toContain(`release (${TARGET}`);
    expect(v.stdout).toContain(`(via ${join(ag(), "current")})`);
    const h = await run(shim(), ["--help"], env());
    expect(h.code).toBe(0);
    expect(h.stdout).toContain("agentgate update");
    expect((await run(shim(), ["--version"], env())).stdout.trim()).toBe("0.1.0");
  });

  it("the hook shim fails closed (exit 2) and observe events never block (exit 0)", async () => {
    const hook = join(ag(), "current", "bin", "agentgate-hook.sh");
    const bad = await run(hook, [], env(), { input: "not json" });
    expect(bad.code).toBe(2);
    expect(bad.stderr).toContain("AgentGate blocked this action");
    expect((await run(hook, ["--agentgate-observe"], env(), { input: "{}" })).code).toBe(0);
    expect((await run(hook, ["--agentgate-provider=../x"], env(), { input: "{}" })).code).toBe(2);
    const missing = join(root, "broken");
    cpSync(join(ag(), "versions", "0.1.0", "bin"), join(missing, "bin"), { recursive: true });
    const r = await run(join(missing, "bin", "agentgate"), ["exec", "--approval", "apr_x", "--", "touch", join(root, "ran")], env());
    expect(r.code).toBe(77);
    expect(existsSync(join(root, "ran"))).toBe(false);
  });

  it("setup (fake launchd) starts the bundled server; persisted paths use ~/.agentgate/current", async () => {
    const r = await run(shim(), ["setup", "--port", String(port), "--no-pair"], launchdEnv());
    expect(r.code, r.stderr).toBe(0);
    expect(r.stderr).toContain(`server healthy at http://127.0.0.1:${port}`);
    const plist = readFileSync(join(home, "Library", "LaunchAgents", "dev.agentgate.server.plist"), "utf8");
    expect(plist).toContain(`<string>${join(ag(), "current", "bin", "agentgate")}</string>\n    <string>serve</string>`);
    expect(plist).not.toContain("versions/");

    const project = join(root, "project");
    mkdirSync(project);
    writeFileSync(join(project, ".mcp.json"), `${JSON.stringify({ mcpServers: { demo: { command: "npx", args: ["demo-mcp"] } } })}\n`);
    const i = await run(shim(), ["install", "claude-code", "--project", project], env(), { cwd: project });
    expect(i.code, i.stderr).toBe(0);
    const settings = readFileSync(join(project, ".claude", "settings.local.json"), "utf8");
    expect(settings).toContain(`${join(ag(), "current", "bin", "agentgate-hook.sh")} --agentgate-install=claude-code/v1`);
    expect(settings).toContain(`AGENTGATE_NODE=${join(ag(), "current", "libexec", "node")}`);
    expect(settings).not.toContain("versions/");
    const m = await run(shim(), ["mcp", "install", "--client", "claude-code", "--project", project, "--all"], env(), { cwd: project });
    expect(m.code, m.stderr).toBe(0);
    const mcp = JSON.parse(readFileSync(join(project, ".mcp.json"), "utf8"));
    expect(mcp.mcpServers.demo.command).toBe(join(ag(), "current", "bin", "agentgate"));
    expect(mcp.mcpServers.demo.env.AGENTGATE_NODE).toBe(join(ag(), "current", "libexec", "node"));
    const managed = readFileSync(join(ag(), "server", "managed-hooks.json"), "utf8");
    expect(managed).toContain(join(ag(), "current", "bin", "agentgate-hook.sh"));
    expect(managed).not.toContain("versions/");
  });

  it("agentgate update installs the next signed release and restarts the idle server", async () => {
    buildAndPublish("0.1.1", true);
    const check = await run(shim(), ["update", "--check"], env({ AGENTGATE_RELEASE_BASE_URL: pathToFileURL(base).href }));
    expect(check.code, check.stderr).toBe(0);
    expect(check.stdout).toContain("update available: 0.1.0 → 0.1.1");
    const u = await run(shim(), ["update"], launchdEnv({ AGENTGATE_RELEASE_BASE_URL: pathToFileURL(base).href }));
    expect(u.code, `${u.stdout}\n${u.stderr}`).toBe(0);
    expect(u.stderr).toContain("signature verified");
    expect(u.stderr).toContain("checksum verified");
    expect(u.stderr).toContain("server restarted");
    expect(readlinkSync(join(ag(), "current"))).toBe("versions/0.1.1");
    expect(readlinkSync(join(ag(), "previous"))).toBe("versions/0.1.0");
    expect((await run(shim(), ["--version"], env())).stdout.trim()).toBe("0.1.1");
    const health = await fetch(`http://127.0.0.1:${port}/healthz`);
    expect(health.ok).toBe(true);
    // Hook commands written by 0.1.0 still resolve (stable path).
    const bad = await run(join(ag(), "current", "bin", "agentgate-hook.sh"), [], env(), { input: "not json" });
    expect(bad.code).toBe(2);
  });

  it("a release signed with another key is refused by update", async () => {
    const evil = join(root, "evil-update");
    cpSync(join(base, "download", "v0.1.1"), join(evil, "download", "v0.1.1"), { recursive: true });
    const other = generateKeyPairSync("ed25519");
    const otherSeed = other.privateKey.export({ format: "der", type: "pkcs8" }).subarray(16).toString("base64url");
    const otherPub = other.publicKey.export({ format: "der", type: "spki" }).subarray(12).toString("base64url");
    const s = spawnSync(process.execPath, ["--import", "tsx", join(REPO, "scripts", "sign-release.mjs"), join(evil, "download", "v0.1.1")], {
      cwd: REPO,
      env: { ...process.env, AGENTGATE_RELEASE_SIGNING_KEY: otherSeed, AGENTGATE_RELEASE_PUBLIC_KEY: otherPub },
      encoding: "utf8",
    });
    expect(s.status, s.stderr).toBe(0);
    const u = await run(shim(), ["update", "--version", "0.1.1"], env({ AGENTGATE_RELEASE_BASE_URL: pathToFileURL(evil).href }));
    expect(u.code).toBe(77);
    expect(u.stderr).toMatch(/signature/);
    expect(readlinkSync(join(ag(), "current"))).toBe("versions/0.1.1");
  });

  it("update --rollback returns to the previous version", async () => {
    const r = await run(shim(), ["update", "--rollback"], launchdEnv());
    expect(r.code, r.stderr).toBe(0);
    expect(readlinkSync(join(ag(), "current"))).toBe("versions/0.1.0");
    expect((await run(shim(), ["--version"], env())).stdout.trim()).toBe("0.1.0");
  });

  it("uninstall --yes removes hooks, launchd agent, versions, current and the shim; keeps data", async () => {
    const r = await run(shim(), ["uninstall", "--yes"], launchdEnv());
    expect(r.code, `${r.stdout}\n${r.stderr}`).toBe(0);
    expect(existsSync(join(home, "Library", "LaunchAgents", "dev.agentgate.server.plist"))).toBe(false);
    expect(existsSync(join(ag(), "versions"))).toBe(false);
    expect(existsSync(join(ag(), "current"))).toBe(false);
    expect(existsSync(shim())).toBe(false);
    const settings = join(root, "project", ".claude", "settings.local.json");
    expect(existsSync(settings) && readFileSync(settings, "utf8").includes("agentgate-hook.sh")).toBe(false);
    expect(JSON.parse(readFileSync(join(root, "project", ".mcp.json"), "utf8")).mcpServers.demo.command).toBe("npx");
    expect(existsSync(join(ag(), "server", "server.json"))).toBe(true);
    await expect(fetch(`http://127.0.0.1:${port}/healthz`, { signal: AbortSignal.timeout(1000) })).rejects.toThrow();
  });
});
