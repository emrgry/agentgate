/**
 * `agentgate update` logic: signature required, checksum enforced, atomic flip, rollback,
 * keep-2 pruning and "no restart while agent sessions run". Network and launchd are mocked
 * (in-memory fetcher, injected probe/restart); tarballs are real (system tar).
 */
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { releasePublicKey, signReleaseManifest } from "@agentgate/signing/release";
import { updateCommand, type SessionProbe, type UpdateEnv } from "../src/commands/update.ts";
import { computeLayout } from "../src/install-layout.ts";
import { setSink } from "../src/output.ts";
import { DEV_PLACEHOLDER_RELEASE_PUBLIC_KEY } from "../src/release-key.ts";
import { compareVersions, parseSums, ReleaseStore, resolveRelease, UpdateError, versionFromSums, type Fetcher } from "../src/updater.ts";

const TARGET = "darwin-arm64";
const BASE = "https://releases.example.test/agentgate/releases";
const seed = new Uint8Array(randomBytes(32));
const PUB = releasePublicKey(seed);
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

let root: string;
let lines: string[];
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "agentgate-update-")));
  lines = [];
  setSink((l) => lines.push(l));
});
afterEach(() => setSink(null));

function tarball(version: string, opts: { versionFile?: string; symlink?: boolean; omit?: string } = {}): Uint8Array {
  const dir = mkdtempSync(join(root, "src-"));
  const files: Record<string, string> = {
    "bin/agentgate": "#!/bin/sh\necho agentgate\n",
    "bin/agentgate-hook.sh": "#!/bin/sh\nexit 2\n",
    "libexec/node": "#!/bin/sh\n",
    "lib/agentgate.mjs": "export {};\n",
    "lib/api.mjs": "export {};\n",
    VERSION: `${opts.versionFile ?? version}\n`,
  };
  for (const [f, content] of Object.entries(files)) {
    if (f === opts.omit) continue;
    mkdirSync(join(dir, f, ".."), { recursive: true });
    writeFileSync(join(dir, f), content, { mode: 0o755 });
  }
  if (opts.symlink) symlinkSync("/etc/passwd", join(dir, "lib", "evil"));
  const out = join(root, `${version}-${Math.random()}.tar.gz`);
  const r = spawnSync("tar", ["-czf", out, "-C", dir, "."]);
  if (r.status !== 0) throw new Error(String(r.stderr));
  return new Uint8Array(readFileSync(out));
}

interface Published {
  files: Map<string, Uint8Array>;
  publish(version: string, opts?: { tarball?: Uint8Array; sums?: string; sig?: string | null; latest?: boolean }): void;
  fetch: Fetcher;
  requested: string[];
}

function releases(): Published {
  const files = new Map<string, Uint8Array>();
  const requested: string[] = [];
  const enc = (s: string) => new TextEncoder().encode(s);
  return {
    files,
    requested,
    publish(version, o = {}) {
      const tb = o.tarball ?? tarball(version);
      const name = `agentgate-${version}-${TARGET}.tar.gz`;
      const sums = o.sums ?? `${sha(tb)}  ${name}\n${"0".repeat(64)}  agentgate-${version}-darwin-x64.tar.gz\n`;
      const sig = o.sig === undefined ? signReleaseManifest(enc(sums), seed) : o.sig;
      const dirs = [`${BASE}/download/v${version}`, ...(o.latest === false ? [] : [`${BASE}/latest/download`])];
      for (const d of dirs) {
        files.set(`${d}/${name}`, tb);
        files.set(`${d}/SHA256SUMS`, enc(sums));
        if (sig === null) files.delete(`${d}/SHA256SUMS.sig`);
        else files.set(`${d}/SHA256SUMS.sig`, enc(sig));
      }
    },
    fetch: async (url) => {
      requested.push(url);
      const f = files.get(url);
      if (!f) throw new UpdateError("network", `HTTP 404 ${url}`);
      return f;
    },
  };
}

function seedInstall(version: string) {
  const home = join(root, "home");
  const store = new ReleaseStore(home);
  const tb = tarball(version);
  store.install(version, tb, sha(tb));
  store.activate(version);
  return { home, store };
}

function env(home: string, p: Published, o: Partial<UpdateEnv> & { probe?: SessionProbe; running?: string } = {}) {
  const calls = { restart: 0, probe: 0 };
  const l = computeLayout({
    release: { version: o.running ?? "1.0.0", target: TARGET, node: "24.21.0" },
    moduleDir: join(home, "versions", o.running ?? "1.0.0", "lib"),
    execPath: "/x/node",
    home: join(root, "userhome"),
  });
  const e: UpdateEnv = {
    layout: l,
    runningVersion: o.running ?? "1.0.0",
    target: TARGET,
    baseUrl: BASE,
    publicKey: PUB,
    fetch: p.fetch,
    serverInstalled: () => true,
    probeSessions: async () => {
      calls.probe++;
      return o.probe ?? { kind: "idle" };
    },
    restart: () => {
      calls.restart++;
      return 0;
    },
    ...o,
  };
  return { e, calls };
}

const opts = (o: Partial<Parameters<typeof updateCommand>[0]> = {}) => ({ check: false, rollback: false, restart: false, prune: false, ...o });
const current = (home: string) => readlinkSync(join(home, "current"));

describe("manifest parsing", () => {
  it("compares versions", () => {
    expect(compareVersions("1.2.10", "1.2.9")).toBe(1);
    expect(compareVersions("1.0.0-rc.1", "1.0.0")).toBe(-1);
    expect(compareVersions("2.0.0", "2.0.0")).toBe(0);
  });

  it("parses SHA256SUMS strictly and finds exactly one version", () => {
    const s = parseSums(`${"a".repeat(64)}  agentgate-1.2.3-darwin-arm64.tar.gz\n${"b".repeat(64)}  agentgate-1.2.3-darwin-x64.tar.gz\n`);
    expect(versionFromSums(s, "darwin-arm64")).toBe("1.2.3");
    expect(() => versionFromSums(s, "linux-x64")).toThrow(/no build for linux-x64/);
    expect(() => parseSums("garbage\n")).toThrow(UpdateError);
    const two = parseSums(`${"a".repeat(64)}  agentgate-1.2.3-darwin-arm64.tar.gz\n${"b".repeat(64)}  agentgate-1.2.4-darwin-x64.tar.gz\n`);
    expect(() => versionFromSums(two, "darwin-arm64")).toThrow(/exactly one release/);
  });

  it("never turns a hostile version string into a path", () => {
    const s = parseSums(`${"a".repeat(64)}  agentgate-..-darwin-arm64.tar.gz\n`);
    expect(() => versionFromSums(s, "darwin-arm64")).toThrow(/invalid release version/);
    expect(() => new ReleaseStore(root).dirOf("../../etc")).toThrow();
  });

  it("refuses plain-http release URLs except loopback", async () => {
    const p = releases();
    await expect(resolveRelease({ baseUrl: "http://evil.example/rel", target: TARGET, publicKey: PUB, fetch: p.fetch })).rejects.toThrow(/refusing release URL/);
  });
});

describe("signature is required (fail closed)", () => {
  it("missing SHA256SUMS.sig → blocked, nothing downloaded or installed", async () => {
    const { home } = seedInstall("1.0.0");
    const p = releases();
    p.publish("1.1.0", { sig: null });
    const { e } = env(home, p);
    expect(await updateCommand(opts(), e)).toBe(77);
    expect(lines.join("\n")).toMatch(/signature \(SHA256SUMS.sig\) is missing/);
    expect(p.requested.some((u) => u.endsWith(".tar.gz"))).toBe(false);
    expect(existsSync(join(home, "versions", "1.1.0"))).toBe(false);
    expect(current(home)).toBe("versions/1.0.0");
  });

  it("signature by another key → blocked", async () => {
    const { home } = seedInstall("1.0.0");
    const p = releases();
    const other = new Uint8Array(randomBytes(32));
    const name = `agentgate-1.1.0-${TARGET}.tar.gz`;
    const tb = tarball("1.1.0");
    const sums = `${sha(tb)}  ${name}\n`;
    p.publish("1.1.0", { tarball: tb, sums, sig: signReleaseManifest(new TextEncoder().encode(sums), other) });
    expect(await updateCommand(opts(), env(home, p).e)).toBe(77);
    expect(lines.join("\n")).toMatch(/signature is not valid \(bad_signature\)/);
    expect(current(home)).toBe("versions/1.0.0");
  });

  it("SHA256SUMS modified after signing → blocked", async () => {
    const { home } = seedInstall("1.0.0");
    const p = releases();
    p.publish("1.1.0");
    const url = `${BASE}/latest/download/SHA256SUMS`;
    p.files.set(url, new TextEncoder().encode(`${new TextDecoder().decode(p.files.get(url))}${"c".repeat(64)}  extra.txt\n`));
    expect(await updateCommand(opts(), env(home, p).e)).toBe(77);
    expect(current(home)).toBe("versions/1.0.0");
  });

  it("a build with the development placeholder key refuses to update", async () => {
    const { home } = seedInstall("1.0.0");
    const p = releases();
    p.publish("1.1.0");
    expect(await updateCommand(opts(), env(home, p, { publicKey: DEV_PLACEHOLDER_RELEASE_PUBLIC_KEY }).e)).toBe(77);
    expect(lines.join("\n")).toMatch(/no release signing key/);
    expect(p.requested).toEqual([]);
  });
});

describe("checksum", () => {
  it("tarball that does not match the signed checksum → rejected, current unchanged", async () => {
    const { home } = seedInstall("1.0.0");
    const p = releases();
    p.publish("1.1.0");
    // Swap the tarball after the manifest was signed (e.g. compromised CDN).
    p.files.set(`${BASE}/latest/download/agentgate-1.1.0-${TARGET}.tar.gz`, tarball("1.1.0", { versionFile: "1.1.0 " }));
    expect(await updateCommand(opts(), env(home, p).e)).toBe(77);
    expect(lines.join("\n")).toMatch(/checksum mismatch/);
    expect(existsSync(join(home, "versions", "1.1.0"))).toBe(false);
    expect(current(home)).toBe("versions/1.0.0");
  });

  it("a signed tarball with a symlink, a missing file or a wrong VERSION is refused", () => {
    const store = new ReleaseStore(join(root, "h2"));
    for (const [tb, re] of [
      [tarball("2.0.0", { symlink: true }), /symlink/],
      [tarball("2.0.0", { omit: "lib/api.mjs" }), /missing lib\/api.mjs/],
      [tarball("2.0.0", { versionFile: "9.9.9" }), /VERSION/],
    ] as const) {
      expect(() => store.install("2.0.0", tb, sha(tb))).toThrow(re);
      expect(existsSync(join(root, "h2", "versions", "2.0.0"))).toBe(false);
    }
  });
});

describe("update flow", () => {
  it("installs the latest signed release, flips current atomically and keeps previous", async () => {
    const { home } = seedInstall("1.0.0");
    const p = releases();
    p.publish("1.1.0");
    const { e, calls } = env(home, p);
    expect(await updateCommand(opts(), e)).toBe(0);
    expect(current(home)).toBe("versions/1.1.0");
    expect(readlinkSync(join(home, "previous"))).toBe("versions/1.0.0");
    expect(readFileSync(join(home, "current", "VERSION"), "utf8").trim()).toBe("1.1.0");
    expect(calls.restart).toBe(1);
    // Up to date now.
    lines.length = 0;
    expect(await updateCommand(opts(), env(home, p, { running: "1.1.0" }).e)).toBe(0);
    expect(lines.join("\n")).toMatch(/already on 1.1.0/);
  });

  it("--check reports without installing", async () => {
    const { home } = seedInstall("1.0.0");
    const p = releases();
    p.publish("1.1.0");
    expect(await updateCommand(opts({ check: true }), env(home, p).e)).toBe(0);
    expect(existsSync(join(home, "versions", "1.1.0"))).toBe(false);
    expect(p.requested.every((u) => !u.endsWith(".tar.gz"))).toBe(true);
  });

  it("does not downgrade to an older 'latest' unless --version is explicit", async () => {
    const { home } = seedInstall("1.2.0");
    const p = releases();
    p.publish("1.1.0");
    expect(await updateCommand(opts(), env(home, p, { running: "1.2.0" }).e)).toBe(0);
    expect(current(home)).toBe("versions/1.2.0");
    expect(await updateCommand(opts({ version: "1.1.0" }), env(home, p, { running: "1.2.0" }).e)).toBe(0);
    expect(current(home)).toBe("versions/1.1.0");
  });

  it("--rollback swaps current and previous", async () => {
    const { home } = seedInstall("1.0.0");
    const p = releases();
    p.publish("1.1.0");
    await updateCommand(opts(), env(home, p).e);
    const { e, calls } = env(home, p, { running: "1.1.0" });
    expect(await updateCommand(opts({ rollback: true }), e)).toBe(0);
    expect(current(home)).toBe("versions/1.0.0");
    expect(readlinkSync(join(home, "previous"))).toBe("versions/1.1.0");
    expect(calls.restart).toBe(1);
    expect(await updateCommand(opts({ rollback: true }), env(home, p).e)).toBe(0);
    expect(current(home)).toBe("versions/1.1.0");
  });

  it("rollback without a previous version fails cleanly", async () => {
    const { home } = seedInstall("1.0.0");
    expect(await updateCommand(opts({ rollback: true }), env(home, releases()).e)).toBe(1);
    expect(current(home)).toBe("versions/1.0.0");
  });

  it("keeps at most 2 old versions (previous first), never the running one", async () => {
    const { home } = seedInstall("1.0.0");
    const p = releases();
    let running = "1.0.0";
    for (const v of ["1.1.0", "1.2.0", "1.3.0", "1.4.0"]) {
      p.publish(v);
      expect(await updateCommand(opts(), env(home, p, { running }).e)).toBe(0);
      running = v;
    }
    const s = new ReleaseStore(home).state();
    expect(s.current).toBe("1.4.0");
    expect(s.previous).toBe("1.3.0");
    expect(s.installed).toEqual(["1.2.0", "1.3.0", "1.4.0"]);
    // The running version is protected even when it would be pruned.
    const store = new ReleaseStore(home);
    const tb = tarball("0.9.0");
    store.install("0.9.0", tb, sha(tb));
    expect(store.prune(2, ["0.9.0"])).toEqual([]);
    expect(store.prune(2, [])).toEqual(["0.9.0"]);
  });

  it("refuses to run from a dev checkout", async () => {
    const l = computeLayout({ release: null, moduleDir: join(root, "repo", "daemon", "agentgate", "src"), execPath: "/x/node", home: root });
    const { e } = env(join(root, "home"), releases(), { layout: l });
    expect(await updateCommand(opts(), e)).toBe(1);
    expect(lines.join("\n")).toMatch(/development checkout/);
  });

  it("a concurrent update is refused", async () => {
    const { home, store } = seedInstall("1.0.0");
    const unlock = store.lock();
    const p = releases();
    p.publish("1.1.0");
    expect(await updateCommand(opts(), env(home, p).e)).toBe(1);
    expect(lines.join("\n")).toMatch(/another update is in progress/);
    unlock();
  });
});

describe("server restart only when no agent session runs", () => {
  for (const [probe, restarts] of [
    [{ kind: "idle" }, 1],
    [{ kind: "down" }, 1],
    [{ kind: "busy", count: 2 }, 0],
    [{ kind: "unknown", reason: "not logged in" }, 0],
  ] as Array<[SessionProbe, number]>) {
    it(`${probe.kind} → ${restarts ? "restart" : "no restart"}`, async () => {
      const { home } = seedInstall("1.0.0");
      const p = releases();
      p.publish("1.1.0");
      const { e, calls } = env(home, p, { probe });
      expect(await updateCommand(opts(), e)).toBe(0);
      expect(current(home)).toBe("versions/1.1.0"); // the update itself always lands
      expect(calls.restart).toBe(restarts);
      if (!restarts) expect(lines.join("\n")).toMatch(/not restarting the server now[\s\S]*agentgate update --restart/);
    });
  }

  it("--restart restarts when idle, not when busy; nothing to do without a server", async () => {
    const { home } = seedInstall("1.0.0");
    const busy = env(home, releases(), { probe: { kind: "busy", count: 1 } });
    expect(await updateCommand(opts({ restart: true }), busy.e)).toBe(0);
    expect(busy.calls.restart).toBe(0);
    const idle = env(home, releases());
    expect(await updateCommand(opts({ restart: true }), idle.e)).toBe(0);
    expect(idle.calls.restart).toBe(1);
    const none = env(home, releases(), { serverInstalled: () => false });
    expect(await updateCommand(opts({ restart: true }), none.e)).toBe(0);
    expect(none.calls.restart + none.calls.probe).toBe(0);
  });
});
