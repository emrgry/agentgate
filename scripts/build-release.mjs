#!/usr/bin/env node
/**
 * Builds self-contained AgentGate release tarballs (no Node/npm/git needed on the user's
 * machine):
 *
 *   dist/release/agentgate-<version>-<os>-<arch>.tar.gz
 *     bin/agentgate           POSIX launcher → libexec/node lib/agentgate.mjs (exit 77 if it can't start)
 *     bin/agentgate-hook.sh   fail-closed Claude Code hook shim (exit 0 / 2 only)
 *     libexec/node            official Node.js runtime (pinned, SHA-256 verified)
 *     lib/                    esbuild bundles (agentgate.mjs, api.mjs, chunks), PGlite wasm/data, profiles
 *     VERSION, LICENSE.md, THIRD_PARTY_LICENSES.txt
 *   dist/release/SHA256SUMS   (sign it with scripts/sign-release.mjs)
 *   dist/release/install.sh   (release signing key substituted)
 *
 * Runs on Linux or macOS; only needs node, npm deps and `tar` (to unpack the Node.js
 * distribution). The output tarballs are written by a small deterministic ustar writer, so
 * no GNU/BSD tar differences leak into the artifacts.
 *
 * Usage: node scripts/build-release.mjs [--targets darwin-arm64,darwin-x64] [--all]
 *                                      [--out dist/release] [--require-release-key]
 *                                      [--version-override X]   (tests only)
 * Env:   AGENTGATE_RELEASE_PUBLIC_KEY   override the embedded release key (base64url)
 *        AGENTGATE_NODE_CACHE           Node.js download cache (default .cache/node)
 *        SOURCE_DATE_EPOCH              mtime for tar entries (default: HEAD commit time)
 */
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, cpSync, createReadStream, createWriteStream, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import { fileURLToPath } from "node:url";
import { createGzip } from "node:zlib";
import { createRequire } from "node:module";
import { build } from "esbuild";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// ── pinned runtime ──────────────────────────────────────────────────────────────
// Node.js 24 "Krypton" (Active LTS). Hashes from https://nodejs.org/dist/v24.21.0/SHASUMS256.txt,
// pinned here so a compromised mirror/CDN cannot substitute the runtime. Bump all together.
export const NODE_VERSION = "24.21.0";
const NODE_SHA256 = {
  "darwin-arm64": "bed7eea5325e1108f32ce5228ddd6a5f0f08a499ee42aa7442aea583702f6057",
  "darwin-x64": "1462cb3b3046b815cf8ea436d3da450ec1a9f11dac7e5a46b0ada5305d7e8097",
  "linux-arm64": "724282c3b43aec998aa9527380465b45d229e021b58035f5f4f63095eabfe5d5",
  "linux-x64": "6e1db87ef58b8819e5d5402eff1536491b18edd8eb7bee5ef7897876e88dc5ff",
};
export const DEFAULT_TARGETS = ["darwin-arm64", "darwin-x64"];
export const ALL_TARGETS = Object.keys(NODE_SHA256);

const PGLITE_ASSETS = ["pglite.wasm", "pglite.data", "initdb.wasm"];

function arg(name) {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}
const flag = (name) => process.argv.includes(name);
const log = (m) => process.stderr.write(`build-release: ${m}\n`);
function die(m) {
  log(`ERROR: ${m}`);
  process.exit(1);
}

const sha256File = (p) =>
  new Promise((ok, fail) => {
    const h = createHash("sha256");
    createReadStream(p).on("data", (d) => h.update(d)).on("end", () => ok(h.digest("hex"))).on("error", fail);
  });

// ── version + key ───────────────────────────────────────────────────────────────

function readVersion() {
  const pkg = JSON.parse(readFileSync(join(REPO, "package.json"), "utf8")).version;
  const src = /SOURCE_VERSION = "([^"]+)"/.exec(readFileSync(join(REPO, "daemon/agentgate/src/version.ts"), "utf8"))?.[1];
  if (src !== pkg) die(`daemon/agentgate/src/version.ts SOURCE_VERSION (${src}) != package.json version (${pkg}) — bump both`);
  // Tests only (e.g. to produce a second release for update tests); never used by CI.
  const v = arg("--version-override") ?? pkg;
  if (v !== pkg) log(`WARNING: version overridden: ${pkg} → ${v} (test builds only)`);
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.]*)?$/.test(v)) die(`invalid version: ${v}`);
  return v;
}

export function sourceKeys() {
  const src = readFileSync(join(REPO, "daemon/agentgate/src/release-key.ts"), "utf8");
  const placeholder = /DEV_PLACEHOLDER_RELEASE_PUBLIC_KEY = "([A-Za-z0-9_-]{43})"/.exec(src)?.[1];
  const sourceLine = /SOURCE_RELEASE_PUBLIC_KEY = (?:"([A-Za-z0-9_-]{43})"|DEV_PLACEHOLDER_RELEASE_PUBLIC_KEY);/.exec(src);
  if (!placeholder || !sourceLine) die("cannot parse daemon/agentgate/src/release-key.ts");
  return { placeholder, source: sourceLine[1] ?? placeholder };
}

function releaseKey() {
  const { placeholder, source } = sourceKeys();
  const override = process.env.AGENTGATE_RELEASE_PUBLIC_KEY?.trim();
  if (override && !/^[A-Za-z0-9_-]{43}$/.test(override)) die("AGENTGATE_RELEASE_PUBLIC_KEY must be a base64url raw 32-byte Ed25519 public key (43 chars)");
  const key = override || source;
  if (key === placeholder) {
    if (flag("--require-release-key")) die("the release key is still the development placeholder — set SOURCE_RELEASE_PUBLIC_KEY in daemon/agentgate/src/release-key.ts (docs/releasing.md)");
    log("WARNING: building with the development PLACEHOLDER release key — `agentgate update` in these builds will refuse every release");
  }
  return key;
}

/** Ed25519 SPKI PEM for a raw base64url public key (for openssl in install.sh). */
export function pemFromRawKey(b64url) {
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(b64url, "base64url")]);
  return `-----BEGIN PUBLIC KEY-----\n${der.toString("base64")}\n-----END PUBLIC KEY-----`;
}

// ── bundle (target independent) ─────────────────────────────────────────────────

async function bundle(libDir, version, pubkey, target) {
  const result = await build({
    absWorkingDir: REPO,
    entryPoints: { agentgate: "daemon/agentgate/src/release-entry.ts", api: "apps/api/src/main.ts" },
    bundle: true,
    splitting: true,
    format: "esm",
    platform: "node",
    target: "node24",
    outdir: libDir,
    outExtension: { ".js": ".mjs" },
    chunkNames: "chunk-[hash]",
    entryNames: "[name]",
    metafile: true,
    minifyWhitespace: true,
    minifySyntax: true,
    legalComments: "none", // collected into THIRD_PARTY_LICENSES.txt instead
    logLevel: "warning",
    // Optional native accelerators / drivers we never ship (their callers fall back).
    external: ["pg-native", "bufferutil", "utf-8-validate"],
    define: {
      __AGENTGATE_RELEASE__: JSON.stringify({ version, target, node: NODE_VERSION }),
      __AGENTGATE_RELEASE_PUBKEY__: JSON.stringify(pubkey),
    },
    // CommonJS dependencies inside ESM chunks need require/__dirname.
    banner: {
      js: "import { createRequire as __agRequire } from 'node:module'; const require = __agRequire(import.meta.url);",
    },
  });
  return result.metafile;
}

/** One license text per third-party package that ended up in the bundle. */
function thirdPartyLicenses(metafile) {
  const pkgs = new Map();
  for (const input of Object.keys(metafile.inputs)) {
    const m = /^(.*node_modules\/(?:@[^/]+\/)?[^/]+)\//.exec(input);
    if (!m) continue;
    const dir = join(REPO, m[1]);
    if (pkgs.has(dir)) continue;
    try {
      const pj = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
      const lic = readdirSync(dir).find((f) => /^(licen[cs]e|copying)(\.|$)/i.test(f));
      pkgs.set(dir, { name: pj.name, version: pj.version, license: pj.license ?? "UNKNOWN", text: lic ? readFileSync(join(dir, lic), "utf8").trim() : "(no license file in package)" });
    } catch {
      /* skip */
    }
  }
  const list = [...pkgs.values()].sort((a, b) => a.name.localeCompare(b.name));
  return [
    "Third-party software bundled in AgentGate release builds.",
    "The Node.js runtime (libexec/node) is covered by libexec/NODE_LICENSE.",
    "",
    ...list.flatMap((p) => ["=".repeat(78), `${p.name}@${p.version} (${p.license})`, "=".repeat(78), p.text, ""]),
  ].join("\n");
}

// ── Node.js runtime ─────────────────────────────────────────────────────────────

async function download(url, dest) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`GET ${url}: HTTP ${res.status}`);
  const tmp = `${dest}.part-${process.pid}`;
  await pipeline(res.body, createWriteStream(tmp));
  renameSync(tmp, dest);
}

async function nodeRuntime(target) {
  const cache = resolve(process.env.AGENTGATE_NODE_CACHE || join(REPO, ".cache", "node"));
  mkdirSync(cache, { recursive: true });
  const name = `node-v${NODE_VERSION}-${target}.tar.gz`;
  const file = join(cache, name);
  const base = `https://nodejs.org/dist/v${NODE_VERSION}`;
  const expected = NODE_SHA256[target];
  if (!expected) die(`no pinned Node.js checksum for ${target}`);
  if (!existsSync(file) || (await sha256File(file)) !== expected) {
    log(`downloading ${base}/${name}`);
    // Cross-check the pinned hash against the published SHASUMS256.txt as well.
    const sums = await (await fetch(`${base}/SHASUMS256.txt`)).text();
    const published = sums.split("\n").find((l) => l.endsWith(`  ${name}`))?.split(/\s+/)[0];
    if (published !== expected) die(`Node.js SHASUMS256.txt (${published}) disagrees with the pinned checksum for ${name}`);
    await download(`${base}/${name}`, file);
  }
  const got = await sha256File(file);
  if (got !== expected) {
    rmSync(file, { force: true });
    die(`checksum mismatch for ${name}: expected ${expected}, got ${got}`);
  }
  const tmp = mkdtempSync(join(tmpdir(), "agentgate-node-"));
  const top = `node-v${NODE_VERSION}-${target}`;
  const r = spawnSync("tar", ["-xzf", file, "-C", tmp, `${top}/bin/node`, `${top}/LICENSE`], { stdio: "inherit" });
  if (r.status !== 0) die(`could not unpack ${name}`);
  return { node: join(tmp, top, "bin", "node"), license: join(tmp, top, "LICENSE"), cleanup: () => rmSync(tmp, { recursive: true, force: true }) };
}

// ── deterministic tar.gz ────────────────────────────────────────────────────────

function listTree(root) {
  const out = [];
  const walk = (d) => {
    for (const n of readdirSync(d).sort()) {
      const p = join(d, n);
      const st = statSync(p);
      const rel = relative(root, p);
      if (st.isDirectory()) {
        out.push({ rel: `${rel}/`, dir: true, mode: 0o755 });
        walk(p);
      } else if (st.isFile()) out.push({ rel, path: p, dir: false, size: st.size, mode: st.mode & 0o111 ? 0o755 : 0o644 });
      else die(`unexpected file type: ${p}`);
    }
  };
  walk(root);
  return out;
}

function tarHeader(e, mtime) {
  const h = Buffer.alloc(512, 0);
  let name = e.rel;
  let prefix = "";
  if (Buffer.byteLength(name) > 100) {
    const cut = name.lastIndexOf("/", name.length - 2 > 155 ? 155 : name.length - 2);
    prefix = name.slice(0, cut);
    name = name.slice(cut + 1);
    if (Buffer.byteLength(name) > 100 || Buffer.byteLength(prefix) > 155) die(`path too long for ustar: ${e.rel}`);
  }
  const oct = (n, len) => n.toString(8).padStart(len - 1, "0") + "\0";
  h.write(name, 0, 100, "utf8");
  h.write(oct(e.mode, 8), 100);
  h.write(oct(0, 8), 108);
  h.write(oct(0, 8), 116);
  h.write(oct(e.dir ? 0 : e.size, 12), 124);
  h.write(oct(mtime, 12), 136);
  h.write("        ", 148);
  h.write(e.dir ? "5" : "0", 156);
  h.write("ustar\0", 257);
  h.write("00", 263);
  h.write(prefix, 345, 155, "utf8");
  let sum = 0;
  for (const b of h) sum += b;
  h.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148);
  return h;
}

async function writeTarGz(root, dest, mtime) {
  const entries = listTree(root);
  const gz = createGzip({ level: 9 });
  const out = createWriteStream(dest);
  const done = pipeline(gz, out);
  const write = (b) => (gz.write(b) ? Promise.resolve() : new Promise((r) => gz.once("drain", r)));
  for (const e of entries) {
    await write(tarHeader(e, mtime));
    if (e.dir) continue;
    for await (const chunk of createReadStream(e.path)) await write(chunk);
    const pad = (512 - (e.size % 512)) % 512;
    if (pad) await write(Buffer.alloc(pad, 0));
  }
  await write(Buffer.alloc(1024, 0));
  gz.end();
  await done;
}

function sourceDateEpoch() {
  if (process.env.SOURCE_DATE_EPOCH) return Number(process.env.SOURCE_DATE_EPOCH);
  try {
    return Number(execFileSync("git", ["log", "-1", "--format=%ct"], { cwd: REPO, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim());
  } catch {
    return Math.floor(Date.now() / 1000);
  }
}

// ── main ────────────────────────────────────────────────────────────────────────

async function main() {
  const version = readVersion();
  const pubkey = releaseKey();
  const targets = flag("--all") ? ALL_TARGETS : (arg("--targets")?.split(",").map((s) => s.trim()).filter(Boolean) ?? DEFAULT_TARGETS);
  for (const t of targets) if (!NODE_SHA256[t]) die(`unknown target ${t} (known: ${ALL_TARGETS.join(", ")})`);
  const outDir = resolve(arg("--out") ?? join(REPO, "dist", "release"));
  const mtime = sourceDateEpoch();
  mkdirSync(outDir, { recursive: true });
  for (const f of readdirSync(outDir)) if (/^agentgate-.*\.tar\.gz$|^SHA256SUMS(\.sig)?$|^install\.sh$/.test(f)) rmSync(join(outDir, f));
  const work = mkdtempSync(join(tmpdir(), "agentgate-release-"));
  log(`version ${version}, targets ${targets.join(", ")}, node ${NODE_VERSION}, key ${pubkey.slice(0, 8)}…`);

  const pgliteDir = dirname(createRequire(join(REPO, "apps/api/package.json")).resolve("@electric-sql/pglite"));
  const sums = [];
  try {
    for (const target of targets) {
      const stage = join(work, target);
      const lib = join(stage, "lib");
      mkdirSync(lib, { recursive: true });
      const meta = await bundle(lib, version, pubkey, target);
      for (const f of PGLITE_ASSETS) copyFileSync(join(pgliteDir, f), join(lib, f));
      cpSync(join(REPO, "adapters/generic/profiles"), join(lib, "profiles"), { recursive: true });
      writeFileSync(join(stage, "THIRD_PARTY_LICENSES.txt"), thirdPartyLicenses(meta));
      copyFileSync(join(REPO, "LICENSE.md"), join(stage, "LICENSE.md"));
      writeFileSync(join(stage, "VERSION"), `${version}\n`);

      mkdirSync(join(stage, "bin"));
      for (const f of ["agentgate", "agentgate-hook.sh"]) {
        copyFileSync(join(REPO, "daemon/agentgate/release/bin", f), join(stage, "bin", f));
        chmodSync(join(stage, "bin", f), 0o755);
      }
      const rt = await nodeRuntime(target);
      mkdirSync(join(stage, "libexec"));
      copyFileSync(rt.node, join(stage, "libexec", "node"));
      chmodSync(join(stage, "libexec", "node"), 0o755);
      copyFileSync(rt.license, join(stage, "libexec", "NODE_LICENSE"));
      rt.cleanup();

      const name = `agentgate-${version}-${target}.tar.gz`;
      await writeTarGz(stage, join(outDir, name), mtime);
      const sha = await sha256File(join(outDir, name));
      sums.push(`${sha}  ${name}`);
      log(`${name}  ${(statSync(join(outDir, name)).size / 1048576).toFixed(1)} MiB`);
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
  writeFileSync(join(outDir, "SHA256SUMS"), `${sums.sort((a, b) => a.slice(66).localeCompare(b.slice(66))).join("\n")}\n`);

  // install.sh with the release key substituted (the repo copy has a placeholder).
  const installer = readFileSync(join(REPO, "install.sh"), "utf8");
  if (!installer.includes("__AGENTGATE_RELEASE_PUBKEY_PEM__")) die("install.sh: key placeholder not found");
  writeFileSync(join(outDir, "install.sh"), installer.replace("__AGENTGATE_RELEASE_PUBKEY_PEM__", pemFromRawKey(pubkey)), { mode: 0o755 });
  log(`wrote ${relative(REPO, outDir) || outDir}/SHA256SUMS and install.sh`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => die(e?.stack ?? String(e)));
}
