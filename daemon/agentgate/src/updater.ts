import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyReleaseManifest } from "@agentgate/signing/release";

/**
 * Release installation state under an install home (default ~/.agentgate):
 *
 *   versions/<version>/   extracted release tarballs (bin/, libexec/node, lib/, VERSION)
 *   current  → versions/<version>   (relative symlink, flipped atomically with rename(2))
 *   previous → versions/<version>   (what `agentgate update --rollback` returns to)
 *
 * Everything that reaches the network is verified before it is used: SHA256SUMS must carry
 * a valid Ed25519 signature by the pinned release key, and the tarball must match the
 * signed checksum. Nothing is extracted or activated otherwise (fail closed).
 */

export const DEFAULT_RELEASE_BASE_URL = "https://github.com/emrgry/agentgate/releases";
/** Strict: versions become path components. */
export const VERSION_RE = /^\d{1,6}\.\d{1,6}\.\d{1,6}(?:-[0-9A-Za-z][0-9A-Za-z.]{0,31})?$/;
export const TARGET_RE = /^(?:darwin|linux)-(?:arm64|x64)$/;
/** Old versions kept besides `current` (the newest ones, `previous` first). */
export const KEEP_OLD_VERSIONS = 2;
const MAX_DOWNLOAD_BYTES = 400 * 1024 * 1024;
const REQUIRED_FILES = ["bin/agentgate", "bin/agentgate-hook.sh", "libexec/node", "lib/agentgate.mjs", "lib/api.mjs", "VERSION"];

export class UpdateError extends Error {
  constructor(
    readonly code: "signature" | "checksum" | "manifest" | "network" | "layout" | "state" | "locked",
    message: string,
  ) {
    super(message);
  }
}

export function isVersion(v: unknown): v is string {
  return typeof v === "string" && VERSION_RE.test(v);
}

/** Semver-ish comparison (numeric core; a prerelease sorts before its release). */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string) => {
    const [core, pre] = v.split("-", 2) as [string, string | undefined];
    return { nums: core.split(".").map(Number), pre };
  };
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < 3; i++) {
    const d = (x.nums[i] ?? 0) - (y.nums[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  if (x.pre === y.pre) return 0;
  if (x.pre === undefined) return 1;
  if (y.pre === undefined) return -1;
  return x.pre < y.pre ? -1 : 1;
}

export const releaseFileName = (version: string, target: string) => `agentgate-${version}-${target}.tar.gz`;

/** Parses `<sha256>  <file>` lines (sha256sum/shasum format). Throws on anything else. */
export function parseSums(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    const m = /^([0-9a-f]{64}) [ *]([A-Za-z0-9._-]+)$/.exec(line);
    if (!m) throw new UpdateError("manifest", `malformed SHA256SUMS line: ${JSON.stringify(line.slice(0, 120))}`);
    if (out.has(m[2]!)) throw new UpdateError("manifest", `duplicate SHA256SUMS entry for ${m[2]}`);
    out.set(m[2]!, m[1]!);
  }
  if (out.size === 0) throw new UpdateError("manifest", "SHA256SUMS is empty");
  return out;
}

/** The single release version named by the tarballs in SHA256SUMS; the target must be present. */
export function versionFromSums(sums: Map<string, string>, target: string): string {
  const versions = new Set<string>();
  for (const f of sums.keys()) {
    const m = /^agentgate-(.+)-((?:darwin|linux)-(?:arm64|x64))\.tar\.gz$/.exec(f);
    if (m) versions.add(m[1]!);
  }
  if (versions.size !== 1) throw new UpdateError("manifest", `SHA256SUMS must describe exactly one release (found ${versions.size})`);
  const version = [...versions][0]!;
  if (!isVersion(version)) throw new UpdateError("manifest", `invalid release version in SHA256SUMS: ${JSON.stringify(version)}`);
  if (!sums.has(releaseFileName(version, target))) throw new UpdateError("manifest", `release ${version} has no build for ${target}`);
  return version;
}

export const sha256Hex = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

// ── network ─────────────────────────────────────────────────────────────────

export type Fetcher = (url: string) => Promise<Uint8Array>;

/** Release base URL: https (any host), http only for loopback (tests), file:// (tests/mirrors). */
export function checkBaseUrl(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new UpdateError("network", `invalid release URL: ${raw}`);
  }
  const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(u.hostname);
  if (!(u.protocol === "https:" || u.protocol === "file:" || (u.protocol === "http:" && loopback))) {
    throw new UpdateError("network", `refusing release URL ${raw} (https, file: or loopback http only)`);
  }
  return raw.replace(/\/+$/, "");
}

export const defaultFetcher: Fetcher = async (url) => {
  if (url.startsWith("file:")) {
    try {
      return new Uint8Array(readFileSync(fileURLToPath(url)));
    } catch (err) {
      throw new UpdateError("network", `cannot read ${url}: ${(err as Error).message}`);
    }
  }
  let res: Response;
  try {
    res = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(300_000), headers: { "user-agent": "agentgate-update" } });
  } catch (err) {
    throw new UpdateError("network", `download failed (${url}): ${(err as Error).message}`);
  }
  if (!res.ok) throw new UpdateError("network", `download failed (${url}): HTTP ${res.status}`);
  const len = Number(res.headers.get("content-length") ?? 0);
  if (len > MAX_DOWNLOAD_BYTES) throw new UpdateError("network", `download too large (${len} bytes)`);
  const buf = new Uint8Array(await res.arrayBuffer());
  if (buf.length > MAX_DOWNLOAD_BYTES) throw new UpdateError("network", "download too large");
  return buf;
};

export interface ResolvedRelease {
  version: string;
  fileName: string;
  sha256: string;
  /** URL of the directory the assets were read from. */
  dir: string;
}

/**
 * Downloads SHA256SUMS + SHA256SUMS.sig for `version` (or the latest release) and returns
 * the verified checksum of this target's tarball. The signature is REQUIRED.
 */
export async function resolveRelease(o: { baseUrl: string; version?: string; target: string; publicKey: string; fetch: Fetcher }): Promise<ResolvedRelease> {
  if (o.version !== undefined && !isVersion(o.version)) throw new UpdateError("manifest", `invalid version: ${JSON.stringify(o.version)}`);
  if (!TARGET_RE.test(o.target)) throw new UpdateError("layout", `unsupported target ${o.target}`);
  const base = checkBaseUrl(o.baseUrl);
  const dir = o.version ? `${base}/download/v${o.version}` : `${base}/latest/download`;
  const sums = await o.fetch(`${dir}/SHA256SUMS`);
  let sig: Uint8Array;
  try {
    sig = await o.fetch(`${dir}/SHA256SUMS.sig`);
  } catch (err) {
    throw new UpdateError("signature", `release signature (SHA256SUMS.sig) is missing — refusing to update (${(err as Error).message})`);
  }
  const v = verifyReleaseManifest(sums, new TextDecoder().decode(sig), o.publicKey);
  if (!v.ok) throw new UpdateError("signature", `release signature is not valid (${v.reason}) — refusing to update`);
  const parsed = parseSums(new TextDecoder("utf-8", { fatal: true }).decode(sums));
  const version = versionFromSums(parsed, o.target);
  if (o.version && version !== o.version) throw new UpdateError("manifest", `asked for ${o.version} but the signed manifest describes ${version}`);
  const fileName = releaseFileName(version, o.target);
  return { version, fileName, sha256: parsed.get(fileName)!, dir };
}

// ── local store ─────────────────────────────────────────────────────────────

export interface StoreState {
  current: string | null;
  previous: string | null;
  installed: string[];
}

export type Extractor = (tarball: string, dest: string) => void;

export const tarExtractor: Extractor = (tarball, dest) => {
  const tar = existsSync("/usr/bin/tar") ? "/usr/bin/tar" : "tar";
  const r = spawnSync(tar, ["-xzf", tarball, "-C", dest], { encoding: "utf8", timeout: 300_000 });
  if (r.status !== 0) throw new UpdateError("layout", `could not extract the release: ${(r.stderr || r.error?.message || "").trim()}`);
};

export class ReleaseStore {
  readonly versionsDir: string;
  readonly currentLink: string;
  readonly previousLink: string;

  constructor(
    readonly installHome: string,
    private readonly extract: Extractor = tarExtractor,
  ) {
    this.versionsDir = join(installHome, "versions");
    this.currentLink = join(installHome, "current");
    this.previousLink = join(installHome, "previous");
  }

  private linkVersion(link: string): string | null {
    try {
      const t = readlinkSync(link);
      const m = /^versions\/(.+)$/.exec(t) ?? (t.startsWith(`${this.versionsDir}/`) ? [t, t.slice(this.versionsDir.length + 1)] : null);
      return m && isVersion(m[1]) ? m[1]! : null;
    } catch {
      return null;
    }
  }

  state(): StoreState {
    let installed: string[] = [];
    try {
      installed = readdirSync(this.versionsDir).filter((n) => isVersion(n) && this.isComplete(n));
    } catch {
      /* none */
    }
    installed.sort(compareVersions);
    return { current: this.linkVersion(this.currentLink), previous: this.linkVersion(this.previousLink), installed };
  }

  dirOf(version: string): string {
    if (!isVersion(version)) throw new UpdateError("state", `invalid version ${version}`);
    return join(this.versionsDir, version);
  }

  isComplete(version: string): boolean {
    const d = join(this.versionsDir, version);
    try {
      return REQUIRED_FILES.every((f) => statSync(join(d, f)).isFile()) && readFileSync(join(d, "VERSION"), "utf8").trim() === version;
    } catch {
      return false;
    }
  }

  /** Verifies the checksum, extracts into versions/<version> (replacing an old copy). */
  install(version: string, tarball: Uint8Array, expectedSha256: string): string {
    const dest = this.dirOf(version);
    const got = sha256Hex(tarball);
    if (got !== expectedSha256.toLowerCase()) throw new UpdateError("checksum", `checksum mismatch for ${version}: expected ${expectedSha256}, got ${got} — refusing to install`);
    mkdirSync(this.versionsDir, { recursive: true, mode: 0o755 });
    const work = mkdtempSync(join(this.versionsDir, ".incoming-"));
    try {
      const file = join(work, "release.tar.gz");
      writeFileSync(file, tarball, { mode: 0o600 });
      const tree = join(work, "tree");
      mkdirSync(tree, { mode: 0o755 });
      this.extract(file, tree);
      validateTree(tree, version);
      if (existsSync(dest)) {
        const old = join(work, "old");
        renameSync(dest, old);
      }
      renameSync(tree, dest);
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
    return dest;
  }

  private setLink(link: string, version: string) {
    const tmp = `${link}.tmp-${process.pid}-${Date.now()}`;
    symlinkSync(`versions/${version}`, tmp);
    renameSync(tmp, link); // atomic replacement (rename(2) never follows the destination symlink)
  }

  /** Points `current` at `version`; the old current becomes `previous`. */
  activate(version: string): { from: string | null; to: string } {
    if (!this.isComplete(version)) throw new UpdateError("state", `version ${version} is not (completely) installed`);
    const from = this.state().current;
    if (from && from !== version) this.setLink(this.previousLink, from);
    this.setLink(this.currentLink, version);
    return { from, to: version };
  }

  /** Swaps `current` and `previous`. */
  rollback(): { from: string; to: string } {
    const s = this.state();
    if (!s.previous || !this.isComplete(s.previous)) throw new UpdateError("state", "no previous version to roll back to");
    if (!s.current) throw new UpdateError("state", "no current version");
    this.setLink(this.currentLink, s.previous);
    this.setLink(this.previousLink, s.current);
    return { from: s.current, to: s.previous };
  }

  /**
   * Removes old versions so at most `keep` remain besides `current` (`previous` is always
   * kept first, then the newest). `protect` (e.g. the running version) is never removed.
   */
  prune(keep = KEEP_OLD_VERSIONS, protect: string[] = []): string[] {
    const s = this.state();
    const old = s.installed.filter((v) => v !== s.current).sort((a, b) => compareVersions(b, a));
    const ordered = s.previous && old.includes(s.previous) ? [s.previous, ...old.filter((v) => v !== s.previous)] : old;
    const removed: string[] = [];
    for (const v of ordered.slice(keep)) {
      if (protect.includes(v)) continue;
      rmSync(join(this.versionsDir, v), { recursive: true, force: true });
      removed.push(v);
    }
    // Leftovers of interrupted installs (never the one in progress: those are locked).
    try {
      for (const n of readdirSync(this.versionsDir)) {
        if (n.startsWith(".incoming-")) rmSync(join(this.versionsDir, n), { recursive: true, force: true });
      }
    } catch {
      /* none */
    }
    return removed;
  }

  /** Exclusive lock for update operations (stale after 30 min). */
  lock(): () => void {
    mkdirSync(this.installHome, { recursive: true, mode: 0o700 });
    const file = join(this.installHome, "update.lock");
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const fd = openSync(file, "wx", 0o600);
        writeFileSync(fd, String(process.pid));
        closeSync(fd);
        return () => rmSync(file, { force: true });
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
        try {
          if (Date.now() - statSync(file).mtimeMs > 30 * 60_000) {
            unlinkSync(file);
            continue;
          }
        } catch {
          continue;
        }
        throw new UpdateError("locked", `another update is in progress (${file})`);
      }
    }
    throw new UpdateError("locked", `could not take ${file}`);
  }
}

/** The extracted tree must be exactly a release: regular files + dirs, required files, right VERSION. */
export function validateTree(tree: string, version: string): void {
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      const st = lstatSync(p);
      if (st.isSymbolicLink()) throw new UpdateError("layout", `release contains a symlink (${p.slice(tree.length + 1)}) — refusing`);
      if (st.isDirectory()) {
        chmodSync(p, st.mode & 0o755);
        walk(p);
      } else if (st.isFile()) chmodSync(p, st.mode & 0o755);
      else throw new UpdateError("layout", `release contains a special file (${p.slice(tree.length + 1)}) — refusing`);
    }
  };
  walk(tree);
  for (const f of REQUIRED_FILES) {
    if (!existsSync(join(tree, f))) throw new UpdateError("layout", `release is missing ${f}`);
  }
  const v = readFileSync(join(tree, "VERSION"), "utf8").trim();
  if (v !== version) throw new UpdateError("layout", `release VERSION is ${JSON.stringify(v)}, expected ${version}`);
}
