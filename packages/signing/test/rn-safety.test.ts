/**
 * RN / Hermes safety: the main entry point (and everything it transitively imports,
 * including @agentgate/protocol and the @noble files it loads) must not import a Node
 * builtin or reference Buffer / process / require. Static scan of the import graph.
 */
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { builtinModules, createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(here, "..");
const repoRoot = resolve(pkgRoot, "../..");
const ENTRY = join(pkgRoot, "src/index.ts");
const NODE_ENTRY = join(pkgRoot, "src/node.ts");

/** Bare specifiers the RN bundle may load. */
const ALLOWED_PACKAGES = [/^@noble\/curves\//, /^@noble\/hashes\//, /^@agentgate\/protocol$/, /^zod$/];
/** Packages whose sources we also scan (zod is large and RN-proven; not scanned). */
const SCANNED_PACKAGES = [/^@noble\//, /^@agentgate\/protocol$/];
const NODE_BUILTINS = new Set([...builtinModules, ...builtinModules.map((m) => `node:${m}`)]);

const IMPORT_RE = /(?:^|[\s;])(?:import|export)\s[^'"`]*?from\s*["']([^"']+)["']|(?:^|[\s;(])import\s*\(\s*["']([^"']+)["']\s*\)|(?:^|[\s;])import\s*["']([^"']+)["']/g;

function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'`\\])\/\/[^\n]*/g, "$1");
}

function specifiers(src: string): string[] {
  const out: string[] = [];
  for (const m of stripComments(src).matchAll(IMPORT_RE)) out.push((m[1] ?? m[2] ?? m[3])!);
  return out;
}

function resolveRelative(from: string, spec: string): string {
  const base = resolve(dirname(from), spec);
  for (const c of [base, `${base}.ts`, `${base}.js`, join(base, "index.ts"), join(base, "index.js")]) {
    if (existsSync(c) && !c.endsWith("/")) return c;
  }
  throw new Error(`cannot resolve ${spec} from ${from}`);
}

const req = createRequire(join(pkgRoot, "package.json"));
function resolvePackage(spec: string): string {
  if (spec === "@agentgate/protocol") return join(repoRoot, "packages/protocol/src/index.ts");
  return req.resolve(spec);
}

interface Finding {
  file: string;
  problem: string;
}

function scan(entry: string): { files: string[]; findings: Finding[] } {
  const seen = new Set<string>();
  const findings: Finding[] = [];
  const queue = [entry];
  while (queue.length) {
    const file = queue.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    const src = readFileSync(file, "utf8");
    const code = stripComments(src);
    if (/\bBuffer\b/.test(code)) findings.push({ file, problem: "references Buffer" });
    if (/\bprocess\s*\./.test(code) || /\bprocess\s*\[/.test(code)) findings.push({ file, problem: "references process" });
    if (/\brequire\s*\(/.test(code)) findings.push({ file, problem: "uses require()" });
    for (const spec of specifiers(src)) {
      if (spec.startsWith(".")) {
        queue.push(resolveRelative(file, spec));
      } else if (NODE_BUILTINS.has(spec) || spec.startsWith("node:")) {
        findings.push({ file, problem: `imports Node builtin ${spec}` });
      } else if (file.startsWith(pkgRoot) && !ALLOWED_PACKAGES.some((re) => re.test(spec))) {
        findings.push({ file, problem: `imports non-allowlisted package ${spec}` });
      } else if (SCANNED_PACKAGES.some((re) => re.test(spec))) {
        queue.push(resolvePackage(spec));
      }
    }
  }
  return { files: [...seen], findings };
}

describe("RN safety: @agentgate/signing main entry", () => {
  const result = scan(ENTRY);

  it("walks our sources, the protocol package and the noble files actually loaded", () => {
    const rel = result.files.map((f) => f.replace(`${repoRoot}/`, ""));
    expect(rel).toContain("packages/signing/src/index.ts");
    expect(rel).toContain("packages/signing/src/encoding.ts");
    expect(rel).toContain("packages/signing/src/canonical-json.ts");
    expect(rel).toContain("packages/protocol/src/index.ts");
    expect(rel.some((f) => f.includes("@noble/curves/ed25519.js"))).toBe(true);
    expect(rel.some((f) => f.includes("@noble/hashes/sha2.js"))).toBe(true);
    expect(rel).not.toContain("packages/signing/src/node.ts");
  });

  it("imports no node: builtin and never references Buffer / process / require", () => {
    expect(result.findings).toEqual([]);
  });

  it("the scanner itself catches violations (sanity check on the node entry)", () => {
    const bad = scan(NODE_ENTRY);
    expect(bad.findings.some((f) => /Node builtin node:crypto/.test(f.problem))).toBe(true);
  });

  it("the scanner catches Buffer, process, require and bare builtins in a synthetic file", () => {
    const dir = mkdtempSync(join(tmpdir(), "rn-scan-"));
    const f = join(dir, "bad.ts");
    writeFileSync(f, 'import fs from "fs";\nconst b = Buffer.from("x");\nconst e = process.env.X;\nconst c = require("crypto");\n// Buffer in a comment is fine\n');
    const problems = scan(f).findings.map((x) => x.problem);
    expect(problems).toEqual(expect.arrayContaining(["references Buffer", "references process", "uses require()", "imports Node builtin fs"]));
    const ok = join(dir, "ok.ts");
    writeFileSync(ok, "// Buffer and process.env mentioned only in comments\n/* require('x') */\nexport const a = 1;\n");
    expect(scan(ok).findings).toEqual([]);
  });

  it("package.json exposes the node helpers only under ./node", () => {
    const pkg = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
    expect(pkg.exports["."]).toBe("./src/index.ts");
    expect(pkg.exports["./node"]).toBe("./src/node.ts");
    expect(pkg.dependencies["@noble/curves"]).toMatch(/^\d+\.\d+\.\d+$/); // pinned exactly
    expect(pkg.dependencies["@noble/hashes"]).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
