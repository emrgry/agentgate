#!/usr/bin/env node
/**
 * Signs a release manifest: SHA256SUMS → SHA256SUMS.sig (Ed25519, see
 * packages/signing/src/release.ts for the exact message format).
 *
 *   AGENTGATE_RELEASE_SIGNING_KEY=<base64url 32-byte seed> \
 *     node --import tsx scripts/sign-release.mjs [dist/release]
 *
 * The seed is read from the environment only (never from a file or argv, so it does not
 * end up in shell history or process listings). Before writing anything the script checks
 * that the seed belongs to the public key the CLI build embeds (release-key.ts, or the
 * AGENTGATE_RELEASE_PUBLIC_KEY build override), then verifies the signature it produced.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseReleaseSeed, releasePublicKey, signReleaseManifest, verifyReleaseManifest } from "../packages/signing/src/release.ts";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const die = (m) => {
  process.stderr.write(`sign-release: ERROR: ${m}\n`);
  process.exit(1);
};

const dir = resolve(process.argv[2] ?? join(REPO, "dist", "release"));
const raw = process.env.AGENTGATE_RELEASE_SIGNING_KEY;
if (!raw) die("AGENTGATE_RELEASE_SIGNING_KEY is not set");
let seed;
try {
  seed = parseReleaseSeed(raw);
} catch (e) {
  die(e.message);
}
const pub = releasePublicKey(seed);

const src = readFileSync(join(REPO, "daemon/agentgate/src/release-key.ts"), "utf8");
const placeholder = /DEV_PLACEHOLDER_RELEASE_PUBLIC_KEY = "([A-Za-z0-9_-]{43})"/.exec(src)?.[1];
const source = /SOURCE_RELEASE_PUBLIC_KEY = (?:"([A-Za-z0-9_-]{43})"|DEV_PLACEHOLDER_RELEASE_PUBLIC_KEY);/.exec(src);
if (!placeholder || !source) die("cannot parse daemon/agentgate/src/release-key.ts");
const embedded = process.env.AGENTGATE_RELEASE_PUBLIC_KEY?.trim() || source[1] || placeholder;
if (pub !== embedded) {
  die(`the signing key's public key (${pub}) is not the key embedded in the CLI build (${embedded}) — the release would be rejected by \`agentgate update\``);
}

const manifest = readFileSync(join(dir, "SHA256SUMS"));
const sig = signReleaseManifest(new Uint8Array(manifest), seed);
const check = verifyReleaseManifest(new Uint8Array(manifest), sig, pub);
if (!check.ok) die(`self-check failed: ${check.reason}`);
writeFileSync(join(dir, "SHA256SUMS.sig"), sig);
process.stderr.write(`sign-release: signed ${join(dir, "SHA256SUMS")} with ${pub}\n`);
