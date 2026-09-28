#!/usr/bin/env node
/**
 * Generates a new Ed25519 release signing key pair.
 *
 *   node scripts/gen-release-key.mjs            prints the PUBLIC key only (+ fingerprint)
 *   node scripts/gen-release-key.mjs --seed     ALSO prints the secret seed on stdout
 *
 * Nothing is written to disk. Put the seed straight into the GitHub secret, e.g.
 *   node scripts/gen-release-key.mjs --seed | tail -n 1 | gh secret set AGENTGATE_RELEASE_SIGNING_KEY
 * and the public key into daemon/agentgate/src/release-key.ts (SOURCE_RELEASE_PUBLIC_KEY).
 * See docs/releasing.md.
 */
import { createHash, generateKeyPairSync } from "node:crypto";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(16); // raw 32-byte seed
const pub = publicKey.export({ format: "der", type: "spki" }).subarray(12); // raw 32-byte key
if (seed.length !== 32 || pub.length !== 32) throw new Error("unexpected key encoding");
const fp = createHash("sha256").update(pub).digest("base64url").slice(0, 22);

process.stderr.write(`public key (SOURCE_RELEASE_PUBLIC_KEY in daemon/agentgate/src/release-key.ts):\n`);
process.stdout.write(`${pub.toString("base64url")}\n`);
process.stderr.write(`fingerprint: ${fp}\n`);
if (process.argv.includes("--seed")) {
  process.stderr.write(`secret seed (AGENTGATE_RELEASE_SIGNING_KEY; store it ONLY in the GitHub secret / a password manager):\n`);
  process.stdout.write(`${seed.toString("base64url")}\n`);
} else {
  process.stderr.write("(secret seed not shown; this key pair is useless — re-run with --seed when you are ready to store it)\n");
}
