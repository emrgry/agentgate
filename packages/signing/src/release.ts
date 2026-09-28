/**
 * Release signing: Ed25519 over the release's SHA256SUMS manifest.
 *
 * The release pipeline signs SHA256SUMS (scripts/sign-release.mjs) with a key held only in
 * the CI secret AGENTGATE_RELEASE_SIGNING_KEY. `agentgate update` verifies the signature
 * against a public key pinned in the CLI build before trusting any checksum in it.
 *
 * Signed message = UTF-8("agentgate-release:v1\n") ‖ raw SHA256SUMS bytes (domain separated,
 * so a release signature can never be confused with any other AgentGate signature).
 * SHA256SUMS.sig = base64url(64-byte signature) + "\n".
 *
 * Pure JS (no node: builtins) like the rest of this package.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { base64urlDecode, base64urlEncode, utf8Encode } from "./encoding.ts";

export const RELEASE_SIGNATURE_PREFIX = "agentgate-release:v1\n";

/** The exact bytes that are signed for a manifest. */
export function releaseMessage(manifest: Uint8Array): Uint8Array {
  const prefix = utf8Encode(RELEASE_SIGNATURE_PREFIX);
  const out = new Uint8Array(prefix.length + manifest.length);
  out.set(prefix, 0);
  out.set(manifest, prefix.length);
  return out;
}

/** Sign SHA256SUMS bytes with a raw 32-byte seed. Returns the .sig file content. */
export function signReleaseManifest(manifest: Uint8Array, seed: Uint8Array): string {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new TypeError("release signing key must be a raw 32-byte Ed25519 seed");
  return `${base64urlEncode(ed25519.sign(releaseMessage(manifest), seed))}\n`;
}

/** base64url raw public key for a seed. */
export function releasePublicKey(seed: Uint8Array): string {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new TypeError("release signing key must be a raw 32-byte Ed25519 seed");
  return base64urlEncode(ed25519.getPublicKey(seed));
}

/** Parse a base64url raw 32-byte seed (AGENTGATE_RELEASE_SIGNING_KEY). Throws on anything else. */
export function parseReleaseSeed(text: string): Uint8Array {
  const raw = base64urlDecode(text.trim());
  if (!raw || raw.length !== 32) throw new TypeError("expected a base64url-encoded raw 32-byte Ed25519 seed");
  return raw;
}

export type ReleaseVerification = { ok: true } | { ok: false; reason: "bad_public_key" | "malformed_signature" | "bad_signature" };

/**
 * Strict verification (RFC 8032, no ZIP-215 leniency). The signature file may carry
 * surrounding whitespace only; anything else is malformed.
 */
export function verifyReleaseManifest(manifest: Uint8Array, signatureFile: string, publicKeyB64url: string): ReleaseVerification {
  const pub = typeof publicKeyB64url === "string" && publicKeyB64url.length === 43 ? base64urlDecode(publicKeyB64url) : null;
  if (!pub || pub.length !== 32) return { ok: false, reason: "bad_public_key" };
  const text = typeof signatureFile === "string" ? signatureFile.trim() : "";
  const sig = /^[A-Za-z0-9_-]{86}$/.test(text) ? base64urlDecode(text) : null;
  if (!sig || sig.length !== 64) return { ok: false, reason: "malformed_signature" };
  let ok = false;
  try {
    ok = ed25519.verify(sig, releaseMessage(manifest), pub, { zip215: false });
  } catch {
    ok = false;
  }
  return ok ? { ok: true } : { ok: false, reason: "bad_signature" };
}
