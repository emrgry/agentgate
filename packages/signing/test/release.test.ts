import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { parseReleaseSeed, releasePublicKey, signReleaseManifest, verifyReleaseManifest, RELEASE_SIGNATURE_PREFIX } from "../src/release.ts";
import { base64urlEncode } from "../src/encoding.ts";
import { ed25519 } from "@noble/curves/ed25519.js";

const enc = (s: string) => new TextEncoder().encode(s);
const SUMS = enc(`${"a".repeat(64)}  agentgate-1.2.3-darwin-arm64.tar.gz\n`);

describe("release manifest signatures", () => {
  const seed = new Uint8Array(randomBytes(32));
  const pub = releasePublicKey(seed);

  it("round-trips", () => {
    const sig = signReleaseManifest(SUMS, seed);
    expect(sig).toMatch(/^[A-Za-z0-9_-]{86}\n$/);
    expect(verifyReleaseManifest(SUMS, sig, pub)).toEqual({ ok: true });
  });

  it("rejects a modified manifest, another key, and malformed input", () => {
    const sig = signReleaseManifest(SUMS, seed);
    const tampered = enc(`${"b".repeat(64)}  agentgate-1.2.3-darwin-arm64.tar.gz\n`);
    expect(verifyReleaseManifest(tampered, sig, pub)).toEqual({ ok: false, reason: "bad_signature" });
    expect(verifyReleaseManifest(SUMS, sig, releasePublicKey(new Uint8Array(randomBytes(32))))).toEqual({ ok: false, reason: "bad_signature" });
    expect(verifyReleaseManifest(SUMS, "", pub)).toEqual({ ok: false, reason: "malformed_signature" });
    expect(verifyReleaseManifest(SUMS, `${sig.trim()}x`, pub)).toEqual({ ok: false, reason: "malformed_signature" });
    expect(verifyReleaseManifest(SUMS, sig, "not-a-key")).toEqual({ ok: false, reason: "bad_public_key" });
  });

  it("is domain separated: a raw signature over SHA256SUMS alone does not verify", () => {
    const raw = `${base64urlEncode(ed25519.sign(SUMS, seed))}\n`;
    expect(verifyReleaseManifest(SUMS, raw, pub).ok).toBe(false);
    const prefixed = new Uint8Array([...enc(RELEASE_SIGNATURE_PREFIX), ...SUMS]);
    expect(verifyReleaseManifest(SUMS, `${base64urlEncode(ed25519.sign(prefixed, seed))}\n`, pub).ok).toBe(true);
  });

  it("parses seeds strictly", () => {
    expect(parseReleaseSeed(` ${base64urlEncode(seed)}\n`)).toEqual(seed);
    expect(() => parseReleaseSeed("abc")).toThrow();
    expect(() => parseReleaseSeed(base64urlEncode(new Uint8Array(31)))).toThrow();
  });

  it("matches node:crypto Ed25519 (seed format used by gen-release-key.mjs)", async () => {
    const { createPrivateKey, createPublicKey } = await import("node:crypto");
    const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed)]);
    const spki = createPublicKey(createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" })).export({ format: "der", type: "spki" });
    expect(Buffer.from(spki.subarray(12)).toString("base64url")).toBe(pub);
  });
});
